/* سند الصحي - خادم كامل دون حزم خارجية. متطلبات التشغيل: Node.js 22.13+ */
'use strict';
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {DatabaseSync} = require('node:sqlite');
const ROOT = __dirname;
const PUBLIC = path.join(ROOT, 'public');
const DATA = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : path.join(ROOT,'data');
const PRIVATE = process.env.UPLOAD_DIR ? path.resolve(process.env.UPLOAD_DIR) : path.join(ROOT,'private_uploads');
for (const d of [DATA,PRIVATE]) fs.mkdirSync(d,{recursive:true,mode:0o700});
const db = new DatabaseSync(path.join(DATA,'sanad.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
 name TEXT NOT NULL, phone TEXT DEFAULT '', email TEXT DEFAULT '', national_id TEXT DEFAULT '',
 role TEXT NOT NULL CHECK(role IN ('admin','supervisor','member')),
 status TEXT NOT NULL DEFAULT 'pending', permissions TEXT NOT NULL DEFAULT '[]', condition TEXT DEFAULT '',
 plan TEXT DEFAULT 'free', member_number TEXT UNIQUE, joined_at TEXT, expires_at TEXT,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS applications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL UNIQUE REFERENCES users(id),
 status TEXT NOT NULL DEFAULT 'pending', medical_doc TEXT, identity_doc TEXT,
 supervisor_id INTEGER, supervisor_note TEXT DEFAULT '', supervisor_decision TEXT DEFAULT '',
 admin_id INTEGER, admin_note TEXT DEFAULT '', created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
 reviewed_at TEXT, approved_at TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS sessions (
 token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 csrf TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS content (
 id INTEGER PRIMARY KEY AUTOINCREMENT, type TEXT NOT NULL CHECK(type IN ('ads','offers','partners')),
 title TEXT NOT NULL, details TEXT NOT NULL DEFAULT '', category TEXT NOT NULL DEFAULT '',
 value TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notifications (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 title TEXT NOT NULL, message TEXT NOT NULL DEFAULT '', seen INTEGER NOT NULL DEFAULT 0,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit (
 id INTEGER PRIMARY KEY AUTOINCREMENT, actor INTEGER, action TEXT NOT NULL,
 object_type TEXT NOT NULL, object_id INTEGER, note TEXT NOT NULL DEFAULT '',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_app_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);`);
const PREHASH = 'scrypt$48ba5ff7e00580eac1c820876a1f2826$ca3634950369c4459cc3895b4b09bc7e5324fcf8ffbd417627677229cf8c3b12a88665fd02547978a307ed59c6e595bc37eac4985a01a5b18f7cacb1ab860a55';
function initialPasswordHash(password){const salt=crypto.randomBytes(16).toString('hex');return 'scrypt$'+salt+'$'+crypto.scryptSync(password,salt,64).toString('hex')};
const admin = db.prepare('SELECT id,role FROM users WHERE username=?').get('admin');
if(!admin){
 const h = process.env.ADMIN_INITIAL_PASSWORD ? initialPasswordHash(process.env.ADMIN_INITIAL_PASSWORD) : PREHASH;
 db.prepare(`INSERT INTO users(username,password_hash,name,role,status,permissions) VALUES (?,?,?,?,?,?)`)
 .run('admin',h,'المدير العام','admin','active','["*"]');
}
for (const [k,v] of Object.entries({site_name:'سند الصحي',review_mode:'supervisor_then_admin',annual_premium_price:'20',allow_signup:'true'}))
 db.prepare('INSERT OR IGNORE INTO settings(key,value) VALUES (?,?)').run(k,v);
const now = () => new Date().toISOString();
const txt = (v,max=255) => String(v??'').trim().slice(0,max);
const hashPassword = (password) => {const salt=crypto.randomBytes(16).toString('hex');return 'scrypt$'+salt+'$'+crypto.scryptSync(password,salt,64).toString('hex')};
function verifyPassword(password,stored){
 try{const [alg,salt,hex]=stored.split('$');if(alg!=='scrypt'||!salt||!hex)return false;
 const expected=Buffer.from(hex,'hex');const got=crypto.scryptSync(password,salt,expected.length);
 return expected.length===got.length && crypto.timingSafeEqual(expected,got)}catch{return false}
}
const rid=()=>crypto.randomBytes(24).toString('hex');
const sha=(s)=>crypto.createHash('sha256').update(s).digest('hex');
const fail=(status,msg)=>{let err=new Error(msg);err.status=status;throw err};
function json(res,obj,status=200,headers={}){res.writeHead(status,{'Content-Type':'application/json; charset=utf-8','Cache-Control':'no-store',...headers});res.end(JSON.stringify(obj))}
function ip(req){return txt(req.socket.remoteAddress,90)}
const limits=new Map();
function rate(req,key,limit,period){
 const k=ip(req)+'/'+key,t=Date.now();const a=(limits.get(k)||[]).filter(x=>x>t-period);a.push(t);limits.set(k,a);
 if(a.length>limit)fail(429,'محاولات كثيرة. حاول بعد قليل.');
 if(limits.size>15000) for(const key of limits.keys()){limits.delete(key);if(limits.size<10000)break}
}
function parseCookies(req){const cookies={};(req.headers.cookie||'').split(';').forEach(p=>{let i=p.indexOf('=');if(i>0)cookies[p.slice(0,i).trim()]=p.slice(i+1).trim()});return cookies}
function auth(req){const token=parseCookies(req).sanad_sid;if(!token||!/^[a-f0-9]{48}$/.test(token))return null;
 const s=db.prepare(`SELECT sessions.csrf,sessions.expires_at AS session_expires_at,users.* FROM sessions JOIN users ON sessions.user_id=users.id WHERE sessions.token_hash=?`).get(sha(token));
 if(!s||s.session_expires_at<Date.now()||(['suspended','deleted'].includes(s.status)))return null;
 s.perms = JSON.parse(s.permissions||'[]');return s;
}
function requireAuth(u){if(!u)fail(401,'يجب تسجيل الدخول أولاً');return u}
function can(u,p){return !!u && (u.role==='admin' || (u.role==='supervisor' && u.status==='active' && u.perms.includes(p)))}
function permit(u,p){requireAuth(u);if(!can(u,p))fail(403,'ليس لديك صلاحية لهذه العملية')}
function isAdmin(u){requireAuth(u);if(u.role!=='admin')fail(403,'هذه الصلاحية للمدير العام فقط')}
function activeMember(u){requireAuth(u);if(u.role==='member'&&u.status!=='active')fail(403,'الحساب قيد مراجعة الإدارة؛ لم تُفعّل العضوية بعد')}
function safeUser(u){if(!u)return null;return {id:u.id,username:u.username,name:u.name,phone:u.phone,email:u.email,role:u.role,status:u.status,permissions:u.role==='admin'?['*']:(u.perms||JSON.parse(u.permissions||'[]')),condition:u.condition,plan:u.plan,memberNumber:u.member_number,joinedAt:u.joined_at,expiresAt:u.expires_at,createdAt:u.created_at}}
function audit(actor,action,type,id,note=''){db.prepare('INSERT INTO audit(actor,action,object_type,object_id,note) VALUES(?,?,?,?,?)').run(actor?.id||null,action,type,id||null,txt(note,600))}
function notify(userId,title,message){db.prepare('INSERT INTO notifications(user_id,title,message) VALUES(?,?,?)').run(userId,txt(title),txt(message,800))}
function alertStaff(title,message){db.prepare("SELECT id FROM users WHERE role IN ('admin','supervisor') AND status='active'").all().forEach(x=>notify(x.id,title,message))}
function settings(){return Object.fromEntries(db.prepare('SELECT key,value FROM settings').all().map(x=>[x.key,x.value]))}
function issueSession(req,res,u){const token=rid(),csrf=rid(),expires=Date.now()+7*86400000;
 db.prepare('INSERT INTO sessions(token_hash,user_id,csrf,expires_at) VALUES(?,?,?,?)').run(sha(token),u.id,csrf,expires);
 const secure=process.env.COOKIE_SECURE==='true' || req.headers['x-forwarded-proto']==='https';
 res.setHeader('Set-Cookie',`sanad_sid=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=604800${secure?'; Secure':''}`);
 return csrf;
}
async function body(req,max=14*1024*1024){let chunks=[],n=0;for await(const chunk of req){n+=chunk.length;if(n>max)fail(413,'حجم البيانات كبير');chunks.push(chunk)};
 try{return JSON.parse(Buffer.concat(chunks).toString('utf8')||'{}')}catch{fail(400,'بيانات JSON غير صحيحة')}
}
const types={pdf:'application/pdf',jpg:'image/jpeg',png:'image/png'};
function saveDoc(file,owner,kind){if(!file)return null;
 if(typeof file!=='object'||!['application/pdf','image/png','image/jpeg'].includes(file.mime))fail(400,'نوع ملف غير مقبول');
 const b64=String(file.data||'');if(b64.length>8e6)fail(413,'الملف كبير');
 const binary=Buffer.from(b64,'base64');if(binary.length>5*1024*1024||binary.length<8)fail(400,'يجب أن يكون الملف أقل من 5 ميغابايت');
 const pdf=binary.subarray(0,5).toString()==='%PDF-', jpg=binary[0]===255&&binary[1]===216&&binary[2]===255, png=binary.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]));
 const extension=pdf?'pdf':jpg?'jpg':png?'png':null;
 if(!extension||types[extension]!==file.mime)fail(400,'محتوى الملف لا يطابق نوعه');
 const fname=`${owner}_${kind}_${crypto.randomBytes(12).toString('hex')}.${extension}`;
 fs.writeFileSync(path.join(PRIVATE,fname),binary,{mode:0o600,flag:'wx'});return fname;
}
function docUrl(app,id,kind){return app?.[kind]?`/api/documents/${id}/${kind}`:null}
function makeMemberNumber(id){return 'SH-'+new Date().getFullYear()+'-'+String(id).padStart(6,'0')}
function datePlusYear(){const d=new Date();d.setFullYear(d.getFullYear()+1);return d.toISOString().slice(0,10)}
function approveApplication(u,a,actor,note){
 const memberNo=u.member_number||makeMemberNumber(u.id); const date=new Date().toISOString().slice(0,10);
 db.prepare("UPDATE applications SET status='approved',admin_id=?,admin_note=?,approved_at=?,updated_at=? WHERE id=?").run(actor.id,txt(note,600),now(),now(),a.id);
 db.prepare("UPDATE users SET status='active',member_number=?,joined_at=COALESCE(joined_at,?),expires_at=?,updated_at=? WHERE id=?").run(memberNo,date,datePlusYear(),now(),u.id);
 audit(actor,'approve','applications',a.id,note);notify(u.id,'تم قبول طلبك','تمت الموافقة الإدارية على عضويتك في سند الصحي. يمكنك الآن استخدام بطاقتك الرقمية.');
}
function asRow(u,a){return {id:a.id,userId:u.id,name:u.name,username:u.username,phone:u.phone,email:u.email,nationalId:u.national_id,condition:u.condition,plan:u.plan,status:a.status,createdAt:a.created_at,reviewedAt:a.reviewed_at,supervisorId:a.supervisor_id,supervisorDecision:a.supervisor_decision,supervisorNote:a.supervisor_note,adminNote:a.admin_note,identityUrl:docUrl(a,a.id,'identity_doc'),medicalUrl:docUrl(a,a.id,'medical_doc')}}
function csvEscape(v){return '"'+String(v??'').replaceAll('"','""')+'"'}
function csv(res,rows){res.writeHead(200,{'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="sanad-report.csv"','Cache-Control':'no-store'});res.end('\ufeff'+rows.map(r=>r.map(csvEscape).join(',')).join('\r\n'))}
async function api(req,res,url,method){const p=url.pathname, u=auth(req);
 if(method==='POST'&&!['/api/login','/api/register'].includes(p)){requireAuth(u);if(req.headers['x-csrf-token']!==u.csrf)fail(403,'رمز حماية الطلب غير صالح')}
 if(method==='PATCH'||method==='PUT'||method==='DELETE'){requireAuth(u);if(req.headers['x-csrf-token']!==u.csrf)fail(403,'رمز حماية الطلب غير صالح')}
 if(p==='/api/me'&&method==='GET')return json(res,{user:safeUser(u),csrf:u?.csrf||null});
 if(p==='/api/register'&&method==='POST'){
 rate(req,'register',10,3600000);if(settings().allow_signup!=='true')fail(403,'التسجيل متوقف مؤقتاً');const b=await body(req);
 const username=txt(b.username,35).toLowerCase(),name=txt(b.name,120),phone=txt(b.phone,30),nid=txt(b.nationalId,30),pass=String(b.password||'');
 if(!/^[a-zA-Z0-9._-]{3,35}$/.test(username)||name.length<3||!/^05\d{8}$/.test(phone)||!/^\d{10}$/.test(nid)||pass.length<8)fail(400,'تحقق من الاسم واسم المستخدم ورقم الجوال والهوية وكلمة المرور (8 أحرف على الأقل)');
 if(!['diabetes','kidney','cancer','donor'].includes(b.condition))fail(400,'اختر فئة البرنامج');
 if(!['free','premium'].includes(b.plan))fail(400,'اختر نوع الاشتراك');
 if(b.consent!==true)fail(400,'تجب الموافقة على شروط الاستخدام وسياسة الخصوصية');
 if(db.prepare('SELECT id FROM users WHERE username=? OR national_id=?').get(username,nid))fail(409,'اسم المستخدم أو رقم الهوية مسجل مسبقاً');
 // لا تُقبل البيانات الطبية دون الملفين المطلوبين في هذا المثال.
 if(!b.identityDoc||!b.medicalDoc)fail(400,'أرفق إثبات الهوية والتقرير الطبي للتحقق');
 const row=db.prepare('INSERT INTO users(username,password_hash,name,phone,email,national_id,role,status,condition,plan) VALUES(?,?,?,?,?,?,?,?,?,?)')
 .run(username,hashPassword(pass),name,phone,txt(b.email,120),'', 'member','pending',b.condition,b.plan);
 const uid=Number(row.lastInsertRowid);let identity=null,medical=null;
 try{identity=saveDoc(b.identityDoc,uid,'identity');medical=saveDoc(b.medicalDoc,uid,'medical');
 db.prepare('UPDATE users SET national_id=? WHERE id=?').run(nid,uid);
 db.prepare("INSERT INTO applications(user_id,status,identity_doc,medical_doc) VALUES(?,'pending',?,?)").run(uid,identity,medical);
 }catch(err){if(identity)try{fs.unlinkSync(path.join(PRIVATE,identity))}catch{};if(medical)try{fs.unlinkSync(path.join(PRIVATE,medical))}catch{};
 db.prepare('DELETE FROM users WHERE id=?').run(uid);throw err}
 audit(null,'submit','applications',uid,'new request');alertStaff('طلب تسجيل جديد',`وصل طلب جديد من ${name} بانتظار مراجعة الإدارة`);
 return json(res,{ok:true,status:'pending',message:'تم إرسال طلبك، ولن تتفعّل عضويتك إلا بعد موافقة الإدارة'},201);
 }
 if(p==='/api/login'&&method==='POST'){
 rate(req,'login',20,10*60000);const b=await body(req,1024*20);const username=txt(b.username,35).toLowerCase();const candidate=String(b.password||'');
 const person=db.prepare('SELECT * FROM users WHERE username=?').get(username);
 if(!person || !verifyPassword(candidate,person.password_hash))fail(401,'اسم المستخدم أو كلمة المرور غير صحيحة');
 if(['suspended','deleted'].includes(person.status))fail(403,'الحساب موقوف. يرجى التواصل مع الإدارة');
 const csrf=issueSession(req,res,person);audit(person,'login','users',person.id);return json(res,{ok:true,user:safeUser({...person,perms:JSON.parse(person.permissions||'[]')}),csrf});
 }
 if(p==='/api/logout'&&method==='POST'){const token=parseCookies(req).sanad_sid;if(token)db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(token));res.setHeader('Set-Cookie','sanad_sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0');return json(res,{ok:true})}
 if(p==='/api/change-password'&&method==='POST'){requireAuth(u);const b=await body(req,3000);if(!verifyPassword(String(b.current||''),u.password_hash)||String(b.newPassword||'').length<10)fail(400,'كلمة المرور الحالية غير صحيحة أو الجديدة أقل من 10 أحرف');
 db.prepare('UPDATE users SET password_hash=?,updated_at=? WHERE id=?').run(hashPassword(b.newPassword),now(),u.id);audit(u,'change_password','users',u.id);return json(res,{ok:true})}
 if(p==='/api/my-application'&&method==='GET'){requireAuth(u);if(u.role!=='member')return json(res,{application:null});const a=db.prepare('SELECT * FROM applications WHERE user_id=?').get(u.id);return json(res,{application:a?asRow(u,a):null})}
 if(p==='/api/my-profile'&&method==='GET'){requireAuth(u);return json(res,{user:safeUser(u)})}
 if(p==='/api/my-profile'&&method==='PATCH'){requireAuth(u);const b=await body(req);const name=txt(b.name,120),email=txt(b.email,120),phone=txt(b.phone,30);if(name.length<3||!/^05\d{8}$/.test(phone))fail(400,'تحقق من الاسم ورقم الجوال');db.prepare('UPDATE users SET name=?,email=?,phone=?,updated_at=? WHERE id=?').run(name,email,phone,now(),u.id);audit(u,'update_own_profile','users',u.id);return json(res,{ok:true})}
 if(p==='/api/my-application/resubmit'&&method==='POST'){requireAuth(u);if(u.role!=='member')fail(403,'غير متاح');const a=db.prepare('SELECT * FROM applications WHERE user_id=?').get(u.id);if(!a||!['needs_info','rejected'].includes(a.status))fail(400,'لا يمكن تعديل الطلب في هذه الحالة');const b=await body(req);let idDoc=null,medDoc=null;if(b.identityDoc)idDoc=saveDoc(b.identityDoc,u.id,'identity');if(b.medicalDoc)medDoc=saveDoc(b.medicalDoc,u.id,'medical');if(!idDoc&&!medDoc)fail(400,'أرفق الوثائق المطلوبة للتحديث');db.prepare("UPDATE applications SET status='pending',identity_doc=COALESCE(?,identity_doc),medical_doc=COALESCE(?,medical_doc),supervisor_decision='',supervisor_note='',admin_note='',updated_at=? WHERE id=?").run(idDoc,medDoc,now(),a.id);db.prepare("UPDATE users SET status='pending' WHERE id=?").run(u.id);audit(u,'resubmit','applications',a.id);alertStaff('طلب أُعيد تقديمه',`أعاد ${u.name} تقديم طلبه`);return json(res,{ok:true})}
 if(p==='/api/notifications'&&method==='GET'){requireAuth(u);return json(res,{items:db.prepare('SELECT id,title,message,seen,created_at FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 80').all(u.id)})}
 if(p==='/api/notifications/read'&&method==='POST'){requireAuth(u);db.prepare('UPDATE notifications SET seen=1 WHERE user_id=?').run(u.id);return json(res,{ok:true})}
 if(p.startsWith('/api/documents/')&&method==='GET'){
 requireAuth(u);const match=/^\/api\/documents\/(\d+)\/(identity_doc|medical_doc)$/.exec(p);if(!match)fail(404,'الملف غير موجود');const a=db.prepare('SELECT * FROM applications WHERE id=?').get(Number(match[1]));if(!a)fail(404,'الملف غير موجود');if(u.id!==a.user_id&&!can(u,'applications:read'))fail(403,'لا يمكنك الوصول للملف');const fname=a[match[2]];if(!fname)fail(404,'الملف غير موجود');const f=path.join(PRIVATE,path.basename(fname));if(!fs.existsSync(f))fail(404,'الملف غير موجود');const ext=path.extname(f).slice(1);res.writeHead(200,{'Content-Type':types[ext]||'application/octet-stream','Content-Disposition':`attachment; filename="${match[2]}.${ext}"`,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});fs.createReadStream(f).pipe(res);return;
 }
 if(p==='/api/content'&&method==='GET'){activeMember(u);const type=txt(url.searchParams.get('type'),15);if(!['ads','offers','partners'].includes(type))fail(400,'نوع المحتوى غير معروف');return json(res,{items:db.prepare('SELECT id,type,title,details,category,value,active,created_at FROM content WHERE type=? AND active=1 ORDER BY id DESC').all(type)})}
 if(p==='/api/dashboard'&&method==='GET'){
 permit(u,'stats:read');const buckets=db.prepare("SELECT status,COUNT(*) n FROM applications GROUP BY status").all();const members=db.prepare("SELECT condition,COUNT(*) n FROM users WHERE role='member' AND status='active' GROUP BY condition").all();
 return json(res,{counts:{requests:db.prepare('SELECT COUNT(*) n FROM applications').get().n,pending:db.prepare("SELECT COUNT(*) n FROM applications WHERE status IN ('pending','reviewed','needs_info')").get().n,approved:db.prepare("SELECT COUNT(*) n FROM applications WHERE status='approved'").get().n,rejected:db.prepare("SELECT COUNT(*) n FROM applications WHERE status='rejected'").get().n,members:db.prepare("SELECT COUNT(*) n FROM users WHERE role='member' AND status='active'").get().n,supervisors:db.prepare("SELECT COUNT(*) n FROM users WHERE role='supervisor' AND status='active'").get().n},buckets,members})
 }
 if(p==='/api/requests'&&method==='GET'){
 permit(u,'applications:read');const status=txt(url.searchParams.get('status'),30),query=txt(url.searchParams.get('q'),100);
 let rows=db.prepare(`SELECT a.*,u.name,u.username,u.phone,u.email,u.national_id,u.condition,u.plan,u.member_number,u.role,u.status user_status FROM applications a JOIN users u ON a.user_id=u.id ORDER BY a.id DESC LIMIT 500`).all();
 if(status&&status!=='all')rows=rows.filter(x=>x.status===status);if(query)rows=rows.filter(x=>[x.name,x.username,x.phone,x.national_id].some(s=>String(s||'').includes(query)));
 return json(res,{items:rows.map(a=>asRow({...a,id:a.user_id},a))})
 }
 const reqMatch=/^\/api\/requests\/(\d+)\/(review|approve|reject|need-info)$/.exec(p);
 if(reqMatch&&method==='POST'){
 const id=Number(reqMatch[1]),act=reqMatch[2];const a=db.prepare('SELECT * FROM applications WHERE id=?').get(id);if(!a)fail(404,'الطلب غير موجود');
 const target=db.prepare('SELECT * FROM users WHERE id=?').get(a.user_id);const b=await body(req);const note=txt(b.note,600);
 if(act==='review'){
 permit(u,'applications:review');if(!['pending','needs_info','reviewed'].includes(a.status))fail(400,'الطلب غير قابل للمراجعة');
 const decision=b.decision==='reject'?'reject':'recommend';
 db.prepare("UPDATE applications SET status='reviewed',supervisor_id=?,supervisor_note=?,supervisor_decision=?,reviewed_at=?,updated_at=? WHERE id=?").run(u.id,note,decision,now(),now(),id);
 audit(u,decision==='reject'?'recommend_rejection':'recommend_approval','applications',id);alertStaff('مراجعة طلب',`تمت مراجعة طلب ${target.name} وهو بانتظار قرار الإدارة النهائي`);
 }else{
 permit(u,'applications:approve');if(!['pending','reviewed','needs_info'].includes(a.status))fail(400,'لا يمكن اتخاذ هذا القرار الآن');
 if(act==='approve'){
 const required=settings().review_mode==='supervisor_then_admin';
 if(required && !a.supervisor_decision){
   if(u.role!=='admin')fail(409,'يجب تسجيل توصية المشرف أولاً');
   if(note.length<6)fail(400,'للموافقة المباشرة دون مراجعة مشرف، يجب تسجيل سبب إداري واضح (6 أحرف على الأقل)');
   audit(u,'override_supervisor_review','applications',id,note);
 }
 approveApplication(target,a,u,note)
 }
 if(act==='reject'){db.prepare("UPDATE applications SET status='rejected',admin_id=?,admin_note=?,updated_at=? WHERE id=?").run(u.id,note,now(),id);db.prepare("UPDATE users SET status='rejected' WHERE id=?").run(target.id);audit(u,'reject','applications',id);notify(target.id,'لم تتم الموافقة على الطلب',note||'لم تتم الموافقة على طلب التسجيل. يمكنك إعادة التقديم بمستندات مكتملة.')}
 if(act==='need-info'){db.prepare("UPDATE applications SET status='needs_info',admin_id=?,admin_note=?,updated_at=? WHERE id=?").run(u.id,note,now(),id);db.prepare("UPDATE users SET status='needs_info' WHERE id=?").run(target.id);audit(u,'needs_info','applications',id);notify(target.id,'نحتاج مستندات إضافية',note||'يرجى تحديث المستندات ثم إعادة تقديم الطلب.')}
 }
 return json(res,{ok:true})
 }
 if(p==='/api/users'&&method==='GET'){
 permit(u,'members:read');const q=txt(url.searchParams.get('q'),120),status=txt(url.searchParams.get('status'),25);
 let rows=db.prepare("SELECT * FROM users WHERE role='member' ORDER BY id DESC LIMIT 1000").all().map(safeUser);
 if(q)rows=rows.filter(x=>[x.name,x.phone,x.username,x.memberNumber].some(v=>String(v||'').includes(q)));
 if(status&&status!=='all')rows=rows.filter(x=>x.status===status);return json(res,{items:rows})
 }
 if(p==='/api/users'&&method==='POST'){
 permit(u,'members:create');const b=await body(req);const username=txt(b.username,35).toLowerCase(),pass=String(b.password||''),name=txt(b.name,120),phone=txt(b.phone,30);
 if(!/^[a-zA-Z0-9._-]{3,35}$/.test(username)||pass.length<8||name.length<3||!/^05\d{8}$/.test(phone))fail(400,'بيانات الحساب الجديد غير صحيحة');
 if(db.prepare('SELECT id FROM users WHERE username=?').get(username))fail(409,'اسم المستخدم مستخدم');
 const r=db.prepare(`INSERT INTO users(username,password_hash,name,phone,email,role,status,condition,plan,joined_at,expires_at) VALUES(?,?,?,?,?,'member','active',?,?,?,?)`)
 .run(username,hashPassword(pass),name,phone,txt(b.email,120),['diabetes','kidney','cancer','donor'].includes(b.condition)?b.condition:'donor',b.plan==='premium'?'premium':'free',now().slice(0,10),datePlusYear());const id=Number(r.lastInsertRowid);
 db.prepare('UPDATE users SET member_number=? WHERE id=?').run(makeMemberNumber(id),id);audit(u,'create_member','users',id);return json(res,{ok:true,id},201)
 }
 const userMatch=/^\/api\/users\/(\d+)$/.exec(p);
 if(userMatch && method==='PATCH'){
 permit(u,'members:update');const id=Number(userMatch[1]);const target=db.prepare("SELECT * FROM users WHERE id=? AND role='member'").get(id);if(!target)fail(404,'المستفيد غير موجود');const b=await body(req);
 const name=typeof b.name==='string'?txt(b.name,120):target.name,phone=typeof b.phone==='string'?txt(b.phone,30):target.phone;
 if(name.length<3||!/^05\d{8}$/.test(phone))fail(400,'تحقق من البيانات');
 const newStatus=['active','suspended'].includes(b.status)?b.status:target.status;
 db.prepare('UPDATE users SET name=?,phone=?,email=?,condition=?,plan=?,status=?,updated_at=? WHERE id=?')
 .run(name,phone,typeof b.email==='string'?txt(b.email,120):target.email,['diabetes','kidney','cancer','donor'].includes(b.condition)?b.condition:target.condition,['free','premium'].includes(b.plan)?b.plan:target.plan,newStatus,now(),id);
 audit(u,'update_member','users',id);notify(id,'تعديل على حسابك','قامت الإدارة بتحديث بيانات حسابك.');return json(res,{ok:true})
 }
 if(userMatch && method==='DELETE'){
 permit(u,'members:delete');const id=Number(userMatch[1]);const target=db.prepare("SELECT id FROM users WHERE id=? AND role='member'").get(id);if(!target)fail(404,'المستفيد غير موجود');db.prepare("UPDATE users SET status='deleted',updated_at=? WHERE id=?").run(now(),id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(u,'archive_member','users',id);return json(res,{ok:true})
 }
 if(p==='/api/supervisors'&&method==='GET'){
 isAdmin(u);return json(res,{items:db.prepare("SELECT * FROM users WHERE role='supervisor' ORDER BY id DESC").all().map(safeUser)})
 }
 if(p==='/api/supervisors'&&method==='POST'){
 isAdmin(u);const b=await body(req);const username=txt(b.username,35).toLowerCase(),name=txt(b.name,120),pass=String(b.password||''),phone=txt(b.phone,30),perms=normalizePerms(b.permissions);
 if(!/^[a-zA-Z0-9._-]{3,35}$/.test(username)||name.length<3||pass.length<8||!/^05\d{8}$/.test(phone))fail(400,'أدخل بيانات صحيحة للمشرف');
 if(db.prepare('SELECT id FROM users WHERE username=?').get(username))fail(409,'اسم المستخدم مستخدم');
 const r=db.prepare(`INSERT INTO users(username,password_hash,name,phone,role,status,permissions) VALUES(?,?,?,?,'supervisor','active',?)`).run(username,hashPassword(pass),name,phone,JSON.stringify(perms));audit(u,'create_supervisor','users',Number(r.lastInsertRowid));return json(res,{ok:true},201)
 }
 const supervisorMatch=/^\/api\/supervisors\/(\d+)$/.exec(p);
 if(supervisorMatch&&(method==='PATCH'||method==='DELETE')){
 isAdmin(u);const id=Number(supervisorMatch[1]);const target=db.prepare("SELECT * FROM users WHERE id=? AND role='supervisor'").get(id);if(!target)fail(404,'المشرف غير موجود');
 if(method==='DELETE'){db.prepare("UPDATE users SET status='deleted' WHERE id=?").run(id);db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);audit(u,'delete_supervisor','users',id);return json(res,{ok:true})}
 const b=await body(req);const name=typeof b.name==='string'?txt(b.name,120):target.name,status=['active','suspended'].includes(b.status)?b.status:target.status;
 const perms=Array.isArray(b.permissions)?normalizePerms(b.permissions):JSON.parse(target.permissions||'[]');
 if(name.length<3)fail(400,'اسم غير صحيح');db.prepare('UPDATE users SET name=?,status=?,permissions=?,updated_at=? WHERE id=?').run(name,status,JSON.stringify(perms),now(),id);
 if(b.password){if(String(b.password).length<8)fail(400,'كلمة مرور المشرف قصيرة');db.prepare('UPDATE users SET password_hash=? WHERE id=?').run(hashPassword(b.password),id)}
 if(status!=='active')db.prepare('DELETE FROM sessions WHERE user_id=?').run(id);
 audit(u,'update_supervisor','users',id);return json(res,{ok:true})
 }
 if(p==='/api/admin/content'&&method==='GET'){
 permit(u,'content:read');let type=txt(url.searchParams.get('type'),15);if(!['ads','offers','partners'].includes(type))type='offers';
 return json(res,{items:db.prepare('SELECT * FROM content WHERE type=? ORDER BY id DESC').all(type)})
 }
 if(p==='/api/admin/content'&&method==='POST'){
 permit(u,'content:manage');const b=await body(req);const type=txt(b.type,15),title=txt(b.title,180);if(!['ads','offers','partners'].includes(type)||title.length<3)fail(400,'حدد نوع المحتوى وعنوانه');
 const r=db.prepare('INSERT INTO content(type,title,details,category,value,active) VALUES(?,?,?,?,?,?)').run(type,title,txt(b.details,2000),txt(b.category,80),txt(b.value,70),b.active===false?0:1);
 audit(u,'create_content',type,Number(r.lastInsertRowid));return json(res,{ok:true},201)
 }
 const contentMatch=/^\/api\/admin\/content\/(\d+)$/.exec(p);
 if(contentMatch&&(method==='PATCH'||method==='DELETE')){
 permit(u,'content:manage');const id=Number(contentMatch[1]),target=db.prepare('SELECT * FROM content WHERE id=?').get(id);if(!target)fail(404,'المحتوى غير موجود');
 if(method==='DELETE'){db.prepare('DELETE FROM content WHERE id=?').run(id);audit(u,'delete_content',target.type,id);return json(res,{ok:true})}
 const b=await body(req);const title=typeof b.title==='string'?txt(b.title,180):target.title;
 if(title.length<3)fail(400,'العنوان غير صحيح');db.prepare('UPDATE content SET title=?,details=?,category=?,value=?,active=?,updated_at=? WHERE id=?').run(title,typeof b.details==='string'?txt(b.details,2000):target.details,typeof b.category==='string'?txt(b.category,80):target.category,typeof b.value==='string'?txt(b.value,70):target.value,typeof b.active==='boolean'?(b.active?1:0):target.active,now(),id);
 audit(u,'update_content',target.type,id);return json(res,{ok:true})
 }
 if(p==='/api/settings'&&method==='GET'){isAdmin(u);return json(res,{settings:settings()})}
 if(p==='/api/settings'&&method==='PATCH'){isAdmin(u);const b=await body(req);for(const k of ['site_name','review_mode','annual_premium_price','allow_signup']){
 if(b[k]===undefined)continue;const val=txt(b[k],255);
 if(k==='review_mode'&&!['supervisor_then_admin','admin_only'].includes(val))fail(400,'نمط المراجعة غير صحيح');
 if(k==='allow_signup'&&!['true','false'].includes(val))fail(400,'إعداد التسجيل غير صحيح');
 db.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').run(k,val);
 }audit(u,'update_settings','settings',null);return json(res,{ok:true})}
 if(p==='/api/audit'&&method==='GET'){isAdmin(u);return json(res,{items:db.prepare('SELECT a.*,u.name actor_name FROM audit a LEFT JOIN users u ON u.id=a.actor ORDER BY a.id DESC LIMIT 200').all()})}
 if(p==='/api/export.csv'&&method==='GET'){permit(u,'stats:export');const users=db.prepare("SELECT id,name,username,phone,role,status,condition,plan,member_number,created_at FROM users WHERE role='member' ORDER BY id DESC").all();audit(u,'export_csv','users',null);return csv(res,[['الرقم','الاسم','اسم المستخدم','الجوال','الصفة','الحالة','الفئة','الخطة','العضوية','التاريخ'],...users.map(x=>[x.id,x.name,x.username,x.phone,x.role,x.status,x.condition,x.plan,x.member_number,x.created_at])])}
 fail(404,'هذه الخدمة غير موجودة');
}
const ALLOWED_PERMISSIONS=['stats:read','stats:export','applications:read','applications:review','applications:approve','members:read','members:create','members:update','members:delete','content:read','content:manage'];
function normalizePerms(perms){
 if(!Array.isArray(perms))return [];
 const accepted=new Set(perms.filter(p=>typeof p==='string'&&ALLOWED_PERMISSIONS.includes(p)));
 // Operations that modify records also need the corresponding read access.
 const needsRead={
  'stats:export':'stats:read', 'applications:review':'applications:read',
  'applications:approve':'applications:read','members:create':'members:read',
  'members:update':'members:read','members:delete':'members:read',
  'content:manage':'content:read'
 };
 for(const p of [...accepted]) if(needsRead[p])accepted.add(needsRead[p]);
 return [...accepted];
}
const MIME={'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8','.png':'image/png','.jpg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon','.json':'application/json'};
const server=http.createServer(async(req,res)=>{
 res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('X-Frame-Options','DENY');res.setHeader('Referrer-Policy','no-referrer');res.setHeader('Permissions-Policy','geolocation=(), camera=(), microphone=()');res.setHeader('Content-Security-Policy',"default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
 try{
 const url=new URL(req.url,'http://localhost');const method=req.method||'GET';if(url.pathname.startsWith('/api/'))return await api(req,res,url,method);
 if(method!=='GET'&&method!=='HEAD')fail(405,'طريقة غير مسموحة');
 const p=url.pathname==='/'?'/index.html':url.pathname;let decoded;try{decoded=decodeURIComponent(p)}catch{fail(400,'عنوان غير صحيح')}
 const filename=path.resolve(PUBLIC,'.'+decoded);if(!(filename===PUBLIC||filename.startsWith(PUBLIC+path.sep)))fail(403,'غير مصرح');
 if(!fs.existsSync(filename)||!fs.statSync(filename).isFile())fail(404,'الصفحة غير موجودة');
 res.writeHead(200,{'Content-Type':MIME[path.extname(filename).toLowerCase()]||'application/octet-stream','Cache-Control':'public,max-age=1800'});
 if(method==='HEAD')res.end();else fs.createReadStream(filename).pipe(res);
 }catch(err){if(res.headersSent){res.destroy();return}
 const code=err.status||500;
 if(code>=500)console.error('SERVER ERROR',err.message);json(res,{error:code>=500?'حدث خطأ بالخادم':err.message},code)}
});
const PORT=Number(process.env.PORT||3000),HOST=process.env.HOST||'127.0.0.1';
server.listen(PORT,HOST,()=>console.log(`Sanad Health listening on http://${HOST}:${PORT}`));
