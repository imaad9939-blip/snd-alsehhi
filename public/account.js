document.addEventListener('DOMContentLoaded', () => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const grid = $('#dashboardGrid');
  const notice = $('#pageNotice');
  const csrf = '';
  let csrfToken = csrf;
  let currentUser = null;
  let pendingRequest = null;
  let requestsCache = [];
  const permissionGroups = [
    { title: 'الإحصائيات', permissions: [['stats:read', 'عرض الإحصائيات'], ['stats:export', 'تصدير التقارير']] },
    { title: 'الطلبات', permissions: [['applications:read', 'عرض الطلبات'], ['applications:review', 'مراجعة الطلبات'], ['applications:approve', 'اعتماد أو رفض الطلبات']] },
    { title: 'المستفيدون', permissions: [['members:read', 'عرض المستفيدين'], ['members:create', 'إضافة مستفيد'], ['members:update', 'تعديل بيانات المستفيدين'], ['members:delete', 'حذف المستفيدين']] },
    { title: 'المحتوى', permissions: [['content:read', 'عرض المحتوى'], ['content:manage', 'إدارة العروض والإعلانات والشركاء']] },
  ];
  const permissionNames = Object.fromEntries(permissionGroups.flatMap((group) => group.permissions));
  const roleNames = { admin: 'المدير العام', supervisor: 'مشرف', member: 'مستفيد' };
  const statusNames = { pending: 'قيد المراجعة', reviewed: 'تمت المراجعة', needs_info: 'بحاجة لمعلومات', approved: 'مقبول', rejected: 'مرفوض', active: 'نشط', suspended: 'موقوف' };
  const conditionNames = { diabetes: 'السكري', kidney: 'الكلى', cancer: 'الأورام', donor: 'متبرع' };

  function escapeHTML(value) {
    return String(value ?? '').replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
  }
  function showNotice(message, type = 'error') {
    notice.textContent = message;
    notice.hidden = !message;
    notice.classList.toggle('notice-success', type === 'success');
  }
  async function api(url, options = {}) {
    const headers = { Accept: 'application/json', ...(options.body ? { 'Content-Type': 'application/json' } : {}), ...options.headers };
    if (['POST', 'PATCH', 'PUT', 'DELETE'].includes(options.method)) headers['x-csrf-token'] = csrfToken;
    const response = await fetch(url, { credentials: 'same-origin', ...options, headers });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      if (response.status === 401) window.location.assign('/');
      throw new Error(data.error || 'تعذر إكمال العملية. حاول مرة أخرى.');
    }
    return data;
  }
  function has(permission) {
    return currentUser?.role === 'admin' || (currentUser?.permissions || []).includes(permission);
  }
  function statusPill(status) {
    const label = statusNames[status] || status || 'غير محدد';
    return `<span class="status-pill status-${escapeHTML(status)}">${escapeHTML(label)}</span>`;
  }
  function permissionCheckboxes(selected = [], prefix = 'permission') {
    const checked = new Set(selected);
    return permissionGroups.map((group) => `<div class="permission-group"><strong>${escapeHTML(group.title)}</strong>${group.permissions.map(([key, label]) => `<label class="permission-option"><input type="checkbox" name="${escapeHTML(prefix)}" value="${escapeHTML(key)}" ${checked.has(key) ? 'checked' : ''}><span>${escapeHTML(label)}</span></label>`).join('')}</div>`).join('');
  }
  function selectedPermissions(container) {
    return $$('input[type="checkbox"]:checked', container).map((input) => input.value);
  }
  function showPanel(id, visible) {
    const panel = document.getElementById(id);
    if (panel) panel.hidden = !visible;
  }
  function displayProfile(user) {
    $('#profileInfo').innerHTML = [
      ['الاسم', user.name], ['اسم المستخدم', user.username], ['الدور', roleNames[user.role] || user.role],
      ['رقم الجوال', user.phone || '—'], ['الحالة', statusNames[user.status] || user.status],
      ['الصلاحيات', user.role === 'admin' ? 'كاملة' : `${(user.permissions || []).length} صلاحية`],
    ].map(([label, value]) => `<div class="profile-field"><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></div>`).join('');
  }
  function renderStats(counts) {
    const names = { requests: 'إجمالي الطلبات', pending: 'طلبات قيد الإجراء', members: 'المستفيدون', supervisors: 'المشرفون', active: 'عضويات نشطة' };
    const entries = Object.entries(counts || {}).filter(([, value]) => typeof value === 'number' || typeof value === 'string');
    $('#statsGrid').innerHTML = entries.length ? entries.map(([key, value]) => `<div class="stat-card"><span>${escapeHTML(names[key] || key)}</span><strong>${escapeHTML(value)}</strong></div>`).join('') : '<p class="muted">لا توجد إحصائيات متاحة حالياً.</p>';
  }
  async function loadStats() {
    if (!has('stats:read')) return;
    try { const data = await api('/api/dashboard'); renderStats(data.counts); }
    catch (error) { $('#statsGrid').innerHTML = `<p class="muted">${escapeHTML(error.message)}</p>`; }
  }
  function requestActions(item) {
    if (item.status === 'approved' || item.status === 'rejected') return '<span class="muted">لا يوجد إجراء</span>';
    const id = Number(item.id);
    const actions = [];
    if (has('applications:review')) actions.push(`<button class="action-button" data-request-action="review" data-id="${id}">توصية المشرف</button>`);
    if (currentUser.role === 'admin' && has('applications:approve')) {
      actions.push(`<button class="action-button" data-request-action="approve" data-id="${id}">اعتماد</button>`);
      actions.push(`<button class="action-button danger" data-request-action="reject" data-id="${id}">رفض</button>`);
      actions.push(`<button class="action-button" data-request-action="need-info" data-id="${id}">طلب معلومات</button>`);
    }
    return actions.length ? `<div class="row-actions">${actions.join('')}</div>` : '<span class="muted">عرض فقط</span>';
  }
  function renderRequests(items) {
    requestsCache = items || [];
    const query = ($('#requestSearch').value || '').trim().toLowerCase();
    const status = $('#requestStatus').value;
    const filtered = requestsCache.filter((item) => {
      const matchesQuery = !query || [item.name, item.username, item.phone, item.nationalId].some((value) => String(value || '').toLowerCase().includes(query));
      return matchesQuery && (status === 'all' || item.status === status);
    });
    $('#requestsTable').innerHTML = filtered.length ? filtered.map((item) => `<tr><td><span class="person-name">${escapeHTML(item.name)}</span><span class="person-sub">${escapeHTML(item.username || '')} · ${escapeHTML(item.phone || '')}</span></td><td>${escapeHTML(conditionNames[item.condition] || item.condition || '—')}</td><td>${statusPill(item.status)}</td><td>${escapeHTML(String(item.createdAt || '—').slice(0, 10))}</td><td>${requestActions(item)}</td></tr>`).join('') : '<tr><td class="empty-cell" colspan="5">لا توجد طلبات تطابق البحث.</td></tr>';
  }
  async function loadRequests() {
    if (!has('applications:read')) return;
    $('#requestsTable').innerHTML = '<tr><td colspan="5" class="empty-cell">جارٍ تحميل الطلبات…</td></tr>';
    try { const data = await api('/api/requests?status=all'); renderRequests(data.items || []); }
    catch (error) { $('#requestsTable').innerHTML = `<tr><td colspan="5" class="empty-cell">${escapeHTML(error.message)}</td></tr>`; }
  }
  async function loadMembers() {
    if (!has('members:read')) return;
    $('#membersTable').innerHTML = '<tr><td colspan="4" class="empty-cell">جارٍ تحميل القائمة…</td></tr>';
    try {
      const data = await api('/api/users?status=all');
      const items = data.items || [];
      $('#membersTable').innerHTML = items.length ? items.map((item) => `<tr><td class="person-name">${escapeHTML(item.name)}</td><td>${escapeHTML(item.username)}</td><td>${escapeHTML(item.phone || '—')}</td><td>${statusPill(item.status)}</td></tr>`).join('') : '<tr><td colspan="4" class="empty-cell">لا يوجد مستفيدون.</td></tr>';
    } catch (error) { $('#membersTable').innerHTML = `<tr><td colspan="4" class="empty-cell">${escapeHTML(error.message)}</td></tr>`; }
  }
  function supervisorCard(person) {
    const permissions = person.permissions || [];
    return `<article class="supervisor-card" data-supervisor="${Number(person.id)}"><div class="supervisor-card-head"><div><h4>${escapeHTML(person.name)}</h4><span class="username">@${escapeHTML(person.username)}</span><p class="phone">${escapeHTML(person.phone || '—')} · ${statusPill(person.status)}</p></div><div class="supervisor-tools"><select class="supervisor-status" aria-label="حالة المشرف"><option value="active" ${person.status === 'active' ? 'selected' : ''}>نشط</option><option value="suspended" ${person.status === 'suspended' ? 'selected' : ''}>موقوف</option></select><input class="supervisor-password" type="password" minlength="8" autocomplete="new-password" placeholder="كلمة مرور جديدة (اختياري)" aria-label="كلمة مرور جديدة" /><button class="action-button save-supervisor" type="button">حفظ التعديلات</button></div></div><div class="permission-options">${permissionCheckboxes(permissions, `supervisor-${Number(person.id)}`)}</div></article>`;
  }
  async function loadSupervisors() {
    if (currentUser.role !== 'admin') return;
    $('#supervisorList').innerHTML = '<p class="muted">جارٍ تحميل المشرفين…</p>';
    try {
      const data = await api('/api/supervisors');
      $('#supervisorList').innerHTML = data.items?.length ? data.items.map(supervisorCard).join('') : '<p class="muted">لا يوجد مشرفون بعد. أضف أول مشرف من النموذج أعلاه.</p>';
    } catch (error) { $('#supervisorList').innerHTML = `<p class="muted">${escapeHTML(error.message)}</p>`; }
  }
  function openReview(item, action) {
    pendingRequest = { item, action };
    $('#reviewTitle').textContent = action === 'review' ? 'توصية المشرف' : ({ approve: 'اعتماد الطلب', reject: 'رفض الطلب', 'need-info': 'طلب معلومات إضافية' }[action] || 'إجراء على الطلب');
    $('#reviewPerson').textContent = `${item.name || 'المستفيد'} · ${item.username || ''}`;
    $('#reviewNote').value = '';
    $('#reviewFeedback').textContent = '';
    const buttons = action === 'review'
      ? '<button class="button button-primary" type="submit" data-decision="recommend">التوصية بالموافقة</button><button class="button button-quiet" type="submit" data-decision="reject">التوصية بالرفض</button>'
      : `<button class="button button-primary" type="submit">${escapeHTML(({ approve: 'تأكيد الاعتماد', reject: 'تأكيد الرفض', 'need-info': 'إرسال طلب المعلومات' }[action]))}</button>`;
    $('#reviewActions').innerHTML = buttons;
    $('#reviewDialog').showModal();
  }
  async function submitReview(event) {
    event.preventDefault();
    if (!pendingRequest) return;
    const action = pendingRequest.action;
    const note = $('#reviewNote').value.trim();
    if (action === 'approve' && note.length < 6) {
      $('#reviewFeedback').textContent = 'اكتب سبباً واضحاً لا يقل عن 6 أحرف للاعتماد المباشر.';
      return;
    }
    const submitter = event.submitter;
    const decision = submitter?.dataset.decision || 'recommend';
    const feedback = $('#reviewFeedback');
    feedback.textContent = 'جارٍ حفظ القرار…';
    try {
      const endpointAction = action === 'review' ? 'review' : action;
      await api(`/api/requests/${Number(pendingRequest.item.id)}/${endpointAction}`, { method: 'POST', body: JSON.stringify({ note, decision }) });
      $('#reviewDialog').close();
      showNotice('تم حفظ الإجراء بنجاح.', 'success');
      await Promise.all([loadRequests(), loadStats()]);
    } catch (error) { feedback.textContent = error.message; }
  }

  async function initialize() {
    try {
      const data = await api('/api/me');
      currentUser = data.user;
      csrfToken = data.csrf || '';
      if (!currentUser || !['admin', 'supervisor'].includes(currentUser.role)) {
        $('#welcomeTitle').textContent = 'لوحة تحكم الإدارة';
        $('#welcomeSubtitle').textContent = 'يتم التحقق من صلاحيات الحساب.';
        $('#accessDenied').hidden = false;
        return;
      }
      $('#welcomeTitle').textContent = `مرحباً، ${currentUser.name}`;
      $('#welcomeSubtitle').textContent = currentUser.role === 'admin' ? 'إدارة الموقع والصلاحيات من مكان واحد.' : 'هذه اللوحة تعرض المهام والصلاحيات التي فوّضك بها المدير.';
      $('#roleBadge').textContent = roleNames[currentUser.role];
      displayProfile(currentUser);
      grid.hidden = false;
      showPanel('statsPanel', has('stats:read'));
      showPanel('requestsPanel', has('applications:read'));
      showPanel('membersPanel', has('members:read'));
      showPanel('permissionsPanel', currentUser.role === 'admin');
      $('#newSupervisorPermissions').innerHTML = permissionCheckboxes([], 'newPermission');
      if (currentUser.role === 'supervisor' && !(currentUser.permissions || []).length) {
        showNotice('لم تُمنح لهذا الحساب صلاحيات إدارية بعد. اطلب من المدير تفعيل الصلاحيات المناسبة.');
      }
      await Promise.all([loadStats(), loadRequests(), loadMembers(), loadSupervisors()]);
    } catch (error) {
      if (error.message) showNotice(error.message);
    }
  }

  $('#logoutButton').addEventListener('click', async () => {
    try { await api('/api/logout', { method: 'POST', body: '{}' }); } catch { /* انتهاء الجلسة يعالج في الصفحة الرئيسية */ }
    window.location.assign('/');
  });
  $('#createSupervisorForm').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const feedback = $('#createFeedback');
    feedback.classList.remove('success');
    feedback.textContent = 'جارٍ إنشاء الحساب…';
    const values = Object.fromEntries(new FormData(form));
    try {
      await api('/api/supervisors', { method: 'POST', body: JSON.stringify({ ...values, permissions: selectedPermissions($('#newSupervisorPermissions')) }) });
      form.reset();
      feedback.textContent = 'تم إنشاء حساب المشرف وحفظ صلاحياته.';
      feedback.classList.add('success');
      await loadSupervisors();
    } catch (error) { feedback.textContent = error.message; }
  });
  $('#supervisorList').addEventListener('click', async (event) => {
    const button = event.target.closest('.save-supervisor');
    if (!button) return;
    const card = button.closest('[data-supervisor]');
    const password = $('.supervisor-password', card).value;
    const body = { status: $('.supervisor-status', card).value, permissions: selectedPermissions(card) };
    if (password) body.password = password;
    button.disabled = true;
    try {
      await api(`/api/supervisors/${Number(card.dataset.supervisor)}`, { method: 'PATCH', body: JSON.stringify(body) });
      showNotice('تم تحديث حالة المشرف وصلاحياته.', 'success');
      await loadSupervisors();
    } catch (error) { showNotice(error.message); button.disabled = false; }
  });
  $('#requestsTable').addEventListener('click', (event) => {
    const button = event.target.closest('[data-request-action]');
    if (!button) return;
    const item = requestsCache.find((request) => Number(request.id) === Number(button.dataset.id));
    if (item) openReview(item, button.dataset.requestAction);
  });
  $('#reviewForm').addEventListener('submit', submitReview);
  $('#closeReview').addEventListener('click', () => $('#reviewDialog').close());
  $('#reviewDialog').addEventListener('click', (event) => { if (event.target === $('#reviewDialog')) $('#reviewDialog').close(); });
  $('#requestSearch').addEventListener('input', () => renderRequests(requestsCache));
  $('#requestStatus').addEventListener('change', () => renderRequests(requestsCache));
  $$('[data-action="refresh"]').forEach((button) => button.addEventListener('click', () => loadStats()));
  $$('[data-action="requests"]').forEach((button) => button.addEventListener('click', () => loadRequests()));
  $$('[data-action="members"]').forEach((button) => button.addEventListener('click', () => loadMembers()));
  $$('[data-action="supervisors"]').forEach((button) => button.addEventListener('click', () => loadSupervisors()));
  initialize();
});
