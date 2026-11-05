document.addEventListener('DOMContentLoaded', () => {
  const menuToggle = document.getElementById('menuToggle');
  const mainNav = document.getElementById('mainNav');
  const loginDialog = document.getElementById('loginDialog');
  const loginForm = document.getElementById('loginForm');
  const formMessage = document.getElementById('formMessage');
  const submitLogin = document.getElementById('submitLogin');
  const year = document.getElementById('year');

  year.textContent = new Date().getFullYear();

  menuToggle.addEventListener('click', () => {
    const expanded = menuToggle.getAttribute('aria-expanded') === 'true';
    menuToggle.setAttribute('aria-expanded', String(!expanded));
    menuToggle.setAttribute('aria-label', expanded ? 'فتح القائمة' : 'إغلاق القائمة');
    mainNav.classList.toggle('is-open', !expanded);
  });

  mainNav.querySelectorAll('a').forEach((link) => {
    link.addEventListener('click', () => {
      menuToggle.setAttribute('aria-expanded', 'false');
      menuToggle.setAttribute('aria-label', 'فتح القائمة');
      mainNav.classList.remove('is-open');
    });
  });

  document.querySelectorAll('.login-open').forEach((button) => {
    button.addEventListener('click', () => {
      formMessage.textContent = '';
      formMessage.classList.remove('success');
      loginDialog.showModal();
      document.getElementById('username').focus();
    });
  });

  document.getElementById('dialogClose').addEventListener('click', () => loginDialog.close());
  loginDialog.addEventListener('click', (event) => {
    if (event.target === loginDialog) loginDialog.close();
  });

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    formMessage.textContent = '';
    formMessage.classList.remove('success');
    submitLogin.disabled = true;
    submitLogin.textContent = 'جارٍ تسجيل الدخول…';

    try {
      const response = await fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          username: loginForm.elements.username.value.trim(),
          password: loginForm.elements.password.value,
        }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.error || 'تعذر تسجيل الدخول. حاول مرة أخرى.');

      if (['admin', 'supervisor'].includes(data.user?.role)) {
        window.location.assign('/account.html');
        return;
      }
      const statusText = data.user?.status === 'active'
        ? 'حسابك نشط ويمكنك متابعة طلباتك.'
        : 'تم تسجيل الدخول. حسابك بانتظار مراجعة الإدارة.';
      formMessage.textContent = `أهلاً ${data.user?.name || ''} — ${statusText}`;
      formMessage.classList.add('success');
      loginForm.reset();
    } catch (error) {
      formMessage.textContent = error.message || 'تعذر الاتصال بالخادم. تحقق من اتصالك وحاول مجدداً.';
    } finally {
      submitLogin.disabled = false;
      submitLogin.innerHTML = 'تسجيل الدخول <span aria-hidden="true">←</span>';
    }
  });
});
