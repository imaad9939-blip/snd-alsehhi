document.addEventListener('DOMContentLoaded', () => {
  const result = document.getElementById('result');
  const button = document.getElementById('healthBtn');

  const render = (payload) => {
    result.textContent = JSON.stringify(payload, null, 2);
  };

  button.addEventListener('click', async () => {
    try {
      const response = await fetch('/api/me', { headers: { accept: 'application/json' } });
      if (response.status === 401) {
        render({ ok: false, status: 401, message: 'المستخدم غير مسجل دخول' });
        return;
      }

      const data = await response.json().catch(() => ({}));
      render({ ok: response.ok, status: response.status, data });
    } catch (error) {
      render({ ok: false, error: error.message });
    }
  });

  render({ ok: true, message: 'واجهة الموقع جاهزة' });
});
