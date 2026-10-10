// Progressive enhancement only: every page works without this file except passkeys.
const { startRegistration, startAuthentication } = window.SimpleWebAuthnBrowser ?? {};

for (const el of document.querySelectorAll('.js-confirm')) {
  el.addEventListener('click', e => {
    if (!confirm(el.dataset.confirm)) e.preventDefault();
  });
}

for (const el of document.querySelectorAll('.js-autosubmit')) {
  el.addEventListener('change', () => el.form.submit());
}

for (const el of document.querySelectorAll('code.copy')) {
  el.title = 'Click to copy';
  el.addEventListener('click', () => navigator.clipboard?.writeText(el.textContent.trim()));
}

async function postJson(url, csrf, body) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-csrf-token': csrf },
    body: JSON.stringify(body ?? {}),
    credentials: 'same-origin',
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.message || `Request failed (${res.status})`);
  return data;
}

function report(err) {
  alert(err instanceof Error ? err.message : String(err));
}

const register = document.querySelector('.js-passkey-register');
register?.addEventListener('click', async () => {
  try {
    const csrf = register.dataset.csrf;
    const optionsJSON = await postJson('/settings/passkeys/options', csrf);
    const response = await startRegistration({ optionsJSON });
    const name = document.getElementById('passkey-name')?.value || 'Passkey';
    const done = await postJson('/settings/passkeys/verify', csrf, { name, response });
    location.href = done.redirect;
  } catch (err) {
    report(err);
  }
});

const approve = document.querySelector('.js-passkey-approve');
approve?.addEventListener('click', async () => {
  try {
    const { csrf, approval } = approve.dataset;
    const optionsJSON = await postJson(`/approvals/${approval}/passkey/options`, csrf);
    const response = await startAuthentication({ optionsJSON });
    const done = await postJson(`/approvals/${approval}/passkey/verify`, csrf, response);
    location.href = done.redirect;
  } catch (err) {
    report(err);
  }
});
