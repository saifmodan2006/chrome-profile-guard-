/**
 * Settings dashboard controller.
 *
 * Sensitive actions are gated: the whole page is locked behind unlock, and
 * changing the credential additionally requires the current credential
 * (verified in the service worker via shared/auth.js).
 */

import {
  STATE,
  METHOD,
  AUTO_LOCK_OPTIONS,
  PROTECTION_MODE,
  SUGGESTED_DOMAINS,
  PIN_RULES,
  PASSWORD_RULES,
} from '../../shared/constants.js';
import { validateSecret } from '../../shared/auth.js';
import { api } from '../../shared/messaging.js';

const $ = (id) => document.getElementById(id);

let settings = null;
let protectedConfig = null;

/* ------------------------------------------------------------------ */
/* init + gate                                                         */
/* ------------------------------------------------------------------ */

async function init() {
  let snapshot;
  try {
    ({ snapshot } = await api.getState());
  } catch {
    showToast('Protection needs to be reinitialized.');
    return;
  }

  if (snapshot.state === STATE.SETUP_REQUIRED) {
    location.replace(chrome.runtime.getURL('pages/setup/setup.html'));
    return;
  }

  updateStatusPill(snapshot.state);

  if (snapshot.state !== STATE.UNLOCKED) {
    $('gate').classList.remove('hidden');
    $('content').classList.add('hidden');
    return;
  }

  $('gate').classList.add('hidden');
  $('content').classList.remove('hidden');
  await render();
}

$('gate-unlock').addEventListener('click', () => {
  const back = chrome.runtime.getURL('pages/lock/lock.html') + '?return=' + encodeURIComponent(location.href);
  location.href = back;
});

function updateStatusPill(state) {
  const dot = $('status-pill').querySelector('.dot');
  if (state === STATE.UNLOCKED) {
    dot.className = 'dot dot-green';
    $('status-text').textContent = 'Unlocked';
  } else {
    dot.className = 'dot dot-red';
    $('status-text').textContent = 'Locked';
  }
}

/* ------------------------------------------------------------------ */
/* render                                                              */
/* ------------------------------------------------------------------ */

async function render() {
  const [s, p, st] = await Promise.all([
    api.getSettings(),
    api.getProtected(),
    api.getState(),
  ]);
  settings = s.settings;
  protectedConfig = p.protected;
  const snapshot = st.snapshot;

  // method
  $('method-desc').textContent = snapshot.method === METHOD.PASSWORD ? 'Password' : 'PIN';

  // auto-lock
  const sel = $('autolock');
  sel.innerHTML = '';
  AUTO_LOCK_OPTIONS.forEach((opt) => {
    const o = document.createElement('option');
    o.value = String(opt.value);
    o.textContent = opt.label;
    if (opt.value === settings.autoLockMinutes) o.selected = true;
    sel.appendChild(o);
  });

  // toggles
  $('quicklock').checked = settings.quickLockEnabled;
  $('hide-content').checked = settings.hideContentWhenLocked;
  $('logging').checked = settings.loggingEnabled;
  $('incognito').checked = settings.allowInIncognito;

  // scope
  document.querySelectorAll('input[name="mode"]').forEach((r) => {
    r.checked = r.value === protectedConfig.mode;
  });
  toggleDomainBlock();
  renderDomains();

  // events count
  await refreshEventCount();
}

function toggleDomainBlock() {
  const selected = document.querySelector('input[name="mode"]:checked')?.value === PROTECTION_MODE.SELECTED;
  $('domains-block').classList.toggle('hidden', !selected);
}

function renderDomains() {
  const list = $('domain-list');
  list.innerHTML = '';
  const domains = protectedConfig.domains || [];
  if (domains.length === 0) {
    const empty = document.createElement('li');
    empty.className = 'muted';
    empty.style.padding = '6px 2px';
    empty.textContent = 'No websites added yet.';
    list.appendChild(empty);
    return;
  }
  domains.forEach((d) => {
    const li = document.createElement('li');
    li.className = 'domain-item';
    const host = document.createElement('span');
    host.className = 'host';
    host.textContent = d;
    const rm = document.createElement('button');
    rm.className = 'btn btn-ghost';
    rm.style.height = '30px';
    rm.textContent = 'Remove';
    rm.setAttribute('aria-label', `Remove ${d}`);
    rm.addEventListener('click', () => removeDomain(d));
    li.append(host, rm);
    list.appendChild(li);
  });
}

async function refreshEventCount() {
  try {
    const { events } = await api.getEvents();
    $('events-count').textContent = events.length ? `(${events.length} recent)` : '';
  } catch {
    $('events-count').textContent = '';
  }
}

/* ------------------------------------------------------------------ */
/* domain management                                                   */
/* ------------------------------------------------------------------ */

function normalizeDomain(raw) {
  let s = String(raw).trim().toLowerCase();
  if (!s) return '';
  if (s.includes('://')) {
    try { s = new URL(s).hostname; } catch { /* keep as-is */ }
  } else {
    s = s.split('/')[0];
  }
  return s.replace(/^www\./, '');
}

function isValidDomain(d) {
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(d);
}

async function addDomain() {
  const input = $('domain-input');
  const err = $('domain-error');
  const d = normalizeDomain(input.value);
  if (!d) { err.textContent = 'Enter a website.'; return; }
  if (!isValidDomain(d)) { err.textContent = 'Enter a valid domain, e.g. example.com.'; return; }
  if ((protectedConfig.domains || []).includes(d)) { err.textContent = 'That website is already protected.'; return; }
  err.textContent = '';
  const domains = [...(protectedConfig.domains || []), d];
  ({ protected: protectedConfig } = await api.setProtected({ domains }));
  input.value = '';
  renderDomains();
  showToast(`Added ${d}`);
}

async function removeDomain(d) {
  const domains = (protectedConfig.domains || []).filter((x) => x !== d);
  ({ protected: protectedConfig } = await api.setProtected({ domains }));
  renderDomains();
  showToast(`Removed ${d}`);
}

$('domain-add').addEventListener('click', addDomain);
$('domain-input').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { e.preventDefault(); addDomain(); }
});
$('domain-input').addEventListener('input', () => ($('domain-error').textContent = ''));

$('add-suggested').addEventListener('click', async () => {
  const merged = [...new Set([...(protectedConfig.domains || []), ...SUGGESTED_DOMAINS])];
  ({ protected: protectedConfig } = await api.setProtected({ domains: merged }));
  renderDomains();
  showToast('Added suggested sites');
});

document.querySelectorAll('input[name="mode"]').forEach((r) => {
  r.addEventListener('change', async () => {
    ({ protected: protectedConfig } = await api.setProtected({ mode: r.value }));
    toggleDomainBlock();
    showToast('Protection scope updated');
  });
});

/* ------------------------------------------------------------------ */
/* simple setting toggles                                              */
/* ------------------------------------------------------------------ */

$('autolock').addEventListener('change', async (e) => {
  ({ settings } = await api.setSettings({ autoLockMinutes: Number(e.target.value) }));
  showToast('Auto-lock updated');
});
$('quicklock').addEventListener('change', async (e) => {
  ({ settings } = await api.setSettings({ quickLockEnabled: e.target.checked }));
});
$('hide-content').addEventListener('change', async (e) => {
  ({ settings } = await api.setSettings({ hideContentWhenLocked: e.target.checked }));
});
$('logging').addEventListener('change', async (e) => {
  ({ settings } = await api.setSettings({ loggingEnabled: e.target.checked }));
});
$('incognito').addEventListener('change', async (e) => {
  ({ settings } = await api.setSettings({ allowInIncognito: e.target.checked }));
  showToast(e.target.checked
    ? 'Also enable “Allow in Incognito” from Chrome’s extension details.'
    : 'Incognito tabs will not be guarded.');
});

$('edit-shortcut').addEventListener('click', () => {
  chrome.tabs.create({ url: 'chrome://extensions/shortcuts' });
});

$('clear-events').addEventListener('click', async () => {
  await api.clearEvents();
  await refreshEventCount();
  showToast('Activity log cleared');
});

/* ------------------------------------------------------------------ */
/* lock now / reset                                                    */
/* ------------------------------------------------------------------ */

$('lock-now').addEventListener('click', async () => {
  await api.lockNow();
  updateStatusPill(STATE.LOCKED);
  $('gate').classList.remove('hidden');
  $('content').classList.add('hidden');
});

$('reset').addEventListener('click', () => {
  location.href = chrome.runtime.getURL('pages/reset/reset.html');
});

/* ------------------------------------------------------------------ */
/* change credential dialog                                            */
/* ------------------------------------------------------------------ */

const dialog = $('cred-dialog');

function openCredDialog(currentMethod) {
  $('cred-form').reset();
  $('cred-error').textContent = '';
  $('new-method').value = currentMethod || METHOD.PIN;
  updateCredLabels();
  dialog.classList.add('open');
  setTimeout(() => $('cur').focus(), 0);
}
function closeCredDialog() {
  dialog.classList.remove('open');
}

function updateCredLabels() {
  const m = $('new-method').value;
  const noun = m === METHOD.PIN ? 'PIN' : 'password';
  $('new-secret-label').textContent = `New ${noun}`;
  $('new-confirm-label').textContent = `Confirm new ${noun}`;
  $('new-hint').textContent = m === METHOD.PIN
    ? `At least ${PIN_RULES.MIN} digits — avoid predictable PINs.`
    : `At least ${PASSWORD_RULES.MIN} characters.`;
  const inputs = [$('new-secret'), $('new-confirm')];
  inputs.forEach((el) => {
    if (m === METHOD.PIN) el.setAttribute('inputmode', 'numeric');
    else el.removeAttribute('inputmode');
  });
}

$('change-cred').addEventListener('click', async () => {
  const { snapshot } = await api.getState();
  openCredDialog(snapshot.method);
});
$('new-method').addEventListener('change', updateCredLabels);
$('cred-cancel').addEventListener('click', closeCredDialog);
dialog.addEventListener('click', (e) => { if (e.target === dialog) closeCredDialog(); });
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && dialog.classList.contains('open')) closeCredDialog();
});

// reveal buttons (dialog)
document.querySelectorAll('.reveal[data-target]').forEach((btn) => {
  btn.addEventListener('click', () => {
    const input = $(btn.dataset.target);
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    btn.textContent = showing ? 'Show' : 'Hide';
    input.focus();
  });
});

$('cred-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const method = $('new-method').value;
  const noun = method === METHOD.PIN ? 'PIN' : 'password';
  const current = $('cur').value;
  const next = $('new-secret').value;
  const confirm = $('new-confirm').value;
  const err = $('cred-error');

  if (!current) { err.textContent = 'Enter your current credential.'; return; }
  const check = validateSecret(method, next);
  if (!check.ok) { err.textContent = check.error; return; }
  if (next !== confirm) { err.textContent = `Your new ${noun}s do not match.`; return; }

  $('cred-save').disabled = true;
  try {
    const res = await api.changeCredential({ current, method, next });
    if (!res.ok) {
      err.textContent = res.error || 'Could not update your credential.';
      $('cred-save').disabled = false;
      return;
    }
    closeCredDialog();
    await render();
    showToast('Credential updated');
  } catch {
    err.textContent = 'Something went wrong. Please try again.';
  } finally {
    $('cred-save').disabled = false;
  }
});

/* ------------------------------------------------------------------ */
/* toast                                                               */
/* ------------------------------------------------------------------ */

let toastTimer = null;
function showToast(text) {
  const toast = $('toast');
  toast.textContent = text;
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 2200);
}

init();
