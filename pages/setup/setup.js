/**
 * Setup onboarding controller.
 *
 * Uses the pure validators from shared/auth.js for instant client-side
 * feedback; the service worker re-validates on CONFIGURE, so the stored
 * result is authoritative regardless of the page.
 */

import { METHOD, AUTO_LOCK_OPTIONS, PIN_RULES, PASSWORD_RULES, DEFAULT_SETTINGS } from '../../shared/constants.js';
import { validateSecret, passwordStrength } from '../../shared/auth.js';
import { api } from '../../shared/messaging.js';

const state = { method: null };

const $ = (id) => document.getElementById(id);
const steps = ['welcome', 'method', 'create'];

/* ---------- navigation ---------- */

function showStep(name) {
  document.querySelectorAll('.step').forEach((el) => el.classList.add('hidden'));
  $(`step-${name}`).classList.remove('hidden');
  updateStepper(name);
  // Move focus to the step heading for screen readers.
  const heading = $(`step-${name}`).querySelector('h1');
  if (heading) heading.setAttribute('tabindex', '-1'), heading.focus();
}

function updateStepper(name) {
  const idx = steps.indexOf(name);
  document.querySelectorAll('#stepper li').forEach((li, i) => {
    li.classList.toggle('active', i === idx);
    li.classList.toggle('done', idx > i);
  });
}

/* ---------- step 1: welcome ---------- */

$('btn-start').addEventListener('click', () => showStep('method'));

/* ---------- step 2: method ---------- */

function selectMethod(method) {
  state.method = method;
  document.querySelectorAll('.choice[data-method]').forEach((btn) => {
    const on = btn.dataset.method === method;
    btn.classList.toggle('selected', on);
    btn.setAttribute('aria-pressed', String(on));
  });
  $('next-method').disabled = false;
}

$('choose-pin').addEventListener('click', () => selectMethod(METHOD.PIN));
$('choose-password').addEventListener('click', () => selectMethod(METHOD.PASSWORD));
$('back-method').addEventListener('click', () => showStep('welcome'));
$('next-method').addEventListener('click', () => {
  if (state.method) enterCreateStep();
});

/* ---------- step 3: create ---------- */

function enterCreateStep() {
  const isPin = state.method === METHOD.PIN;
  const noun = isPin ? 'PIN' : 'password';
  $('create-title').textContent = isPin ? 'Create your PIN' : 'Create your password';
  $('label-secret').textContent = `Enter ${noun}`;
  $('label-confirm').textContent = `Confirm ${noun}`;
  $('secret-hint').textContent = isPin
    ? `At least ${PIN_RULES.MIN} digits — ${PIN_RULES.RECOMMENDED} recommended. Avoid predictable PINs.`
    : `At least ${PASSWORD_RULES.MIN} characters.`;

  const secret = $('secret');
  const confirm = $('confirm');
  secret.value = '';
  confirm.value = '';
  if (isPin) {
    secret.setAttribute('inputmode', 'numeric');
    secret.setAttribute('maxlength', String(PIN_RULES.MAX));
    confirm.setAttribute('inputmode', 'numeric');
    confirm.setAttribute('maxlength', String(PIN_RULES.MAX));
    $('strength').classList.add('hidden');
  } else {
    secret.removeAttribute('inputmode');
    secret.removeAttribute('maxlength');
    confirm.removeAttribute('maxlength');
    $('strength').classList.remove('hidden');
  }
  $('create-error').textContent = '';
  showStep('create');
}

// Populate auto-lock options.
const sel = $('autolock');
AUTO_LOCK_OPTIONS.forEach((opt) => {
  const o = document.createElement('option');
  o.value = String(opt.value);
  o.textContent = opt.label;
  if (opt.value === DEFAULT_SETTINGS.autoLockMinutes) o.selected = true;
  sel.appendChild(o);
});

// PIN digit filtering + live feedback.
$('secret').addEventListener('input', () => {
  const isPin = state.method === METHOD.PIN;
  const input = $('secret');
  if (isPin) input.value = input.value.replace(/\D/g, '');
  input.setAttribute('aria-invalid', 'false');
  $('create-error').textContent = '';

  if (!isPin) {
    const { score, label } = passwordStrength(input.value);
    document.querySelectorAll('.strength-seg').forEach((seg) => {
      const i = Number(seg.dataset.i);
      seg.className = 'strength-seg' + (i <= score ? ` on-${score}` : '');
    });
    $('strength-label').textContent = input.value ? label : '';
  }
});

$('confirm').addEventListener('input', () => {
  if (state.method === METHOD.PIN) $('confirm').value = $('confirm').value.replace(/\D/g, '');
  $('create-error').textContent = '';
});

// Reveal toggles.
function wireReveal(btnId, inputId) {
  $(btnId).addEventListener('click', () => {
    const input = $(inputId);
    const showing = input.type === 'text';
    input.type = showing ? 'password' : 'text';
    $(btnId).textContent = showing ? 'Show' : 'Hide';
    input.focus();
  });
}
wireReveal('reveal-1', 'secret');
wireReveal('reveal-2', 'confirm');

$('back-create').addEventListener('click', () => showStep('method'));

$('create-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const noun = state.method === METHOD.PIN ? 'PIN' : 'password';
  const secret = $('secret').value;
  const confirm = $('confirm').value;
  const err = $('create-error');

  const check = validateSecret(state.method, secret);
  if (!check.ok) {
    $('secret').setAttribute('aria-invalid', 'true');
    err.textContent = check.error;
    $('secret').focus();
    return;
  }
  if (secret !== confirm) {
    $('confirm').setAttribute('aria-invalid', 'true');
    err.textContent = `Your ${noun}s do not match.`;
    $('confirm').focus();
    return;
  }

  const scope = document.querySelector('input[name="scope"]:checked')?.value || 'everything';
  const payload = {
    method: state.method,
    secret,
    settings: { autoLockMinutes: Number($('autolock').value) },
    protectedConfig: { mode: scope, domains: [] },
  };

  $('finish').disabled = true;
  try {
    const res = await api.configure(payload);
    if (!res.ok) {
      err.textContent = res.error || 'Setup could not be completed. Please try again.';
      $('finish').disabled = false;
      return;
    }
    showStep('done');
  } catch {
    err.textContent = 'Your security settings could not be saved. Please try again.';
    $('finish').disabled = false;
  }
});

/* ---------- done ---------- */

$('open-settings').addEventListener('click', () => chrome.runtime.openOptionsPage());
$('lock-now').addEventListener('click', async (e) => {
  const btn = e.currentTarget;
  btn.disabled = true;
  try {
    await api.lockNow();
    btn.textContent = 'Locked ✓';
  } catch {
    btn.disabled = false;
  }
});

/* ---------- limits disclosure ---------- */

$('learn-limits').addEventListener('click', (e) => {
  e.preventDefault();
  if (document.getElementById('limits-note')) return;
  const note = document.createElement('div');
  note.id = 'limits-note';
  note.className = 'notice info';
  note.style.marginTop = '10px';
  note.textContent =
    'This is a browsing-workspace lock built on Chrome extension APIs. It stops casual ' +
    'access to your open tabs and protected sites, but it cannot lock Chrome’s native ' +
    'profile picker, and a user who disables the extension can bypass it. Your credential ' +
    'never leaves this device.';
  e.target.closest('p').after(note);
});

/* ---------- init ---------- */

showStep('welcome');
