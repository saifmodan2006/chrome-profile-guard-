/**
 * Popup controller — compact status and inline unlock.
 */

import { STATE, AUTO_LOCK_OPTIONS } from '../shared/constants.js';
import { api } from '../shared/messaging.js';

const $ = (id) => document.getElementById(id);
let countdown = null;

function show(view) {
  ['unlocked', 'locked', 'setup'].forEach((v) => {
    $(`view-${v}`).classList.toggle('hidden', v !== view);
  });
}

function autoLockLabel(minutes) {
  const opt = AUTO_LOCK_OPTIONS.find((o) => o.value === minutes);
  return opt ? opt.label : `${minutes} min`;
}

async function render() {
  let snapshot;
  try {
    ({ snapshot } = await api.getState());
  } catch {
    show('setup');
    return;
  }

  if (snapshot.state === STATE.SETUP_REQUIRED) {
    show('setup');
    return;
  }

  if (snapshot.state === STATE.UNLOCKED) {
    $('autolock-line').textContent =
      snapshot.autoLockMinutes > 0
        ? `Auto-lock: ${autoLockLabel(snapshot.autoLockMinutes)}`
        : 'Auto-lock: Off';
    show('unlocked');
    return;
  }

  // locked / temporarily locked
  const noun = snapshot.method === 'password' ? 'password' : 'PIN';
  $('secret').setAttribute('placeholder', `Enter ${noun}`);
  if (noun === 'PIN') $('secret').setAttribute('inputmode', 'numeric');
  $('forgot').textContent = `Forgot your ${noun}?`;
  show('locked');
  if (snapshot.state === STATE.TEMPORARILY_LOCKED && snapshot.remainingMs > 0) {
    startCountdown(snapshot.remainingMs);
  } else {
    setTimeout(() => $('secret').focus(), 30);
  }
}

/* ---------- unlocked actions ---------- */

$('lock-now').addEventListener('click', async () => {
  await api.lockNow();
  await render();
});
$('open-settings').addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
  window.close();
});

/* ---------- setup ---------- */

$('open-setup').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/setup/setup.html') });
  window.close();
});

/* ---------- locked actions ---------- */

$('reveal').addEventListener('click', () => {
  const input = $('secret');
  const showing = input.type === 'text';
  input.type = showing ? 'password' : 'text';
  $('reveal').textContent = showing ? 'Show' : 'Hide';
  input.focus();
});

$('secret').addEventListener('input', () => {
  $('secret').setAttribute('aria-invalid', 'false');
  $('error').textContent = '';
});

$('unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('secret');
  const secret = input.value;
  if (!secret) {
    $('error').textContent = 'Enter your credential.';
    return;
  }
  $('unlock').disabled = true;
  let res;
  try {
    res = await api.verify(secret);
  } catch {
    $('unlock').disabled = false;
    $('error').textContent = 'Something went wrong. Please try again.';
    return;
  }
  if (res.ok) {
    await render();
    return;
  }
  $('unlock').disabled = false;
  input.value = '';
  input.setAttribute('aria-invalid', 'true');
  $('error').textContent = res.error || 'Incorrect credential. Please try again.';
  if (res.lockedOut && res.remainingMs) startCountdown(res.remainingMs);
  input.focus();
});

$('forgot').addEventListener('click', () => {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/reset/reset.html') });
  window.close();
});

function startCountdown(ms) {
  const input = $('secret');
  const unlock = $('unlock');
  let remaining = Math.ceil(ms / 1000);
  input.disabled = true;
  unlock.disabled = true;
  const tick = () => {
    if (remaining <= 0) {
      clearInterval(countdown);
      countdown = null;
      input.disabled = false;
      unlock.disabled = false;
      $('error').textContent = '';
      input.focus();
      return;
    }
    const label = remaining >= 60 ? `${Math.ceil(remaining / 60)} min` : `${remaining}s`;
    $('error').textContent = `Too many attempts. Try again in ${label}.`;
    remaining--;
  };
  tick();
  countdown = setInterval(tick, 1000);
}

render();
