/**
 * Lock page controller.
 *
 * Reached two ways:
 *   1. The service worker redirects a protected tab here (with ?return=<url>).
 *   2. Opened directly (no return url) as a general lock screen.
 *
 * On success it returns to the requested page where that is safe.
 */

import { STATE } from '../../shared/constants.js';
import { isGuardableScheme, isExceptionUrl } from '../../shared/lock-state.js';
import { api } from '../../shared/messaging.js';

const $ = (id) => document.getElementById(id);
let countdown = null;

function returnUrl() {
  const raw = new URLSearchParams(location.search).get('return');
  if (!raw) return null;
  // Our own extension pages (e.g. the settings gate) are always safe to return to.
  if (raw.startsWith(chrome.runtime.getURL(''))) return raw;
  if (!isGuardableScheme(raw) || isExceptionUrl(raw)) return null;
  return raw;
}

function goTo(url) {
  // Replace so the lock page doesn't linger in history.
  location.replace(url);
}

async function init() {
  let snapshot;
  try {
    ({ snapshot } = await api.getState());
  } catch {
    $('error').textContent = 'Protection needs to be reinitialized.';
    return;
  }

  if (snapshot.state === STATE.SETUP_REQUIRED) {
    goTo(chrome.runtime.getURL('pages/setup/setup.html'));
    return;
  }
  if (snapshot.state === STATE.UNLOCKED) {
    const ret = returnUrl();
    if (ret) goTo(ret);
    else showUnlocked();
    return;
  }

  // Locked — adapt copy to the method.
  const noun = snapshot.method === 'password' ? 'password' : 'PIN';
  $('secret-label').textContent = `Enter ${noun}`;
  $('subtitle').textContent = `This browsing workspace is protected. Enter your ${noun} to continue.`;
  $('forgot').textContent = `Forgot your ${noun}?`;
  const input = $('secret');
  if (noun === 'PIN') input.setAttribute('inputmode', 'numeric');

  if (snapshot.state === STATE.TEMPORARILY_LOCKED && snapshot.remainingMs > 0) {
    startCountdown(snapshot.remainingMs);
  }
  input.focus();
}

/* ---------- interactions ---------- */

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

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('secret');
  const secret = input.value;
  if (!secret) {
    $('error').textContent = 'Enter your credential to continue.';
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
    const ret = returnUrl();
    if (ret) goTo(ret);
    else showUnlocked();
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
  goTo(chrome.runtime.getURL('pages/reset/reset.html'));
});

/* ---------- helpers ---------- */

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
    const label = remaining >= 60
      ? `${Math.ceil(remaining / 60)} minute(s)`
      : `${remaining}s`;
    $('error').textContent = `Too many incorrect attempts. Try again in ${label}.`;
    remaining--;
  };
  tick();
  countdown = setInterval(tick, 1000);
}

function showUnlocked() {
  document.querySelector('.lock-card').innerHTML = `
    <svg class="mark" viewBox="0 0 24 24" fill="none" aria-hidden="true" style="margin:0 auto 16px; color:var(--success);">
      <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="1.6"/>
      <path d="M8.5 12.5l2.5 2.5 4.5-5" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <h1 class="title">Unlocked</h1>
    <p class="subtitle">Your browsing workspace is available. You can close this tab or open a new one.</p>`;
}

init();
