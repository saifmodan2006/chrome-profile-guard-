/*
 * Chrome Profile Guard — content guard (overlay).
 *
 * Self-contained content script (MV3 content scripts cannot use ES imports).
 * It asks the service worker whether the current page should be covered and,
 * if so, renders a neutral lock screen inside a Shadow DOM so page CSS can
 * neither style nor hide it. The underlying page is hidden via guard.css.
 *
 * This is defense-in-depth (Layer 4). The primary hard block is the service
 * worker's navigation redirect (Layer 3). This overlay covers tabs that are
 * ALREADY open when a lock happens, preserving their page state so browsing
 * resumes exactly where it left off after unlock.
 */

(() => {
  // Idempotent: if injected twice (manifest + programmatic), just re-evaluate.
  if (window.__cpgGuardLoaded) {
    if (typeof window.__cpgGuardReeval === 'function') window.__cpgGuardReeval();
    return;
  }
  window.__cpgGuardLoaded = true;

  const MSG = {
    GUARD_DECISION: 'GUARD_DECISION',
    STATE_CHANGED: 'STATE_CHANGED',
    VERIFY_OVERLAY: 'VERIFY_OVERLAY',
    OPEN_RESET: 'OPEN_RESET',
  };
  const LOCKED_STATES = new Set(['LOCKED', 'TEMPORARILY_LOCKED']);

  let host = null;
  let root = null;
  let method = 'pin';
  let countdown = null;

  async function evaluate() {
    let res;
    try {
      res = await chrome.runtime.sendMessage({ type: MSG.GUARD_DECISION, url: location.href });
    } catch {
      return; // extension reloaded / context invalidated
    }
    if (!res || !res.ok) return;
    method = res.method || 'pin';
    if (res.guard) showOverlay();
    else removeOverlay();
  }
  window.__cpgGuardReeval = evaluate;

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg && msg.type === MSG.STATE_CHANGED) {
      if (LOCKED_STATES.has(msg.state)) evaluate();
      else removeOverlay();
    }
  });

  /* ---------------------------------------------------------------- */
  /* overlay lifecycle                                                */
  /* ---------------------------------------------------------------- */

  function showOverlay() {
    if (host) {
      focusInput();
      return;
    }
    document.documentElement.setAttribute('data-cpg-guarded', 'true');

    host = document.createElement('div');
    host.id = '__cpg_overlay_host';
    host.style.cssText = 'all: initial; position: fixed; inset: 0; z-index: 2147483647;';
    root = host.attachShadow({ mode: 'open' });
    root.innerHTML = markup();
    (document.documentElement || document).appendChild(host);

    wire();
    focusInput();
  }

  function removeOverlay() {
    if (countdown) {
      clearInterval(countdown);
      countdown = null;
    }
    document.documentElement.removeAttribute('data-cpg-guarded');
    if (host && host.parentNode) host.parentNode.removeChild(host);
    host = null;
    root = null;
  }

  /* ---------------------------------------------------------------- */
  /* markup + styles (Shadow DOM)                                     */
  /* ---------------------------------------------------------------- */

  function markup() {
    const isPin = method === 'pin';
    const label = isPin ? 'PIN' : 'password';
    return `
      <style>
        :host { all: initial; }
        * { box-sizing: border-box; font-family: 'Segoe UI', Roboto, Arial, sans-serif; }
        .backdrop {
          position: fixed; inset: 0; background: #F8F9FA;
          display: flex; align-items: center; justify-content: center; padding: 24px;
        }
        .card {
          width: 100%; max-width: 360px; background: #FFFFFF;
          border: 1px solid #DADCE0; border-radius: 12px; padding: 32px 28px;
          text-align: center;
        }
        .mark { width: 40px; height: 40px; margin: 0 auto 16px; color: #5F6368; }
        h1 { font-size: 18px; font-weight: 500; color: #202124; margin: 0 0 6px; }
        p.sub { font-size: 13px; color: #5F6368; margin: 0 0 22px; line-height: 1.5; }
        form { margin: 0; }
        .field { position: relative; margin-bottom: 12px; text-align: left; }
        label { display: block; font-size: 12px; color: #5F6368; margin-bottom: 6px; }
        input {
          width: 100%; height: 42px; padding: 0 40px 0 12px;
          font-size: 15px; color: #202124; background: #FFFFFF;
          border: 1px solid #DADCE0; border-radius: 8px; outline: none;
          letter-spacing: 0.06em;
        }
        input:focus { border-color: #1A73E8; box-shadow: 0 0 0 1px #1A73E8; }
        input[aria-invalid="true"] { border-color: #D93025; }
        .toggle {
          position: absolute; right: 6px; top: 27px; width: 30px; height: 30px;
          border: none; background: transparent; color: #5F6368; cursor: pointer;
          border-radius: 6px; font-size: 12px;
        }
        .toggle:hover { background: #F1F3F4; }
        .error { min-height: 18px; font-size: 12px; color: #D93025; margin: 2px 0 10px; text-align: left; }
        button.primary {
          width: 100%; height: 42px; border: none; border-radius: 8px;
          background: #1A73E8; color: #FFFFFF; font-size: 14px; font-weight: 500;
          cursor: pointer;
        }
        button.primary:hover { background: #1B66C9; }
        button.primary:disabled { background: #A6C8F5; cursor: default; }
        .forgot { display: inline-block; margin-top: 18px; font-size: 12px; color: #1A73E8; background: none; border: none; cursor: pointer; }
        .forgot:hover { text-decoration: underline; }
        :focus-visible { outline: 2px solid #1A73E8; outline-offset: 2px; }
      </style>
      <div class="backdrop" role="dialog" aria-modal="true" aria-label="Browser locked">
        <div class="card">
          <svg class="mark" viewBox="0 0 24 24" fill="none" aria-hidden="true">
            <rect x="4.5" y="10.5" width="15" height="10" rx="2" stroke="currentColor" stroke-width="1.6"/>
            <path d="M8 10.5V8a4 4 0 0 1 8 0v2.5" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>
          </svg>
          <h1>Browser locked</h1>
          <p class="sub">This browsing workspace is protected. Enter your ${label} to continue.</p>
          <form id="f" novalidate>
            <div class="field">
              <label for="secret">Enter ${label}</label>
              <input id="secret" type="password"
                autocomplete="off" aria-label="Enter ${label}"
                ${isPin ? 'inputmode="numeric" pattern="[0-9]*" maxlength="12"' : ''} />
              <button type="button" class="toggle" id="toggle" aria-label="Show ${label}">Show</button>
            </div>
            <div class="error" id="err" role="alert" aria-live="assertive"></div>
            <button type="submit" class="primary" id="submit">Unlock</button>
          </form>
          <button class="forgot" id="forgot">Forgot your ${label}?</button>
        </div>
      </div>
    `;
  }

  /* ---------------------------------------------------------------- */
  /* interactions                                                     */
  /* ---------------------------------------------------------------- */

  function $(sel) {
    return root.querySelector(sel);
  }

  function focusInput() {
    const input = root && $('#secret');
    if (input) setTimeout(() => input.focus(), 0);
  }

  function wire() {
    const form = $('#f');
    const input = $('#secret');
    const toggle = $('#toggle');
    const submit = $('#submit');
    const err = $('#err');
    const forgot = $('#forgot');

    toggle.addEventListener('click', () => {
      const showing = input.type === 'text';
      input.type = showing ? 'password' : 'text';
      toggle.textContent = showing ? 'Show' : 'Hide';
      input.focus();
    });

    input.addEventListener('input', () => {
      input.setAttribute('aria-invalid', 'false');
      err.textContent = '';
    });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const secret = input.value;
      if (!secret) {
        showError('Enter your credential to continue.');
        return;
      }
      submit.disabled = true;
      let res;
      try {
        res = await chrome.runtime.sendMessage({ type: MSG.VERIFY_OVERLAY, secret });
      } catch {
        submit.disabled = false;
        showError('Something went wrong. Please try again.');
        return;
      }
      if (res && res.ok) {
        removeOverlay(); // SW also broadcasts UNLOCKED to any other tabs
        return;
      }
      submit.disabled = false;
      input.value = '';
      input.setAttribute('aria-invalid', 'true');
      showError((res && res.error) || 'Incorrect credential. Please try again.');
      if (res && res.lockedOut && res.remainingMs) startCountdown(res.remainingMs);
      input.focus();
    });

    forgot.addEventListener('click', () => {
      chrome.runtime.sendMessage({ type: MSG.OPEN_RESET }).catch(() => {});
    });

    // Keep focus inside the dialog.
    root.addEventListener('keydown', (e) => {
      if (e.key !== 'Tab') return;
      const focusables = [...root.querySelectorAll('input, button')].filter((el) => !el.disabled);
      if (focusables.length === 0) return;
      const first = focusables[0];
      const last = focusables[focusables.length - 1];
      const active = root.activeElement;
      if (e.shiftKey && active === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && active === last) {
        e.preventDefault();
        first.focus();
      }
    });
  }

  function showError(text) {
    const err = root && $('#err');
    if (err) err.textContent = text;
  }

  function startCountdown(ms) {
    const input = $('#secret');
    const submit = $('#submit');
    let remaining = Math.ceil(ms / 1000);
    input.disabled = true;
    submit.disabled = true;
    const tick = () => {
      if (remaining <= 0) {
        clearInterval(countdown);
        countdown = null;
        input.disabled = false;
        submit.disabled = false;
        showError('');
        input.focus();
        return;
      }
      showError(`Too many incorrect attempts. Try again in ${remaining}s.`);
      remaining--;
    };
    tick();
    countdown = setInterval(tick, 1000);
  }

  // Kick off on load.
  evaluate();
})();
