/**
 * Chrome Profile Guard — authentication logic.
 *
 * Owns credential validation, configuration, verification, brute-force
 * lockout accounting, credential change, and reset. Pure with respect to the
 * browser: it touches storage + crypto only, so it is fully unit-testable
 * with a mocked `chrome`. Side effects on tabs/alarms live in the service
 * worker, not here.
 */

import {
  METHOD,
  PIN_RULES,
  PASSWORD_RULES,
  WEAK_PINS,
  LOCKOUT_SCHEDULE_MS,
  DEFAULT_SETTINGS,
  DEFAULT_PROTECTED,
  EVENT,
} from './constants.js';
import { hashSecret, verifySecret } from './crypto.js';
import {
  getAuth,
  setAuth,
  clearAll,
  setSettings,
  setProtected,
  setUnlocked,
  appendEvent,
  ensureSchemaVersion,
} from './storage.js';

/* ------------------------------------------------------------------ */
/* validation                                                          */
/* ------------------------------------------------------------------ */

function isAllSameDigit(pin) {
  return /^(\d)\1*$/.test(pin);
}

function isSequential(pin) {
  if (pin.length < 2) return false;
  let asc = true;
  let desc = true;
  for (let i = 1; i < pin.length; i++) {
    const diff = pin.charCodeAt(i) - pin.charCodeAt(i - 1);
    if (diff !== 1) asc = false;
    if (diff !== -1) desc = false;
  }
  return asc || desc;
}

/**
 * @returns {{ok:boolean, error?:string, warning?:string}}
 */
export function validatePin(pin) {
  if (typeof pin !== 'string' || pin.length === 0) {
    return { ok: false, error: 'Enter a PIN.' };
  }
  if (!/^\d+$/.test(pin)) {
    return { ok: false, error: 'A PIN can contain digits only.' };
  }
  if (pin.length < PIN_RULES.MIN) {
    return { ok: false, error: `Use at least ${PIN_RULES.MIN} digits.` };
  }
  if (pin.length > PIN_RULES.MAX) {
    return { ok: false, error: `Use at most ${PIN_RULES.MAX} digits.` };
  }
  if (WEAK_PINS.includes(pin) || isAllSameDigit(pin) || isSequential(pin)) {
    return { ok: false, error: 'That PIN is too easy to guess. Choose a less predictable one.' };
  }
  if (pin.length < PIN_RULES.RECOMMENDED) {
    return { ok: true, warning: `A ${PIN_RULES.RECOMMENDED}-digit PIN is recommended.` };
  }
  return { ok: true };
}

/**
 * Password strength on a 0–4 scale with a human label.
 * @returns {{score:number, label:string}}
 */
export function passwordStrength(pw) {
  if (!pw) return { score: 0, label: 'Too short' };
  let score = 0;
  if (pw.length >= PASSWORD_RULES.MIN) score++;
  if (pw.length >= 12) score++;
  if (/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
  if (/\d/.test(pw)) score++;
  if (/[^A-Za-z0-9]/.test(pw)) score++;
  score = Math.min(score, 4);
  const labels = ['Very weak', 'Weak', 'Fair', 'Good', 'Strong'];
  return { score, label: labels[score] };
}

/**
 * @returns {{ok:boolean, error?:string, strength?:object}}
 */
export function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length === 0) {
    return { ok: false, error: 'Enter a password.' };
  }
  if (pw.length < PASSWORD_RULES.MIN) {
    return { ok: false, error: `Use at least ${PASSWORD_RULES.MIN} characters.` };
  }
  if (pw.length > PASSWORD_RULES.MAX) {
    return { ok: false, error: `Use at most ${PASSWORD_RULES.MAX} characters.` };
  }
  return { ok: true, strength: passwordStrength(pw) };
}

/** Validate a secret for the chosen method. */
export function validateSecret(method, secret) {
  return method === METHOD.PIN ? validatePin(secret) : validatePassword(secret);
}

/* ------------------------------------------------------------------ */
/* lockout accounting                                                  */
/* ------------------------------------------------------------------ */

function cooldownFor(failedAttempts) {
  const idx = Math.min(failedAttempts, LOCKOUT_SCHEDULE_MS.length - 1);
  return LOCKOUT_SCHEDULE_MS[idx];
}

/**
 * @returns {{lockedOut:boolean, remainingMs:number, failedAttempts:number}}
 */
export async function getLockoutStatus() {
  const auth = await getAuth();
  const failedAttempts = auth?.failedAttempts || 0;
  const lockoutUntil = auth?.lockoutUntil || 0;
  const remainingMs = Math.max(0, lockoutUntil - Date.now());
  return { lockedOut: remainingMs > 0, remainingMs, failedAttempts };
}

/* ------------------------------------------------------------------ */
/* configure (first-run setup)                                         */
/* ------------------------------------------------------------------ */

/**
 * Configure protection for the first time.
 * @param {{method:string, secret:string, settings?:object, protectedConfig?:object}} opts
 * @returns {Promise<{ok:boolean, error?:string}>}
 */
export async function configure({ method, secret, settings, protectedConfig }) {
  const existing = await getAuth();
  if (existing?.authConfigured) {
    return { ok: false, error: 'Protection is already configured.' };
  }
  const check = validateSecret(method, secret);
  if (!check.ok) return { ok: false, error: check.error };

  const record = await hashSecret(secret);
  await setAuth({
    authConfigured: true,
    authMethod: method,
    ...record,
    failedAttempts: 0,
    lockoutUntil: null,
    createdAt: Date.now(),
  });
  await setSettings({ ...DEFAULT_SETTINGS, ...(settings || {}) });
  await setProtected({ ...DEFAULT_PROTECTED, ...(protectedConfig || {}) });
  await ensureSchemaVersion();
  await appendEvent(EVENT.INITIALIZED);
  return { ok: true };
}

/* ------------------------------------------------------------------ */
/* verify (unlock attempt)                                             */
/* ------------------------------------------------------------------ */

/**
 * Verify a secret. On success clears counters and marks the session unlocked.
 * On failure increments the attempt counter and applies progressive cooldown.
 * The returned error text is identical for "wrong credential" regardless of
 * how close the guess was — no partial-match signal is ever exposed.
 *
 * @param {string} secret
 * @returns {Promise<{ok:boolean, error?:string, lockedOut?:boolean, remainingMs?:number}>}
 */
export async function verify(secret) {
  const auth = await getAuth();
  if (!auth?.authConfigured) {
    return { ok: false, error: 'Protection is not set up.' };
  }

  // Respect an active cooldown before doing any expensive work.
  const now = Date.now();
  if (auth.lockoutUntil && auth.lockoutUntil > now) {
    return {
      ok: false,
      lockedOut: true,
      remainingMs: auth.lockoutUntil - now,
      error: cooldownMessage(auth.lockoutUntil - now),
    };
  }

  if (typeof secret !== 'string' || secret.length === 0) {
    return { ok: false, error: 'Enter your credential to continue.' };
  }

  const match = await verifySecret(secret, auth);
  if (match) {
    await setAuth({ ...auth, failedAttempts: 0, lockoutUntil: null });
    await setUnlocked(true);
    await appendEvent(EVENT.UNLOCKED);
    return { ok: true };
  }

  const failedAttempts = (auth.failedAttempts || 0) + 1;
  const cooldown = cooldownFor(failedAttempts);
  const lockoutUntil = cooldown > 0 ? now + cooldown : null;
  await setAuth({ ...auth, failedAttempts, lockoutUntil });
  await appendEvent(EVENT.FAILED_AUTH);

  if (lockoutUntil) {
    return {
      ok: false,
      lockedOut: true,
      remainingMs: cooldown,
      error: cooldownMessage(cooldown),
    };
  }
  return { ok: false, error: 'Incorrect credential. Please try again.' };
}

function cooldownMessage(ms) {
  const seconds = Math.ceil(ms / 1000);
  if (seconds >= 60) {
    const minutes = Math.ceil(seconds / 60);
    return `Too many incorrect attempts. Try again in ${minutes} minute${minutes === 1 ? '' : 's'}.`;
  }
  return `Too many incorrect attempts. Try again in ${seconds} seconds.`;
}

/* ------------------------------------------------------------------ */
/* change credential                                                   */
/* ------------------------------------------------------------------ */

/**
 * Change the credential. Requires the current credential to authenticate the
 * change (an unauthenticated caller cannot silently replace the password).
 * @param {{current:string, method:string, next:string}} opts
 */
export async function changeCredential({ current, method, next }) {
  const auth = await getAuth();
  if (!auth?.authConfigured) return { ok: false, error: 'Protection is not set up.' };

  const currentOk = await verifySecret(current, auth);
  if (!currentOk) return { ok: false, error: 'Your current credential is incorrect.' };

  const check = validateSecret(method, next);
  if (!check.ok) return { ok: false, error: check.error };

  const record = await hashSecret(next);
  await setAuth({
    ...auth,
    authMethod: method,
    ...record,
    failedAttempts: 0,
    lockoutUntil: null,
    updatedAt: Date.now(),
  });
  await appendEvent(EVENT.CREDENTIAL_CHANGED);
  return { ok: true };
}

/* ------------------------------------------------------------------ */
/* reset                                                               */
/* ------------------------------------------------------------------ */

/**
 * Full reset: wipe all local + session data. Because credentials are stored
 * only as derived keys with no recovery path, reset is the intended and only
 * way out of a forgotten credential.
 */
export async function resetProtection() {
  await clearAll();
  return { ok: true };
}
