/**
 * Chrome Profile Guard — test suite (dependency-free).
 *
 * Run with:  npm test   (or)   node tests/run-tests.mjs
 *
 * Covers the security-critical logic layer (crypto, storage, auth, lock-state)
 * plus packaging integrity and content-script/constant consistency. Browser
 * side effects (tab redirects, idle detection) live in the service worker and
 * are exercised here at the decision level — the pure functions the worker
 * calls — which is where the correctness actually lives.
 *
 * IMPORTANT: chrome-mock must be imported first so `globalThis.chrome` exists
 * before the shared modules evaluate.
 */

import { resetChrome, dumpLocal, dumpSession, putRawLocal } from './chrome-mock.mjs';

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import {
  MSG,
  METHOD,
  STATE,
  PROTECTION_MODE,
  LOCAL_KEYS,
} from '../shared/constants.js';
import {
  randomBytes,
  bytesToBase64,
  base64ToBytes,
  hashSecret,
  verifySecret,
  constantTimeEqual,
} from '../shared/crypto.js';
import {
  getAuth,
  isConfigured,
  getSettings,
  setSettings,
  getProtected,
  setProtected,
  getUnlocked,
  setUnlocked,
  getEvents,
  appendEvent,
} from '../shared/storage.js';
import {
  validatePin,
  validatePassword,
  passwordStrength,
  validateSecret,
  getLockoutStatus,
  configure,
  verify,
  changeCredential,
  resetProtection,
} from '../shared/auth.js';
import {
  getState,
  getSnapshot,
  isProtectedUrl,
  shouldGuard,
  isExceptionUrl,
  isGuardableScheme,
  domainMatches,
  hostnameOf,
} from '../shared/lock-state.js';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

/* ------------------------------------------------------------------ */
/* deterministic clock                                                 */
/* ------------------------------------------------------------------ */

const REAL_NOW = Date.now();
let _now = 1_700_000_000_000; // fixed base for reproducible lockout math
Date.now = () => _now;
const advance = (ms) => { _now += ms; };
const setNow = (ms) => { _now = ms; };

/* ------------------------------------------------------------------ */
/* tiny test harness                                                   */
/* ------------------------------------------------------------------ */

let passed = 0;
let failed = 0;
const failures = [];
let currentGroup = '';

function group(name) {
  currentGroup = name;
  console.log(`\n${name}`);
}

async function test(name, fn) {
  resetChrome();
  setNow(1_700_000_000_000);
  try {
    await fn();
    passed++;
    console.log(`  \u2713 ${name}`);
  } catch (err) {
    failed++;
    failures.push({ group: currentGroup, name, err });
    console.log(`  \u2717 ${name}`);
    console.log(`      ${err && err.message ? err.message : err}`);
  }
}

function fmt(v) {
  if (typeof v === 'string') return JSON.stringify(v);
  if (typeof v === 'object') return JSON.stringify(v);
  return String(v);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}
function eq(actual, expected, msg) {
  if (actual !== expected) {
    throw new Error(`${msg || 'expected equal'} — got ${fmt(actual)}, expected ${fmt(expected)}`);
  }
}
function ne(a, b, msg) {
  if (a === b) throw new Error(`${msg || 'expected different'} — both ${fmt(a)}`);
}
function includes(haystack, needle, msg) {
  if (!haystack.includes(needle)) throw new Error(`${msg || 'expected to include'} ${fmt(needle)}`);
}
function excludes(haystack, needle, msg) {
  if (haystack.includes(needle)) throw new Error(`${msg || 'expected NOT to include'} ${fmt(needle)}`);
}

/* Convenience: configure with a strong PIN and return once done. */
async function setupPin(pin = '835192') {
  const res = await configure({ method: METHOD.PIN, secret: pin });
  eq(res.ok, true, 'setup PIN should succeed');
  return pin;
}
async function setupPassword(pw = 'Str0ng-Pass!') {
  const res = await configure({ method: METHOD.PASSWORD, secret: pw });
  eq(res.ok, true, 'setup password should succeed');
  return pw;
}

/* ================================================================== */
/* 1. Credential validation                                            */
/* ================================================================== */

group('Credential validation');

await test('accepts a strong 6-digit PIN with no warning', () => {
  const r = validatePin('835192');
  eq(r.ok, true, 'should accept');
  eq(r.warning, undefined, 'no warning for 6+ digits');
});

await test('accepts a 4-digit PIN but recommends 6', () => {
  const r = validatePin('8351');
  eq(r.ok, true, 'should accept 4 digits');
  assert(r.warning && r.warning.includes('6'), 'should recommend a 6-digit PIN');
});

await test('rejects PIN shorter than 4 digits', () => {
  eq(validatePin('123').ok, false);
});

await test('rejects non-numeric PIN', () => {
  eq(validatePin('12ab').ok, false);
});

await test('rejects known weak PINs (1234, 0000, 1111, 123456)', () => {
  for (const weak of ['1234', '0000', '1111', '123456', '654321']) {
    eq(validatePin(weak).ok, false, `should reject ${weak}`);
  }
});

await test('rejects all-same-digit and sequential PINs', () => {
  eq(validatePin('444444').ok, false, 'all same');
  eq(validatePin('456789').ok, false, 'ascending');
  eq(validatePin('987654').ok, false, 'descending');
});

await test('rejects PIN longer than 12 digits', () => {
  eq(validatePin('1234567890123').ok, false);
});

await test('rejects password shorter than 8 characters', () => {
  eq(validatePassword('short').ok, false);
});

await test('accepts an 8+ character password and returns strength', () => {
  const r = validatePassword('password1');
  eq(r.ok, true);
  assert(r.strength && typeof r.strength.score === 'number', 'includes strength');
});

await test('rejects password longer than 128 characters', () => {
  eq(validatePassword('a'.repeat(129)).ok, false);
});

await test('password strength scales from very weak to strong', () => {
  eq(passwordStrength('').score, 0);
  assert(passwordStrength('aaaaaaaa').score <= 1, 'lowercase-only 8 chars is weak');
  assert(passwordStrength('Password1').score >= 3, 'mixed+digit is good');
  eq(passwordStrength('Str0ng-Passphrase!').score, 4, 'complex+long is strong');
});

await test('validateSecret dispatches by method', () => {
  eq(validateSecret(METHOD.PIN, '835192').ok, true);
  eq(validateSecret(METHOD.PIN, '1234').ok, false);
  eq(validateSecret(METHOD.PASSWORD, 'password1').ok, true);
  eq(validateSecret(METHOD.PASSWORD, 'x').ok, false);
});

/* ================================================================== */
/* 2. Cryptography                                                      */
/* ================================================================== */

group('Cryptography');

await test('base64 round-trips arbitrary bytes', () => {
  const bytes = randomBytes(32);
  const back = base64ToBytes(bytesToBase64(bytes));
  eq(back.length, bytes.length);
  for (let i = 0; i < bytes.length; i++) eq(back[i], bytes[i], `byte ${i}`);
});

await test('hashSecret never returns the plaintext and includes salt + params', async () => {
  const rec = await hashSecret('CorrectHorse42$');
  ne(rec.derivedKey, 'CorrectHorse42$', 'derived key is not the secret');
  assert(rec.salt && rec.salt.length > 0, 'has salt');
  assert(rec.iterations >= 210000, 'uses >= 210k iterations');
  eq(rec.algo, 'PBKDF2');
  eq(rec.hash, 'SHA-256');
});

await test('verifySecret accepts the right secret and rejects the wrong one', async () => {
  const rec = await hashSecret('open-sesame-9');
  eq(await verifySecret('open-sesame-9', rec), true, 'correct verifies');
  eq(await verifySecret('open-sesame-8', rec), false, 'wrong rejects');
});

await test('salt is unique per hash (no reuse across calls)', async () => {
  const a = await hashSecret('samePassword1');
  const b = await hashSecret('samePassword1');
  ne(a.salt, b.salt, 'salts differ');
  ne(a.derivedKey, b.derivedKey, 'derived keys differ despite same secret');
});

await test('constantTimeEqual is correct for equal, differing, and length-mismatched inputs', () => {
  eq(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])), true);
  eq(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4])), false);
  eq(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3])), false);
  eq(constantTimeEqual(new Uint8Array([]), new Uint8Array([])), true);
});

/* ================================================================== */
/* 3. Setup / configure                                                */
/* ================================================================== */

group('Setup / configure');

await test('fresh install reports SETUP_REQUIRED', async () => {
  eq(await getState(), STATE.SETUP_REQUIRED);
  eq(await isConfigured(), false);
});

await test('configure with a weak PIN fails and stores nothing', async () => {
  const res = await configure({ method: METHOD.PIN, secret: '1234' });
  eq(res.ok, false);
  eq(await isConfigured(), false, 'must not be configured after failed setup');
});

await test('configure with a valid PIN succeeds and leaves workspace LOCKED', async () => {
  await setupPin();
  eq(await isConfigured(), true);
  // The pure layer does not auto-unlock; the service worker sets the session
  // flag after setup for UX. By itself, a configured-but-unopened session is LOCKED.
  eq(await getState(), STATE.LOCKED);
});

await test('configure a second time is rejected (already configured)', async () => {
  await setupPin();
  const res = await configure({ method: METHOD.PIN, secret: '778291' });
  eq(res.ok, false, 'cannot reconfigure over an existing credential');
});

await test('configure honors custom settings and protection scope', async () => {
  await configure({
    method: METHOD.PASSWORD,
    secret: 'Str0ng-Pass!',
    settings: { autoLockMinutes: 15 },
    protectedConfig: { mode: PROTECTION_MODE.SELECTED, domains: ['github.com'] },
  });
  const s = await getSettings();
  const p = await getProtected();
  eq(s.autoLockMinutes, 15);
  eq(p.mode, PROTECTION_MODE.SELECTED);
  eq(p.domains[0], 'github.com');
});

/* ================================================================== */
/* 4. Unlock / verify                                                  */
/* ================================================================== */

group('Unlock / verify');

await test('correct PIN unlocks the workspace', async () => {
  const pin = await setupPin();
  const res = await verify(pin);
  eq(res.ok, true);
  eq(await getState(), STATE.UNLOCKED);
  eq(await getUnlocked(), true);
});

await test('correct password unlocks the workspace', async () => {
  const pw = await setupPassword();
  eq((await verify(pw)).ok, true);
  eq(await getState(), STATE.UNLOCKED);
});

await test('incorrect PIN fails and stays LOCKED', async () => {
  await setupPin('835192');
  const res = await verify('835191');
  eq(res.ok, false);
  eq(await getState(), STATE.LOCKED);
  eq(await getUnlocked(), false);
});

await test('incorrect password fails and stays LOCKED', async () => {
  await setupPassword('Str0ng-Pass!');
  eq((await verify('wrong-pass!')).ok, false);
  eq(await getState(), STATE.LOCKED);
});

await test('empty credential is rejected without counting as a failed attempt', async () => {
  await setupPin();
  const res = await verify('');
  eq(res.ok, false);
  const { failedAttempts } = await getLockoutStatus();
  eq(failedAttempts, 0, 'empty submit must not burn an attempt');
});

await test('verify before setup reports "not set up"', async () => {
  const res = await verify('anything');
  eq(res.ok, false);
  includes(res.error, 'not set up');
});

await test('wrong guesses reveal no partial-match signal (identical error text)', async () => {
  await setupPin('835192');
  const near = await verify('835191'); // one digit off
  const far = await verify('111119');  // totally different (and not weak-listed)
  eq(near.error, far.error, 'error text must not vary with closeness');
  excludes(near.error.toLowerCase(), 'digit', 'must not hint at matched digits');
});

/* ================================================================== */
/* 5. Brute-force lockout                                              */
/* ================================================================== */

group('Brute-force lockout');

await test('attempts 1–4 retry freely, 5th triggers a 10s cooldown', async () => {
  await setupPin('835192');
  for (let i = 0; i < 4; i++) {
    const r = await verify('000009');
    eq(r.ok, false);
    assert(!r.lockedOut, `attempt ${i + 1} should not lock out`);
  }
  const fifth = await verify('000009');
  eq(fifth.ok, false);
  eq(fifth.lockedOut, true, '5th attempt locks out');
  eq(fifth.remainingMs, 10000, '10 second cooldown');
  eq(await getState(), STATE.TEMPORARILY_LOCKED);
});

await test('cooldown escalates 10s → 30s → 1m → 5m → 15m (plateau)', async () => {
  await setupPin('835192');
  const expected = [10000, 30000, 60000, 300000, 900000, 900000];
  // burn the 4 free attempts
  for (let i = 0; i < 4; i++) await verify('000009');
  for (const ms of expected) {
    const r = await verify('000009');
    eq(r.lockedOut, true, 'should be locked out');
    eq(r.remainingMs, ms, `cooldown should be ${ms}ms`);
    advance(ms + 1); // wait out the cooldown to make the next attempt
  }
});

await test('correct credential is refused DURING an active cooldown', async () => {
  const pin = await setupPin('835192');
  for (let i = 0; i < 5; i++) await verify('000009'); // triggers 10s lockout
  const res = await verify(pin); // correct, but we are in cooldown
  eq(res.ok, false, 'must not unlock during cooldown');
  eq(res.lockedOut, true);
  eq(await getUnlocked(), false);
});

await test('correct credential works once the cooldown expires, and resets counters', async () => {
  const pin = await setupPin('835192');
  for (let i = 0; i < 5; i++) await verify('000009');
  advance(10001);
  const res = await verify(pin);
  eq(res.ok, true, 'unlocks after cooldown');
  const { failedAttempts, lockedOut } = await getLockoutStatus();
  eq(failedAttempts, 0, 'attempts reset on success');
  eq(lockedOut, false);
});

/* ================================================================== */
/* 6. Change credential                                               */
/* ================================================================== */

group('Change credential');

await test('changing credential requires the correct current one', async () => {
  await setupPin('835192');
  const bad = await changeCredential({ current: '000000', method: METHOD.PIN, next: '778291' });
  eq(bad.ok, false);
  includes(bad.error.toLowerCase(), 'current');
});

await test('changing credential validates the new one', async () => {
  const pin = await setupPin('835192');
  const res = await changeCredential({ current: pin, method: METHOD.PIN, next: '1234' });
  eq(res.ok, false, 'weak new PIN rejected');
});

await test('after a successful change the old fails and the new works', async () => {
  const pin = await setupPin('835192');
  const res = await changeCredential({ current: pin, method: METHOD.PIN, next: '778291' });
  eq(res.ok, true);
  eq((await verify('835192')).ok, false, 'old PIN no longer works');
  eq((await verify('778291')).ok, true, 'new PIN works');
});

await test('changing method from PIN to password works', async () => {
  const pin = await setupPin('835192');
  const res = await changeCredential({ current: pin, method: METHOD.PASSWORD, next: 'Str0ng-Pass!' });
  eq(res.ok, true);
  eq((await verify('Str0ng-Pass!')).ok, true);
  const snap = await getSnapshot();
  eq(snap.method, METHOD.PASSWORD);
});

/* ================================================================== */
/* 7. Reset                                                            */
/* ================================================================== */

group('Reset');

await test('reset wipes credentials and returns to SETUP_REQUIRED', async () => {
  const pin = await setupPin();
  await verify(pin);
  await resetProtection();
  eq(await getAuth(), null, 'auth cleared');
  eq(await isConfigured(), false);
  eq(await getState(), STATE.SETUP_REQUIRED);
  eq(await getUnlocked(), false);
  eq((await getEvents()).length, 0, 'events cleared too');
});

/* ================================================================== */
/* 8. Lock state, session, restart                                    */
/* ================================================================== */

group('Lock state / session / restart');

await test('browser restart locks the workspace (session flag evaporates)', async () => {
  const pin = await setupPin();
  await verify(pin);
  eq(await getState(), STATE.UNLOCKED);
  // Simulate a Chrome restart: memory-only session storage is gone.
  await chrome.storage.session.clear();
  eq(await getState(), STATE.LOCKED, 'restart returns to LOCKED');
  eq(await isConfigured(), true, 'credential still configured across restart');
});

await test('Lock Now (session flag off) returns to LOCKED', async () => {
  const pin = await setupPin();
  await verify(pin);
  await setUnlocked(false); // what lockNow() does under the hood
  eq(await getState(), STATE.LOCKED);
});

await test('auto-lock on idle locks when a timeout is set', async () => {
  // Mirrors service-worker idle handler: idle + autoLockMinutes>0 -> lock.
  const pin = await setupPin();
  await verify(pin);
  await setSettings({ autoLockMinutes: 5 });
  const s = await getSettings();
  if ((await getState()) === STATE.UNLOCKED && s.autoLockMinutes > 0) await setUnlocked(false);
  eq(await getState(), STATE.LOCKED);
});

await test('auto-lock on idle does NOT lock when auto-lock is Never', async () => {
  const pin = await setupPin();
  await verify(pin);
  await setSettings({ autoLockMinutes: 0 });
  const s = await getSettings();
  if ((await getState()) === STATE.UNLOCKED && s.autoLockMinutes > 0) await setUnlocked(false);
  eq(await getState(), STATE.UNLOCKED, 'stays unlocked on idle when Never');
});

await test('OS lock always locks, regardless of the auto-lock setting', async () => {
  const pin = await setupPin();
  await verify(pin);
  await setSettings({ autoLockMinutes: 0 });
  // Mirrors service-worker idle handler: newState === 'locked' -> always lock.
  await setUnlocked(false);
  eq(await getState(), STATE.LOCKED);
});

await test('snapshot reports method, scope and counters', async () => {
  await setupPin('835192');
  const snap = await getSnapshot();
  eq(snap.state, STATE.LOCKED);
  eq(snap.method, METHOD.PIN);
  eq(snap.autoLockMinutes, 5);
  eq(snap.protectionMode, PROTECTION_MODE.EVERYTHING);
  eq(snap.protectedCount, 0);
  eq(snap.failedAttempts, 0);
  eq(snap.remainingMs, 0);
});

/* ================================================================== */
/* 9. Protected-scope detection                                       */
/* ================================================================== */

group('Protected-scope detection');

await test('Protect Everything mode guards all http(s) pages', () => {
  const cfg = { mode: PROTECTION_MODE.EVERYTHING, domains: [] };
  eq(isProtectedUrl('https://example.com/x', cfg), true);
  eq(isProtectedUrl('http://foo.test/', cfg), true);
});

await test('Selected mode guards only listed domains and their subdomains', () => {
  const cfg = { mode: PROTECTION_MODE.SELECTED, domains: ['github.com', 'mail.google.com'] };
  eq(isProtectedUrl('https://github.com/', cfg), true, 'exact domain');
  eq(isProtectedUrl('https://gist.github.com/x', cfg), true, 'subdomain');
  eq(isProtectedUrl('https://mail.google.com/', cfg), true, 'listed host');
  eq(isProtectedUrl('https://drive.google.com/', cfg), false, 'unlisted sibling');
  eq(isProtectedUrl('https://example.com/', cfg), false, 'unlisted domain');
});

await test('domain matching resists suffix spoofing (notgithub.com !== github.com)', () => {
  eq(domainMatches('notgithub.com', 'github.com'), false);
  eq(domainMatches('github.com.evil.com', 'github.com'), false);
  eq(domainMatches('a.b.github.com', 'github.com'), true);
  eq(domainMatches('github.com', 'github.com'), true);
});

await test('domain matching normalizes wildcard/leading-dot entries', () => {
  eq(domainMatches('app.example.com', '*.example.com'), true);
  eq(domainMatches('example.com', '.example.com'), true);
});

await test('hostnameOf returns empty for opaque URLs', () => {
  eq(hostnameOf('https://Example.COM/a'), 'example.com');
  eq(hostnameOf('not a url'), '');
});

/* ================================================================== */
/* 10. Exceptions & guardable schemes                                 */
/* ================================================================== */

group('Exceptions & guardable schemes');

await test('Chrome internal and extension pages are never in scope', () => {
  const cfg = { mode: PROTECTION_MODE.EVERYTHING, domains: [] };
  for (const url of [
    'chrome://settings',
    'chrome://extensions',
    'chrome-extension://abcdef/page.html',
    'about:blank',
    'edge://settings',
    'devtools://devtools/bundled/x.html',
    'view-source:https://example.com',
    'https://chromewebstore.google.com/detail/x',
    'https://chrome.google.com/webstore/detail/x',
  ]) {
    eq(isExceptionUrl(url), true, `${url} should be an exception`);
    eq(isProtectedUrl(url, cfg), false, `${url} should not be protected`);
  }
});

await test('only http/https are guardable schemes', () => {
  eq(isGuardableScheme('http://x'), true);
  eq(isGuardableScheme('https://x'), true);
  eq(isGuardableScheme('file:///c:/x'), false);
  eq(isGuardableScheme('ftp://x'), false);
  eq(isGuardableScheme('mailto:a@b.c'), false);
  eq(isGuardableScheme('chrome://x'), false);
  eq(isGuardableScheme(''), false);
});

/* ================================================================== */
/* 11. shouldGuard state gating (multi-tab decision)                  */
/* ================================================================== */

group('shouldGuard state gating');

await test('guards protected pages only while locked', () => {
  const cfg = { mode: PROTECTION_MODE.EVERYTHING, domains: [] };
  eq(shouldGuard('https://example.com', STATE.LOCKED, cfg), true);
  eq(shouldGuard('https://example.com', STATE.TEMPORARILY_LOCKED, cfg), true);
  eq(shouldGuard('https://example.com', STATE.UNLOCKED, cfg), false);
  eq(shouldGuard('https://example.com', STATE.SETUP_REQUIRED, cfg), false);
});

await test('never guards exception URLs even while locked (no redirect loops)', () => {
  const cfg = { mode: PROTECTION_MODE.EVERYTHING, domains: [] };
  eq(shouldGuard('chrome://settings', STATE.LOCKED, cfg), false);
  eq(shouldGuard('chrome-extension://abc/lock.html', STATE.LOCKED, cfg), false);
});

await test('a mixed set of open tabs each get the right decision', () => {
  const cfg = { mode: PROTECTION_MODE.SELECTED, domains: ['github.com'] };
  const tabs = [
    { url: 'https://github.com/a', expect: true },
    { url: 'https://gist.github.com/b', expect: true },
    { url: 'https://example.com/c', expect: false },
    { url: 'chrome://settings', expect: false },
    { url: 'chrome-extension://x/lock.html', expect: false },
    { url: 'ftp://legacy/d', expect: false },
  ];
  for (const t of tabs) {
    eq(shouldGuard(t.url, STATE.LOCKED, cfg), t.expect, `decision for ${t.url}`);
  }
});

/* ================================================================== */
/* 12. No plaintext at rest (SECURITY)                                */
/* ================================================================== */

group('No plaintext at rest');

await test('a configured PIN never appears anywhere in storage', async () => {
  await configure({ method: METHOD.PIN, secret: '835192' });
  const blob = JSON.stringify(dumpLocal()) + JSON.stringify(dumpSession());
  excludes(blob, '835192', 'PIN plaintext must not be stored');
  const auth = dumpLocal()[LOCAL_KEYS.AUTH];
  assert(auth.derivedKey && auth.salt, 'derived key + salt stored');
  ne(auth.derivedKey, '835192', 'stored value is not the PIN');
});

await test('a configured password never appears anywhere in storage', async () => {
  await configure({ method: METHOD.PASSWORD, secret: 'CorrectHorse42$' });
  const blob = JSON.stringify(dumpLocal()) + JSON.stringify(dumpSession());
  excludes(blob, 'CorrectHorse42$', 'password plaintext must not be stored');
});

await test('a changed credential also leaves no plaintext behind', async () => {
  const pin = await setupPin('835192');
  await changeCredential({ current: pin, method: METHOD.PASSWORD, next: 'Rotated-Secret-9' });
  const blob = JSON.stringify(dumpLocal()) + JSON.stringify(dumpSession());
  excludes(blob, 'Rotated-Secret-9', 'new secret plaintext must not be stored');
  excludes(blob, '835192', 'old secret must be gone');
});

/* ================================================================== */
/* 13. Storage corruption resilience                                  */
/* ================================================================== */

group('Storage corruption resilience');

await test('corrupt auth record is treated as unconfigured, not a crash', async () => {
  await putRawLocal(LOCAL_KEYS.AUTH, 'total-garbage');
  eq(await getAuth(), null);
  eq(await isConfigured(), false);
  eq(await getState(), STATE.SETUP_REQUIRED);
});

await test('auth without a derived key is not considered configured', async () => {
  await putRawLocal(LOCAL_KEYS.AUTH, { authConfigured: true });
  eq(await isConfigured(), false);
  eq(await getState(), STATE.SETUP_REQUIRED);
});

await test('corrupt settings fall back to defaults', async () => {
  await putRawLocal(LOCAL_KEYS.SETTINGS, 'oops');
  const s = await getSettings();
  eq(s.autoLockMinutes, 5);
  eq(s.loggingEnabled, true);
});

await test('corrupt protected config falls back to a safe default', async () => {
  await putRawLocal(LOCAL_KEYS.PROTECTED, 42);
  const p = await getProtected();
  eq(p.mode, PROTECTION_MODE.EVERYTHING);
  assert(Array.isArray(p.domains), 'domains is always an array');
});

await test('corrupt event log does not crash appendEvent', async () => {
  await putRawLocal(LOCAL_KEYS.EVENTS, { not: 'an array' });
  eq((await getEvents()).length, 0, 'reads back as empty array');
  await appendEvent('locked'); // must not throw
  const events = await getEvents();
  assert(Array.isArray(events) && events.length === 1, 'recovers to a valid array');
});

/* ================================================================== */
/* 14. Domain normalization on write                                  */
/* ================================================================== */

group('Domain normalization on write');

await test('setProtected lowercases, trims and de-duplicates domains', async () => {
  await setupPin();
  const p = await setProtected({
    mode: PROTECTION_MODE.SELECTED,
    domains: ['  GitHub.com ', 'github.com', 'Mail.Google.com', ''],
  });
  eq(p.domains.length, 2, 'blank dropped, duplicate merged');
  assert(p.domains.includes('github.com'), 'lowercased');
  assert(p.domains.includes('mail.google.com'), 'lowercased');
});

/* ================================================================== */
/* 15. Local logging is opt-out                                       */
/* ================================================================== */

group('Local logging opt-out');

await test('disabling logging stops new events from being recorded', async () => {
  await setupPin();
  await setSettings({ loggingEnabled: false });
  const before = (await getEvents()).length;
  await appendEvent('locked');
  eq((await getEvents()).length, before, 'no new event appended when logging is off');
});

/* ================================================================== */
/* 16. Message-type / content-script consistency                      */
/* ================================================================== */

group('Content-script constant consistency');

await test('content guard uses message literals that match MSG constants', () => {
  const guard = readFileSync(join(ROOT, 'content', 'guard.js'), 'utf8');
  for (const key of ['GUARD_DECISION', 'STATE_CHANGED', 'VERIFY_OVERLAY', 'OPEN_RESET']) {
    eq(MSG[key], key, `MSG.${key} value`);
    includes(guard, `${key}: '${key}'`, `guard.js declares ${key}`);
  }
});

await test('content guard remains import-free (MV3 content-script constraint)', () => {
  const guard = readFileSync(join(ROOT, 'content', 'guard.js'), 'utf8');
  excludes(guard, "import {", 'content script must not use ES imports');
  excludes(guard, "from '../shared", 'content script must not import shared modules');
});

/* ================================================================== */
/* 17. Packaging / manifest integrity                                 */
/* ================================================================== */

group('Packaging / manifest integrity');

const manifest = JSON.parse(readFileSync(join(ROOT, 'manifest.json'), 'utf8'));

await test('manifest is MV3 with required identity fields', () => {
  eq(manifest.manifest_version, 3);
  assert(manifest.name && manifest.version, 'name + version present');
});

await test('service worker is an ES module and exists on disk', () => {
  eq(manifest.background.type, 'module');
  assert(existsSync(join(ROOT, manifest.background.service_worker)), 'service worker file exists');
});

await test('every file the manifest references exists', () => {
  const refs = [
    manifest.action.default_popup,
    manifest.options_page,
    ...Object.values(manifest.icons),
    ...Object.values(manifest.action.default_icon),
  ];
  for (const cs of manifest.content_scripts) {
    refs.push(...cs.js, ...cs.css);
  }
  for (const rel of refs) {
    assert(existsSync(join(ROOT, rel)), `missing referenced file: ${rel}`);
  }
});

await test('all extension pages referenced by code exist', () => {
  for (const rel of [
    'pages/setup/setup.html',
    'pages/lock/lock.html',
    'pages/settings/settings.html',
    'pages/reset/reset.html',
  ]) {
    assert(existsSync(join(ROOT, rel)), `missing page: ${rel}`);
  }
});

await test('permissions are the minimal declared set (no over-reach)', () => {
  const perms = new Set(manifest.permissions);
  for (const need of ['storage', 'idle', 'webNavigation', 'tabs', 'scripting']) {
    assert(perms.has(need), `should request ${need}`);
  }
  for (const forbidden of ['history', 'cookies', 'webRequest', 'management', 'downloads', 'bookmarks', 'alarms', 'debugger', 'proxy']) {
    assert(!perms.has(forbidden), `must NOT request ${forbidden}`);
  }
});

await test('quick-lock command is declared with a shortcut', () => {
  assert(manifest.commands && manifest.commands['quick-lock'], 'quick-lock command present');
  assert(manifest.commands['quick-lock'].suggested_key.default, 'has a default shortcut');
});

/* ================================================================== */
/* summary                                                             */
/* ================================================================== */

Date.now = () => REAL_NOW; // restore

console.log(`\n${'-'.repeat(50)}`);
console.log(`  ${passed} passed, ${failed} failed  (${passed + failed} total)`);
console.log('-'.repeat(50));

if (failed > 0) {
  console.log('\nFailures:');
  for (const f of failures) console.log(`  [${f.group}] ${f.name}\n    ${f.err.message}`);
  process.exit(1);
}
