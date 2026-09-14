/**
 * Chrome Profile Guard — storage layer.
 *
 * Thin, typed wrappers over chrome.storage.local (persistent) and
 * chrome.storage.session (memory-only, cleared on browser restart).
 *
 * All persistent configuration lives in storage.local. The "unlocked" flag
 * lives in storage.session precisely because we WANT it to evaporate on
 * restart — that is what makes "locked on every Chrome restart" free and
 * reliable rather than something we have to remember to enforce.
 *
 * Every read has a defined default so callers never deal with `undefined`.
 * Storage failures are surfaced as thrown errors for callers to translate
 * into user-friendly messages (never raw errors in the UI).
 */

import {
  LOCAL_KEYS,
  SESSION_KEYS,
  DEFAULT_SETTINGS,
  DEFAULT_PROTECTED,
  SCHEMA_VERSION,
  MAX_EVENTS,
} from './constants.js';

/* ------------------------------------------------------------------ */
/* low-level promisified access                                        */
/* ------------------------------------------------------------------ */

function localGet(keys) {
  return chrome.storage.local.get(keys);
}
function localSet(obj) {
  return chrome.storage.local.set(obj);
}
function localRemove(keys) {
  return chrome.storage.local.remove(keys);
}
function sessionGet(keys) {
  return chrome.storage.session.get(keys);
}
function sessionSet(obj) {
  return chrome.storage.session.set(obj);
}
function sessionRemove(keys) {
  return chrome.storage.session.remove(keys);
}

/* ------------------------------------------------------------------ */
/* auth record                                                         */
/* ------------------------------------------------------------------ */

/** @returns {Promise<object|null>} the raw auth record, or null if unset/corrupt. */
export async function getAuth() {
  const data = await localGet(LOCAL_KEYS.AUTH);
  const value = data[LOCAL_KEYS.AUTH];
  // Guard against corrupted storage: only a plain object is a valid record.
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

export async function setAuth(record) {
  await localSet({ [LOCAL_KEYS.AUTH]: record });
}

export async function clearAuth() {
  await localRemove(LOCAL_KEYS.AUTH);
}

export async function isConfigured() {
  const auth = await getAuth();
  return Boolean(auth && auth.authConfigured && auth.derivedKey);
}

/* ------------------------------------------------------------------ */
/* settings                                                            */
/* ------------------------------------------------------------------ */

export async function getSettings() {
  const data = await localGet(LOCAL_KEYS.SETTINGS);
  const stored = data[LOCAL_KEYS.SETTINGS];
  const safe = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {};
  return { ...DEFAULT_SETTINGS, ...safe };
}

export async function setSettings(patch) {
  const current = await getSettings();
  const next = { ...current, ...patch };
  await localSet({ [LOCAL_KEYS.SETTINGS]: next });
  return next;
}

/* ------------------------------------------------------------------ */
/* protected scope                                                     */
/* ------------------------------------------------------------------ */

export async function getProtected() {
  const data = await localGet(LOCAL_KEYS.PROTECTED);
  const stored = data[LOCAL_KEYS.PROTECTED];
  const safe = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {};
  const merged = { ...DEFAULT_PROTECTED, ...safe };
  if (!Array.isArray(merged.domains)) merged.domains = [];
  return merged;
}

export async function setProtected(value) {
  const current = await getProtected();
  const next = { ...current, ...value };
  // De-duplicate and normalise domains defensively.
  if (Array.isArray(next.domains)) {
    next.domains = [...new Set(next.domains.map((d) => String(d).trim().toLowerCase()).filter(Boolean))];
  }
  await localSet({ [LOCAL_KEYS.PROTECTED]: next });
  return next;
}

/* ------------------------------------------------------------------ */
/* session (unlocked) flag                                             */
/* ------------------------------------------------------------------ */

export async function getUnlocked() {
  const data = await sessionGet(SESSION_KEYS.UNLOCKED);
  return data[SESSION_KEYS.UNLOCKED] === true;
}

export async function setUnlocked(value) {
  if (value) {
    await sessionSet({
      [SESSION_KEYS.UNLOCKED]: true,
      [SESSION_KEYS.UNLOCKED_AT]: Date.now(),
    });
  } else {
    await sessionRemove([SESSION_KEYS.UNLOCKED, SESSION_KEYS.UNLOCKED_AT]);
  }
}

export async function getUnlockedAt() {
  const data = await sessionGet(SESSION_KEYS.UNLOCKED_AT);
  return data[SESSION_KEYS.UNLOCKED_AT] || 0;
}

/* ------------------------------------------------------------------ */
/* pending return URLs (set when a locked navigation is redirected)    */
/* ------------------------------------------------------------------ */

export async function setPendingReturn(tabId, url) {
  const data = await sessionGet(SESSION_KEYS.PENDING_RETURN);
  const map = data[SESSION_KEYS.PENDING_RETURN] || {};
  map[tabId] = url;
  await sessionSet({ [SESSION_KEYS.PENDING_RETURN]: map });
}

export async function takePendingReturn(tabId) {
  const data = await sessionGet(SESSION_KEYS.PENDING_RETURN);
  const map = data[SESSION_KEYS.PENDING_RETURN] || {};
  const url = map[tabId];
  if (url) {
    delete map[tabId];
    await sessionSet({ [SESSION_KEYS.PENDING_RETURN]: map });
  }
  return url || null;
}

/* ------------------------------------------------------------------ */
/* local activity log (opt-out, minimal, no URLs/secrets)              */
/* ------------------------------------------------------------------ */

export async function getEvents() {
  const data = await localGet(LOCAL_KEYS.EVENTS);
  const value = data[LOCAL_KEYS.EVENTS];
  // Guard against corruption: the log must always be an array.
  return Array.isArray(value) ? value : [];
}

export async function appendEvent(type) {
  const settings = await getSettings();
  if (!settings.loggingEnabled) return;
  const events = await getEvents();
  events.push({ type, at: Date.now() });
  // Ring buffer — keep only the most recent MAX_EVENTS.
  const trimmed = events.slice(-MAX_EVENTS);
  await localSet({ [LOCAL_KEYS.EVENTS]: trimmed });
}

export async function clearEvents() {
  await localRemove(LOCAL_KEYS.EVENTS);
}

/* ------------------------------------------------------------------ */
/* schema + full reset                                                 */
/* ------------------------------------------------------------------ */

export async function ensureSchemaVersion() {
  await localSet({ [LOCAL_KEYS.SCHEMA_VERSION]: SCHEMA_VERSION });
}

/** Remove all extension data (used by Reset Protection). */
export async function clearAll() {
  await chrome.storage.local.clear();
  await chrome.storage.session.clear();
}
