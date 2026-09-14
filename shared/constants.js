/**
 * Chrome Profile Guard — shared constants.
 *
 * Single source of truth for storage keys, state names, message types,
 * crypto parameters, defaults, and validation rules. Imported by the
 * service worker and all extension pages (ES modules).
 *
 * The content script (content/guard.js) is intentionally self-contained and
 * does NOT import this file, because MV3 content scripts cannot use static
 * ES module imports. The small set of message-type strings it needs are kept
 * in sync manually and covered by the test suite.
 */

/** Product identity. */
export const APP_NAME = 'Chrome Profile Guard';

/** Keys used in chrome.storage.local (persistent across restarts). */
export const LOCAL_KEYS = Object.freeze({
  AUTH: 'auth',            // credential material + lockout counters
  SETTINGS: 'settings',    // user preferences (auto-lock, scope, shortcut...)
  PROTECTED: 'protected',  // { mode, domains: [] }
  EVENTS: 'events',        // local, minimal activity log (opt-out)
  SCHEMA_VERSION: 'schemaVersion',
});

/** Keys used in chrome.storage.session (memory-only, cleared on restart). */
export const SESSION_KEYS = Object.freeze({
  UNLOCKED: 'unlocked',        // boolean — true only after a successful unlock
  UNLOCKED_AT: 'unlockedAt',   // epoch ms of last unlock (for auto-lock math)
  PENDING_RETURN: 'pendingReturn', // { [tabId]: url } captured on redirect
});

/** Storage schema version — bump when the persisted shape changes. */
export const SCHEMA_VERSION = 1;

/** Lock-state machine values. */
export const STATE = Object.freeze({
  SETUP_REQUIRED: 'SETUP_REQUIRED',
  LOCKED: 'LOCKED',
  UNLOCKING: 'UNLOCKING',
  UNLOCKED: 'UNLOCKED',
  TEMPORARILY_LOCKED: 'TEMPORARILY_LOCKED',
});

/** Credential methods. */
export const METHOD = Object.freeze({
  PIN: 'pin',
  PASSWORD: 'password',
});

/** Protection scope modes. */
export const PROTECTION_MODE = Object.freeze({
  EVERYTHING: 'everything', // all http(s) browsing requires unlock
  SELECTED: 'selected',     // only listed domains are protected
});

/**
 * Runtime message types (SW <-> pages <-> content script).
 * Keep the values that content/guard.js also uses (GUARD_*, STATE_CHANGED,
 * VERIFY_OVERLAY, PING) stable — they are duplicated as string literals there.
 */
export const MSG = Object.freeze({
  GET_STATE: 'GET_STATE',
  STATE_CHANGED: 'STATE_CHANGED',
  VERIFY: 'VERIFY',                 // { secret } -> verify + unlock
  VERIFY_OVERLAY: 'VERIFY_OVERLAY', // from content overlay -> unlock
  LOCK_NOW: 'LOCK_NOW',
  CONFIGURE: 'CONFIGURE',
  CHANGE_CREDENTIAL: 'CHANGE_CREDENTIAL',
  RESET: 'RESET',
  GET_SETTINGS: 'GET_SETTINGS',
  SET_SETTINGS: 'SET_SETTINGS',
  GET_PROTECTED: 'GET_PROTECTED',
  SET_PROTECTED: 'SET_PROTECTED',
  GET_EVENTS: 'GET_EVENTS',
  CLEAR_EVENTS: 'CLEAR_EVENTS',
  GUARD_DECISION: 'GUARD_DECISION', // content asks: should I cover this URL?
  OPEN_RESET: 'OPEN_RESET',         // content overlay -> open reset page in a tab
  PING: 'PING',
});

/** Auto-lock choices, in minutes. 0 === Never. */
export const AUTO_LOCK_OPTIONS = Object.freeze([
  { value: 0, label: 'Never' },
  { value: 1, label: '1 minute' },
  { value: 5, label: '5 minutes' },
  { value: 15, label: '15 minutes' },
  { value: 30, label: '30 minutes' },
  { value: 60, label: '1 hour' },
]);

/** Web Crypto / PBKDF2 parameters. */
export const CRYPTO = Object.freeze({
  ALGO: 'PBKDF2',
  HASH: 'SHA-256',
  ITERATIONS: 210000, // OWASP 2023 guidance for PBKDF2-HMAC-SHA256
  SALT_BYTES: 16,
  KEY_BITS: 256,
});

/** PIN rules. */
export const PIN_RULES = Object.freeze({
  MIN: 4,
  RECOMMENDED: 6,
  MAX: 12,
});

/** Password rules. */
export const PASSWORD_RULES = Object.freeze({
  MIN: 8,
  MAX: 128,
});

/**
 * PINs that are too predictable to accept. Kept short and specific; we also
 * reject all-same-digit and simple ascending/descending runs programmatically
 * in shared/auth.js so this list stays maintainable.
 */
export const WEAK_PINS = Object.freeze([
  '1234', '0000', '1111', '2222', '3333', '4444', '5555', '6666',
  '7777', '8888', '9999', '1212', '123456', '654321', '111111',
  '000000', '121212', '112233', '696969', '420420',
]);

/**
 * Progressive lockout schedule. Index === failed-attempt count *after* the
 * failure. Values are cooldown milliseconds; the last entry is reused for all
 * further attempts (progressive plateau).
 */
export const LOCKOUT_SCHEDULE_MS = Object.freeze([
  0,      // 0 failures
  0,      // 1
  0,      // 2
  0,      // 3
  0,      // 4  (attempts 1–4 retry freely)
  10000,  // 5  -> 10s
  30000,  // 6  -> 30s
  60000,  // 7  -> 1m
  300000, // 8  -> 5m
  900000, // 9+ -> 15m plateau
]);

/** Default user settings applied at first configure. */
export const DEFAULT_SETTINGS = Object.freeze({
  autoLockMinutes: 5,
  lockOnRestart: true,   // conceptual default; restart always locks regardless
  quickLockEnabled: true,
  allowInIncognito: false,
  loggingEnabled: true,
  hideContentWhenLocked: true, // Privacy Mode: opaque overlay vs. blur only
});

/** Default protection scope. */
export const DEFAULT_PROTECTED = Object.freeze({
  mode: PROTECTION_MODE.EVERYTHING,
  domains: [],
});

/** Suggested sensitive domains for the "Private mode" preset. */
export const SUGGESTED_DOMAINS = Object.freeze([
  'mail.google.com',
  'drive.google.com',
  'facebook.com',
  'instagram.com',
  'notion.so',
  'github.com',
]);

/** Local activity-log event names (no URLs, no secrets). */
export const EVENT = Object.freeze({
  INITIALIZED: 'initialized',
  LOCKED: 'locked',
  UNLOCKED: 'unlocked',
  FAILED_AUTH: 'failed_auth',
  CREDENTIAL_CHANGED: 'credential_changed',
  SETTINGS_CHANGED: 'settings_changed',
  RESET: 'reset',
});

/** Max events retained locally (ring buffer). */
export const MAX_EVENTS = 100;

/** Command name declared in manifest for the Quick Lock shortcut. */
export const QUICK_LOCK_COMMAND = 'quick-lock';

/** chrome.idle detection floor (Chrome minimum is 15s). */
export const IDLE_MIN_SECONDS = 15;
