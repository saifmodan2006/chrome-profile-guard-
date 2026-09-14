/**
 * Chrome Profile Guard — lock-state and URL scoping.
 *
 * The lock state is DERIVED, never stored as a separate source of truth:
 *   - not configured        -> SETUP_REQUIRED
 *   - active lockout window  -> TEMPORARILY_LOCKED
 *   - session "unlocked"     -> UNLOCKED
 *   - otherwise              -> LOCKED
 *
 * Because the "unlocked" flag lives in memory-only session storage, a browser
 * restart wipes it and the profile returns to LOCKED with zero extra work.
 *
 * This module also decides WHICH urls are in the protection scope, and which
 * are always exempt (Chrome internals, the extension's own pages) so we never
 * create redirect loops or try to inject where Chrome forbids it.
 */

import { STATE, PROTECTION_MODE } from './constants.js';
import {
  isConfigured,
  getAuth,
  getUnlocked,
  getProtected,
  getSettings,
} from './storage.js';

/** @returns {Promise<string>} one of STATE.* */
export async function getState() {
  if (!(await isConfigured())) return STATE.SETUP_REQUIRED;
  const auth = await getAuth();
  if (auth?.lockoutUntil && auth.lockoutUntil > Date.now()) {
    return STATE.TEMPORARILY_LOCKED;
  }
  return (await getUnlocked()) ? STATE.UNLOCKED : STATE.LOCKED;
}

/** A compact snapshot for popups and pages. */
export async function getSnapshot() {
  const [state, auth, settings, protectedConfig] = await Promise.all([
    getState(),
    getAuth(),
    getSettings(),
    getProtected(),
  ]);
  const remainingMs = auth?.lockoutUntil ? Math.max(0, auth.lockoutUntil - Date.now()) : 0;
  return {
    state,
    method: auth?.authMethod || null,
    autoLockMinutes: settings.autoLockMinutes,
    protectionMode: protectedConfig.mode,
    protectedCount: protectedConfig.domains?.length || 0,
    failedAttempts: auth?.failedAttempts || 0,
    remainingMs,
  };
}

/* ------------------------------------------------------------------ */
/* URL scoping                                                         */
/* ------------------------------------------------------------------ */

/** Parse a hostname, returning '' for opaque/invalid URLs. */
export function hostnameOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/**
 * URLs we must NEVER guard/redirect: Chrome internals and any extension page
 * (including our own lock/setup/reset). Guarding these would either fail
 * (Chrome forbids injection) or create redirect loops.
 */
export function isExceptionUrl(url) {
  if (!url) return true;
  const lower = url.toLowerCase();
  return (
    lower.startsWith('chrome:') ||
    lower.startsWith('chrome-extension:') ||
    lower.startsWith('edge:') ||
    lower.startsWith('about:') ||
    lower.startsWith('devtools:') ||
    lower.startsWith('view-source:') ||
    lower.startsWith('chrome-search:') ||
    lower.startsWith('chrome-untrusted:') ||
    lower.startsWith('https://chrome.google.com/webstore') ||
    lower.startsWith('https://chromewebstore.google.com')
  );
}

/** True only for http/https pages (the surface we can actually guard). */
export function isGuardableScheme(url) {
  return /^https?:/i.test(url || '');
}

/** Does `hostname` fall under `domain` (exact or subdomain)? */
export function domainMatches(hostname, domain) {
  if (!hostname || !domain) return false;
  hostname = hostname.toLowerCase();
  domain = domain.toLowerCase().replace(/^\*\./, '').replace(/^\./, '');
  return hostname === domain || hostname.endsWith('.' + domain);
}

/**
 * Is this URL within the user's protection scope?
 * @param {string} url
 * @param {{mode:string, domains:string[]}} protectedConfig
 */
export function isProtectedUrl(url, protectedConfig) {
  if (!isGuardableScheme(url)) return false;
  if (isExceptionUrl(url)) return false;
  if (protectedConfig.mode === PROTECTION_MODE.EVERYTHING) return true;
  const host = hostnameOf(url);
  return (protectedConfig.domains || []).some((d) => domainMatches(host, d));
}

/**
 * Should the guard cover / block this URL right now?
 * @param {string} url
 * @param {string} state one of STATE.*
 * @param {{mode:string, domains:string[]}} protectedConfig
 */
export function shouldGuard(url, state, protectedConfig) {
  const locked = state === STATE.LOCKED || state === STATE.TEMPORARILY_LOCKED;
  if (!locked) return false;
  return isProtectedUrl(url, protectedConfig);
}
