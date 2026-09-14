/**
 * Chrome Profile Guard — background service worker (MV3, ES module).
 *
 * Responsibilities:
 *   - open the setup page on first install
 *   - keep the toolbar badge in sync with lock state
 *   - route messages from popup / pages / content scripts
 *   - enforce protection at the navigation layer (redirect protected tabs to
 *     the lock page while locked) and cover already-open protected tabs
 *   - auto-lock on inactivity (chrome.idle) and on OS lock
 *   - handle the Quick Lock keyboard command
 *
 * It is event-driven — no polling loops. Any state it needs is derived on
 * demand from storage, so the worker can be torn down and revived freely.
 */

import {
  MSG,
  STATE,
  EVENT,
  QUICK_LOCK_COMMAND,
  IDLE_MIN_SECONDS,
} from '../shared/constants.js';
import {
  isConfigured,
  getSettings,
  setSettings,
  getProtected,
  setProtected,
  setUnlocked,
  getEvents,
  clearEvents,
  appendEvent,
  ensureSchemaVersion,
  setPendingReturn,
  takePendingReturn,
} from '../shared/storage.js';
import {
  getState,
  getSnapshot,
  shouldGuard,
  isProtectedUrl,
  isExceptionUrl,
  isGuardableScheme,
} from '../shared/lock-state.js';
import {
  configure,
  verify,
  changeCredential,
  resetProtection,
} from '../shared/auth.js';

const LOCK_PAGE = chrome.runtime.getURL('pages/lock/lock.html');

/* ------------------------------------------------------------------ */
/* lifecycle                                                           */
/* ------------------------------------------------------------------ */

chrome.runtime.onInstalled.addListener(async (details) => {
  await ensureSchemaVersion();
  await applyAutoLock();
  await updateBadge();
  if (details.reason === 'install' && !(await isConfigured())) {
    await chrome.tabs.create({ url: chrome.runtime.getURL('pages/setup/setup.html') });
  }
});

// Browser restart: session storage is already empty (so we are LOCKED), but be
// explicit and refresh the idle timer + badge.
chrome.runtime.onStartup.addListener(async () => {
  await setUnlocked(false);
  await applyAutoLock();
  await updateBadge();
  await appendEvent(EVENT.INITIALIZED);
});

// Runs on every service-worker wake — re-apply the idle interval (which does
// not survive worker teardown) and refresh the badge.
init().catch(reportError);
async function init() {
  await applyAutoLock();
  await updateBadge();
}

/* ------------------------------------------------------------------ */
/* message routing                                                     */
/* ------------------------------------------------------------------ */

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessage(msg, sender)
    .then(sendResponse)
    .catch((err) => sendResponse({ ok: false, error: friendly(err) }));
  return true; // keep the channel open for the async response
});

async function handleMessage(msg, sender) {
  switch (msg?.type) {
    case MSG.PING:
      return { ok: true, pong: true };

    case MSG.GET_STATE:
      return { ok: true, snapshot: await getSnapshot() };

    case MSG.GUARD_DECISION: {
      const url = msg.url || sender?.url || sender?.tab?.url;
      const [state, protectedConfig, settings] = await Promise.all([
        getState(),
        getProtected(),
        getSettings(),
      ]);
      const snapshot = await getSnapshot();
      let guard = shouldGuard(url, state, protectedConfig);
      // Respect the Incognito preference: don't guard incognito tabs unless allowed.
      if (guard && sender?.tab?.incognito && !settings.allowInIncognito) guard = false;
      return { ok: true, guard, state, method: snapshot.method };
    }

    case MSG.VERIFY:
    case MSG.VERIFY_OVERLAY: {
      const result = await verify(msg.secret);
      if (result.ok) {
        await onUnlocked();
      } else {
        await updateBadge();
      }
      return result;
    }

    case MSG.LOCK_NOW:
      return await lockNow(false);

    case MSG.CONFIGURE: {
      const result = await configure(msg.payload || {});
      if (result.ok) {
        await applyAutoLock();
        // Setup completes in an UNLOCKED state so the user can immediately use
        // the browser; they can Lock Now from the final setup screen.
        await setUnlocked(true);
        await updateBadge();
      }
      return result;
    }

    case MSG.CHANGE_CREDENTIAL:
      return await changeCredential(msg.payload || {});

    case MSG.RESET: {
      const result = await resetProtection();
      await applyAutoLock();
      await updateBadge();
      await broadcastToTabs({ type: MSG.STATE_CHANGED, state: STATE.SETUP_REQUIRED });
      return result;
    }

    case MSG.GET_SETTINGS:
      return { ok: true, settings: await getSettings() };

    case MSG.SET_SETTINGS: {
      const settings = await setSettings(msg.patch || {});
      await applyAutoLock();
      await updateBadge();
      await appendEvent(EVENT.SETTINGS_CHANGED);
      return { ok: true, settings };
    }

    case MSG.GET_PROTECTED:
      return { ok: true, protected: await getProtected() };

    case MSG.SET_PROTECTED: {
      const value = await setProtected(msg.value || {});
      await appendEvent(EVENT.SETTINGS_CHANGED);
      // If we are currently locked, re-cover tabs that just came into scope.
      const state = await getState();
      if (state === STATE.LOCKED || state === STATE.TEMPORARILY_LOCKED) {
        await coverAllProtectedTabs();
      }
      return { ok: true, protected: value };
    }

    case MSG.GET_EVENTS:
      return { ok: true, events: await getEvents() };

    case MSG.CLEAR_EVENTS:
      await clearEvents();
      return { ok: true };

    case MSG.OPEN_RESET:
      await chrome.tabs.create({ url: chrome.runtime.getURL('pages/reset/reset.html') });
      return { ok: true };

    default:
      return { ok: false, error: 'Unknown request.' };
  }
}

/* ------------------------------------------------------------------ */
/* lock / unlock                                                       */
/* ------------------------------------------------------------------ */

async function lockNow() {
  if (!(await isConfigured())) return { ok: false, error: 'Protection is not set up.' };
  await setUnlocked(false);
  await appendEvent(EVENT.LOCKED);
  await updateBadge();
  await coverAllProtectedTabs();
  return { ok: true };
}

async function onUnlocked() {
  await updateBadge();
  // Tell content scripts to remove any overlays.
  await broadcastToTabs({ type: MSG.STATE_CHANGED, state: STATE.UNLOCKED });
  // Release tabs that were redirected to the lock page back to their target.
  const tabs = await safeQueryTabs({});
  for (const tab of tabs) {
    if (tab.url && tab.url.startsWith(LOCK_PAGE)) {
      const stored = await takePendingReturn(tab.id);
      const target = stored || parseReturn(tab.url);
      if (target && isGuardableScheme(target) && !isExceptionUrl(target)) {
        try { await chrome.tabs.update(tab.id, { url: target }); } catch { /* tab gone */ }
      }
    }
  }
}

/** Cover every open, in-scope tab with the lock overlay. */
async function coverAllProtectedTabs() {
  const [protectedConfig, settings, tabs] = await Promise.all([
    getProtected(),
    getSettings(),
    safeQueryTabs({}),
  ]);
  await Promise.all(tabs.map((tab) => coverTab(tab, protectedConfig, settings.allowInIncognito)));
}

async function coverTab(tab, protectedConfig, allowIncognito) {
  if (!tab.id || tab.id < 0) return;
  if (tab.incognito && !allowIncognito) return;
  if (!isGuardableScheme(tab.url) || isExceptionUrl(tab.url)) return;
  if (!isProtectedUrl(tab.url, protectedConfig)) return;

  // Prefer messaging an existing content script (state-preserving overlay).
  try {
    await chrome.tabs.sendMessage(tab.id, { type: MSG.STATE_CHANGED, state: STATE.LOCKED });
    return;
  } catch { /* no content script yet (tab predates install/update) */ }

  // Fall back to injecting the guard, which self-covers on load.
  try {
    await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ['content/guard.js'] });
  } catch { /* restricted page — cannot inject; navigation layer still applies */ }
}

/* ------------------------------------------------------------------ */
/* navigation guard                                                    */
/* ------------------------------------------------------------------ */

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return; // top frame only
  await guardTab(details.tabId, details.url);
});

// Secondary net: catches URL changes (incl. some redirects) the above may miss.
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  if (changeInfo.url) await guardTab(tabId, changeInfo.url);
});

async function guardTab(tabId, url) {
  if (tabId == null || tabId < 0 || !url) return;
  if (!isGuardableScheme(url) || isExceptionUrl(url)) return; // never touch our own pages
  const [state, protectedConfig] = await Promise.all([getState(), getProtected()]);
  if (!shouldGuard(url, state, protectedConfig)) return;

  // Respect the Incognito preference.
  const settings = await getSettings();
  if (!settings.allowInIncognito) {
    let incognito = false;
    try { incognito = (await chrome.tabs.get(tabId)).incognito; } catch { /* tab gone */ }
    if (incognito) return;
  }

  await setPendingReturn(tabId, url);
  const target = LOCK_PAGE + '?return=' + encodeURIComponent(url);
  try { await chrome.tabs.update(tabId, { url: target }); } catch { /* tab closed */ }
}

/* ------------------------------------------------------------------ */
/* auto-lock (inactivity + OS lock)                                    */
/* ------------------------------------------------------------------ */

async function applyAutoLock() {
  const settings = await getSettings();
  const seconds = settings.autoLockMinutes > 0
    ? Math.max(IDLE_MIN_SECONDS, settings.autoLockMinutes * 60)
    : IDLE_MIN_SECONDS; // still listen so OS-lock can lock us
  try { chrome.idle.setDetectionInterval(seconds); } catch { /* ignore */ }
}

chrome.idle.onStateChanged.addListener(async (newState) => {
  if ((await getState()) !== STATE.UNLOCKED) return;
  if (newState === 'locked') {
    await lockNow(); // OS locked -> always lock the workspace
    return;
  }
  if (newState === 'idle') {
    const settings = await getSettings();
    if (settings.autoLockMinutes > 0) await lockNow();
  }
});

/* ------------------------------------------------------------------ */
/* quick lock command                                                  */
/* ------------------------------------------------------------------ */

chrome.commands.onCommand.addListener(async (command) => {
  if (command !== QUICK_LOCK_COMMAND) return;
  const settings = await getSettings();
  if (settings.quickLockEnabled) await lockNow();
});

/* ------------------------------------------------------------------ */
/* badge                                                               */
/* ------------------------------------------------------------------ */

async function updateBadge() {
  const state = await getState();
  const action = chrome.action;
  try {
    if (state === STATE.UNLOCKED) {
      await action.setBadgeText({ text: '' });
      await action.setTitle({ title: 'Chrome Profile Guard — unlocked' });
    } else if (state === STATE.SETUP_REQUIRED) {
      await action.setBadgeBackgroundColor({ color: '#F9AB00' });
      await action.setBadgeText({ text: '!' });
      await action.setTitle({ title: 'Chrome Profile Guard — set up protection' });
    } else {
      await action.setBadgeBackgroundColor({ color: '#D93025' });
      await action.setBadgeText({ text: '\u{1F512}' });
      await action.setTitle({ title: 'Chrome Profile Guard — locked' });
    }
  } catch { /* action API not ready during teardown */ }
}

/* ------------------------------------------------------------------ */
/* helpers                                                             */
/* ------------------------------------------------------------------ */

function parseReturn(lockUrl) {
  try {
    const u = new URL(lockUrl);
    return u.searchParams.get('return');
  } catch {
    return null;
  }
}

async function broadcastToTabs(message) {
  const tabs = await safeQueryTabs({});
  await Promise.all(
    tabs.map((tab) =>
      tab.id != null && tab.id >= 0
        ? chrome.tabs.sendMessage(tab.id, message).catch(() => {})
        : Promise.resolve(),
    ),
  );
}

async function safeQueryTabs(query) {
  try {
    return await chrome.tabs.query(query);
  } catch {
    return [];
  }
}

function friendly(err) {
  // Never surface a raw error object to the UI.
  console.error('[Chrome Profile Guard]', err);
  return 'Something went wrong. Please try again.';
}

function reportError(err) {
  console.error('[Chrome Profile Guard] init', err);
}
