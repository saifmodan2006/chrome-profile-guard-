/**
 * Minimal in-memory mock of the `chrome.storage` APIs used by the shared
 * modules, installed on `globalThis` at import time so that importing this
 * module BEFORE the shared modules makes `chrome` available when they load.
 *
 * Only what the pure logic layer touches is implemented: storage.local and
 * storage.session with get/set/remove/clear. Browser-side effects (tabs,
 * idle, webNavigation, scripting) live in the service worker and are exercised
 * via decision-level tests, not mocked here.
 */

function makeArea() {
  const store = new Map();
  const clone = (v) => (v === undefined ? undefined : structuredClone(v));

  return {
    async get(keys) {
      if (keys === null || keys === undefined) {
        const out = {};
        for (const [k, v] of store) out[k] = clone(v);
        return out;
      }
      if (typeof keys === 'string') {
        return store.has(keys) ? { [keys]: clone(store.get(keys)) } : {};
      }
      if (Array.isArray(keys)) {
        const out = {};
        for (const k of keys) if (store.has(k)) out[k] = clone(store.get(k));
        return out;
      }
      if (typeof keys === 'object') {
        const out = {};
        for (const k of Object.keys(keys)) out[k] = store.has(k) ? clone(store.get(k)) : keys[k];
        return out;
      }
      return {};
    },
    async set(obj) {
      for (const [k, v] of Object.entries(obj)) store.set(k, clone(v));
    },
    async remove(keys) {
      const arr = Array.isArray(keys) ? keys : [keys];
      for (const k of arr) store.delete(k);
    },
    async clear() {
      store.clear();
    },
    _raw: store,
  };
}

const local = makeArea();
const session = makeArea();

globalThis.chrome = {
  storage: { local, session },
};

/** Wipe both storage areas (call between tests for isolation). */
export function resetChrome() {
  local._raw.clear();
  session._raw.clear();
}

/** Snapshot of everything currently in storage.local. */
export function dumpLocal() {
  const out = {};
  for (const [k, v] of local._raw) out[k] = structuredClone(v);
  return out;
}

/** Snapshot of everything currently in storage.session. */
export function dumpSession() {
  const out = {};
  for (const [k, v] of session._raw) out[k] = structuredClone(v);
  return out;
}

/** Directly write a raw value (used to simulate corrupted storage). */
export async function putRawLocal(key, value) {
  await local.set({ [key]: value });
}
