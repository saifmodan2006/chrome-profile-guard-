/**
 * Chrome Profile Guard — page/popup messaging helper.
 *
 * Thin wrapper around chrome.runtime.sendMessage that surfaces runtime errors
 * as thrown Errors and returns the service worker's response object. Keeps the
 * page code readable and consistent.
 */

import { MSG } from './constants.js';

export async function send(type, extra = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...extra });
  if (res == null) throw new Error('No response from background service.');
  return res;
}

export const api = {
  getState: () => send(MSG.GET_STATE),
  verify: (secret) => send(MSG.VERIFY, { secret }),
  lockNow: () => send(MSG.LOCK_NOW),
  configure: (payload) => send(MSG.CONFIGURE, { payload }),
  changeCredential: (payload) => send(MSG.CHANGE_CREDENTIAL, { payload }),
  reset: () => send(MSG.RESET),
  getSettings: () => send(MSG.GET_SETTINGS),
  setSettings: (patch) => send(MSG.SET_SETTINGS, { patch }),
  getProtected: () => send(MSG.GET_PROTECTED),
  setProtected: (value) => send(MSG.SET_PROTECTED, { value }),
  getEvents: () => send(MSG.GET_EVENTS),
  clearEvents: () => send(MSG.CLEAR_EVENTS),
};
