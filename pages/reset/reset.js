/**
 * Reset flow controller.
 *
 * There is no password recovery by design (credentials are stored only as a
 * derived key with no server account). Reset is the deliberate, clearly
 * confirmed way out of a forgotten credential.
 */

import { api } from '../../shared/messaging.js';

const $ = (id) => document.getElementById(id);

$('ack').addEventListener('change', (e) => {
  $('reset').disabled = !e.target.checked;
});

$('cancel').addEventListener('click', () => {
  // Go back if we can, otherwise close the tab-worthy page gracefully.
  if (history.length > 1) history.back();
  else location.replace(chrome.runtime.getURL('pages/settings/settings.html'));
});

$('reset').addEventListener('click', async () => {
  $('reset').disabled = true;
  try {
    const res = await api.reset();
    if (!res.ok) {
      $('reset').disabled = false;
      return;
    }
    $('confirm-view').classList.add('hidden');
    $('done-view').classList.remove('hidden');
  } catch {
    $('reset').disabled = false;
  }
});

$('setup-again').addEventListener('click', () => {
  location.replace(chrome.runtime.getURL('pages/setup/setup.html'));
});
