/* Zakladka MDM i dzwonek - audyt 2026-10-09 (N4, N5). */
import test from 'node:test';
import assert from 'node:assert/strict';
import { eventTone, isCriticalNote, isMeaningfulEvent } from './mdm.js';

test('stare os_update_failed z count 0 nie jest alarmem ani wpisem', () => {
  const stale = { kind: 'os_update_failed', detail: '{"count": 0}' };
  const real = { kind: 'os_update_failed', detail: '{"count": 2, "reason": "NoSpace"}' };
  assert.equal(isMeaningfulEvent(stale), false);
  assert.equal(isMeaningfulEvent({ kind: 'os_update_failed', detail: { count: 0 } }), false);
  assert.equal(isMeaningfulEvent(real), true);
  assert.equal(eventTone(real), 'warn');
  assert.equal(isMeaningfulEvent({ kind: 'enrolled', detail: null }), true);
});

test('zmiana nadzoru: utrata ostrzega, odzyskanie nie', () => {
  assert.equal(eventTone({ kind: 'supervision_changed', detail: '{"supervised": false}' }), 'warn');
  assert.equal(eventTone({ kind: 'supervision_changed', detail: '{"supervised": true}' }), 'ok');
  assert.equal(eventTone({ kind: 'checkout', detail: '{}' }), 'warn');
  assert.equal(eventTone({ kind: 'authenticate', detail: '{}' }), '');
});

test('dzwonek wyroznia powazne alarmy MDM, nie informacje', () => {
  assert.equal(isCriticalNote({ kind: 'mdm', priority: 5 }), true); // profil zdjety
  assert.equal(isCriticalNote({ kind: 'mdm', priority: 4 }), true);
  assert.equal(isCriticalNote({ kind: 'mdm', priority: 3 }), false); // zapisany do MDM
  assert.equal(isCriticalNote({ kind: 'watchdog', priority: 3 }), true);
  assert.equal(isCriticalNote({ kind: 'session_start', priority: 5 }), false);
});
