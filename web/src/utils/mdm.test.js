/* Zakladka MDM i dzwonek - audyt 2026-10-09 (N4, N5). */
import test from 'node:test';
import assert from 'node:assert/strict';
import { eventTone, isCriticalNote, isMeaningfulEvent, mdmDevice } from './mdm.js';

test('karta MDM: iPhone ma ikone telefonu, iOS i restart tylko pod nadzorem', () => {
  assert.deepEqual(mdmDevice({ kind: 'iphone', supervised: false }),
    { icon: 'phone', os: 'iOS', canRestart: false, restartHint: 'Restart wymaga nadzoru urządzenia' });
  assert.equal(mdmDevice({ product: 'iPhone16,2' }).os, 'iOS');
  const ipad = mdmDevice({ kind: 'ipad', product: 'iPad13,18', supervised: true });
  assert.deepEqual(ipad, { icon: 'tablet', os: 'iPadOS', canRestart: true, restartHint: '' });
  assert.equal(mdmDevice({ product: 'iPad13,18' }).icon, 'tablet');
});

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

/* Audyt 2026-10-10 (S-2, N-4): uzgadnianie, pushe i kolejka w zakladce MDM. */
import { pendingBadge, serverBadges } from './mdm.js';

const NOW = Date.parse('2026-10-10T12:00:00Z');
const at = (min) => new Date(NOW - min * 60000).toISOString();

test('plakietki serwera: zdrowe uzgadnianie i pushe', () => {
  const b = serverBadges({ last_reconcile_ok_at: at(3), last_reconcile_error: null, last_push_ok_at: at(10) }, NOW);
  assert.deepEqual(b.map((x) => [x.key, x.tone, x.text]), [
    ['reconcile', 'ok', 'uzgadnianie 3 min temu'], ['push', 'ok', 'ostatni push 10 min temu'],
  ]);
  assert.deepEqual(serverBadges({ apns: {} }, NOW), []); // starszy serwer: bez plakietek
});

test('plakietki serwera: pushe padaja, uzgadnianie stoi', () => {
  const b = serverBadges({
    last_reconcile_ok_at: at(120), last_reconcile_error: 'wszystkie pushe APNs nieudane (1)',
    push_failing_since: at(180), push_failures: 7, last_push_error: '503 ServiceUnavailable',
  }, NOW);
  assert.equal(b[0].tone, 'warn');
  assert.equal(b[0].title, 'wszystkie pushe APNs nieudane (1)');
  assert.equal(b[1].text, 'pushe APNs nie wychodzą od 3 h (7× z rzędu)');
  assert.equal(b[1].title, '503 ServiceUnavailable');
});

test('kolejka komend: najstarsza i ostrzezenie po dobie', () => {
  assert.equal(pendingBadge({ pending_commands: 0, oldest_pending: null }, NOW), null);
  const fresh = pendingBadge({ pending_commands: 2, oldest_pending: { request_type: 'DeviceLock', status: 'not_now', created_at: at(30) } }, NOW);
  assert.deepEqual([fresh.tone, fresh.text], ['info', 'w kolejce: 2 · najstarsza 30 min']);
  const stuck = pendingBadge({ pending_commands: 1, oldest_pending: { request_type: 'InstallProfile', status: 'queued', created_at: at(30 * 60) } }, NOW);
  assert.deepEqual([stuck.tone, stuck.text], ['warn', 'w kolejce: 1 · najstarsza 30 h']);
});
