/* Testy bez frameworka: `npm test` (node --test, strefa ustawiona w skrypcie).
   Audyt runda 4, pkt 11: os doby dzielila przez stale 24 h. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { dayPct, defaultPauseUntil, localInputValue, pauseUntil } from './format.js';

test('doba 25 h (25.10): 23:30 nie przykleja sie do konca osi', () => {
  // 23:30 to 24,5 h od polnocy w dobie 25-godzinnej.
  assert.equal(dayPct('2026-10-25T23:30:00+01:00', '2026-10-25'), (24.5 / 25) * 100);
  // 04:00 po zmianie czasu: 5 h od polnocy, nie 4.
  assert.equal(dayPct('2026-10-25T04:00:00+01:00', '2026-10-25'), (5 / 25) * 100);
});

test('doba 23 h (29.03) i zwykla doba', () => {
  assert.equal(dayPct('2026-03-29T12:00:00+02:00', '2026-03-29'), (11 / 23) * 100);
  assert.equal(dayPct('2026-10-03T12:00:00+02:00', '2026-10-03'), 50);
  assert.equal(dayPct('2026-10-04T01:00:00+02:00', '2026-10-03'), 100);
});

test('pauza TV: domyslny termin za 7 dni o pelnej godzinie, w czasie lokalnym', () => {
  assert.equal(defaultPauseUntil(new Date('2026-10-03T18:42:10+02:00')), '2026-10-10T18:00');
  // Przez zmiane czasu (25.10): ta sama godzina na zegarze, nie +168 h.
  assert.equal(defaultPauseUntil(new Date('2026-10-22T09:15:00+02:00')), '2026-10-29T09:00');
  assert.equal(localInputValue(new Date('2026-01-05T07:03:00+01:00')), '2026-01-05T07:03');
});

test('pauza TV: etykieta terminu', () => {
  assert.equal(pauseUntil(null), 'do odwołania');
  assert.match(pauseUntil('2026-10-10T18:00:00+02:00'), /^do 10 .*18:00$/);
});
