/* Rola `podglad`: co front chowa. Serwer odmawia niezaleznie (403). */
import test from 'node:test';
import assert from 'node:assert/strict';
import { can, isViewer, sectionsFor } from './rola.js';

const OWNER = { login: 'rodzic1', rola: 'wlasciciel' };
const VIEW = { login: 'rodzic2', rola: 'podglad' };
const SECTIONS = ['pulpit', 'notifications', 'screens', 'usage', 'trends', 'day', 'mdm']
  .map((key) => ({ key }));

test('podglad nie widzi MDM, wlasciciel widzi wszystko', () => {
  assert.deepEqual(sectionsFor(SECTIONS, VIEW).map((s) => s.key),
    ['pulpit', 'notifications', 'screens', 'usage', 'trends', 'day']);
  assert.equal(sectionsFor(SECTIONS, OWNER).length, SECTIONS.length);
});

test('podglad bez czasu gry, WhatsAppa, aplikacji TV i MDM; pauza TV zostaje', () => {
  for (const a of ['mdm', 'game', 'whatsapp', 'tvApp']) {
    assert.equal(can(VIEW, a), false, a);
    assert.equal(can(OWNER, a), true, a);
  }
  assert.equal(can(VIEW, 'tvPause'), true);
});

test('brak pola rola (starszy serwer) = jak dotad, wlasciciel', () => {
  assert.equal(isViewer({ login: 'rodzic1' }), false);
  assert.equal(can({ login: 'rodzic1' }, 'mdm'), true);
  assert.equal(isViewer(VIEW), true);
});
