/* Co front chowa wedlug `uprawnienia` z /api/auth/me. Serwer odmawia niezaleznie (403). */
import test from 'node:test';
import assert from 'node:assert/strict';
import { ALL, can, isViewer, sectionsFor } from './uprawnienia.js';

const OWNER = { login: 'rodzic1', rola: 'wlasciciel', uprawnienia: [...ALL] };
const VIEW = { login: 'rodzic2', rola: 'podglad', uprawnienia: ['konto.wlasne', 'podglad.historia'] };
const SECTIONS = ['pulpit', 'notifications', 'screens', 'usage', 'trends', 'day', 'mdm']
  .map((key) => ({ key }));

test('podglad nie widzi MDM, wlasciciel widzi wszystko', () => {
  assert.deepEqual(sectionsFor(SECTIONS, VIEW).map((s) => s.key),
    ['pulpit', 'notifications', 'screens', 'usage', 'trends', 'day']);
  assert.equal(sectionsFor(SECTIONS, OWNER).length, SECTIONS.length);
});

test('podglad bez zadnej czynnosci, takze bez pauzy TV', () => {
  for (const p of ['mdm.komendy', 'czas_gry.zmiana', 'whatsapp.konfiguracja', 'tv.aplikacja', 'tv.pauza']) {
    assert.equal(can(VIEW, p), false, p);
    assert.equal(can(OWNER, p), true, p);
  }
});

test('decyduje lista uprawnien, nie nazwa roli', () => {
  // podglad z nadana pauza TV (CLI: user-uprawnienia <login> +tv.pauza)
  const plus = { ...VIEW, uprawnienia: [...VIEW.uprawnienia, 'tv.pauza'] };
  assert.equal(can(plus, 'tv.pauza'), true);
  assert.equal(isViewer(plus), true);
  // wlasciciel z odebranym podgladem MDM
  const minus = { ...OWNER, uprawnienia: ALL.filter((p) => p !== 'mdm.podglad') };
  assert.equal(sectionsFor(SECTIONS, minus).some((s) => s.key === 'mdm'), false);
});

test('brak pola uprawnienia = nic (fail-closed), takze dla roli wlasciciel', () => {
  assert.equal(can({ login: 'rodzic1', rola: 'wlasciciel' }, 'mdm.komendy'), false);
  assert.equal(can(null, 'tv.pauza'), false);
  assert.equal(can({ uprawnienia: 'tv.pauza' }, 'tv.pauza'), false);
});
