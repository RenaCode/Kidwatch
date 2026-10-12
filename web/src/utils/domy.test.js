/* Przelacznik domu, prefiks sciezki i chowanie przyciskow per dom. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { domPath, homeLabel, pickHome, roleLabel, showSwitcher, userInHome } from './domy.js';
import { can, isViewer, sectionsFor } from './uprawnienia.js';

const ME = {
  login: 'konto-a',
  domy: [
    { id: 1, nazwa: 'Dom 1', rola: 'podglad', administracja: false,
      uprawnienia: ['konto.wlasne', 'podglad.historia'] },
    { id: 2, nazwa: 'Dom 2', rola: 'wlasciciel-domu', administracja: false,
      uprawnienia: ['konto.wlasne', 'podglad.historia', 'mdm.podglad', 'czas_gry.zmiana', 'tv.pauza'] },
  ],
};

test('prefiks domu tylko dla tras domu, z zachowaniem zapytania', () => {
  assert.equal(domPath('/api/day?day=2026-10-01&child=A', 2), '/api/domy/2/day?day=2026-10-01&child=A');
  assert.equal(domPath('/api/mdm/devices/0000-AAAA', 2), '/api/domy/2/mdm/devices/0000-AAAA');
  assert.equal(domPath('/api/konto/powiadomienia', 7), '/api/domy/7/konto/powiadomienia');
  assert.equal(domPath('/api/export.csv?from=2026-01-01', 1), '/api/domy/1/export.csv?from=2026-01-01');
  // Konto i instancja - bez domu.
  for (const p of ['/api/auth/me', '/api/auth/logout', '/api/konto/kanaly', '/api/profile/notify',
    '/api/profile/whatsapp/qr', '/api/health']) {
    assert.equal(domPath(p, 2), p, p);
  }
  // Juz z domem i bez wybranego domu - bez zmian (alias po stronie serwera).
  assert.equal(domPath('/api/domy/1/day', 2), '/api/domy/1/day');
  assert.equal(domPath('/api/day', null), '/api/day');
  // Prefiks wymaga dalszej sciezki; podobna nazwa nie jest trasa domu.
  assert.equal(domPath('/api/mdm/devices/', 2), '/api/mdm/devices/');
  assert.equal(domPath('/api/dayx', 2), '/api/dayx');
});

test('przelacznik: ukryty przy jednym domu, zapamietany dom tylko widoczny', () => {
  assert.equal(showSwitcher(ME.domy), true);
  assert.equal(showSwitcher(ME.domy.slice(0, 1)), false);
  assert.equal(showSwitcher(undefined), false);
  assert.equal(pickHome(ME.domy, '2'), 2);
  assert.equal(pickHome(ME.domy, 9), 1); // dom, ktorego konto juz nie widzi
  assert.equal(pickHome([], 1), null);
});

test('przyciski chowane per dom: ta sama osoba, inne uprawnienia', () => {
  const w1 = userInHome(ME, 1);
  const w2 = userInHome(ME, 2);
  assert.equal(can(w1, 'czas_gry.zmiana'), false);
  assert.equal(can(w2, 'czas_gry.zmiana'), true);
  assert.equal(isViewer(w1), true);
  assert.equal(isViewer(w2), false);
  const S = ['pulpit', 'mdm'].map((key) => ({ key }));
  assert.deepEqual(sectionsFor(S, w1).map((s) => s.key), ['pulpit']);
  assert.deepEqual(sectionsFor(S, w2).map((s) => s.key), ['pulpit', 'mdm']);
  // Dom spoza listy: nic (fail-closed).
  assert.deepEqual(userInHome(ME, 3).uprawnienia, []);
});

test('etykiety: rola w domu i wglad administratora', () => {
  assert.equal(roleLabel('wlasciciel-domu'), 'właściciel domu');
  assert.equal(roleLabel('zarzadca'), 'zarządca');
  assert.equal(homeLabel({ nazwa: 'Dom 2', administracja: true }), 'Dom 2 · administracja');
  assert.equal(homeLabel({ nazwa: 'Dom 1', administracja: false }), 'Dom 1');
});
