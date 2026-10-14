/* Przelacznik aplikacji RenaCode w gornym pasku. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { APPS, CURRENT_APP, appItems, visibleApps } from './aplikacje.js';

test('aplikacje RenaCode w stalej kolejnosci, z opisem po polsku; Argo CD tylko dla wlasciciela', () => {
  assert.deepEqual(APPS.map((a) => a.name), ['Trader', 'Kidwatch', 'Dietetyk', 'Argo CD']);
  assert.deepEqual(APPS.map((a) => a.url), [
    'https://trader.renacode.com/', 'https://kidwatch.renacode.com/', 'https://dietetyk.renacode.com/',
    'https://argocd.renacode.com/',
  ]);
  assert.deepEqual(APPS.map((a) => a.desc),
    ['Handel i ryzyko', 'Czas ekranowy dzieci', 'Dieta i zdrowie', 'Wdrożenia i klaster']);
  for (const a of APPS) assert.equal(a.initial.length, 1, a.key);
  assert.deepEqual(APPS.filter((a) => a.adminOnly).map((a) => a.key), ['argocd']);
});

test('Argo CD widoczne tylko przy pokaz_argo === true z serwera', () => {
  const keys = (user) => appItems(APPS, CURRENT_APP, user).map((a) => a.key);
  const zwykle = ['trader', 'kidwatch', 'dietetyk'];
  assert.deepEqual(keys({ rola: 'wlasciciel', pokaz_argo: true }), [...zwykle, 'argocd']);
  assert.deepEqual(keys({ admin_instancji: true, pokaz_argo: true }), [...zwykle, 'argocd']);
  // Front nie zgaduje z roli ani flagi admina - rozstrzyga tylko pole z serwera.
  for (const user of [null, undefined, {}, { rola: 'podglad', pokaz_argo: false },
    { rola: 'wlasciciel' }, { admin_instancji: true }, { pokaz_argo: 'true' }, { pokaz_argo: 1 }]) {
    assert.deepEqual(keys(user), zwykle, JSON.stringify(user));
  }
  // Domyslne wywolanie (bez konta) tez bez Argo.
  assert.deepEqual(appItems().map((a) => a.key), zwykle);
  assert.deepEqual(visibleApps(APPS, { pokaz_argo: true }).length, APPS.length);
  const argo = appItems(APPS, CURRENT_APP, { pokaz_argo: true }).find((a) => a.key === 'argocd');
  assert.equal(argo.href, 'https://argocd.renacode.com/');
  assert.equal(argo.current, false);
});

test('Kidwatch jest biezacy i nie jest linkiem, reszta prowadzi do swoich adresow', () => {
  assert.equal(CURRENT_APP, 'kidwatch');
  const items = appItems();
  assert.deepEqual(items.map((a) => [a.key, a.current, a.href]), [
    ['trader', false, 'https://trader.renacode.com/'],
    ['kidwatch', true, null],
    ['dietetyk', false, 'https://dietetyk.renacode.com/'],
  ]);
  assert.equal(items.filter((a) => a.current).length, 1);
});

test('adres spoza https nie trafia do linku', () => {
  const apps = [
    { key: 'a', name: 'A', url: 'javascript:alert(1)' },
    { key: 'b', name: 'B', url: 'http://b.renacode.com/' },
    { key: 'c', name: 'C', url: 'nie-adres' },
    { key: 'd', name: 'D', url: 'https://d.renacode.com/' },
  ];
  assert.deepEqual(appItems(apps, 'x').map((a) => a.key), ['d']);
  // Biezaca aplikacja zostaje nawet z blednym adresem - nie jest linkiem.
  assert.deepEqual(appItems(apps, 'a').map((a) => [a.key, a.href]), [['a', null], ['d', 'https://d.renacode.com/']]);
});

/* Bez renderera (testy biegna w czystym node): sprawdzamy zrodlo, ze
   przelacznik siedzi w gornym pasku i ma atrybuty dostepnosci. */
test('przelacznik jest w gornym pasku panelu, przed logo', async () => {
  const { readFile } = await import('node:fs/promises');
  const src = await readFile(new URL('../App.jsx', import.meta.url), 'utf8');
  const header = src.slice(src.indexOf('<header className={`topbar'), src.indexOf('</header>'));
  assert.ok(header.length > 0, 'brak gornego paska');
  const sw = header.indexOf('<AppSwitcher user={user} />');
  assert.ok(sw >= 0, 'AppSwitcher poza gornym paskiem');
  assert.ok(sw < header.indexOf('brand-mark'), 'siatka ma byc na lewym koncu');
  const comp = src.slice(src.indexOf('function AppSwitcher('), src.indexOf('function useDismiss('));
  for (const attr of ['aria-label="Przełącz aplikację"', 'aria-haspopup="dialog"', 'aria-expanded={open}',
    "aria-controls={open ? 'app-switch-panel' : undefined}", 'aria-current="page"', 'Aplikacje RenaCode']) {
    assert.ok(comp.includes(attr), attr);
  }
  // Argo CD filtruje appItems z kontem z /api/auth/me; link w tej samej karcie.
  assert.ok(comp.includes('appItems(undefined, undefined, user)'));
  assert.doesNotMatch(comp, /target=/);
  // Inline handlery HTML lamalyby CSP (script-src 'self').
  assert.doesNotMatch(comp, /\son[a-z]+="/);
});
