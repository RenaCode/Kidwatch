/* Przelacznik aplikacji RenaCode w gornym pasku. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { APPS, CURRENT_APP, appItems } from './aplikacje.js';

test('trzy aplikacje RenaCode w stalej kolejnosci, z opisem po polsku', () => {
  assert.deepEqual(APPS.map((a) => a.name), ['Trader', 'Kidwatch', 'Dietetyk']);
  assert.deepEqual(APPS.map((a) => a.url), [
    'https://trader.renacode.com/', 'https://kidwatch.renacode.com/', 'https://dietetyk.renacode.com/',
  ]);
  assert.deepEqual(APPS.map((a) => a.desc), ['Handel i ryzyko', 'Czas ekranowy dzieci', 'Dieta i zdrowie']);
  for (const a of APPS) assert.equal(a.initial.length, 1, a.key);
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
