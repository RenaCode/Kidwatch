import test from 'node:test';
import assert from 'node:assert/strict';
import { WYNIKI, opisAkcji, stanWylacznika, wynikLabel } from './komendy.js';

test('kazdy wynik serwera ma etykiete, nieznany przechodzi surowo', () => {
  // Ta sama lista co stale wynikow w src/kidwatch/komendy_baza.py.
  for (const w of ['nieznany-numer', 'bez-uprawnien', 'wylaczone', 'limit', 'zablokowany',
    'przeterminowana', 'nie-rozumiem', 'bez-llm', 'dopytanie', 'czeka-na-kod', 'zly-kod',
    'kod-wygasl', 'odmowa', 'wykonane', 'blad', 'odpowiedz']) {
    assert.ok(WYNIKI[w], w);
  }
  assert.deepEqual(wynikLabel('nowy-wynik'), ['nowy-wynik', '']);
});

test('opis akcji z celem i minutami', () => {
  assert.equal(opisAkcji({ akcja: 'dodaj', cel: 'Dziecko A', minuty: 15 }), 'więcej czasu · Dziecko A · +15 min');
  assert.equal(opisAkcji({ akcja: 'odejmij', cel: 'Dziecko A', minuty: 10 }), 'mniej czasu · Dziecko A · -10 min');
  assert.equal(opisAkcji({ akcja: null }), '');
});

test('stan wylacznika', () => {
  assert.match(stanWylacznika({ wlaczone: false }), /konfiguracji/);
  assert.match(stanWylacznika({ wlaczone: true, wylaczone: { kto: 'admin' } }), /WYŁĄCZONE.*admin/);
  assert.match(stanWylacznika({ wlaczone: true, wylaczone: null }), /Działają/);
});
