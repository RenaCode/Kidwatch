/* Audyt 2026-10-09 (N3): Ekrany, Uzycie i Dzien wisialy na „Wczytywanie…". */
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadState } from './loadState.js';

test('blad bez danych to blad, nie ladowanie', () => {
  assert.equal(loadState({ data: null, error: 'HTTP 503' }), 'error');
  assert.equal(loadState({ data: null, error: null }), 'loading');
  assert.equal(loadState({ data: { x: 1 }, error: 'HTTP 503' }), 'ready');
});

/* Audyt 2026-10-10 (S-1): Pulpit zostal przy starym wzorcu - blad pierwszego
   odczytu /api/usage dawal plakietke bledu i wieczne „Wczytywanie…". Kazda
   sekcja, ktora czyta useApi i pokazuje ladowanie, musi miec galaz bledu. */
import { readdirSync, readFileSync } from 'node:fs';

test('kazda sekcja z useApi ma galaz bledu pierwszego odczytu', () => {
  const dir = new URL('../components/', import.meta.url);
  const checked = [];
  readdirSync(dir).filter((f) => f.endsWith('.jsx')).forEach((f) => {
    const src = readFileSync(new URL(f, dir), 'utf8');
    if (!src.includes('useApi(') || !/(Wczytywanie|Ładowanie)…/.test(src)) return;
    checked.push(f);
    const handled = src.includes('loadState(') || /error && !(res\.)?data/.test(src);
    assert.ok(handled, `${f}: blad bez danych konczy sie wiecznym ladowaniem`);
  });
  assert.ok(checked.includes('Dashboard.jsx'), checked.join(', '));
});
