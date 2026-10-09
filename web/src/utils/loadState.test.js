/* Audyt 2026-10-09 (N3): Ekrany, Uzycie i Dzien wisialy na „Wczytywanie…". */
import test from 'node:test';
import assert from 'node:assert/strict';
import { loadState } from './loadState.js';

test('blad bez danych to blad, nie ladowanie', () => {
  assert.equal(loadState({ data: null, error: 'HTTP 503' }), 'error');
  assert.equal(loadState({ data: null, error: null }), 'loading');
  assert.equal(loadState({ data: { x: 1 }, error: 'HTTP 503' }), 'ready');
});
