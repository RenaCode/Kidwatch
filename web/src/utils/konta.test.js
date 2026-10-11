import test from 'node:test';
import assert from 'node:assert/strict';
import {
  channelsSummary, modeNotice, permissionChange, prefsFromProfile, prefsPayload, quietProblem,
  samePrefs, toggle, toggleChild,
} from './konta.js';

const ORDER = ['sesje', 'alarmy', 'raporty', 'gra', 'mdm', 'czujka', 'inne'];

test('cisza: obie godziny albo zadna, format GG:MM', () => {
  assert.equal(quietProblem('', ''), null);
  assert.equal(quietProblem('22:00', '07:00'), null);
  assert.match(quietProblem('22:00', ''), /obie/);
  assert.match(quietProblem('7:00', '08:00'), /GG:MM/);
  assert.match(quietProblem('24:00', '08:00'), /GG:MM/);
  assert.match(quietProblem('08:00', '08:00'), /takie same/);
});

test('przelacznik zachowuje kolejnosc katalogu', () => {
  assert.deepEqual(toggle(['mdm', 'sesje'], 'alarmy', true, ORDER), ['sesje', 'alarmy', 'mdm']);
  assert.deepEqual(toggle(['sesje', 'mdm'], 'mdm', false, ORDER), ['sesje']);
});

test('dzieci: wszystkie to null, odznaczenie daje reszte', () => {
  const all = ['A', 'B'];
  assert.deepEqual(toggleChild(null, 'A', false, all), ['B']);
  assert.equal(toggleChild(['B'], 'A', true, all), null);
});

test('profil <-> formularz', () => {
  const p = { kategorie: ['sesje'], cisza_od: '22:00', cisza_do: '07:00', cisza_alarmy: false,
    dzieci: null, aktywne: true };
  const f = prefsFromProfile(p);
  assert.deepEqual(prefsPayload(f), { kategorie: ['sesje'], cisza_od: '22:00', cisza_do: '07:00',
    cisza_alarmy: false, dzieci: null, aktywne: true });
  assert.equal(samePrefs(f, prefsFromProfile(p)), true);
  assert.equal(samePrefs(f, { ...f, cisza_od: '' }), false);
  assert.equal(prefsPayload({ ...f, cisza_od: ' ', cisza_do: '' }).cisza_od, null);
});

test('kanaly tylko zamaskowane z serwera', () => {
  assert.equal(channelsSummary({ whatsapp: '...201', email: null }), 'WhatsApp ...201');
  assert.equal(channelsSummary({}), 'brak kanału');
});

test('zmiana uprawnienia: zgodna z rola zdejmuje odstepstwo', () => {
  const role = ['konto.wlasne', 'podglad.historia'];
  assert.deepEqual(permissionChange(role, 'mdm.podglad', true), { 'mdm.podglad': true });
  assert.deepEqual(permissionChange(role, 'mdm.podglad', false), { 'mdm.podglad': null });
  assert.deepEqual(permissionChange(role, 'podglad.historia', false), { 'podglad.historia': false });
});

test('komunikat trybu tylko w trybie tras', () => {
  assert.equal(modeNotice('konta'), null);
  assert.match(modeNotice('trasy'), /tryb tras/);
});
