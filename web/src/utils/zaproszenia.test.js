import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canRevoke, inviteLink, isInvitePath, newAccountProblem, statusLabel, tokenFromHash,
} from './zaproszenia.js';

const TOKEN = 'a'.repeat(43);

test('token tylko z poprawnego fragmentu', () => {
  assert.equal(tokenFromHash(`#${TOKEN}`), TOKEN);
  assert.equal(tokenFromHash(TOKEN), TOKEN);
  assert.equal(tokenFromHash(''), null);
  assert.equal(tokenFromHash('#krotki'), null);
  assert.equal(tokenFromHash(`#${TOKEN}<script>`), null);
  assert.equal(tokenFromHash(`#${'b'.repeat(129)}`), null);
});

test('link: token we fragmencie, nie w sciezce ani w zapytaniu', () => {
  const link = inviteLink('https://panel.example.com/', TOKEN);
  assert.equal(link, `https://panel.example.com/zaproszenie#${TOKEN}`);
  const u = new URL(link);
  assert.equal(u.pathname, '/zaproszenie');
  assert.equal(u.search, '');
  assert.equal(u.hash, `#${TOKEN}`);
});

test('sciezka ekranu przyjecia', () => {
  assert.ok(isInvitePath('/zaproszenie'));
  assert.ok(isInvitePath('/zaproszenie/'));
  assert.ok(!isInvitePath('/'));
  assert.ok(!isInvitePath('/zaproszenie/x'));
});

test('nowe konto: login jak w SSO, haslo z polityki serwera', () => {
  const ok = { login: 'gosc-1', haslo: 'x'.repeat(12), haslo2: 'x'.repeat(12) };
  assert.equal(newAccountProblem(ok), null);
  assert.match(newAccountProblem({ ...ok, login: 'Duze' }), /Login/);
  assert.match(newAccountProblem({ ...ok, haslo: 'krotkie', haslo2: 'krotkie' }), /12/);
  assert.match(newAccountProblem({ ...ok, haslo2: 'y'.repeat(12) }), /różnią/);
  assert.match(newAccountProblem({ ...ok, haslo: 'x'.repeat(13), haslo2: 'x'.repeat(13) }, 14), /14/);
});

test('stany i odwolanie', () => {
  assert.equal(statusLabel('przyjete'), 'przyjęte');
  assert.equal(statusLabel('nowy'), 'nowy');
  assert.ok(canRevoke({ stan: 'oczekuje' }));
  assert.ok(!canRevoke({ stan: 'przyjete' }));
  assert.ok(!canRevoke({ stan: 'odwolane' }));
});
