/* Wylogowanie i odmowy przy SSO (Authelia przed panelem). */
import test from 'node:test';
import assert from 'node:assert/strict';
import { reloadAllowed, safeLogoutUrl, signOutLabel, signOutTarget, ssoDenial } from './sso.js';

const PORTAL = 'https://auth.renacode.com/logout?rd=https%3A%2F%2Fkidwatch.renacode.com%2F';

test('wyloguj przez SSO idzie na portal, bez SSO zostaje w panelu', () => {
  assert.equal(signOutTarget({ ok: true, logout_url: PORTAL }, { logout_url: PORTAL }), PORTAL);
  assert.equal(signOutTarget({ ok: true }, { login: 'rodzic1', logout_url: null }), null);
  assert.equal(signOutTarget(null, { login: 'rodzic1' }), null);
});

test('nieudany POST wylogowania i tak konczy sesje Authelii', () => {
  assert.equal(signOutTarget(undefined, { logout_url: PORTAL }), PORTAL);
});

test('przycisk mowi, ze wylogowanie dotyczy SSO', () => {
  assert.equal(signOutLabel({ logout_url: PORTAL }), 'Wyloguj (SSO)');
  assert.equal(signOutLabel({ logout_url: null }), 'Wyloguj');
  assert.equal(signOutLabel(null), 'Wyloguj');
});

test('adres spoza https nie trafia do window.location', () => {
  for (const zly of ['javascript:alert(1)', 'http://auth.renacode.com/logout', '/logout', '', 42, null]) {
    assert.equal(safeLogoutUrl(zly), null, String(zly));
    assert.equal(signOutTarget({ logout_url: zly }, null), null);
  }
});

test('odmowa SSO z /api/auth/me to komunikat i portal, nie ekran logowania', () => {
  const err = { status: 403, message: 'Brak konta w Kidwatchu dla użytkownika „nieznany”', data: { logout_url: PORTAL } };
  assert.deepEqual(ssoDenial(err), { message: err.message, logoutUrl: PORTAL });
  assert.equal(ssoDenial({ ...err, status: 400 }).logoutUrl, PORTAL);
  // 401 bez SSO albo 403 bez adresu portalu - zwykly ekran logowania.
  assert.equal(ssoDenial({ status: 401, message: 'x', data: { logout_url: PORTAL } }), null);
  assert.equal(ssoDenial({ status: 403, message: 'x', data: {} }), null);
  assert.equal(ssoDenial(new Error('siec')), null);
});

test('przeladowanie po wygasnieciu Authelii nie czesciej niz co 30 s', () => {
  assert.equal(reloadAllowed(1000, 0), true);
  assert.equal(reloadAllowed(20000, 1000), false);
  assert.equal(reloadAllowed(31000, 1000), true);
});
