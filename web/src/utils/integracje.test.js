import test from 'node:test';
import assert from 'node:assert/strict';
import {
  applySaved, applyState, canEditIntegrations, formFromIntegration, fromInput, isDirty, reloadNotice, savePayload,
  secretPlaceholder, toInput, waitingForReload,
} from './integracje.js';

const UNIFI = {
  typ: 'unifi',
  nazwa: 'UniFi',
  wlaczona: true,
  ustawienia: { url: 'https://192.0.2.1', cert_sha256: 'ab'.repeat(32), poll_seconds: 60 },
  pola: [
    { pole: 'url', rodzaj: 'tekst', domyslna: 'https://192.168.1.1', wymagane: false },
    { pole: 'site', rodzaj: 'tekst', domyslna: 'default', wymagane: false },
    { pole: 'cert_sha256', rodzaj: 'tekst', domyslna: '', wymagane: false },
    { pole: 'poll_seconds', rodzaj: 'float', domyslna: 60, wymagane: false },
    { pole: 'window_minutes', rodzaj: 'int', domyslna: 15, wymagane: false },
  ],
  sekrety: [{ pole: 'api_key', opis: 'klucz API', ustawiony: true, maska: '…a073' }],
};

const TV = {
  typ: 'tv',
  wlaczona: false,
  ustawienia: {},
  pola: [
    { pole: 'host', rodzaj: 'tekst', domyslna: '', wymagane: false },
    { pole: 'sony', rodzaj: 'bool', domyslna: true, wymagane: false },
    { pole: 'nextdns_ids', rodzaj: 'lista', domyslna: [], wymagane: false },
    { pole: 'apps', rodzaj: 'slownik', domyslna: {}, wymagane: false },
    { pole: 'unifi_mac', rodzaj: 'tekst', domyslna: null, wymagane: false },
  ],
  sekrety: [],
};

const NEXTDNS = {
  typ: 'nextdns', wlaczona: true, ustawienia: { profile_id: 'abc123' },
  pola: [{ pole: 'profile_id', rodzaj: 'tekst', domyslna: null, wymagane: true }],
  sekrety: [{ pole: 'api_key', ustawiony: false, maska: null }],
};

test('pola formularza: zapisane ustawienia, a reszta z wartosci domyslnych', () => {
  const f = formFromIntegration(UNIFI);
  assert.equal(f.pola.url, 'https://192.0.2.1');
  assert.equal(f.pola.site, 'default');
  assert.equal(f.pola.window_minutes, '15');
  assert.deepEqual(f.sekrety, { api_key: '' });
  assert.equal(f.wlaczona, true);
});

test('zapis: tylko odstepstwa od domyslnych, pusty sekret = bez zmian', () => {
  const f = formFromIntegration(UNIFI);
  const { body } = savePayload(UNIFI, f);
  assert.deepEqual(body, {
    typ: 'unifi', wlaczona: true,
    ustawienia: { url: 'https://192.0.2.1', cert_sha256: 'ab'.repeat(32) },
    sekrety: {},
  });
  const z = savePayload(UNIFI, { ...f, sekrety: { api_key: '  ' } });
  assert.deepEqual(z.body.sekrety, {});
  const k = savePayload(UNIFI, { ...f, sekrety: { api_key: 'nowy-klucz-testowy' } });
  assert.deepEqual(k.body.sekrety, { api_key: 'nowy-klucz-testowy' });
});

test('zapis: wymagane puste i zla liczba to blad formularza', () => {
  const f = formFromIntegration(NEXTDNS);
  assert.match(savePayload(NEXTDNS, { ...f, pola: { profile_id: '' } }).error, /wymagane/);
  const u = formFromIntegration(UNIFI);
  assert.match(savePayload(UNIFI, { ...u, pola: { ...u.pola, window_minutes: '1.5' } }).error, /całkowita/);
  assert.equal(savePayload(NEXTDNS, f).body.ustawienia.profile_id, 'abc123');
});

test('lista, slownik i bool w obie strony', () => {
  assert.equal(toInput('lista', ['a', 'b']), 'a, b');
  assert.deepEqual(fromInput('lista', 'a, ,b').value, ['a', 'b']);
  assert.equal(toInput('slownik', { 'com.x': 'X' }), 'com.x=X');
  assert.deepEqual(fromInput('slownik', 'com.x = X\n\ncom.y=Y').value, { 'com.x': 'X', 'com.y': 'Y' });
  assert.match(fromInput('slownik', 'bez-rownasie', 'apps').error, /klucz=wartość/);
  assert.equal(fromInput('float', '2,5').value, 2.5);
  const f = formFromIntegration(TV);
  assert.equal(f.pola.sony, true);
  assert.equal(f.pola.unifi_mac, '');
  // Nic nie zmienione: puste ustawienia (same wartosci domyslne, null pominiety).
  assert.deepEqual(savePayload(TV, f).body.ustawienia, {});
  const z = savePayload(TV, { ...f, pola: { ...f.pola, sony: false, nextdns_ids: 'tv-1' } });
  assert.deepEqual(z.body.ustawienia, { sony: false, nextdns_ids: ['tv-1'] });
});

test('zmiana formularza: przelacznik, pole, wpisany sekret', () => {
  const f = formFromIntegration(UNIFI);
  assert.equal(isDirty(UNIFI, f), false);
  assert.equal(isDirty(UNIFI, { ...f, wlaczona: false }), true);
  assert.equal(isDirty(UNIFI, { ...f, pola: { ...f.pola, site: 'inna' } }), true);
  assert.equal(isDirty(UNIFI, { ...f, sekrety: { api_key: 'x' } }), true);
});

test('placeholder sekretu to maska, nigdy wartosc', () => {
  assert.equal(secretPlaceholder(UNIFI.sekrety[0]), 'ustawiony: …a073 — wpisz, aby zmienić');
  assert.equal(secretPlaceholder(NEXTDNS.sekrety[0]), 'nie ustawiony');
});

test('przeladowanie: bez automatu ekran mowi wprost o restarcie', () => {
  const r = reloadNotice({ automatyczne: false, wersja: 3, komunikat: 'Zmiana zadziała po restarcie Kidwatcha.' });
  assert.equal(r.kind, 'warn');
  assert.match(r.text, /po restarcie/);
  assert.equal(waitingForReload({ automatyczne: false }), false);
});

test('przeladowanie: czeka, dziala, nie wystartowalo', () => {
  const czeka = { automatyczne: true, wersja: 5, wersja_dzialajaca: 4, aktualna: false };
  assert.equal(reloadNotice(czeka).kind, 'info');
  assert.match(reloadNotice(czeka).text, /jeszcze na wersji 4/);
  assert.equal(waitingForReload(czeka), true);
  const ok = { automatyczne: true, wersja: 5, wersja_dzialajaca: 5, aktualna: true };
  assert.equal(reloadNotice(ok).kind, 'ok');
  assert.equal(waitingForReload(ok), false);
  const blad = { ...czeka, nieudana: 5, blad: 'brak sekretu nextdns.api_key' };
  assert.equal(reloadNotice(blad).kind, 'bad');
  assert.match(reloadNotice(blad).text, /dalej na wersji 4/);
  assert.equal(waitingForReload(blad), false);
  // Stara nieudana wersja nie zaslania nowego zapisu.
  assert.equal(reloadNotice({ ...blad, wersja: 6 }).kind, 'info');
});

test('przeladowanie: nowy dom czeka na konfiguracje — informacja, nie blad', () => {
  const p = { automatyczne: true, wersja: 3, wersja_dzialajaca: null, aktualna: false,
    czeka: 'brak wlaczonego zrodla DNS (integracja NextDNS)' };
  const r = reloadNotice(p);
  assert.equal(r.kind, 'info');
  assert.match(r.text, /czeka na konfigurację: brak wlaczonego zrodla DNS/);
  assert.doesNotMatch(r.text, /wersji \?/);
  // Po zapisie integracji ekran dalej sonduje, az dom wystartuje.
  assert.equal(waitingForReload(p), true);
});

test('ekran tylko dla aktywnego administratora z dom.integracje', () => {
  assert.equal(canEditIntegrations({ admin_instancji: true, uprawnienia: ['dom.integracje'] }), true);
  assert.equal(canEditIntegrations({ admin_instancji: false, uprawnienia: ['dom.integracje'] }), false);
  assert.equal(canEditIntegrations({ admin_instancji: true, uprawnienia: [] }), false);
  assert.equal(canEditIntegrations(null), false);
});

test('zapis przelaczajacy zrodlo DNS podmienia obie karty i wersje domu', () => {
  const data = {
    dom: { id: 2, wersja: 5 }, start: null, przeladowanie: { automatyczne: true },
    integracje: [{ typ: 'nextdns', wlaczona: true }, { typ: 'adguard', wlaczona: false }, UNIFI],
  };
  const r = {
    ok: true, dom: { id: 2, wersja: 7 }, start: null, przeladowanie: { automatyczne: true, wersja: 7 },
    zmienione: [{ typ: 'adguard', wlaczona: true }, { typ: 'nextdns', wlaczona: false }],
  };
  const d = applySaved(data, r);
  assert.equal(d.dom.wersja, 7);
  assert.deepEqual(d.integracje.map((i) => [i.typ, i.wlaczona]),
    [['nextdns', false], ['adguard', true], ['unifi', true]]);
  // Sondowanie stanu nie rusza kart ani wersji z wlasnego zapisu.
  const s = applyState(d, { dom: { id: 2, wersja: 7 }, start: 'x', przeladowanie: { aktualna: true } });
  assert.equal(s.integracje, d.integracje);
  assert.equal(s.start, 'x');
  assert.equal(s.dom.wersja, 7);
  assert.equal(s.obcaZmiana, false);
});

test('sondowanie nie podnosi wersji ekranu: cudza zmiana zostaje chroniona przez 409', () => {
  const data = { dom: { id: 2, wersja: 7 }, start: null, przeladowanie: {}, integracje: [] };
  const s = applyState(data, { dom: { id: 2, wersja: 9 }, start: null, przeladowanie: { wersja: 9 } });
  assert.equal(s.dom.wersja, 7);
  assert.equal(s.obcaZmiana, true);
  // Raz wykryta zostaje do odswiezenia ekranu.
  assert.equal(applyState(s, { dom: { id: 2, wersja: 7 }, start: null, przeladowanie: {} }).obcaZmiana, true);
});
