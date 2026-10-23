import test from 'node:test';
import assert from 'node:assert/strict';
import {
  cialoZapisu, czyZmieniony, formZEkranu, hostPrywatnegoDns, noweDziecko, noweUrzadzenie,
  profilUrzadzenia, ustawionePrzezAdmina, walidujFormularz, zablokowaneUsuniecie,
} from './urzadzenia.js';

const RODZAJE = [
  { rodzaj: 'ipad', nazwa: 'iPad' }, { rodzaj: 'iphone', nazwa: 'iPhone' },
  { rodzaj: 'phone-android', nazwa: 'Telefon z Androidem' },
];

const EKRAN = {
  dom: { id: 2, nazwa: 'Dom B', wersja: 7 },
  administrator: false,
  dzieci: [{ id: 3, nazwa: 'Dziecko A' }],
  urzadzenia: [
    {
      id: 10, nazwa: 'iPad A', dziecko: 'Dziecko A', rodzaj: 'ipad', source_ids: ['ipad-a'],
      nextdns_profile: null, chronione: true,
      administrator: { udid: true, host: true, unifi_mac: false, unifi_ip: false, mdm: false, known_apps: true },
    },
  ],
  rodzaje: RODZAJE,
  profil_nextdns: 'abc123',
};

test('host Prywatnego DNS: spacje jako --, profil na koncu', () => {
  assert.deepEqual(hostPrywatnegoDns('Telefon Dziecka 1', 'abc123'),
    { host: 'Telefon--Dziecka--1-abc123.dns.nextdns.io' });
  assert.deepEqual(hostPrywatnegoDns('  Telefon   A ', 'abc123'),
    { host: 'Telefon--A-abc123.dns.nextdns.io' });
});

test('host Prywatnego DNS: polskie znaki, brak profilu, za dluga nazwa - blad', () => {
  assert.match(hostPrywatnegoDns('Telefon Zośki', 'abc123').error, /polskich/);
  assert.match(hostPrywatnegoDns('Telefon A', null).error, /profilu/);
  assert.match(hostPrywatnegoDns('', 'abc123').error, /nazwę/);
  assert.match(hostPrywatnegoDns('a'.repeat(60), 'abc123').error, /za długa/);
});

test('profil urzadzenia: wlasny przed profilem domu', () => {
  assert.equal(profilUrzadzenia({ nextdns_profile: 'xyz9' }, 'abc123'), 'xyz9');
  assert.equal(profilUrzadzenia({ nextdns_profile: '' }, 'abc123'), 'abc123');
  assert.equal(profilUrzadzenia({}, null), null);
});

test('formularz -> cialo: id wierszy, dziecko po imieniu, bez pol technicznych roli domu', () => {
  const form = formZEkranu(EKRAN);
  assert.equal(czyZmieniony(EKRAN, form), false);
  // Zmiana imienia dziecka nie odpina urzadzenia (klucz, nie imie).
  form.dzieci[0].nazwa = 'Dziecko A2';
  form.urzadzenia[0].nazwa = 'iPad A nowy';
  form.urzadzenia[0].nextdns = 'ipad-a, ipad-a2';
  const body = cialoZapisu(form, { wersja: 7 });
  assert.deepEqual(body, {
    wersja: 7,
    dzieci: [{ id: 3, nazwa: 'Dziecko A2' }],
    urzadzenia: [{
      id: 10, nazwa: 'iPad A nowy', dziecko: 'Dziecko A2', rodzaj: 'ipad',
      source_ids: ['ipad-a', 'ipad-a2'], nextdns_profile: null,
    }],
  });
  assert.equal(czyZmieniony(EKRAN, form), true);
  assert.equal(walidujFormularz(form, { rodzaje: RODZAJE }), null);
});

test('administrator wysyla pola techniczne (puste = wyczysc)', () => {
  const ekran = {
    ...EKRAN, administrator: true,
    urzadzenia: [{ ...EKRAN.urzadzenia[0], techniczne: { udid: 'U-1', host: '192.0.2.9', unifi_mac: null, unifi_ip: null } }],
  };
  const form = formZEkranu(ekran);
  form.urzadzenia[0].techniczne.host = ' ';
  const u = cialoZapisu(form, { wersja: 7, administrator: true }).urzadzenia[0];
  assert.deepEqual([u.udid, u.host, u.unifi_mac, u.unifi_ip], ['U-1', null, null, null]);
});

test('walidacja: imiona, nazwy, dziecko, NextDNS, profil, dziecko bez urzadzenia', () => {
  const ok = formZEkranu(EKRAN);
  const zle = (zmien) => {
    const f = structuredClone(ok);
    zmien(f);
    return walidujFormularz(f, { rodzaje: RODZAJE });
  };
  assert.match(zle((f) => { f.dzieci[0].nazwa = ' '; }), /imię/);
  assert.match(zle((f) => { f.dzieci.push({ ...noweDziecko(), nazwa: 'Dziecko A' }); }), /dwa razy/);
  assert.match(zle((f) => { f.urzadzenia[0].nazwa = ''; }), /nazwę/);
  assert.match(zle((f) => { f.urzadzenia.push({ ...noweUrzadzenie(f.dzieci[0].klucz), nazwa: 'iPad A', nextdns: 'x' }); }), /dwa razy/);
  assert.match(zle((f) => { f.urzadzenia[0].dziecko = 'brak'; }), /wybierz dziecko/);
  assert.match(zle((f) => { f.urzadzenia[0].rodzaj = 'tv'; }), /rodzaj/);
  assert.match(zle((f) => { f.urzadzenia[0].nextdns = ' , '; }), /NextDNS/);
  assert.match(zle((f) => { f.urzadzenia[0].nextdns_profile = 'ABC'; }), /małe litery/);
  assert.match(zle((f) => { f.dzieci.push({ ...noweDziecko(), nazwa: 'Dziecko B' }); }), /Dziecko B nie ma urządzenia/);
});

test('usuniecie urzadzenia z polami administratora - tylko administrator', () => {
  const [u] = formZEkranu(EKRAN).urzadzenia;
  assert.equal(zablokowaneUsuniecie(u, false), true);
  assert.equal(zablokowaneUsuniecie(u, true), false);
  assert.deepEqual(ustawionePrzezAdmina(u), ['UDID', 'adres w sieci domu', 'lista aplikacji']);
});
