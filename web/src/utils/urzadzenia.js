/* Dzieci i urzadzenia domu - ekran wlasciciela domu i zarzadcy
   (uprawnienie dom.urzadzenia). Serwer: GET /api/domy/<id>/urzadzenia
   i POST .../urzadzenia/zapisz (src/kidwatch/panel_urzadzenia.py).

   Zapis to pelna lista dzieci i urzadzen z `id` wierszy z bazy (nowe bez id)
   - serwer dopasowuje po id, wiec zmiana nazwy nie gubi UDID-u ani adresu,
   ktore ustawil administrator. Te pola (UDID, adres, MAC) rola domu widzi
   tylko jako flagi; wysyla je wylacznie administrator instalacji. */

export const RODZAJ_ANDROID = 'phone-android';
const NEXTDNS_SUFIKS = '.dns.nextdns.io';
/* Etykieta DNS: najwyzej 63 znaki. */
const MAX_ETYKIETA = 63;
export const POLA_ADMINA = ['udid', 'host', 'unifi_mac', 'unifi_ip'];
export const OPISY_ADMINA = {
  udid: 'UDID', host: 'adres w sieci domu', unifi_mac: 'MAC (UniFi)', unifi_ip: 'IP (UniFi)',
  mdm: 'MDM', known_apps: 'lista aplikacji',
};

/* Host Prywatnego DNS Androida dla NextDNS: spacje -> `--`, na koncu
   `-<ID profilu>.dns.nextdns.io` (renacode-infra: docs/projekty/kidwatch/
   telefon-android.md). NextDNS pokaze wtedy urzadzenie pod ta nazwa.
   { host } albo { error }. */
export function hostPrywatnegoDns(nazwa, profil) {
  const n = String(nazwa ?? '').trim();
  if (!n) return { error: 'Wpisz nazwę urządzenia w NextDNS.' };
  if (!profil) return { error: 'Brak ID profilu NextDNS (integracja NextDNS albo pole „Profil NextDNS”).' };
  if (!/^[A-Za-z0-9 -]+$/.test(n)) {
    return { error: 'Do hosta Prywatnego DNS nazwa może mieć tylko litery bez polskich znaków, cyfry, spacje i „-”.' };
  }
  const etykieta = `${n.split(/\s+/).join('--')}-${profil}`;
  if (etykieta.length > MAX_ETYKIETA) return { error: 'Nazwa za długa do hosta Prywatnego DNS — skróć ją.' };
  return { host: `${etykieta}${NEXTDNS_SUFIKS}` };
}

/* Profil NextDNS urzadzenia: wlasny albo profil domu. */
export const profilUrzadzenia = (u, profilDomu) => (u.nextdns_profile || '').trim() || profilDomu || null;

/* "a, b" -> ['a', 'b'] (nazwy w NextDNS). */
export const nazwyNextdns = (tekst) => String(tekst ?? '').split(',').map((s) => s.trim()).filter(Boolean);

let licznik = 0;
const nowyKlucz = () => `n${++licznik}`;

/* Odpowiedz serwera -> stan formularza. Dziecko ma `klucz` (id albo
   tymczasowy) - urzadzenie wskazuje dziecko kluczem, wiec zmiana imienia
   nie odpina urzadzen. */
export function formZEkranu(ekran) {
  const dzieci = ekran.dzieci.map((d) => ({ klucz: `d${d.id}`, id: d.id, nazwa: d.nazwa }));
  const kluczDziecka = Object.fromEntries(dzieci.map((d) => [d.nazwa, d.klucz]));
  const urzadzenia = ekran.urzadzenia.map((u) => ({
    klucz: `u${u.id}`,
    id: u.id,
    nazwa: u.nazwa,
    dziecko: kluczDziecka[u.dziecko] ?? '',
    rodzaj: u.rodzaj,
    nextdns: (u.source_ids || []).join(', '),
    nextdns_profile: u.nextdns_profile || '',
    administrator: u.administrator || {},
    chronione: !!u.chronione,
    techniczne: Object.fromEntries(POLA_ADMINA.map((p) => [p, u.techniczne?.[p] ?? ''])),
  }));
  return { dzieci, urzadzenia };
}

export const noweDziecko = () => ({ klucz: nowyKlucz(), id: null, nazwa: '' });
export const noweUrzadzenie = (kluczDziecka, rodzaj = RODZAJ_ANDROID) => ({
  klucz: nowyKlucz(), id: null, nazwa: '', dziecko: kluczDziecka, rodzaj, nextdns: '',
  nextdns_profile: '', administrator: {}, chronione: false,
  techniczne: Object.fromEntries(POLA_ADMINA.map((p) => [p, ''])),
});

/* Ustawione przez administratora pola urzadzenia (do opisu na ekranie). */
export const ustawionePrzezAdmina = (u) => Object.entries(u.administrator || {})
  .filter(([, v]) => v).map(([k]) => OPISY_ADMINA[k] || k);

/* Pierwszy blad formularza albo null. Serwer sprawdza to samo (i wiecej:
   walidatory config.yaml), tu - zeby nie wysylac oczywistych pomylek. */
export function walidujFormularz(form, { rodzaje = [] } = {}) {
  const imiona = new Set();
  for (const d of form.dzieci) {
    const n = d.nazwa.trim();
    if (!n) return 'Wpisz imię każdego dziecka.';
    if (imiona.has(n)) return `Dziecko „${n}” jest na liście dwa razy.`;
    imiona.add(n);
  }
  const nazwy = new Set();
  const dozwolone = new Set(rodzaje.map((r) => r.rodzaj));
  for (const u of form.urzadzenia) {
    const n = u.nazwa.trim();
    if (!n) return 'Wpisz nazwę każdego urządzenia.';
    if (nazwy.has(n)) return `Urządzenie „${n}” jest na liście dwa razy.`;
    nazwy.add(n);
    if (!form.dzieci.some((d) => d.klucz === u.dziecko)) return `${n}: wybierz dziecko.`;
    if (dozwolone.size && !dozwolone.has(u.rodzaj)) return `${n}: wybierz rodzaj urządzenia.`;
    if (!nazwyNextdns(u.nextdns).length) return `${n}: wpisz nazwę urządzenia w NextDNS.`;
    if (u.nextdns_profile.trim() && !/^[0-9a-z]+$/.test(u.nextdns_profile.trim())) {
      return `${n}: ID profilu NextDNS to małe litery i cyfry (np. abc123).`;
    }
  }
  const bezUrzadzen = form.dzieci.filter((d) => !form.urzadzenia.some((u) => u.dziecko === d.klucz));
  if (bezUrzadzen.length) {
    return `Dziecko ${bezUrzadzen.map((d) => d.nazwa.trim() || '(bez imienia)').join(', ')} nie ma `
      + 'urządzenia — dodaj urządzenie albo usuń dziecko.';
  }
  return null;
}

/* Cialo POST .../urzadzenia/zapisz (bez `confirm`). Pola techniczne tylko
   od administratora - serwer odrzuca je (403) od roli domu. */
export function cialoZapisu(form, { wersja, administrator = false }) {
  const imie = Object.fromEntries(form.dzieci.map((d) => [d.klucz, d.nazwa.trim()]));
  return {
    wersja,
    dzieci: form.dzieci.map((d) => ({ id: d.id, nazwa: d.nazwa.trim() })),
    urzadzenia: form.urzadzenia.map((u) => {
      const out = {
        id: u.id,
        nazwa: u.nazwa.trim(),
        dziecko: imie[u.dziecko] ?? '',
        rodzaj: u.rodzaj,
        source_ids: nazwyNextdns(u.nextdns),
        nextdns_profile: u.nextdns_profile.trim() || null,
      };
      if (administrator) {
        for (const p of POLA_ADMINA) out[p] = String(u.techniczne?.[p] ?? '').trim() || null;
      }
      return out;
    }),
  };
}

/* Czy formularz rozni sie od stanu z serwera. */
export function czyZmieniony(ekran, form) {
  const a = cialoZapisu(formZEkranu(ekran), { wersja: 0, administrator: !!ekran.administrator });
  const b = cialoZapisu(form, { wersja: 0, administrator: !!ekran.administrator });
  return JSON.stringify(a) !== JSON.stringify(b);
}

/* Urzadzenia, ktorych usuniecie wymaga administratora (rola domu). */
export const zablokowaneUsuniecie = (u, administrator) => !administrator && u.chronione;
