/* Integracje domu (NextDNS, UniFi, TV, MDM, ntfy, Home Assistant) - ekran
   administratora instalacji. Serwer: GET /api/domy/<id>/integracje,
   POST .../integracje/zapisz i .../integracje/usun-sekret
   (src/kidwatch/panel_integracje.py).

   Formularz budujemy z opisu pol, ktory podaje serwer (model konfiguracji:
   rodzaj, wartosc domyslna, czy wymagane). Do serwera idzie tylko to, co
   rozni sie od wartosci domyslnej - dom nie zamraza domyslnych wartosci
   z dzisiejszej wersji kodu. Sekrety: puste pole = bez zmian; wartosci nigdy
   nie wracaja z serwera (placeholder to maska, np. "…a073"). */

export const RODZAJE = ['bool', 'int', 'float', 'tekst', 'lista', 'slownik'];

/* Wartosc z ustawien -> tekst pola formularza (bool zostaje bool). */
export function toInput(rodzaj, value) {
  if (rodzaj === 'bool') return !!value;
  if (value == null) return '';
  if (rodzaj === 'lista') return Array.isArray(value) ? value.join(', ') : String(value);
  if (rodzaj === 'slownik') {
    return value && typeof value === 'object'
      ? Object.entries(value).map(([k, v]) => `${k}=${v}`).join('\n') : '';
  }
  return String(value);
}

/* Tekst pola -> wartosc dla serwera albo { error }. */
export function fromInput(rodzaj, text, pole) {
  if (rodzaj === 'bool') return { value: !!text };
  const t = String(text ?? '').trim();
  if (rodzaj === 'int') {
    if (t === '') return { value: null };
    if (!/^-?\d+$/.test(t)) return { error: `${pole}: liczba całkowita` };
    return { value: Number(t) };
  }
  if (rodzaj === 'float') {
    if (t === '') return { value: null };
    const n = Number(t.replace(',', '.'));
    if (!Number.isFinite(n)) return { error: `${pole}: liczba` };
    return { value: n };
  }
  if (rodzaj === 'lista') return { value: t ? t.split(',').map((s) => s.trim()).filter(Boolean) : [] };
  if (rodzaj === 'slownik') {
    const out = {};
    for (const line of t.split('\n').map((l) => l.trim()).filter(Boolean)) {
      const i = line.indexOf('=');
      if (i <= 0) return { error: `${pole}: każda linia jako klucz=wartość` };
      out[line.slice(0, i).trim()] = line.slice(i + 1).trim();
    }
    return { value: out };
  }
  return { value: t === '' ? null : t };
}

const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

/* Stan formularza z integracji z serwera: zapisane ustawienia, a dla pol
   bez zapisu - wartosc domyslna. */
export function formFromIntegration(integ) {
  const pola = {};
  for (const p of integ.pola || []) {
    const stored = Object.prototype.hasOwnProperty.call(integ.ustawienia || {}, p.pole);
    pola[p.pole] = toInput(p.rodzaj, stored ? integ.ustawienia[p.pole] : p.domyslna);
  }
  const sekrety = Object.fromEntries((integ.sekrety || []).map((s) => [s.pole, '']));
  return { wlaczona: !!integ.wlaczona, pola, sekrety };
}

/* Cialo zapisu: { body } albo { error } (pierwszy blad formularza).
   Pole rowne domyslnej i niewymagane - pomijane; puste wymagane - blad. */
export function savePayload(integ, form) {
  const ustawienia = {};
  for (const p of integ.pola || []) {
    const r = fromInput(p.rodzaj, form.pola[p.pole], p.pole);
    if (r.error) return { error: r.error };
    if (r.value === null) {
      if (p.wymagane) return { error: `${p.pole}: pole wymagane` };
      continue;
    }
    if (!p.wymagane && same(r.value, p.domyslna)) continue;
    ustawienia[p.pole] = r.value;
  }
  const sekrety = {};
  for (const [pole, v] of Object.entries(form.sekrety || {})) {
    if (typeof v === 'string' && v.trim()) sekrety[pole] = v;
  }
  return { body: { typ: integ.typ, wlaczona: !!form.wlaczona, ustawienia, sekrety } };
}

/* Czy formularz rozni sie od zapisanego stanu (wpisany sekret tez). */
export function isDirty(integ, form) {
  const saved = formFromIntegration(integ);
  return saved.wlaczona !== form.wlaczona || !same(saved.pola, form.pola)
    || Object.values(form.sekrety || {}).some((v) => typeof v === 'string' && v.trim());
}

/* Placeholder pola sekretu: maska ustawionego albo informacja o braku. */
export function secretPlaceholder(s) {
  return s.ustawiony ? `ustawiony: ${s.maska} — wpisz, aby zmienić` : 'nie ustawiony';
}

/* Co ekran mowi o przeladowaniu domu po zapisie. Nigdy nie udaje, ze zmiana
   juz dziala: bez automatycznego przeladowania - wprost "po restarcie". */
export function reloadNotice(p) {
  if (!p) return null;
  if (!p.automatyczne) {
    return { kind: 'warn', text: p.komunikat || 'Zmiana zadziała po restarcie Kidwatcha.' };
  }
  if (p.czeka) {
    return {
      kind: 'info',
      text: `Dom czeka na konfigurację: ${p.czeka}. Monitoring wystartuje sam po jej `
        + 'uzupełnieniu (w ciągu ok. 10 s od zapisu).',
    };
  }
  if (p.blad && p.nieudana === p.wersja) {
    return {
      kind: 'bad',
      text: `Nowa konfiguracja (wersja ${p.nieudana}) nie wystartowała: ${p.blad}. `
        + `Dom działa dalej na wersji ${p.wersja_dzialajaca ?? '?'}.`,
    };
  }
  if (p.aktualna) return { kind: 'ok', text: `Dom działa na bieżącej konfiguracji (wersja ${p.wersja}).` };
  return {
    kind: 'info',
    text: `Zapisano wersję ${p.wersja}; dom działa jeszcze na wersji ${p.wersja_dzialajaca ?? '?'}. `
      + 'Kidwatch przełączy go w ciągu ok. 10 s.',
  };
}

/* Odswiezac stan, dopoki nadzorca nie przelaczy domu. */
export const waitingForReload = (p) => !!p && p.automatyczne && !p.aktualna
  && !(p.blad && p.nieudana === p.wersja);

/* Ekran tylko dla aktywnego administratora instalacji (serwer i tak 403). */
export const canEditIntegrations = (user) => !!user?.admin_instancji
  && Array.isArray(user?.uprawnienia) && user.uprawnienia.includes('dom.integracje');

/* Sondowanie stanu po zapisie: co 4 s, najwyzej 2 minuty. */
export const POLL_MS = 4000;
export const POLL_LIMIT = 30;

/* Odpowiedz zapisu -> stan ekranu: wszystkie zmienione karty (przelaczenie
   zrodla DNS zmienia dwie), wersja domu, start i przeladowanie. */
export function applySaved(data, r) {
  const zmienione = r.zmienione || (r.integracja ? [r.integracja] : []);
  const byTyp = Object.fromEntries(zmienione.map((i) => [i.typ, i]));
  return {
    ...data,
    dom: r.dom || data.dom,
    start: r.start !== undefined ? r.start : data.start,
    przeladowanie: r.przeladowanie || data.przeladowanie,
    integracje: data.integracje.map((i) => byTyp[i.typ] || i),
  };
}

/* Odpowiedz GET .../integracje/stan -> stan ekranu (karty bez zmian).
   `dom.wersja` zostaje ta z wczytania albo z WLASNEGO zapisu: to nia zapis
   broni sie przed nadpisaniem cudzej zmiany (409). Wersja w bazie wyzsza
   niz znana ekranowi = ktos inny zmienil dom: `obcaZmiana`, ekran prosi
   o odswiezenie zamiast po cichu przyjac nowa wersje. */
export function applyState(data, st) {
  if (!data) return data;
  const obca = !!st.dom && st.dom.wersja > data.dom.wersja;
  return {
    ...data, start: st.start, przeladowanie: st.przeladowanie,
    obcaZmiana: data.obcaZmiana || obca,
  };
}
