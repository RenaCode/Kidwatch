/* Komendy z WhatsAppa - dziennik i wylacznik w panelu (src/kidwatch/
   panel_komendy.py, komendy_baza.py). Logika bez Reacta, testowana w node. */

/* Wynik wpisu w dzienniku -> [etykieta, klasa odznaki]. Nieznany wynik
   (nowszy serwer) pokazujemy surowo, zamiast go chowac. */
export const WYNIKI = {
  'nieznany-numer': ['obcy numer (cisza)', 'warn'],
  'bez-uprawnien': ['konto bez uprawnień', 'warn'],
  wylaczone: ['wyłączone', ''],
  limit: ['limit wiadomości', 'warn'],
  zablokowany: ['numer zablokowany', 'bad'],
  przeterminowana: ['za stara', ''],
  'nie-rozumiem': ['nie zrozumiał', ''],
  'bez-llm': ['bez LLM', 'warn'],
  dopytanie: ['dopytał', ''],
  'czeka-na-kod': ['czeka na kod', 'info'],
  'zly-kod': ['zły kod', 'bad'],
  'kod-wygasl': ['kod wygasł', ''],
  odmowa: ['odmowa', 'warn'],
  wykonane: ['wykonane', 'ok'],
  blad: ['błąd', 'bad'],
  odpowiedz: ['odpowiedź', 'ok'],
};

export function wynikLabel(wynik) {
  return WYNIKI[wynik] || [wynik || '?', ''];
}

export const AKCJE = {
  stan: 'stan',
  koniec: 'koniec',
  zablokuj: 'blokada ekranu',
  odejmij: 'mniej czasu',
  dodaj: 'więcej czasu',
  odblokuj: 'odblokowanie',
  cisza: 'cisza',
  pomoc: 'pomoc',
};

/* Akcja z celem i minutami: "więcej czasu · Dziecko A · +15 min". */
export function opisAkcji(w) {
  if (!w?.akcja) return '';
  const czesci = [AKCJE[w.akcja] || w.akcja];
  if (w.cel) czesci.push(w.cel);
  if (w.minuty) czesci.push(`${w.akcja === 'odejmij' ? '-' : '+'}${w.minuty} min`);
  return czesci.join(' · ');
}

/* `ts` z serwera to sekundy unixowe. */
export function kiedy(ts) {
  return new Date(ts * 1000).toLocaleString('pl-PL');
}

/* Tekst stanu wylacznika dla administratora. */
export function stanWylacznika(stan) {
  if (!stan?.wlaczone) return 'Komendy z WhatsAppa są wyłączone w konfiguracji (whatsapp_komendy.enabled).';
  if (stan.wylaczone) {
    const kto = stan.wylaczone.kto ? ` (${stan.wylaczone.kto})` : '';
    return `WYŁĄCZONE awaryjnie${kto} — bot odpowiada opiekunom, że komendy są wyłączone.`;
  }
  return 'Działają — opiekunowie domów wydają komendy z potwierdzeniem kodem.';
}
