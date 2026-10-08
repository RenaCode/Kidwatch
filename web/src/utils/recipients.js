/* Lista odbiorcow WhatsApp w Profilu. Czyste funkcje (bez Reacta), zeby dalo
   sie je testowac `npm test`. Te same granice co w bramce i w panelu
   (bramka_admin.normalize_recipients) - tu tylko po to, zeby przycisk
   "Zapisz liste" wiedzial wczesniej; decyduje serwer. */

export const MAX_RECIPIENTS = 5;
export const MAX_LABEL = 40;

/* Trasy odbiorcy w bramce (`zrodla`): "*" to wszystko - kidwatch, trader,
   monitoring, wiadomosc probna i aplikacje dopisane pozniej; "kidwatch" to
   tylko informacje o sesjach dzieci (bez alarmow, raportow i czasu gry -
   te ida jako "kidwatch:<kategoria>", patrz notifiers/bramka.py). */
export const ALL = '*';
export const SOURCES_ALL = [ALL];
export const SOURCES_FAMILY = ['kidwatch'];

export const sourcesKey = (s) => (Array.isArray(s) ? s.join(',') : '');

/* Opis tras dla czlowieka. `null` = bramka sprzed tras (wysyla wszystko). */
export function sourcesLabel(sources) {
  if (!Array.isArray(sources) || sources.includes(ALL)) return 'wszystko';
  if (sourcesKey(sources) === sourcesKey(SOURCES_FAMILY)) return 'tylko sesje dzieci';
  return sources.join(', ');
}

/* Czy odbiorca dostaje wiadomosc probna i alarmy spoza kidwatch. */
export const getsEverything = (r) => !Array.isArray(r.sources) || r.sources.includes(ALL);

/* Jak bramka_admin.normalize_number: tylko cyfry ASCII, + i separatory;
   "00" na poczatku (bez +) to prefiks miedzynarodowy. */
export const validNumberInput = (s) => /^\+?[0-9 ().-]+$/.test(String(s ?? '').trim());
export const digits = (s) => {
  const t = String(s ?? '').trim();
  const d = t.replace(/[^0-9]/g, '');
  return !t.startsWith('+') && d.startsWith('00') ? d.slice(2) : d;
};

/* Stan z /api/profile/notify -> wiersze edytora. Bramka sprzed listy zwraca
   tylko `odbiorca` (jeden numer) - pokazujemy go jako jednoelementowa liste. */
export function recipientsFromState(state) {
  if (Array.isArray(state?.odbiorcy)) {
    return state.odbiorcy.map((o) => ({
      number: String(o.numer ?? ''),
      label: String(o.etykieta ?? ''),
      active: o.aktywny !== false,
      // null: bramka sprzed tras - pole nie idzie w zapisie.
      sources: Array.isArray(o.zrodla) ? o.zrodla.map(String) : null,
    }));
  }
  return state?.odbiorca ? [{ number: state.odbiorca, label: '', active: true, sources: null }] : [];
}

/* Pierwszy problem z lista albo null. Komunikat wskazuje pozycje, nie numer. */
export function validateRecipients(list, max = MAX_RECIPIENTS, maxLabel = MAX_LABEL) {
  if (list.length > max) return `Najwyżej ${max} odbiorców.`;
  const seen = new Set();
  for (let i = 0; i < list.length; i += 1) {
    if (!validNumberInput(list[i].number)) return `Odbiorca ${i + 1}: tylko cyfry, + i separatory.`;
    const d = digits(list[i].number);
    if (d.length < 10 || d.length > 15) return `Odbiorca ${i + 1}: numer z kierunkowym, 10–15 cyfr.`;
    if (seen.has(d)) return `Odbiorca ${i + 1}: ten numer jest już na liście.`;
    seen.add(d);
    if (list[i].label.trim().length > maxLabel) return `Odbiorca ${i + 1}: etykieta najwyżej ${maxLabel} znaków.`;
  }
  return null;
}

/* Nowy wiersz: waskie trasy (rodzina). Bramka sprzed tras ich nie zna. */
export const newRecipient = (state) => ({
  number: '', label: '', active: true,
  sources: Array.isArray(state?.odbiorcy?.[0]?.zrodla) || Array.isArray(state?.zrodla_rodziny)
    ? [...(state.zrodla_rodziny || SOURCES_FAMILY)] : null,
});

/* Cialo POST /api/profile/whatsapp/recipients (bez `confirm`). `sources`
   tylko, gdy bramka zna trasy - bez pola bramka zostawia trasy numeru. */
export const recipientsPayload = (list) =>
  list.map((r) => ({
    number: digits(r.number), label: r.label.trim(), active: !!r.active,
    ...(Array.isArray(r.sources) ? { sources: [...r.sources] } : {}),
  }));

export function sameRecipients(a, b) {
  return JSON.stringify(recipientsPayload(a)) === JSON.stringify(recipientsPayload(b));
}

/* Odpowiedz /api/profile/test -> zdanie dla czlowieka. Przy czesciowej
   wysylce bramka zwraca ok + bledy.whatsapp (numery juz zamaskowane). */
export function testSummary(r) {
  if (r?.kanal === 'whatsapp') {
    const o = r.odbiorcy;
    const base = o ? `WhatsApp: doszło do ${o.doszlo} z ${o.wszystkich}.` : 'Wysłano WhatsAppem.';
    return r.bledy?.whatsapp ? `${base} Nie doszło: ${r.bledy.whatsapp}` : base;
  }
  if (r?.kanal === 'email') {
    return r.bledy?.whatsapp ? `Wysłano e-mailem (WhatsApp: ${r.bledy.whatsapp}).` : 'Wysłano e-mailem.';
  }
  return `Wysłano kanałem: ${r?.kanal ?? '?'}.`;
}

export const partialFailure = (r) => r?.kanal === 'whatsapp' && !!r.bledy?.whatsapp;
