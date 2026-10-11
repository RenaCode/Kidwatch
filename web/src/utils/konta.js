/* Powiadomienia per konto i zarzadzanie kontami - logika bez Reacta
   (src/kidwatch/odbiorcy.py, panel_konta.py). Serwer waliduje wszystko
   ponownie; tu tylko to, co front musi wiedziec przed wyslaniem. */

export const QUIET_RE = /^([01][0-9]|2[0-3]):[0-5][0-9]$/;

/* Cisza: obie godziny albo zadna. Zwraca komunikat albo null. */
export function quietProblem(od, doo) {
  const a = (od || '').trim();
  const b = (doo || '').trim();
  if (!a && !b) return null;
  if (!a || !b) return 'Cisza: podaj obie godziny albo żadnej.';
  if (!QUIET_RE.test(a) || !QUIET_RE.test(b)) return 'Godziny w formacie GG:MM, np. 22:00.';
  if (a === b) return 'Początek i koniec ciszy są takie same.';
  return null;
}

/* Profil z serwera -> stan formularza preferencji. `dzieci: null` = wszystkie. */
export function prefsFromProfile(p) {
  return {
    kategorie: [...(p?.kategorie || [])],
    cisza_od: p?.cisza_od || '',
    cisza_do: p?.cisza_do || '',
    cisza_alarmy: p?.cisza_alarmy ?? true,
    dzieci: p?.dzieci == null ? null : [...p.dzieci],
    aktywne: p?.aktywne ?? true,
  };
}

export function prefsPayload(f) {
  return {
    kategorie: f.kategorie,
    cisza_od: f.cisza_od.trim() || null,
    cisza_do: f.cisza_do.trim() || null,
    cisza_alarmy: f.cisza_alarmy,
    dzieci: f.dzieci,
    aktywne: f.aktywne,
  };
}

export function samePrefs(a, b) {
  return JSON.stringify(prefsPayload(a)) === JSON.stringify(prefsPayload(b));
}

/* Przelacznik w liscie: dodaj albo usun, zachowujac kolejnosc katalogu. */
export function toggle(list, id, on, order) {
  const set = new Set(list);
  if (on) set.add(id); else set.delete(id);
  return order.filter((x) => set.has(x));
}

/* Dzieci: null (wszystkie) <-> jawna lista. Odznaczenie dziecka przy
   "wszystkie" daje liste pozostalych. */
export function toggleChild(dzieci, child, on, all) {
  const current = dzieci == null ? [...all] : dzieci;
  const next = toggle(current, child, on, all);
  return next.length === all.length ? null : next;
}

export const CHANNEL_LABEL = { auto: 'WhatsApp, a gdy nie dojdzie — e-mail', whatsapp: 'tylko WhatsApp', email: 'tylko e-mail' };

export function channelsSummary(p) {
  const parts = [];
  if (p?.whatsapp) parts.push(`WhatsApp ${p.whatsapp}`);
  if (p?.email) parts.push(`e-mail ${p.email}`);
  return parts.length ? parts.join(' · ') : 'brak kanału';
}

/* Uprawnienia konta po zmianie checkboxa -> `zmiany` dla /api/konta/uprawnienia.
   Zgodnie z rola = `null` (zdejmuje odstepstwo), inaczej true/false. */
export function permissionChange(roleDefaults, id, on) {
  const fromRole = roleDefaults.includes(id);
  return { [id]: on === fromRole ? null : on };
}

/* Komunikat o trybie: preferencje dzialaja dopiero w trybie kont. */
export function modeNotice(tryb) {
  if (tryb === 'konta') return null;
  return 'Kidwatch wysyła jeszcze według listy odbiorców bramki (tryb tras). '
    + 'Te ustawienia zaczną działać, gdy osoba zarządzająca kontami przełączy '
    + 'powiadomienia na tryb kont.';
}
