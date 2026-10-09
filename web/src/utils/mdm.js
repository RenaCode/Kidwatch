/* Klasyfikacja zdarzen serwera MDM i powiadomien - wspolna dla zakladki MDM
   i dzwonka. Czysta logika, zeby dalo sie ja testowac bez przegladarki. */

function detailOf(event) {
  if (event.detail == null || typeof event.detail === 'object') return event.detail || {};
  try { return JSON.parse(event.detail); } catch { return {}; }
}

/* Czy zdarzenie w ogole cos znaczy. Stare `os_update_failed` sprzed poprawki
   serwera niosa {"count": 0} - to raport BEZ awarii; czujka (mdm.py) je
   odrzuca, wiec panel tez. */
export function isMeaningfulEvent(event) {
  if (event.kind !== 'os_update_failed') return true;
  return (Number(detailOf(event).count) || 0) > 0;
}

const ALARM = new Set(['checkout', 'profile_missing', 'push_token_dead', 'cert_mismatch',
  'enrollment_reuse', 'unknown_identity', 'os_update_failed']);

/* 'warn' | 'ok' | '' - kolor plakietki zdarzenia. Zmiana nadzoru to alarm
   tylko przy UTRACIE; odzyskanie nadzoru jest dobra wiadomoscia. */
export function eventTone(event) {
  if (event.kind === 'supervision_changed') return detailOf(event).supervised ? 'ok' : 'warn';
  return ALARM.has(event.kind) ? 'warn' : '';
}

/* Dzwonek: ktore powiadomienia dnia wyrozniac. Czujka (watchdog), profil DNS
   i alarmy MDM o najwyzszym priorytecie (profil zdjety, utracony nadzor,
   wygasajacy certyfikat APNs). */
export function isCriticalNote(note) {
  if (note.kind === 'watchdog' || note.kind === 'dns_profile') return true;
  return note.kind === 'mdm' && (note.priority ?? 0) >= 4;
}
