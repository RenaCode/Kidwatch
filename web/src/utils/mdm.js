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

/* "40 min" / "3 h" / "2 d" - jak dlugo od chwili `iso`. */
export function duration(iso, now = Date.now()) {
  const min = Math.max(0, Math.round((now - new Date(iso).getTime()) / 60000));
  if (min < 60) return `${min} min`;
  const h = Math.floor(min / 60);
  return h < 48 ? `${h} h` : `${Math.floor(h / 24)} d`;
}

const RECONCILE_STALE_MIN = 30;
const STUCK_HOURS = 24;

/* Plakietki pracy serwera z /api/health: uzgadnianie i pushe do APNs.
   Pole nieobecne (starszy serwer MDM) = brak plakietki, nie alarm. Progi
   jak w czujce (mdm.py): uzgadnianie 30 min. */
export function serverBadges(health, now = Date.now()) {
  const out = [];
  if (health && 'last_reconcile_ok_at' in health) {
    const ok = health.last_reconcile_ok_at;
    const stale = !ok || now - new Date(ok).getTime() > RECONCILE_STALE_MIN * 60000;
    if (health.last_reconcile_error || stale) {
      out.push({
        key: 'reconcile', tone: 'warn', title: health.last_reconcile_error || '',
        text: ok ? `uzgadnianie: problem (ostatnie udane ${duration(ok, now)} temu)` : 'uzgadnianie: jeszcze żadne udane',
      });
    } else {
      out.push({ key: 'reconcile', tone: 'ok', title: ok, text: `uzgadnianie ${duration(ok, now)} temu` });
    }
  }
  if (health?.push_failing_since) {
    out.push({
      key: 'push', tone: 'warn', title: health.last_push_error || '',
      text: `pushe APNs nie wychodzą od ${duration(health.push_failing_since, now)} (${health.push_failures || '?'}× z rzędu)`,
    });
  } else if (health?.last_push_ok_at) {
    out.push({ key: 'push', tone: 'ok', title: health.last_push_ok_at, text: `ostatni push ${duration(health.last_push_ok_at, now)} temu` });
  }
  return out;
}

/* Kolejka komend iPada: ile czeka i od kiedy najstarsza. Wisi > doby =
   ostrzezenie (czujka wysyla wtedy alarm). null = nic nie czeka. */
export function pendingBadge(d, now = Date.now()) {
  const old = d.oldest_pending;
  if (!d.pending_commands || !old) return null;
  const hours = (now - new Date(old.created_at).getTime()) / 3600000;
  return {
    tone: hours >= STUCK_HOURS ? 'warn' : 'info',
    title: `${old.request_type} (${old.status}) od ${old.created_at}`,
    text: `w kolejce: ${d.pending_commands} · najstarsza ${duration(old.created_at, now)}`,
  };
}
