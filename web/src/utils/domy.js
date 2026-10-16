/* Domy (renacode-infra: docs/projekty/kidwatch/architektura-domy.md §4.1): kazda trasa danych domu ma dom
   w SCIEZCE - /api/domy/<id>/... Front zna liste domow konta z /api/auth/me
   (`domy`: id, nazwa, rola, administracja, uprawnienia W TYM domu).

   Prefiks dokleja JEDNO miejsce (api.js przez domPath), wiec komponenty
   dalej wolaja '/api/day'. Zmiana domu montuje panel od nowa (key), wiec
   dane jednego domu nie zostaja pod naglowkiem drugiego. */

// Trasy z zakresem `dom` (panel.py: POST_TRASY, GET_TRASY). Zgodnosc
// z serwerem pilnuje test_domy_panel.py; klucz z '/' na koncu to prefiks.
export const TRASY_DOMU = [
  'meta', 'screens', 'trends', 'devices', 'notifications', 'day', 'usage', 'export.csv',
  'tv/pause', 'tv/resume', 'tv/aplikacja', 'tv/aplikacja/instaluj', 'tv/aplikacja/paruj',
  'game', 'mdm', 'mdm/devices/', 'mdm/refresh', 'mdm/command', 'mdm/enroll', 'mdm/os-update',
  'konto/powiadomienia', 'konta', 'konta/dodaj', 'konta/usun', 'konta/rola',
  'konta/uprawnienia', 'konta/powiadomienia', 'konta/kanaly', 'konta/tryb', 'dziennik',
  'integracje', 'integracje/stan', 'integracje/zapisz', 'integracje/usun-sekret', 'komendy',
  'zaproszenia', 'zaproszenia/utworz', 'zaproszenia/odwolaj',
];

function isHomeRoute(rest) {
  return TRASY_DOMU.some((t) => (t.endsWith('/') ? rest.startsWith(t) && rest.length > t.length : rest === t));
}

/* '/api/day?x=1' -> '/api/domy/2/day?x=1' dla trasy domu; reszta bez zmian.
   Bez domu (null) - stara sciezka, alias jedynego domu konta po stronie
   serwera (przy wielu domach serwer odpowie 409, nie zgadnie). */
export function domPath(path, domId) {
  if (domId == null || !path.startsWith('/api/') || path.startsWith('/api/domy/')) return path;
  const q = path.indexOf('?');
  const base = q < 0 ? path : path.slice(0, q);
  const rest = base.slice('/api/'.length);
  if (!isHomeRoute(rest)) return path;
  return `/api/domy/${encodeURIComponent(domId)}/${rest}${q < 0 ? '' : path.slice(q)}`;
}

/* Dom do pokazania: zapamietany, jesli konto dalej go widzi, inaczej pierwszy.
   Brak domow = null (konto bez domu, np. administracyjne bez grupy). */
export function pickHome(domy, savedId) {
  if (!Array.isArray(domy) || domy.length === 0) return null;
  const saved = domy.find((d) => String(d.id) === String(savedId));
  return (saved || domy[0]).id;
}

export const showSwitcher = (domy) => Array.isArray(domy) && domy.length > 1;

const ROLE_LABEL = {
  'wlasciciel-domu': 'właściciel domu', wlasciciel: 'właściciel', zarzadca: 'zarządca',
  podglad: 'podgląd',
};
export const roleLabel = (rola) => ROLE_LABEL[rola] || rola;

/* Konto w kontekście domu: uprawnienia i rola TEGO domu - dzieki temu
   can(user, ...) i isViewer(user) w komponentach chowaja przyciski per dom. */
export function userInHome(user, domId) {
  const dom = (user?.domy || []).find((d) => d.id === domId);
  if (!dom) return { ...user, uprawnienia: [], rola: null, dom: null };
  return {
    ...user,
    rola: dom.rola === 'wlasciciel-domu' ? 'wlasciciel' : dom.rola,
    uprawnienia: dom.uprawnienia,
    dom,
  };
}

export function homeLabel(dom) {
  return dom.administracja ? `${dom.nazwa} · administracja` : dom.nazwa;
}

/* Ekran „Brak domu”. Konto administracyjne logujace sie haslem (bez
   Authelii) widzi domy dopiero z wlaczonym 2FA panelu - a bez domu nie ma
   Ustawien, wiec wlaczenie 2FA musi byc na tym ekranie. Kazde konto bez
   domu moze je wlaczyc (konto.wlasne); bez klucza na serwerze - komunikat. */
export function noHomeOffers2fa(user) {
  return !!user && !user.sso && !user.totp_enabled && user.totp_available !== false;
}

export function noHomeMessage(user) {
  if (user && !user.sso && !user.totp_enabled) {
    return user.totp_available === false
      ? 'To konto nie należy do żadnego domu. Konto administracyjne logujące się hasłem '
        + 'potrzebuje 2FA, a serwer nie ma klucza PANEL_TOTP_KEY — poproś operatora.'
      : 'To konto nie należy do żadnego domu. Konto administracyjne: włącz niżej '
        + 'weryfikację dwuetapową — rola administratora działa dopiero z 2FA.';
  }
  return 'To konto nie należy do żadnego domu. Poproś osobę zarządzającą domem o dodanie.';
}
