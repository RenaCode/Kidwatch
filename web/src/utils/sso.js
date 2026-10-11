/* SSO (Authelia przed panelem, src/kidwatch/panel_sso.py).

   Serwer podaje `logout_url` (adres portalu `/logout?rd=...`) tylko wtedy,
   gdy zadanie przyszlo przez Authelie. Wtedy samo skasowanie sesji panelu nie
   wystarcza: nastepne zadanie przynioslo by `Remote-User` i zalogowalo od nowa,
   wiec "Wyloguj" musi przejsc przez portal. Bez SSO (port-forward, droga
   awaryjna) - zwykle wylogowanie do ekranu logowania. */

/* Tylko https: adres idzie do window.location, a `javascript:` z odpowiedzi
   bylby wykonaniem kodu. */
export function safeLogoutUrl(url) {
  if (typeof url !== 'string' || !url) return null;
  try {
    const u = new URL(url);
    return u.protocol === 'https:' ? u.href : null;
  } catch { return null; }
}

/* Dokad po "Wyloguj": adres z odpowiedzi POST /api/auth/logout, a gdy ten
   sie nie udal (siec, wygasly CSRF) - z /api/auth/me. null = zostajemy
   w panelu na ekranie logowania. */
export function signOutTarget(response, user) {
  return safeLogoutUrl(response?.logout_url) || safeLogoutUrl(user?.logout_url);
}

export function signOutLabel(user) {
  return safeLogoutUrl(user?.logout_url) ? 'Wyloguj (SSO)' : 'Wyloguj';
}

/* Odmowa SSO z /api/auth/me (403 brak konta albo grupy, 400 zly naglowek):
   ekran logowania nic tu nie da - haslo panelu nie zmieni tozsamosci
   z Authelii. Pokazujemy komunikat i wylogowanie z portalu. */
export function ssoDenial(err) {
  const url = safeLogoutUrl(err?.data?.logout_url);
  if (!url || (err.status !== 403 && err.status !== 400)) return null;
  return { message: err.message, logoutUrl: url };
}

/* Przeladowanie po wygasnieciu sesji Authelii: fetch dostaje przekierowanie
   na portal (inna domena) i konczy sie bledem sieci. Przeladowanie strony
   prowadzi przez logowanie Authelii. Nie czesciej niz co `minGapMs` - przy
   prawdziwym braku sieci odswiezanie w tle przeladowywaloby w kolko. */
export const RELOAD_GAP_MS = 30000;
export function reloadAllowed(now, last, minGapMs = RELOAD_GAP_MS) {
  return !last || now - last >= minGapMs;
}
