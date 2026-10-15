/* Zaproszenia do domu (src/kidwatch/zaproszenia.py, etap E4) - logika bez Reacta.

   Link: https://<panel>/zaproszenie#<token>. Token jest we FRAGMENCIE adresu:
   przegladarka nie wysyla go w zadaniu, wiec nie trafia do logow Traefika
   ani do naglowka Referer. Front czyta go z location.hash, zaraz usuwa
   z paska adresu i odsyla tylko w CIELE zadania POST. Serwer trzyma wylacznie
   SHA-256 tokenu i sprawdza wszystko ponownie - tu tylko to, co front musi
   wiedziec przed wyslaniem. */

export const INVITE_PATH = '/zaproszenie';
// token_urlsafe(32) = 43 znaki base64url; zapas na przyszle dlugosci.
const TOKEN_RE = /^[A-Za-z0-9_-]{20,128}$/;
export const LOGIN_RE = /^[a-z0-9._-]{1,64}$/;

export function isInvitePath(pathname) {
  return pathname === INVITE_PATH || pathname === `${INVITE_PATH}/`;
}

/* '#abc...' -> 'abc...' albo null (pusty, uciety albo z obcymi znakami). */
export function tokenFromHash(hash) {
  const t = (hash || '').replace(/^#/, '').trim();
  return TOKEN_RE.test(t) ? t : null;
}

export function inviteLink(origin, token) {
  return `${String(origin).replace(/\/+$/, '')}${INVITE_PATH}#${token}`;
}

/* Ekran nowego konta (bez SSO): komunikat albo null. */
export function newAccountProblem({ login, haslo, haslo2 }, minLen = 12) {
  if (!LOGIN_RE.test((login || '').trim())) return 'Login: małe litery a-z, cyfry, „.”, „_”, „-”.';
  if ((haslo || '').length < minLen) return `Hasło musi mieć co najmniej ${minLen} znaków.`;
  if (haslo !== haslo2) return 'Hasła się różnią.';
  return null;
}

export const WAZNOSCI = [
  { h: 24, label: '24 godziny' },
  { h: 72, label: '3 dni (domyślnie)' },
  { h: 168, label: '7 dni (najdłużej)' },
];

const STAN = {
  oczekuje: 'czeka', przyjete: 'przyjęte', odwolane: 'odwołane', wygasle: 'wygasło',
  zablokowane: 'zablokowane po próbach',
};
export const statusLabel = (stan) => STAN[stan] || stan;
export const canRevoke = (z) => z?.stan === 'oczekuje' || z?.stan === 'zablokowane';
