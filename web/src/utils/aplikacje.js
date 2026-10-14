/* Przelacznik aplikacji RenaCode (siatka 3x3 w gornym pasku, jak w Jirze).

   Jedna lista dla calego panelu - nowa aplikacja albo zmiana adresu to
   zmiana tylko tutaj. Wszystkie stoja za ta sama Authelia, wiec przejscie
   w tej samej karcie nie wymaga ponownego logowania. `initial` i `color`
   rysuja kafelek (bez ikon z zewnatrz - CSP panelu i tak by ich nie wpuscil).
   `adminOnly`: pozycja tylko dla wlasciciela - o tym, kto nim jest,
   decyduje serwer (`pokaz_argo` z /api/auth/me), front tylko filtruje. */
export const APPS = [
  { key: 'trader',   name: 'Trader',   url: 'https://trader.renacode.com/',   desc: 'Handel i ryzyko',      initial: 'T', color: '#06b6d4' },
  { key: 'kidwatch', name: 'Kidwatch', url: 'https://kidwatch.renacode.com/', desc: 'Czas ekranowy dzieci', initial: 'K', color: '#7c3aed' },
  { key: 'dietetyk', name: 'Dietetyk', url: 'https://dietetyk.renacode.com/', desc: 'Dieta i zdrowie',      initial: 'D', color: '#10b981' },
  { key: 'argocd',   name: 'Argo CD',  url: 'https://argocd.renacode.com/',   desc: 'Wdrożenia i klaster',  initial: 'A', color: '#ef7b4d', adminOnly: true },
];

/* Ta aplikacja. */
export const CURRENT_APP = 'kidwatch';

/* Tylko https: adres trafia do href, a `javascript:` z pomylki w liscie
   bylby wykonaniem kodu po kliknieciu. */
function safeAppUrl(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' ? u.href : null;
  } catch { return null; }
}

/* Pozycje `adminOnly` tylko przy `pokaz_argo === true` z serwera - brak
   pola, null albo cokolwiek innego niz true (stary backend, podglad) = ukryte. */
export function visibleApps(apps = APPS, user = null) {
  const owner = user?.pokaz_argo === true;
  return apps.filter((a) => !a.adminOnly || owner);
}

/* Pozycje menu: biezaca aplikacja oznaczona (bez linku), pozostale
   z bezpiecznym adresem; wpis z adresem spoza https wypada. */
export function appItems(apps = APPS, current = CURRENT_APP, user = null) {
  return visibleApps(apps, user)
    .map((a) => ({ ...a, current: a.key === current, href: a.key === current ? null : safeAppUrl(a.url) }))
    .filter((a) => a.current || a.href);
}
