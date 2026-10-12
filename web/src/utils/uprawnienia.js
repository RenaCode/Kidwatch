/* Uprawnienia konta z /api/auth/me, liczone na serwerze z roli i pojedynczych
   odstepstw konta W DOMU (src/kidwatch/uprawnienia.py, baza panelu - nie
   naglowek SSO). Panel podaje tu konto w kontekscie wybranego domu
   (utils/domy.js: userInHome), wiec `uprawnienia` to uprawnienia w tym domu. Front chowa przyciski wedlug uprawnien, nie
   nazwy roli; serwer i tak odmawia (403) niezaleznie od frontu.

   Brak pola (serwer sprzed modelu uprawnien) = brak uprawnien: lepiej schowac
   przycisk wlascicielowi do przeladowania niz pokazac go kontu podgladu. */
export const VIEWER = 'podglad';

// Ta sama lista co uprawnienia.UPRAWNIENIA - zgodnosc pilnuje test_uprawnienia.py.
export const ALL = [
  'konto.wlasne', 'podglad.historia', 'mdm.podglad', 'mdm.komendy',
  'czas_gry.zmiana', 'tv.pauza', 'tv.aplikacja', 'whatsapp.konfiguracja',
  'konta.zarzadzanie', 'powiadomienia.techniczne', 'dom.urzadzenia', 'dom.integracje',
  'dom.zaproszenia', 'whatsapp.komendy',
];

export function isViewer(user) {
  return user?.rola === VIEWER;
}

export function can(user, permission) {
  return Array.isArray(user?.uprawnienia) && user.uprawnienia.includes(permission);
}

/* Sekcje nawigacji: MDM tylko z prawem podgladu MDM. */
export function sectionsFor(sections, user) {
  return sections.filter((s) => s.key !== 'mdm' || can(user, 'mdm.podglad'));
}
