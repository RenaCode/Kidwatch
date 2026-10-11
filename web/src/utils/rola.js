/* Rola konta panelu z /api/auth/me (`rola`, z bazy panelu - nie z SSO).

   `podglad` tylko oglada: front chowa przyciski, ktorych i tak nie wolno mu
   uzyc (serwer odpowiada na nie 403). Brak pola (starszy serwer) = wlasciciel,
   jak przed wprowadzeniem rol - o uprawnieniach i tak rozstrzyga serwer. */
export const VIEWER = 'podglad';

export function isViewer(user) {
  return user?.rola === VIEWER;
}

// Czynnosci tylko dla wlasciciela. Pauza TV celowo poza lista: to czynnosc
// dla doroslego, ktory sam oglada telewizor (widac, kto ja wlaczyl).
const OWNER_ONLY = new Set(['mdm', 'game', 'whatsapp', 'tvApp']);

export function can(user, action) {
  return !(isViewer(user) && OWNER_ONLY.has(action));
}

/* Sekcje nawigacji widoczne dla roli: MDM to ekran zarzadzania. */
export function sectionsFor(sections, user) {
  return sections.filter((s) => s.key !== 'mdm' || can(user, 'mdm'));
}
