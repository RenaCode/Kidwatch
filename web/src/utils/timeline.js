/* Os dnia na Pulpicie: czysta logika paska (bez Reacta), zeby dalo sie ja
   testowac. Czas to "godzina zegarowa" wzgledem polnocy dnia `day`
   (15:40 -> 15.67, 0:30 nastepnego dnia -> 24.5). Liczymy z zegara, nie
   z milisekund od polnocy: w dniu zmiany czasu podpis 15:00 ma stac pod
   kreska 15, a nie godzine obok. Zegar to strefa serwera (rodziny), nie
   przegladarki - patrz clockHours. */

export const TOP_APPS = 3;
export const OTHER = 'inne';
const EPS = 1e-6;

/* Data i godzina wprost ze znacznika serwera ("2026-10-10T15:40:00+02:00"):
   serwer podaje je w strefie rodziny (cfg.tz), wiec to jest zegar, wedlug
   ktorego przypisal sesje do dnia. Zegar przegladarki przesuwal odcinki
   o roznice stref, gdy rodzic byl w innej strefie (audyt 2026-10-10, N-1). */
const ISO_WALL = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2})(?:\.\d+)?)?(?:Z|[+-]\d{2}:?\d{2})?$/;

function wallClock(iso) {
  const m = ISO_WALL.exec(iso);
  if (m) return m.slice(1).map((x) => Number(x || 0));
  const d = new Date(iso);
  return [d.getFullYear(), d.getMonth() + 1, d.getDate(), d.getHours(), d.getMinutes(), d.getSeconds()];
}

export function clockHours(iso, day) {
  const [y, mo, d, h, mi, s] = wallClock(iso);
  const [dy, dm, dd] = day.split('-').map(Number);
  const dayShift = Math.round((Date.UTC(y, mo - 1, d) - Date.UTC(dy, dm - 1, dd)) / 864e5);
  return dayShift * 24 + h + mi / 60 + s / 3600;
}

/* Odcinek w godzinach zegarowych. Przez cofniecie zegara (ostatnia niedziela
   pazdziernika, 3:00 -> 2:00) koniec bywa PRZED poczatkiem - wtedy szerokosc
   z minut, nie ujemna. Godzina 2-3 wystepuje dwa razy, wiec jej odcinki
   moga na siebie zachodzic; to swiadomy koszt osi „zegarowej". */
function span(startIso, endIso, minutes, day) {
  const start = clockHours(startIso, day);
  const end = clockHours(endIso, day);
  return { start, end: end >= start ? end : start + minutes / 60 };
}

/* "15:40"; godziny po polnocy zawijaja sie (24.5 -> "0:30"). */
export function fmtClock(h) {
  const total = Math.round(h * 60);
  const hh = Math.floor(total / 60) % 24;
  return `${hh}:${String(total % 60).padStart(2, '0')}`;
}

/* Wiersz Pulpitu (dziecko = kilka urzadzen) -> odcinki w godzinach. */
export function rowTimeline(cells, day) {
  const sessions = [];
  const runs = [];
  // `id` jako klucz Reacta: dziecko z dwoma iPadami moze miec te sama
  // aplikacje o tej samej minucie na obu (audyt 2026-10-10, N-3).
  cells.forEach((c, ci) => {
    (c.timeline?.sessions || []).forEach((s, i) => sessions.push({
      id: `s${ci}-${i}`, ...span(s.started_at, s.ended_at, s.minutes, day), minutes: s.minutes,
    }));
    (c.timeline?.runs || []).forEach((r, i) => runs.push({
      id: `r${ci}-${i}`, app: r.app, ...span(r.started_at, r.ended_at, r.minutes, day), minutes: r.minutes,
    }));
  });
  sessions.sort((a, b) => a.start - b.start);
  runs.sort((a, b) => a.start - b.start);
  const totals = appTotals(runs);
  const top = totals.slice(0, TOP_APPS).map((t) => t.app);
  const other = totals.slice(TOP_APPS).reduce((a, t) => a + t.minutes, 0);
  return { sessions, runs, totals, top, other };
}

/* Minuty aplikacji = suma minut jej ciagow; kolejnosc jak top_apps w API
   (malejaco, przy remisie alfabetycznie). */
export function appTotals(runs) {
  const sum = {};
  runs.forEach((r) => { sum[r.app] = (sum[r.app] || 0) + r.minutes; });
  return Object.entries(sum)
    .map(([app, minutes]) => ({ app, minutes }))
    .sort((a, b) => b.minutes - a.minutes || (a.app < b.app ? -1 : a.app > b.app ? 1 : 0));
}

/* Kolor = pozycja w legendzie wiersza (0..2), reszta to "inne". */
export const colorKey = (top, app) => {
  const i = top.indexOf(app);
  return i < 0 ? OTHER : i;
};

/* Wspolny zakres osi dla calej rodziny: od pelnej godziny przed pierwsza
   aktywnoscia do pelnej godziny po ostatniej, co najmniej `minSpan` h
   (krotka sesja nie rozciaga sie na caly pasek). Bez danych - pora dnia,
   w ktorej dzieci zwykle siedza przy ekranie. */
export function axisRange(timelines, { minSpan = 6, fallback = [8, 20] } = {}) {
  let lo = Infinity;
  let hi = -Infinity;
  timelines.forEach((t) => t.sessions.concat(t.runs).forEach((s) => {
    lo = Math.min(lo, s.start);
    hi = Math.max(hi, s.end);
  }));
  if (!Number.isFinite(lo)) return { start: fallback[0], end: fallback[1] };
  let start = Math.max(0, Math.floor(lo));
  let end = Math.max(start + 1, Math.ceil(hi));
  if (end - start < minSpan) {
    const missing = minSpan - (end - start);
    const back = Math.min(start, Math.ceil(missing / 2));
    start -= back;
    end += missing - back;
    if (end > 24 && hi <= 24) {
      start = Math.max(0, start - (end - 24));
      end = 24;
    }
  }
  return { start, end };
}

export const hourToPct = (h, { start, end }) => Math.min(100, Math.max(0, ((h - start) / (end - start)) * 100));
export const pctToHour = (pct, { start, end }) => start + (Math.min(100, Math.max(0, pct)) / 100) * (end - start);

/* Kreski co godzine (co 2 h przy dlugiej osi), podpisy rzadziej - tak, zeby
   na telefonie miescilo sie najwyzej `maxLabels` podpisow. */
export function axisTicks({ start, end }, maxLabels = 7) {
  const span = end - start;
  const tickStep = span > 16 ? 2 : 1;
  const labelStep = [1, 2, 3, 4, 6].find((s) => span / s <= maxLabels - 1) || 6;
  const ticks = [];
  const labels = [];
  for (let h = Math.ceil(start); h <= end; h += 1) {
    if (h > start && h < end && h % tickStep === 0) ticks.push(h);
    if (h % labelStep === 0) labels.push(h);
  }
  return { ticks, labels };
}

/* Co bylo o godzinie `h`: aplikacje z ciagow obejmujacych te chwile, a gdy
   zadnego nie ma - najblizszy ciag w promieniu `tol` h (palec trafia
   w minute na pasku szerokim na 300 px z dokladnoscia kilku minut).
   `prefer` (podswietlona aplikacja) idzie na poczatek listy. */
export function whatAt(tl, h, tol = 0, prefer = null) {
  let hits = tl.runs.filter((r) => r.start <= h + EPS && h + EPS < r.end);
  if (hits.length === 0 && tol > 0) {
    let best = Infinity;
    tl.runs.forEach((r) => {
      const d = h < r.start ? r.start - h : h - r.end;
      // Minuty jako ulamki godzin: remis porownujemy z marginesem.
      if (d > tol + EPS) return;
      if (d < best - EPS) { best = d; hits = [r]; } else if (Math.abs(d - best) <= EPS) hits.push(r);
    });
  }
  const rank = (app) => (app === prefer ? -1 : tl.totals.findIndex((t) => t.app === app));
  const apps = [...new Set(hits.map((r) => r.app))].sort((a, b) => rank(a) - rank(b));
  const inSession = tl.sessions.some((s) => s.start <= h && h <= s.end);
  return { apps, active: apps.length > 0 || inSession };
}

/* Dotkniecie obok krotkiego odcinka: wskaznik przeskakuje na odcinek, zeby
   dymek (liczony bez tolerancji) mowil to samo, co podswietlenie. */
export function snapTo(tl, h, app) {
  let best = h;
  let dist = Infinity;
  tl.runs.filter((r) => r.app === app).forEach((r) => {
    const inside = Math.min(Math.max(h, r.start), r.end - 0.5 / 60);
    if (Math.abs(inside - h) < dist) { dist = Math.abs(inside - h); best = inside; }
  });
  return best;
}

export function describeAt(tl, h, tol = 0, prefer = null) {
  const { apps, active } = whatAt(tl, h, tol, prefer);
  const what = apps.length ? apps.join(', ') : active ? 'aplikacja nierozpoznana' : 'bez aktywności';
  return `${fmtClock(h)} · ${what}`;
}
