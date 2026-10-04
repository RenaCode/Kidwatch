export const KINDS = {
  session_start:    { label: 'Start sesji',      icon: '▶️', badge: 'ok' },
  app:              { label: 'Aplikacja',        icon: '📱', badge: 'info' },
  session_end:      { label: 'Koniec sesji',     icon: '⏹️', badge: '' },
  daily:            { label: 'Podsumowanie',     icon: '📊', badge: 'ai' },
  throttled:        { label: 'Zbiorcze',         icon: '📦', badge: '' },
  watchdog:         { label: 'Czujka',           icon: '🚨', badge: 'bad' },
  device_launch:    { label: 'Uruchomienie',     icon: '🚀', badge: 'info' },
  device_screen:    { label: 'Ekran',            icon: '🔓', badge: '' },
  device_inventory: { label: 'Nowa aplikacja',   icon: '🆕', badge: 'warn' },
  tv_start:         { label: 'TV: start',        icon: '📺', badge: 'info' },
  tv_end:           { label: 'TV: koniec',       icon: '📺', badge: '' },
  dns_profile:      { label: 'Profil DNS',       icon: '🛡️', badge: 'bad' },
  night:            { label: 'Noc',              icon: '🌙', badge: 'warn' },
  weekly:           { label: 'Raport tygodnia',  icon: '📈', badge: 'ai' },
  game:             { label: 'Czas gry',         icon: '🎮', badge: 'info' },
  tv_pause:         { label: 'TV: pauza',        icon: '⏸️', badge: 'warn' },
};

export const kindOf = (k) => KINDS[k] || { label: k, icon: '•', badge: '' };

export function localToday() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

/* Polozenie chwili na osi doby `day` w procentach. Mianownik to dlugosc TEJ
   doby liczona z dat, nie 24 h: 25.10 ma 25 h, a 29.03 23 h — przy stalym
   864e5 sesje po zmianie czasu przesuwaly sie o godzine, a sesja o 23:30
   w dniu z 25 h przyklejala sie do konca osi. */
export function dayPct(iso, day) {
  const start = new Date(`${day}T00:00:00`);
  const end = new Date(start);
  end.setDate(end.getDate() + 1);
  const pct = ((new Date(iso) - start) / (end - start)) * 100;
  return Math.min(100, Math.max(0, pct));
}

export const hhmm = (iso) => (iso
  ? new Date(iso).toLocaleTimeString('pl-PL', { hour: '2-digit', minute: '2-digit' })
  : '—');

export const dayLabel = (iso) => new Date(iso).toLocaleDateString('pl-PL',
  { weekday: 'short', day: 'numeric', month: 'short' });

export function ago(iso) {
  if (!iso) return 'nigdy';
  const min = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (min < 1) return 'przed chwilą';
  if (min < 60) return `${min} min temu`;
  const h = Math.floor(min / 60);
  if (h < 24) return `${h} h temu`;
  return `${Math.floor(h / 24)} d temu`;
}

export const minutes = (m) => (m >= 60 ? `${Math.floor(m / 60)} h ${m % 60} min` : `${m} min`);

/* Pauza monitoringu TV. Termin z <input type="datetime-local"> to czas
   lokalny bez strefy ("2026-10-10T18:00") - serwer czyta go w strefie
   z konfiguracji, tak samo jak CLI `tv-pauza --do`. */
const pad = (n) => String(n).padStart(2, '0');

export function localInputValue(d) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

/* Domyslny koniec pauzy: za `days` dni o pelnej godzinie - wyjazd na
   tydzien to typowy przypadek, a minuty w terminie nikomu nie sa potrzebne. */
export function defaultPauseUntil(now = new Date(), days = 7) {
  const d = new Date(now);
  d.setDate(d.getDate() + days);
  d.setMinutes(0, 0, 0);
  return localInputValue(d);
}

export const pauseUntil = (iso) => (iso
  ? `do ${new Date(iso).toLocaleString('pl-PL', { day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' })}`
  : 'do odwołania');
