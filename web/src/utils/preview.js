/* Zmyslone dane do ogladania UI lokalnie (`npm run dev`, adres z ?preview).
   Importowane WYLACZNIE z galezi import.meta.env.DEV w utils/api.js - do
   builda produkcyjnego nie trafiaja. Imiona i nazwy sa przykladowe. */
import { ApiError } from './api';

const at = (minAgo) => new Date(Date.now() - minAgo * 60000).toISOString();
const today = () => new Date().toISOString().slice(0, 10);

const META = {
  children: ['Jan', 'Anna'],
  devices: [
    { name: 'iPad Jan', child: 'Jan', kind: 'ipad' },
    { name: 'iPad Anna', child: 'Anna', kind: 'ipad' },
    { name: 'Telewizor', child: null, kind: 'tv' },
  ],
};

const game = (mode) => ({
  mode, observed: mode, bonus_until: null, source: 'panel', confirmed_at: at(3),
  error: null, retrying: false, shared_with: [], default_bonus_minutes: 30, request: null,
});

const DEVICES = [
  {
    name: 'iPad Jan', child: 'Jan', kind: 'ipad', reads_device: true,
    presence: { home: true, since: at(240), essid: 'Dom' }, now_playing: null,
    session: { started_at: at(42), last_activity_at: at(1) },
    last_notification: { ts: at(40), title: 'Jan: start sesji' },
    last_device_read: at(2), game: game('blocked'),
    today: { minutes: 185, sessions: 6, top_app: { app: 'YouTube', minutes: 64 } },
  },
  {
    name: 'iPad Anna', child: 'Anna', kind: 'ipad', reads_device: false,
    presence: { home: false, since: at(90), essid: null }, now_playing: null, session: null,
    last_notification: { ts: at(130), title: 'Anna: koniec sesji' },
    last_device_read: null, game: game('allowed'),
    today: { minutes: 105, sessions: 4, top_app: { app: 'Minecraft', minutes: 38 } },
  },
  {
    name: 'Telewizor', child: null, kind: 'tv', reads_device: true, presence: null,
    now_playing: { app: 'Netflix', title: 'Film animowany', channel: null, since: at(25) },
    session: { started_at: at(25), last_activity_at: at(0) },
    last_notification: { ts: at(25), title: 'TV: start' },
    last_device_read: at(1), game: null,
    today: { minutes: 150, sessions: 2, top_app: { app: 'Netflix', minutes: 90 } },
  },
];

function usage(params) {
  const child = params.get('child');
  const devs = META.devices.filter((d) => (child ? d.child === child : true));
  const cell = {
    'iPad Jan': { minutes: 185, sessions: 6, top_apps: [{ app: 'YouTube', minutes: 64 }, { app: 'Roblox', minutes: 40 }, { app: 'Safari', minutes: 12 }] },
    'iPad Anna': { minutes: 105, sessions: 4, top_apps: [{ app: 'Minecraft', minutes: 38 }, { app: 'Duolingo', minutes: 15 }] },
    Telewizor: { minutes: 150, sessions: 2, top_apps: [{ app: 'Netflix', minutes: 90 }, { app: 'YouTube', minutes: 30 }] },
  };
  const day = today();
  const rows = devs.map((d) => ({ name: d.name, ...cell[d.name] }));
  return {
    from: day, until: day, devices: devs,
    days: [{ day, total_minutes: rows.reduce((a, r) => a + r.minutes, 0), devices: rows }],
  };
}

const NOTES = [
  { kind: 'session_start', device: 'iPad Jan', app: null, title: 'Jan: start sesji', text: 'iPad aktywny od chwili.' },
  { kind: 'tv_start', device: 'Telewizor', app: 'Netflix', title: 'TV: start', text: 'Leci: Film animowany (Netflix).' },
  { kind: 'app', device: 'iPad Jan', app: 'Roblox', title: 'Jan: Roblox', text: 'Nowa aplikacja w sesji.' },
  { kind: 'session_end', device: 'iPad Anna', app: null, title: 'Anna: koniec sesji', text: 'Sesja trwała 48 min.' },
  { kind: 'game', device: 'iPad Jan', app: null, title: 'Czas gry: zablokowane', text: 'Gry zablokowane z panelu.' },
];

function notifications(params) {
  const child = params.get('child');
  const items = NOTES.map((n, i) => ({
    ...n, id: 100 - i, cursor: `${at(20 + i * 35)}|${100 - i}`, ts: at(20 + i * 35),
    child: META.devices.find((d) => d.name === n.device)?.child ?? null,
    priority: 0, channels: { whatsapp: true }, delivered: true, data: null,
  })).filter((n) => !child || n.child === child);
  return { items, has_more: false };
}

export function previewResponse(path, method) {
  const url = new URL(path, 'http://podglad');
  const p = url.searchParams;
  if (method !== 'GET') return {};
  switch (url.pathname) {
    case '/api/meta': return META;
    case '/api/devices': return DEVICES.filter((d) => !p.get('child') || d.child === p.get('child'));
    case '/api/usage': return usage(p);
    case '/api/notifications': return notifications(p);
    case '/api/tv/pause': return { available: true, name: 'Telewizor', max_days: 30, active: null, request: null };
    case '/api/tv/aplikacja': return { available: false };
    default: throw new ApiError(404, 'brak danych w podglądzie');
  }
}
