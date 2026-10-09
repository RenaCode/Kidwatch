/* Zmyslone dane do ogladania UI lokalnie (`npm run dev`, adres z ?preview).
   Importowane WYLACZNIE z galezi import.meta.env.DEV w utils/api.js - do
   builda produkcyjnego nie trafiaja. Imiona i nazwy sa przykladowe. */
import { ApiError } from './api';

const at = (minAgo) => new Date(Date.now() - minAgo * 60000).toISOString();
const localDay = () => new Date(Date.now() - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 10);

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

/* Os dnia Pulpitu: sesje i ciagi minut aplikacji w czasie lokalnym dzisiaj.
   Minuty komorki licza sie z tych odcinkow tak jak na serwerze. */
const TIMELINE = {
  'iPad Jan': [
    ['07:35', '08:02', [['YouTube', '07:36', 18], ['Safari', '07:55', 4]]],
    ['14:10', '15:24', [['Roblox', '14:11', 38], ['YouTube', '14:50', 12], ['Spotify', '15:03', 6], ['Roblox', '15:10', 13]]],
    ['17:30', '18:41', [['YouTube', '17:31', 22], ['Roblox', '17:55', 30], ['Safari', '18:30', 8]]],
  ],
  'iPad Anna': [
    ['09:05', '09:40', [['Duolingo', '09:06', 15], ['Minecraft', '09:22', 16]]],
    ['16:00', '17:10', [['Minecraft', '16:02', 40], ['Pinterest', '16:45', 9], ['Duolingo', '16:56', 10]]],
  ],
  Telewizor: [
    ['08:15', '09:00', [['YouTube', '08:15', 45]]],
    ['19:00', '20:45', [['Netflix', '19:00', 90], ['YouTube', '20:30', 15]]],
  ],
};

function cellFor(name, day) {
  const t = (hm) => new Date(`${day}T${hm}:00`);
  const plus = (hm, m) => new Date(t(hm).getTime() + m * 60000).toISOString();
  const sessions = [];
  const runs = [];
  (TIMELINE[name] || []).forEach(([a, b, apps]) => {
    sessions.push({ started_at: t(a).toISOString(), ended_at: t(b).toISOString(), minutes: (t(b) - t(a)) / 60000 });
    apps.forEach(([app, at, m]) => runs.push({ app, started_at: t(at).toISOString(), ended_at: plus(at, m), minutes: m }));
  });
  const sum = {};
  runs.forEach((r) => { sum[r.app] = (sum[r.app] || 0) + r.minutes; });
  return {
    name,
    minutes: sessions.reduce((x, y) => x + y.minutes, 0),
    sessions: sessions.length,
    top_apps: Object.entries(sum).sort((x, y) => y[1] - x[1]).slice(0, 3).map(([app, minutes]) => ({ app, minutes })),
    timeline: { sessions, runs },
  };
}

function usage(params) {
  const child = params.get('child');
  const devs = META.devices.filter((d) => (child ? d.child === child : true));
  const day = localDay();
  const rows = devs.map((d) => cellFor(d.name, day));
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

const MDM = {
  available: true,
  health: { apns: { configured: true, days_left: 214, topic: 'com.apple.mgmt.External.podglad' } },
  devices: [
    { udid: 'PODGLAD-0001', name: 'iPad Jan', product: 'iPad13,18', os_version: '27.0',
      supervised: true, last_seen_at: at(4), checked_out_at: null, ddm_synced: true, serial: 'PODGLAD1' },
    { udid: 'PODGLAD-0002', name: 'iPad Anna', product: 'iPad14,1', os_version: '26.4',
      supervised: false, last_seen_at: at(300), checked_out_at: null, ddm_synced: false,
      push_error: '410 Unregistered', push_error_at: at(60), serial: 'PODGLAD2' },
  ],
  os_update: { effective: null, override: null },
  events: [
    { id: 1, at: at(600), udid: 'PODGLAD-0001', kind: 'enrolled', detail: '{}' },
    { id: 2, at: at(500), udid: 'PODGLAD-0001', kind: 'os_update_failed', detail: '{"count": 0}' },
    { id: 3, at: at(400), udid: 'PODGLAD-0002', kind: 'supervision_changed', detail: '{"supervised": false}' },
    { id: 4, at: at(90), udid: 'PODGLAD-0001', kind: 'apps_installed', detail: '{"apps": []}' },
  ],
};

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
    case '/api/mdm': return MDM;
    default: throw new ApiError(404, 'brak danych w podglądzie');
  }
}
