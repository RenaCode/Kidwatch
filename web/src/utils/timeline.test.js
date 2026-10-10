/* Os dnia na Pulpicie: `npm test` (node --test, TZ=Europe/Warsaw). */
import test from 'node:test';
import assert from 'node:assert/strict';
import {
  appTotals, axisRange, axisTicks, clockHours, colorKey, describeAt, fmtClock,
  hourToPct, pctToHour, rowTimeline, snapTo, whatAt,
} from './timeline.js';

const DAY = '2026-10-02';
const iso = (hm, day = DAY) => `${day}T${hm}:00+02:00`;
const run = (app, a, b, minutes) => ({ app, started_at: iso(a), ended_at: iso(b), minutes });

// Ksztalt komorki z /api/usage?days=1&timeline=1: dwa iPady jednego dziecka.
const CELLS = [
  {
    minutes: 47,
    timeline: {
      sessions: [{ started_at: iso('15:00'), ended_at: iso('15:47'), minutes: 47 }],
      runs: [run('Roblox', '15:00', '15:03', 3), run('YouTube', '15:05', '15:06', 1),
        run('Asphalt', '15:10', '15:30', 20)],
    },
  },
  {
    minutes: 30,
    timeline: {
      sessions: [{ started_at: iso('18:00'), ended_at: iso('18:30'), minutes: 30 }],
      runs: [run('YouTube', '18:01', '18:05', 4), run('Safari', '18:10', '18:12', 2),
        run('Asphalt', '18:20', '18:30', 10)],
    },
  },
];

test('godzina zegarowa: minuty, polnoc nastepnego dnia, zmiana czasu', () => {
  assert.equal(clockHours(iso('15:40'), DAY), 15 + 40 / 60);
  assert.equal(clockHours('2026-10-03T00:30:00+02:00', DAY), 24.5);
  // 25.10: 04:00 po cofnieciu zegara to podpis 4, nie 5 h od polnocy.
  assert.equal(clockHours('2026-10-25T04:00:00+01:00', '2026-10-25'), 4);
  assert.equal(fmtClock(15 + 40 / 60), '15:40');
  assert.equal(fmtClock(24.5), '0:30');
  assert.equal(fmtClock(9.9999), '10:00');
});

test('suma aplikacji w legendzie = suma jej odcinkow, z obu iPadow', () => {
  const tl = rowTimeline(CELLS, DAY);
  assert.deepEqual(tl.totals, [
    { app: 'Asphalt', minutes: 30 }, { app: 'YouTube', minutes: 5 },
    { app: 'Roblox', minutes: 3 }, { app: 'Safari', minutes: 2 },
  ]);
  assert.deepEqual(tl.top, ['Asphalt', 'YouTube', 'Roblox']);
  assert.equal(tl.other, 2);
  assert.equal(colorKey(tl.top, 'YouTube'), 1);
  assert.equal(colorKey(tl.top, 'Safari'), 'inne');
  // Odcinki sesji pokrywaja sume dnia z pigulki.
  assert.equal(tl.sessions.reduce((a, s) => a + s.minutes, 0), 77);
  // Remis: alfabetycznie, jak top_apps w API.
  assert.deepEqual(appTotals([{ app: 'b', minutes: 2 }, { app: 'a', minutes: 2 }]).map((t) => t.app), ['a', 'b']);
});

test('zakres osi: od pelnej godziny przed pierwsza do pelnej po ostatniej', () => {
  const tl = rowTimeline(CELLS, DAY);
  assert.deepEqual(axisRange([tl]), { start: 14, end: 20 }); // 15-19 -> 6 h, po rowno z obu stron
  const late = rowTimeline([{ timeline: { sessions: [
    { started_at: iso('07:20'), ended_at: iso('08:00'), minutes: 40 },
    { started_at: iso('20:10'), ended_at: iso('21:05'), minutes: 55 }], runs: [] } }], DAY);
  assert.deepEqual(axisRange([late]), { start: 7, end: 22 });
  // Krotka sesja wieczorem: zakres nie wychodzi za polnoc.
  const evening = rowTimeline([{ timeline: { sessions: [
    { started_at: iso('22:10'), ended_at: iso('22:30'), minutes: 20 }], runs: [] } }], DAY);
  assert.deepEqual(axisRange([evening]), { start: 18, end: 24 });
  // Sesja przez polnoc wydluza os za 24.
  const night = rowTimeline([{ timeline: { sessions: [
    { started_at: iso('20:00'), ended_at: '2026-10-03T00:40:00+02:00', minutes: 280 }], runs: [] } }], DAY);
  assert.deepEqual(axisRange([night]), { start: 19, end: 25 });
  assert.deepEqual(axisRange([{ sessions: [], runs: [] }]), { start: 8, end: 20 });
});

test('czas <-> pozycja na pasku', () => {
  const r = { start: 6, end: 24 };
  assert.equal(hourToPct(15, r), 50);
  assert.equal(pctToHour(50, r), 15);
  assert.equal(hourToPct(3, r), 0);
  assert.equal(pctToHour(140, r), 24);
  for (const h of [6, 7.25, 13.5, 23.9]) assert.ok(Math.abs(pctToHour(hourToPct(h, r), r) - h) < 1e-9);
});

test('kreski co godzine, podpisow najwyzej 7', () => {
  assert.deepEqual(axisTicks({ start: 15, end: 21 }), { ticks: [16, 17, 18, 19, 20], labels: [15, 16, 17, 18, 19, 20, 21] });
  const long = axisTicks({ start: 6, end: 24 });
  assert.deepEqual(long.labels, [6, 9, 12, 15, 18, 21, 24]);
  assert.deepEqual(long.ticks, [8, 10, 12, 14, 16, 18, 20, 22]);
});

test('co bylo pod wskaznikiem: aplikacja, nierozpoznane, nic', () => {
  const tl = rowTimeline(CELLS, DAY);
  assert.deepEqual(whatAt(tl, 15 + 15 / 60), { apps: ['Asphalt'], active: true });
  assert.equal(describeAt(tl, 15 + 15 / 60), '15:15 · Asphalt');
  // W sesji, ale minuta bez rozpoznanej aplikacji.
  assert.equal(describeAt(tl, 15 + 40 / 60), '15:40 · aplikacja nierozpoznana');
  assert.equal(describeAt(tl, 16.5), '16:30 · bez aktywności');
  // Koniec ciagu jest otwarty: 15:03 to juz nie Roblox.
  assert.deepEqual(whatAt(tl, 15.05).apps, []);
  // Tolerancja palca: 15:04 lapie najblizszy ciag (oba w odleglosci minuty).
  assert.deepEqual(whatAt(tl, 15 + 4 / 60, 2 / 60).apps, ['YouTube', 'Roblox']);
  assert.deepEqual(whatAt(tl, 15 + 4 / 60, 2 / 60, 'Roblox').apps, ['Roblox', 'YouTube']);
});

test('dotkniecie obok odcinka przeskakuje na niego', () => {
  const tl = rowTimeline(CELLS, DAY);
  // 15:04 obok YouTube 15:05-15:06 -> 15:05, juz w odcinku.
  const h = snapTo(tl, 15 + 4 / 60, 'YouTube');
  assert.equal(h, 15 + 5 / 60);
  assert.deepEqual(whatAt(tl, h).apps, ['YouTube']);
  // Za koncem: ostatnie pol minuty odcinka, nie jego otwarty koniec.
  assert.deepEqual(whatAt(tl, snapTo(tl, 15.2, 'Roblox')).apps, ['Roblox']);
});
