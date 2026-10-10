/* Pulpit: dzisiejszy czas przed ekranem per dziecko, karty urzadzen
   i szybka kontrola telewizora. Wszystko z istniejacych endpointow -
   /api/usage?days=1&timeline=1 (minuty, sesje, odcinki sesji i aplikacji),
   /api/devices (stan na zywo) i /api/tv/pause. Pasek to os dnia: odcinki
   w miejscu, w ktorym byly, ze wspolnym zakresem godzin dla calej rodziny;
   suma dnia stoi w naglowku wiersza. */
import React, { useMemo } from 'react';
import { useApi, qs } from '../utils/api';
import { minutes } from '../utils/format';
import Devices from './Devices';
import { TvPauseControl } from './TvPause';
import Icon from './Icons';
import DayBar from './DayBar';
import { axisRange, axisTicks, rowTimeline } from '../utils/timeline';

// Wiersz na dziecko (suma jego urzadzen) i osobno na kazde urzadzenie bez
// dziecka (telewizor) - jak serie w zakladce Uzycie.
function rowsFromUsage(usage, liveDevices) {
  const today = usage?.days?.at(-1);
  if (!today) return [];
  const byName = Object.fromEntries(today.devices.map((d) => [d.name, d]));
  const live = new Set((liveDevices || []).filter((d) => d.session).map((d) => d.name));
  const rows = [];
  const add = (key, label, kind, devs) => {
    const cells = devs.map((d) => byName[d.name]).filter(Boolean);
    rows.push({
      key, label, kind,
      minutes: cells.reduce((a, c) => a + c.minutes, 0),
      sessions: cells.reduce((a, c) => a + c.sessions, 0),
      tl: rowTimeline(cells, today.day),
      live: devs.some((d) => live.has(d.name)),
    });
  };
  const seen = new Set();
  usage.devices.forEach((d) => {
    if (d.child == null) add(d.name, d.name, d.kind, [d]);
    else if (!seen.has(d.child)) {
      seen.add(d.child);
      add(`c-${d.child}`, d.child, 'child', usage.devices.filter((x) => x.child === d.child));
    }
  });
  return rows;
}

const sessionsLabel = (n) => (n === 1 ? 'sesja' : (n % 10 >= 2 && n % 10 <= 4 && (n % 100 < 12 || n % 100 > 14)) ? 'sesje' : 'sesji');

function ScreenTime({ child, devices, notes, onOpenSection }) {
  const res = useApi(`/api/usage${qs({ days: 1, child, timeline: 1 })}`, [], { refreshMs: 60000 });
  // Przeliczane tylko przy nowych danych - nie przy kazdym odswiezeniu stanu
  // urzadzen. Wspolny zakres osi: ta sama godzina stoi w tym samym miejscu
  // paska u kazdego dziecka.
  const rows = useMemo(() => rowsFromUsage(res.data, devices), [res.data, devices]);
  const range = useMemo(() => axisRange(rows.map((r) => r.tl)), [rows]);
  const axis = useMemo(() => axisTicks(range), [range]);

  return (
    <section className="glass-card screen-time" aria-labelledby="st-title">
      <div className="section-head">
        <h2 id="st-title">Dzisiejszy czas przed ekranem</h2>
        {notes != null && (
          <button className="pill-link" onClick={() => onOpenSection('notifications')}>
            <Icon name="bell" size={15} />
            {notes.count === 0 ? 'Brak powiadomień dziś'
              : `${notes.more ? `${notes.count}+` : notes.count} ${notes.count === 1 ? 'powiadomienie' : 'powiadomień'} dziś`}
          </button>
        )}
      </div>

      {res.error && <span className="badge bad">błąd: {res.error}</span>}
      {!res.data ? (
        <div className="empty loading-pulse">Wczytywanie…</div>
      ) : rows.length === 0 ? (
        <div className="empty">Brak urządzeń dla tego wyboru.</div>
      ) : (
        <ul className="st-rows">
          {rows.map((r) => (
            <li key={r.key} className={`st-row ${r.live ? 'live' : ''} ${r.kind === 'tv' ? 'shared' : ''}`}>
              <span className={`st-avatar ${r.kind === 'child' ? '' : 'device'}`} aria-hidden="true">
                {r.kind === 'child' ? r.label.slice(0, 1).toUpperCase() : <Icon name="tv" size={18} />}
              </span>
              <span className="st-name">
                <span className="st-label">{r.label}</span>
                {r.kind === 'tv' && <span className="st-sub">wspólny</span>}
              </span>
              <DayBar label={r.label} tl={r.tl} range={range} axis={axis} total={r.minutes} />
              <span className="st-total" title={`${minutes(r.minutes)} dziś, ${r.sessions} ${sessionsLabel(r.sessions)}`}>
                <strong className={r.minutes > 0 ? '' : 'zero'}>{minutes(r.minutes)}</strong>
                <span className="dim">{r.sessions} {sessionsLabel(r.sessions)}</span>
              </span>
              <span className={`st-state ${r.live ? 'on' : ''}`}
                    title={r.live ? 'teraz aktywne' : 'teraz bezczynne'}>
                <span className="sr-only">{r.live ? 'teraz aktywne' : 'teraz bezczynne'}</span>
              </span>
            </li>
          ))}
        </ul>
      )}
      <p className="hint dim footnote">
        Pasek to oś dnia: kolorowe odcinki to aplikacje (kolory jak w legendzie), jasne tło - sesja
        bez rozpoznanej aplikacji. Przeciągnij po pasku, żeby zobaczyć, co było o danej godzinie;
        dotknij odcinka lub nazwy, żeby podświetlić aplikację i jej minuty. Minuty iPadów to dolne
        oszacowanie z zapytań DNS, telewizora - czas odtwarzania.
      </p>
    </section>
  );
}

// Szybka kontrola telewizora: co leci i pauza monitoringu (ta sama akcja
// co w Ustawieniach). Telewizora nie da sie stad wylaczyc ani zablokowac -
// Kidwatch tylko patrzy, wiec takich przyciskow nie ma.
function TvQuick({ pause, tvDevice, onChanged, onOpenSettings }) {
  const paused = !!pause.active;
  const np = tvDevice?.now_playing;
  let status = null;
  if (paused) status = 'monitoring wstrzymany';
  else if (np) status = `leci: ${np.title || np.app}`;
  else if (tvDevice) status = tvDevice.session ? 'włączony' : 'nic nie gra';
  return (
    <div className="glass-card tv-quick">
      <div className="tvq-head">
        <span className="tvq-icon"><Icon name="tv" size={22} /></span>
        <div>
          <h3 id="tvq-title" className="dev-name">{pause.name}</h3>
          {status && <span className="dim tvq-status">{status}</span>}
        </div>
      </div>
      <div className={`tv-frame ${paused ? 'paused' : ''}`} aria-hidden="true">
        <span className="tv-frame-label">TV</span>
      </div>
      <TvPauseControl hero pause={pause} onChanged={onChanged} />
      <button className="btn-ghost tvq-settings" onClick={onOpenSettings}>
        <Icon name="settings" size={16} /> Ustawienia telewizora
      </button>
    </div>
  );
}

export default function Dashboard({
  child, devices, onDevicesChanged, tvPause, onTvPauseChanged, notes, onOpenSection, onOpenSettings,
}) {
  const tvDevice = (devices || []).find((d) => d.kind === 'tv');
  const showTv = tvPause?.available;
  return (
    <div className="dashboard">
      <ScreenTime child={child} devices={devices} notes={notes} onOpenSection={onOpenSection} />
      <div className={`dash-lower ${showTv ? '' : 'solo'}`}>
        <section aria-labelledby="dev-title">
          <div className="section-head">
            <h2 id="dev-title">Urządzenia</h2>
            <button className="pill-link" onClick={() => onOpenSection('screens')}>Wszystkie ekrany</button>
          </div>
          <Devices devices={devices} onChanged={onDevicesChanged} />
        </section>
        {showTv && (
          <section aria-labelledby="quick-title" className="dash-quick">
            <div className="section-head"><h2 id="quick-title">Szybka kontrola</h2></div>
            <TvQuick pause={tvPause} tvDevice={tvDevice} onChanged={onTvPauseChanged}
                     onOpenSettings={onOpenSettings} />
          </section>
        )}
      </div>
    </div>
  );
}
