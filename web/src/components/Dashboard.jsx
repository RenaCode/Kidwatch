/* Pulpit: dzisiejszy czas przed ekranem per dziecko, karty urzadzen
   i szybka kontrola telewizora. Wszystko z istniejacych endpointow -
   /api/usage?days=1 (minuty, sesje, najczestsze aplikacje), /api/devices
   (stan na zywo) i /api/tv/pause. Celu dziennego w danych nie ma, wiec
   nie ma znacznika celu: pasek mierzy sie wspolna skala godzin. */
import React from 'react';
import { useApi, qs } from '../utils/api';
import { minutes } from '../utils/format';
import Devices from './Devices';
import { TvPauseControl } from './TvPause';
import Icon from './Icons';

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
    const apps = {};
    cells.forEach((c) => c.top_apps.forEach((a) => { apps[a.app] = (apps[a.app] || 0) + a.minutes; }));
    rows.push({
      key, label, kind,
      minutes: cells.reduce((a, c) => a + c.minutes, 0),
      sessions: cells.reduce((a, c) => a + c.sessions, 0),
      apps: Object.entries(apps).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([app]) => app),
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
  const res = useApi(`/api/usage${qs({ days: 1, child })}`, [], { refreshMs: 60000 });
  const rows = rowsFromUsage(res.data, devices);
  // Wspolna skala w pelnych godzinach (min. 2 h): ten sam centymetr paska
  // znaczy to samo u kazdego dziecka. Kreski na torze = kolejne godziny.
  const hours = Math.max(2, Math.ceil(Math.max(0, ...rows.map((r) => r.minutes)) / 60));
  const step = hours > 12 ? 2 : 1;
  const ticks = [];
  for (let h = step; h < hours; h += step) ticks.push(h);

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
          {rows.map((r) => {
            const pct = Math.min(100, (r.minutes / (hours * 60)) * 100);
            return (
              <li key={r.key} className={`st-row ${r.live ? 'live' : ''} ${r.kind === 'tv' ? 'shared' : ''}`}>
                <span className={`st-avatar ${r.kind === 'child' ? '' : 'device'}`} aria-hidden="true">
                  {r.kind === 'child' ? r.label.slice(0, 1).toUpperCase() : <Icon name="tv" size={18} />}
                </span>
                <span className="st-name">
                  <span className="st-label">{r.label}</span>
                  {r.kind === 'tv' && <span className="st-sub">wspólny</span>}
                </span>
                <div className="st-bar">
                  <div className="st-track" role="img"
                       aria-label={`${r.label}: ${minutes(r.minutes)} dziś, skala do ${hours} h`}>
                    {ticks.map((h) => (
                      <span key={h} className="st-tick" style={{ left: `${(h / hours) * 100}%` }} />
                    ))}
                    {r.minutes > 0 && <div className="st-fill" style={{ width: `${pct}%` }} />}
                    <span className={`st-value ${pct < 22 ? 'outside' : ''}`}
                          style={{ left: `${pct}%` }}>
                      {minutes(r.minutes)}
                    </span>
                  </div>
                  {r.apps.length > 0 && (
                    <div className="st-apps" aria-label="Najczęstsze aplikacje dziś">
                      {r.apps.map((a) => <span key={a} className="st-app">{a}</span>)}
                    </div>
                  )}
                </div>
                <span className="st-sessions" title={`${r.sessions} ${sessionsLabel(r.sessions)} dziś`}>
                  <strong>{r.sessions}</strong>
                  <span className="dim">{sessionsLabel(r.sessions)}</span>
                </span>
                <span className={`st-state ${r.live ? 'on' : ''}`}
                      title={r.live ? 'teraz aktywne' : 'teraz bezczynne'}>
                  <span className="sr-only">{r.live ? 'teraz aktywne' : 'teraz bezczynne'}</span>
                </span>
              </li>
            );
          })}
        </ul>
      )}
      <p className="hint dim footnote">
        Skala do {hours} h, kreski co {step === 1 ? 'godzinę' : '2 godziny'}. Minuty iPadów to dolne
        oszacowanie z zapytań DNS, telewizora - czas odtwarzania. Pod paskiem najczęstsze dziś aplikacje.
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
