/* Wszystkie ekrany: iPady (minuty z DNS) i telewizor (minuty z odtwarzacza)
   na jednej osi dnia. Telewizor oglada cala rodzina - przy wybranym dziecku
   jest osobnym, wyszarzonym pasem "wspolny" i NIE wchodzi do sumy dziecka.
   Ukrycie pasa TV pamietamy w przegladarce (localStorage w try/catch, jak
   wybor dziecka w App). */
import React, { useState } from 'react';
import { useApi, qs } from '../utils/api';
import { dayPct, hhmm, localToday, minutes, pauseUntil } from '../utils/format';
import { loadState } from '../utils/loadState';

const TV_KEY = 'kidwatch.screens.hideTv';
function readHideTv() {
  try { return window.localStorage.getItem(TV_KEY) === '1'; } catch { return false; }
}
function saveHideTv(v) {
  try { window.localStorage.setItem(TV_KEY, v ? '1' : '0'); } catch { /* bez pamieci */ }
}

function segTitle(lane, s) {
  const span = `${hhmm(s.started_at)}–${s.open ? 'teraz' : hhmm(s.ended_at)} · ${minutes(s.minutes)}`;
  const what = lane.kind === 'tv'
    ? s.titles.map((t) => t.title || t.app).filter((v, i, a) => a.indexOf(v) === i).join(', ')
    : s.apps.map((a) => a.app).join(', ');
  return what ? `${span}\n${what}` : span;
}

function Lane({ lane, day }) {
  const label = lane.kind === 'tv'
    ? `📺 ${lane.name}${lane.shared ? ' (wspólny)' : ''}`
    : (lane.child ? `${lane.child} · ${lane.name}` : lane.name);
  return (
    <div className={`lane ${lane.shared ? 'shared' : ''}`}>
      <span className="lane-name" title={label}>{label}</span>
      <div className="timeline">
        {/* Pauza monitoringu TV: zakreskowany pas zamiast pustki - brak
            sesji w tym czasie nie znaczy "nikt nie ogladal". */}
        {(lane.pauses || []).map((p) => {
          const left = dayPct(p.since, day);
          const right = p.until ? dayPct(p.until, day) : 100;
          return (
            <div key={`p-${p.since}`} className="seg paused"
                 style={{ left: `${left}%`, width: `${Math.max(0.3, right - left)}%` }}
                 title={`monitoring wstrzymany od ${hhmm(p.since)} ${pauseUntil(p.until)}`} />
          );
        })}
        {lane.sessions.map((s) => {
          const left = dayPct(s.started_at, day);
          const right = s.ended_at ? dayPct(s.ended_at, day) : dayPct(new Date().toISOString(), day);
          return (
            <div key={s.started_at}
                 className={`seg ${lane.kind === 'tv' ? 'tv' : ''} ${s.open ? 'open' : ''}`}
                 style={{ left: `${left}%`, width: `${Math.max(0.3, right - left)}%` }}
                 title={segTitle(lane, s)} />
          );
        })}
      </div>
      <span className="mono" style={{ textAlign: 'right' }}>{minutes(lane.day_minutes)}</span>
    </div>
  );
}

export default function Screens({ child }) {
  const [day, setDay] = useState(localToday());
  const [hideTv, setHideTvState] = useState(readHideTv);
  const setHideTv = (v) => { setHideTvState(v); saveHideTv(v); };
  const res = useApi(`/api/screens${qs({ day, child })}`, [],
                     { refreshMs: day === localToday() ? 60000 : 0 });
  const data = res.data;
  const hasTv = data?.lanes.some((l) => l.kind === 'tv');
  const lanes = (data?.lanes || []).filter((l) => !(hideTv && l.kind === 'tv'));
  const own = child || 'iPady';

  return (
    <>
      <div className="filters">
        <input className="input-field" type="date" value={day} max={localToday()}
               onChange={(e) => setDay(e.target.value || localToday())} aria-label="Dzień" />
        {hasTv && (
          <button className="btn-ghost" onClick={() => setHideTv(!hideTv)}>
            {hideTv ? 'Pokaż TV' : 'Ukryj TV'}
          </button>
        )}
        {res.error && <span className="badge bad">błąd: {res.error}</span>}
      </div>

      {loadState(res) === 'error' ? (
        // Blad pierwszego odczytu: bez danych nie ma czego ladowac - wieczne
        // „Wczytywanie…" obok plakietki bledu udawalo, ze cos jeszcze przyjdzie.
        <div className="notice">Nie udało się pobrać danych: {res.error}</div>
      ) : loadState(res) === 'loading' ? (
        <div className="empty loading-pulse">Wczytywanie…</div>
      ) : (
        <>
          <div className="grid grid-3" style={{ marginBottom: 16 }}>
            <div className="glass-card stat">
              <span className="stat-label">{own} · dziś</span>
              <span className="stat-value sm">{minutes(data.totals.day.own)}</span>
              <span className="stat-sub">tydzień: {minutes(data.totals.week.own)}</span>
            </div>
            {hasTv && !hideTv && (
              <div className="glass-card stat" style={{ opacity: child ? 0.7 : 1 }}>
                <span className="stat-label">TV{child ? ' (wspólny, nie doliczony)' : ''} · dziś</span>
                <span className="stat-value sm">{minutes(data.totals.day.shared)}</span>
                <span className="stat-sub">tydzień: {minutes(data.totals.week.shared)}</span>
              </div>
            )}
            {!child && hasTv && !hideTv && (
              <div className="glass-card stat">
                <span className="stat-label">Wszystkie ekrany · dziś</span>
                <span className="stat-value sm">{minutes(data.totals.day.own + data.totals.day.shared)}</span>
                <span className="stat-sub">tydzień: {minutes(data.totals.week.own + data.totals.week.shared)}</span>
              </div>
            )}
          </div>

          <div className="glass-card">
            <div className="card-title">
              <span>Oś dnia</span>
              <span className="hint">tydzień {data.week_from.slice(5)}–{data.week_to.slice(5)}</span>
            </div>
            {lanes.length === 0 ? <div className="empty">Brak urządzeń</div> : (
              <>
                {lanes.map((l) => <Lane key={l.name} lane={l} day={data.day} />)}
                <div className="lane-hours">
                  <span />
                  <div className="timeline-hours"><span>0</span><span>6</span><span>12</span><span>18</span><span>24</span></div>
                  <span />
                </div>
              </>
            )}
          </div>

          {/* Dokladny czas z Androida obok szacunku z sesji. "Dokladnie" moze
              byc mniej niz szacunek, gdy aplikacja wciaz jest otwarta - Android
              dolicza ja dopiero po zamknieciu. */}
          {data.tv && !hideTv && (
            <div className="glass-card" style={{ marginTop: 16, opacity: child ? 0.8 : 1 }}>
              <div className="card-title">
                <span>📺 {data.tv.name}: czas aplikacji</span>
                <span className="hint">
                  dziś {minutes(data.tv.exact_day_total)} · tydzień {minutes(data.tv.exact_week_total)} (dokładnie, z TV)
                </span>
              </div>
              {data.tv.exact_day.length === 0 ? (
                <div className="dim" style={{ fontSize: '0.82rem' }}>
                  Brak odczytu usagestats z tego dnia.
                </div>
              ) : (
                <table className="table">
                  <thead><tr><th>Aplikacja</th><th>Dokładnie, z TV</th><th>Szacunek z sesji</th></tr></thead>
                  <tbody>
                    {data.tv.exact_day.map((a) => (
                      <tr key={a.app}>
                        <td>{a.app}</td>
                        <td className="mono">{a.minutes == null ? '—' : minutes(a.minutes)}</td>
                        <td className="mono dim">{a.estimate_minutes == null ? '—' : `~${minutes(a.estimate_minutes)}`}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {lanes.some((l) => l.pauses?.length) && (
            <div className="notice" style={{ marginTop: 12 }}>
              ⏸️ W tym dniu monitoring TV wstrzymany (zakreskowany pas) — czas TV z tego okresu
              nie jest liczony ani do sumy dnia, ani tygodnia.
            </div>
          )}

          <div className="hint dim" style={{ fontSize: '0.74rem', marginTop: 12 }}>
            iPady: minuty od pierwszego do ostatniego zapytania DNS w sesji (dolne
            oszacowanie). TV: czas odtwarzania z odczytu co 30 s, a „dokładnie” —
            czas aplikacji na pierwszym planie według samego Androida (odczyt co 15 min).
          </div>
        </>
      )}
    </>
  );
}
