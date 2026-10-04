import React, { useState } from 'react';
import { useApi, qs } from '../utils/api';
import { dayPct, hhmm, localToday, minutes } from '../utils/format';

export default function Day({ child }) {
  const [day, setDay] = useState(localToday());
  const res = useApi(`/api/day${qs({ day, child })}`, [], { refreshMs: day === localToday() ? 60000 : 0 });

  return (
    <>
      <div className="filters">
        <input className="input-field" type="date" value={day} max={localToday()}
               onChange={(e) => setDay(e.target.value || localToday())} aria-label="Dzień" />
        {res.error && <span className="badge bad">błąd: {res.error}</span>}
      </div>

      {!res.data ? (
        <div className="empty loading-pulse">Wczytywanie…</div>
      ) : (
        <div className="grid grid-2">
          {res.data.devices.map((d) => {
            const maxApp = Math.max(1, ...d.top_apps.map((a) => a.minutes));
            return (
              <div key={d.name} className="glass-card">
                <div className="card-title">
                  <span>{d.child ?? d.name}</span>
                  <span className="hint">{d.notifications} powiadomień</span>
                </div>

                <div className="grid grid-3" style={{ marginBottom: 18 }}>
                  <div className="stat">
                    <span className="stat-label">Sesje</span>
                    <span className="stat-value">{d.sessions.length}</span>
                  </div>
                  <div className="stat">
                    <span className="stat-label">Czas sesji</span>
                    <span className="stat-value sm">{minutes(d.session_minutes)}</span>
                    <span className="stat-sub">od pierwszego do ostatniego zapytania</span>
                  </div>
                </div>

                <div className="stat-label" style={{ marginBottom: 8 }}>Oś dnia</div>
                <div className="timeline">
                  {d.sessions.map((s) => {
                    const left = dayPct(s.started_at, res.data.day);
                    const right = s.ended_at ? dayPct(s.ended_at, res.data.day) : dayPct(new Date().toISOString(), res.data.day);
                    return (
                      <div key={s.started_at} className={`seg ${s.open ? 'open' : ''}`}
                           style={{ left: `${left}%`, width: `${Math.max(0.3, right - left)}%` }}
                           title={`${hhmm(s.started_at)}–${s.open ? 'teraz' : hhmm(s.ended_at)} · ${minutes(s.minutes)}`} />
                    );
                  })}
                </div>
                <div className="timeline-hours"><span>0</span><span>6</span><span>12</span><span>18</span><span>24</span></div>

                {/* Telewizor: co lecialo - z odtwarzacza, nie z DNS, wiec tu sa
                    prawdziwe tytuly i czasy z dokladnoscia do odczytu (30 s). */}
                {d.kind === 'tv' && d.titles.length > 0 && (
                  <>
                    <div className="stat-label" style={{ margin: '18px 0 10px' }}>Co leciało</div>
                    <table className="table">
                      <tbody>
                        {d.titles.map((t) => (
                          <tr key={t.started_at}>
                            <td className="mono">{hhmm(t.started_at)}</td>
                            <td>{t.title || t.app}{t.channel && <span className="dim"> · {t.channel}</span>}</td>
                            <td className="dim">{t.title ? t.app : ''}</td>
                            <td className="mono">{t.minutes == null ? 'teraz' : minutes(t.minutes)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}

                <div className="stat-label" style={{ margin: '18px 0 10px' }}>
                  {d.kind === 'tv' ? 'Aplikacje (min odtwarzania)' : 'Aplikacje (min z ruchem DNS)'}
                </div>
                {d.top_apps.length === 0 ? (
                  <div className="dim" style={{ fontSize: '0.82rem' }}>Brak rozpoznanych aplikacji.</div>
                ) : d.top_apps.map((a) => (
                  <div key={a.app} className="app-bar">
                    <div>
                      <div style={{ marginBottom: 4 }}>{a.app}</div>
                      <div className="bar-track">
                        <div className="bar-fill" style={{ width: `${(a.minutes / maxApp) * 100}%`, background: 'var(--gradient-ai)' }} />
                      </div>
                    </div>
                    <span className="mono dim" style={{ textAlign: 'right' }}>{a.minutes}</span>
                  </div>
                ))}

                {d.sessions.length > 0 && (
                  <table className="table" style={{ marginTop: 18 }}>
                    <thead><tr><th>Sesja</th><th>Czas</th><th>Aplikacje</th></tr></thead>
                    <tbody>
                      {d.sessions.map((s) => (
                        <tr key={s.started_at}>
                          <td className="mono">{hhmm(s.started_at)}–{s.open ? 'teraz' : hhmm(s.ended_at)}</td>
                          <td className="mono">{minutes(s.minutes)}</td>
                          <td className="dim">{s.apps.map((a) => a.app).join(', ') || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            );
          })}
        </div>
      )}
    </>
  );
}
