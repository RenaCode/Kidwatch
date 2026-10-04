/* Uzycie dzien po dniu na wszystkich urzadzeniach wybranego dziecka (albo
   calej rodziny). Osobna zakladka, nie sekcja "Dnia": Dzien to przeglad
   jednej doby z wlasnym wyborem daty, a tu zakres to 7-30 dni. */
import React, { useState } from 'react';
import { useApi, qs } from '../utils/api';
import { StackedBars, deviceColor, fmtMinutes } from '../charts';

const RANGES = [7, 14, 30];

const label = (iso) => new Date(`${iso}T12:00:00`).toLocaleDateString('pl-PL',
  { weekday: 'short', day: 'numeric', month: 'short' });
const short = (iso) => `${+iso.slice(8, 10)}.${iso.slice(5, 7)}`;

// Nazwa serii: dziecko, a gdy ma kilka urzadzen - z nazwa urzadzenia.
// Urzadzenie bez dziecka (telewizor) - sama nazwa.
function seriesLabel(dev, all) {
  if (dev.child == null) return dev.name;
  const siblings = all.filter((d) => d.child === dev.child).length;
  return siblings > 1 ? `${dev.child} · ${dev.name}` : dev.child;
}

export default function Usage({ child, meta }) {
  const [days, setDays] = useState(14);
  const res = useApi(`/api/usage${qs({ days, child })}`, [], { refreshMs: 60000 });
  const all = meta?.devices || res.data?.devices || [];

  const series = (res.data?.devices || []).map((d) => ({
    key: d.name, label: seriesLabel(d, all), color: deviceColor(all, d.name),
  }));
  const rows = (res.data?.days || []).map((d) => ({
    key: d.day,
    label: label(d.day),
    short: short(d.day),
    total: d.total_minutes,
    values: Object.fromEntries(d.devices.map((x) => [x.name, x.minutes])),
    detail: d.devices,
  }));
  const sum = rows.reduce((a, r) => a + r.total, 0);
  const active = rows.filter((r) => r.total > 0).length;

  const detail = (day, hovered) => (
    <div className="row-list no-fade" style={{ maxHeight: 'none' }}>
      <div className="stat-label">{hovered ? day.label : `Ostatni dzień · ${day.label}`}</div>
      {day.detail.map((d) => {
        const s = series.find((x) => x.key === d.name);
        return (
          <div key={d.name} className="row-head" style={{ fontSize: '0.84rem', gap: 10 }}>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}>
              <span style={{ width: 10, height: 10, borderRadius: 3, background: s?.color }} />
              {s?.label}
            </span>
            <span className="dim" style={{ flex: 1, textAlign: 'right' }}>
              {d.top_apps.map((a) => a.app).join(', ')}
            </span>
            <span className="mono">
              {d.minutes ? `${fmtMinutes(d.minutes)} · ${d.sessions} ses.` : '—'}
            </span>
          </div>
        );
      })}
    </div>
  );

  return (
    <div className="glass-card">
      <div className="card-title">
        <span>Użycie dzień po dniu</span>
        <span className="hint">
          {res.data ? `razem ${fmtMinutes(sum)} · aktywne dni ${active}/${rows.length}` : ''}
        </span>
      </div>

      <div className="filters">
        <div className="engine-tabs" role="tablist" aria-label="Zakres">
          {RANGES.map((n) => (
            <button key={n} role="tab" aria-selected={days === n}
                    className={`engine-tab ${days === n ? 'active' : ''}`}
                    style={{ padding: '6px 14px' }} onClick={() => setDays(n)}>
              {n} dni
            </button>
          ))}
        </div>
        {res.error && <span className="badge bad">błąd: {res.error}</span>}
      </div>

      {!res.data ? (
        <div className="empty loading-pulse">Wczytywanie…</div>
      ) : (
        <StackedBars days={rows} series={series} renderDetail={detail} />
      )}

      <div className="hint dim" style={{ fontSize: '0.74rem', marginTop: 12 }}>
        Minuty to dolne oszacowanie z zapytań DNS: czas od pierwszego do ostatniego
        zapytania w sesji, przypisany do dnia, w którym sesja się zaczęła. Gra offline
        albo odpowiedzi z pamięci podręcznej iPada nie zostawiają śladu. Telewizor
        liczy czas odtwarzania wprost z odtwarzacza (odczyt co 30 s).
      </div>
    </div>
  );
}
