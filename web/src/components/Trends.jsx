/* Trendy z agregatow dziennych (daily_rollup) - przezywaja retencje surowych
   danych. Tydzien do tygodnia i miesiac do miesiaca: biezacy okres jest
   niepelny, wiec obok sumy stoi srednia dzienna, i to ja porownujemy. */
import React from 'react';
import { useApi, qs } from '../utils/api';
import { LineChart, fmtMinutes } from '../charts';

const COLORS = ['var(--color-primary)', 'var(--color-blue)', 'var(--color-secondary)',
                'var(--color-orange)', '#c084fc', '#f472b6'];

const dm = (iso) => `${+iso.slice(8, 10)}.${iso.slice(5, 7)}`;

function Delta({ cur, prev }) {
  if (!prev) return <span className="dim">—</span>;
  const pctv = Math.round(((cur - prev) / prev) * 100);
  if (pctv === 0) return <span className="dim">0%</span>;
  return <span className={pctv > 0 ? 'delta-up' : 'delta-down'}>{pctv > 0 ? '+' : ''}{pctv}%</span>;
}

function Compare({ title, block }) {
  const c = block.current, p = block.previous;
  return (
    <div className="glass-card">
      <div className="card-title">
        <span>{title}</span>
        <span className="hint">{dm(c.from)}–{dm(c.to)} vs {dm(p.from)}–{dm(p.to)}</span>
      </div>
      <div className="table-scroll">
        <table className="table">
          <thead>
            <tr><th /><th>Suma</th><th>Średnio / dzień</th><th>Zmiana</th><th>Noc</th><th>Top aplikacje</th></tr>
          </thead>
          <tbody>
            {block.series.map((s) => (
              <tr key={s.key} style={{ opacity: s.shared ? 0.6 : 1 }}>
                <td>{s.label}</td>
                <td className="mono">
                  {fmtMinutes(s.current.minutes)}
                  <div className="dim">było {fmtMinutes(s.previous.minutes)}</div>
                </td>
                <td className="mono">
                  {fmtMinutes(s.current.avg_daily)}
                  <div className="dim">było {fmtMinutes(s.previous.avg_daily)}</div>
                </td>
                <td className="mono"><Delta cur={s.current.avg_daily} prev={s.previous.avg_daily} /></td>
                <td className="mono">
                  {s.shared ? '—' : fmtMinutes(s.current.night_minutes)}
                  {!s.shared && <div className="dim">było {fmtMinutes(s.previous.night_minutes)}</div>}
                </td>
                <td className="dim">
                  {s.current.top_apps.map((a) => `${a.app} ${fmtMinutes(a.minutes)}`).join(', ') || '—'}
                  {s.current.tv_exact_minutes != null && (
                    <div>dokładnie z TV: {fmtMinutes(s.current.tv_exact_minutes)}</div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default function Trends({ child }) {
  const res = useApi(`/api/trends${qs({ child })}`, [], { refreshMs: 300000 });
  const data = res.data;
  if (res.error && !data) return <div className="notice">Nie udało się pobrać trendów: {res.error}</div>;
  if (!data) return <div className="empty loading-pulse">Wczytywanie…</div>;

  const series = data.series.map((s, i) => ({
    key: s.key, label: s.label, dashed: s.shared,
    color: s.shared ? 'var(--neutral)' : COLORS[i % COLORS.length],
  }));
  const points = data.weeks.map((w) => ({
    key: w.week, short: dm(w.from), label: `tydzień od ${dm(w.from)}`,
    values: w.values, partial: w.partial,
  }));
  const csv = `/api/export.csv${qs({ child })}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {!data.has_data && (
        <div className="notice info">
          Agregaty dzienne dopiero się zbierają — pierwsze przeliczenie obejmuje całą
          historię z bazy, potem co 15 minut.
        </div>
      )}
      <Compare title="Tydzień do tygodnia" block={data.compare.week} />
      <Compare title="Miesiąc do miesiąca" block={data.compare.month} />
      <div className="glass-card">
        <div className="card-title">
          <span>Ostatnie 12 tygodni</span>
          <a className="btn-ghost" href={csv} download>Eksport CSV (30 dni)</a>
        </div>
        <LineChart points={points} series={series} />
        <div className="hint dim" style={{ fontSize: '0.74rem', marginTop: 12 }}>
          Minuty sesji z agregatów dziennych. Telewizor (przerywana linia) jest wspólny —
          nie wchodzi do sumy dziecka. Pusty punkt = tydzień w toku.
          Pełny zakres CSV: /api/export.csv?from=RRRR-MM-DD&amp;to=RRRR-MM-DD.
        </div>
      </div>
    </div>
  );
}
