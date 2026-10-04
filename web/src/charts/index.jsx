/* Wykresy SVG bez zewnetrznych bibliotek - ten sam sposob co
   Trader-AI/web/src/charts/index.jsx (useWidth, osie z tokenow CSS). Kolory
   serii ida z tokenow, wiec zmiana motywu przenosi sie na wykres. */
import React, { useCallback, useRef, useState } from 'react';

const PAD = { t: 12, r: 12, b: 26, l: 46 };

/* Mierzy realna szerokosc kontenera i uzywa jej jako szerokosci viewBox -
   powod opisany w Traderze: SVG o stalej szerokosci skaluje sie do wysokosci
   i zajmuje pol karty. Callback ref, bo komunikat "brak danych" renderuje sie
   przed kontenerem. */
function useWidth(fallback = 800) {
  const [w, setW] = useState(fallback);
  const observer = useRef(null);

  const ref = useCallback((node) => {
    if (observer.current) {
      observer.current.disconnect();
      observer.current = null;
    }
    if (!node) return;
    const measure = () => {
      const next = node.clientWidth;
      if (next > 0) setW(next);
    };
    measure();
    if (typeof ResizeObserver !== 'undefined') {
      observer.current = new ResizeObserver(measure);
      observer.current.observe(node);
    }
  }, []);

  return [ref, w];
}

/* Podzialka osi w minutach, ale w krokach czytelnych dla czlowieka:
   15/30 min, 1/2/3 h. niceTicks z Tradera dawal 0, 50, 100, 150 - poprawne
   liczbowo, ale "100 min" nikt nie czyta jako "1 h 40 min". */
function minuteTicks(max) {
  const steps = [5, 10, 15, 30, 60, 120, 180, 240, 360, 480];
  const step = steps.find((s) => max / s <= 4) || 720;
  const top = Math.max(step, Math.ceil(max / step) * step);
  const out = [];
  for (let v = 0; v <= top; v += step) out.push(v);
  return out;
}

export const fmtMinutes = (m) => {
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60), r = m % 60;
  return r ? `${h} h ${r} min` : `${h} h`;
};

/* Kolor serii po pozycji urzadzenia w PELNEJ liscie z /api/meta, nie
   w aktualnie widocznej - inaczej iPad Zosi zmienialby kolor po przelaczeniu
   na "Wszyscy". Urzadzenie bez dziecka (telewizor) jest zawsze szare: to nie
   jest "jeszcze jedno dziecko" i nie powinno tak wygladac. */
const PALETTE = ['var(--color-primary)', 'var(--color-blue)', 'var(--color-secondary)',
                 'var(--color-orange)', '#c084fc', '#f472b6'];

export function deviceColor(allDevices, name) {
  const dev = allDevices.find((d) => d.name === name);
  if (dev && dev.child == null) return 'var(--neutral)';
  const kids = allDevices.filter((d) => d.child != null);
  const i = Math.max(0, kids.findIndex((d) => d.name === name));
  return PALETTE[i % PALETTE.length];
}

const axisMinutes = (m) => (m < 60 ? `${m}m` : `${+(m / 60).toFixed(1)}h`);

/* ------------------------------------------------------------ StackedBars
   Slupki dzien po dniu, w kazdym segment na serie (urzadzenie). Stack, nie
   grupy: segmenty sumuja sie do calosci dziecka/rodziny, a to jest pytanie,
   ktore rodzic zadaje najpierw ("ile dzis razem?").

   days:   [{ key, label, total, values: { [serie]: liczba }, detail }]
   series: [{ key, label, color }]
   renderDetail(day) - tresc pod wykresem dla najechanego dnia. */
export function StackedBars({ days, series, height = 220, renderDetail }) {
  const [hover, setHover] = useState(null);
  const [ref, w] = useWidth();
  const h = height;

  if (!days?.length || !series?.length) return <div className="empty">Brak danych do wykresu</div>;

  const max = Math.max(1, ...days.map((d) => d.total));
  const ticks = minuteTicks(max);
  const top = ticks[ticks.length - 1];
  const iw = w - PAD.l - PAD.r, ih = h - PAD.t - PAD.b;
  const slot = iw / days.length;
  const bw = Math.max(3, Math.min(34, slot * 0.68));
  // Co ktora etykiete dnia pokazac, zeby sie nie zlewaly (~34 px na etykiete).
  const every = Math.max(1, Math.ceil(34 / slot));
  const y = (v) => PAD.t + ih - (v / top) * ih;

  const onMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = ((e.clientX - rect.left) / rect.width) * w;
    const idx = Math.floor((x - PAD.l) / slot);
    setHover(idx >= 0 && idx < days.length ? idx : null);
  };

  const active = hover ?? days.length - 1;

  return (
    <div className="chart-wrap" ref={ref}>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} role="img"
           aria-label="Minuty użycia dzień po dniu"
           onMouseMove={onMove} onMouseLeave={() => setHover(null)} onClick={onMove}>
        {ticks.map((tv) => (
          <g key={tv}>
            <line x1={PAD.l} y1={y(tv)} x2={w - PAD.r} y2={y(tv)}
                  stroke="rgba(255,255,255,0.055)" />
            <text x={PAD.l - 8} y={y(tv) + 3.5} textAnchor="end" fill="var(--text-dim)"
                  fontSize="10" fontFamily="var(--font-mono)">{axisMinutes(tv)}</text>
          </g>
        ))}

        {days.map((d, i) => {
          const cx = PAD.l + slot * i + slot / 2;
          let acc = 0;
          return (
            <g key={d.key} opacity={hover === null || hover === i ? 1 : 0.45}>
              {/* Przezroczysty prostokat na cala wysokosc - zeby dymek
                  pojawial sie tez nad pustym dniem, a nie tylko nad slupkiem. */}
              <rect x={cx - slot / 2} y={PAD.t} width={slot} height={ih} fill="transparent">
                <title>{`${d.label}: ${fmtMinutes(d.total)}`}</title>
              </rect>
              {series.map((s) => {
                const v = d.values[s.key] || 0;
                if (!v) return null;
                const y1 = y(acc + v), y0 = y(acc);
                acc += v;
                return (
                  <rect key={s.key} x={cx - bw / 2} y={y1} width={bw}
                        height={Math.max(1, y0 - y1)} rx="2" fill={s.color}>
                    <title>{`${d.label} · ${s.label}: ${fmtMinutes(v)}`}</title>
                  </rect>
                );
              })}
              {i % every === (days.length - 1) % every && (
                <text x={cx} y={h - 8} textAnchor="middle" fill="var(--text-dim)"
                      fontSize="10" fontFamily="var(--font-mono)">{d.short}</text>
              )}
            </g>
          );
        })}
        <line x1={PAD.l} y1={y(0)} x2={w - PAD.r} y2={y(0)} stroke="rgba(255,255,255,0.22)" />
      </svg>

      <div className="chart-legend">
        {series.map((s) => (
          <span key={s.key} className="key">
            <span className="swatch" style={{ background: s.color, height: 10 }} />{s.label}
          </span>
        ))}
      </div>

      {renderDetail && days[active] && (
        <div style={{ marginTop: 12 }}>{renderDetail(days[active], hover !== null)}</div>
      )}
    </div>
  );
}

/* ------------------------------------------------------------- LineChart
   Linie tydzien po tygodniu (trendy). Seria `dashed` to urzadzenie wspolne
   (telewizor) - kreska przerywana, zeby nie mylila sie z dzieckiem.

   points: [{ key, short, label, values: { [serie]: liczba }, partial }]
   series: [{ key, label, color, dashed }] */
export function LineChart({ points, series, height = 220 }) {
  const [hover, setHover] = useState(null);
  const [ref, w] = useWidth();
  const h = height;

  if (!points?.length || !series?.length) return <div className="empty">Brak danych do wykresu</div>;

  const max = Math.max(1, ...points.flatMap((p) => series.map((s) => p.values[s.key] || 0)));
  const ticks = minuteTicks(max);
  const top = ticks[ticks.length - 1];
  const iw = w - PAD.l - PAD.r, ih = h - PAD.t - PAD.b;
  const step = points.length > 1 ? iw / (points.length - 1) : 0;
  const x = (i) => PAD.l + (points.length > 1 ? step * i : iw / 2);
  const y = (v) => PAD.t + ih - (v / top) * ih;
  const every = Math.max(1, Math.ceil(44 / Math.max(1, step)));

  const onMove = (e) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const px = ((e.clientX - rect.left) / rect.width) * w;
    const idx = Math.round((px - PAD.l) / Math.max(1, step));
    setHover(idx >= 0 && idx < points.length ? idx : null);
  };
  const active = hover ?? points.length - 1;

  return (
    <div className="chart-wrap" ref={ref}>
      <svg viewBox={`0 0 ${w} ${h}`} width="100%" height={h} role="img"
           aria-label="Minuty tydzień po tygodniu"
           onMouseMove={onMove} onMouseLeave={() => setHover(null)} onClick={onMove}>
        {ticks.map((tv) => (
          <g key={tv}>
            <line x1={PAD.l} y1={y(tv)} x2={w - PAD.r} y2={y(tv)} stroke="rgba(255,255,255,0.055)" />
            <text x={PAD.l - 8} y={y(tv) + 3.5} textAnchor="end" fill="var(--text-dim)"
                  fontSize="10" fontFamily="var(--font-mono)">{axisMinutes(tv)}</text>
          </g>
        ))}
        <line x1={x(active)} y1={PAD.t} x2={x(active)} y2={PAD.t + ih}
              stroke="rgba(255,255,255,0.12)" strokeDasharray="2 3" />
        {series.map((s) => (
          <g key={s.key}>
            <polyline fill="none" stroke={s.color} strokeWidth="2" strokeLinejoin="round"
                      strokeDasharray={s.dashed ? '5 4' : undefined}
                      points={points.map((p, i) => `${x(i)},${y(p.values[s.key] || 0)}`).join(' ')} />
            {points.map((p, i) => (
              <circle key={p.key} cx={x(i)} cy={y(p.values[s.key] || 0)} r={i === active ? 4 : 2.5}
                      fill={p.partial ? 'var(--bg-inset)' : s.color} stroke={s.color} strokeWidth="1.5">
                <title>{`${p.label} · ${s.label}: ${fmtMinutes(p.values[s.key] || 0)}`}</title>
              </circle>
            ))}
          </g>
        ))}
        {points.map((p, i) => (i % every === (points.length - 1) % every) && (
          <text key={p.key} x={x(i)} y={h - 8} textAnchor="middle" fill="var(--text-dim)"
                fontSize="10" fontFamily="var(--font-mono)">{p.short}</text>
        ))}
      </svg>
      <div className="chart-legend">
        {series.map((s) => (
          <span key={s.key} className="key">
            <span className="swatch" style={{ background: s.color, height: 3 }} />{s.label}
            <span className="mono dim">{fmtMinutes(points[active].values[s.key] || 0)}</span>
          </span>
        ))}
        <span className="key dim">{points[active].label}{points[active].partial ? ' (trwa)' : ''}</span>
      </div>
    </div>
  );
}
