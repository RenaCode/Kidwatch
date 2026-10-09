/* Pasek osi dnia na Pulpicie: odcinki sesji i aplikacji tam, gdzie byly,
   wskaznik z dymkiem pod palcem/myszka i podswietlanie aplikacji.

   Interakcja:
   - mysz: najechanie pokazuje wskaznik, klikniecie podswietla aplikacje,
   - dotyk: przeciagniecie przesuwa wskaznik (pionowe przewijanie strony
     zostaje - touch-action: pan-y), po puszczeniu dymek zostaje do
     dotkniecia poza wierszem; samo dotkniecie podswietla aplikacje,
   - klawiatura: strzalki (z Shift co 30 min), Home/End, Enter/Spacja
     podswietla, Escape czysci.
   Wskaznik zyje w stanie TEGO komponentu i zmienia sie w requestAnimationFrame;
   odcinki sa w osobnym memo, wiec ruch palcem nie przerysowuje ani karty,
   ani odcinkow. */
import React, { memo, useCallback, useEffect, useRef, useState } from 'react';
import { minutes } from '../utils/format';
import {
  OTHER, colorKey, describeAt, fmtClock, hourToPct, pctToHour, snapTo, whatAt,
} from '../utils/timeline';

// Tolerancja trafienia palcem/myszka w krotki odcinek, w pikselach paska.
const TAP_PX = 8;
const DRAG_PX = 6;

const Segments = memo(function Segments({ tl, range, hl }) {
  const span = (s) => {
    const left = hourToPct(s.start, range);
    return { left: `${left}%`, width: `${hourToPct(s.end, range) - left}%` };
  };
  const groupOf = (app) => (tl.top.includes(app) ? app : OTHER);
  // Podswietlona aplikacja rysowana na koncu - nad nachodzacymi odcinkami.
  const runs = hl ? [...tl.runs].sort((a, b) => (groupOf(a.app) === hl) - (groupOf(b.app) === hl)) : tl.runs;
  return (
    <>
      {tl.sessions.map((s) => <span key={`s${s.start}`} className="seg-session" style={span(s)} />)}
      {runs.map((r) => (
        <span key={`${r.app}-${r.start}`} style={span(r)}
              className={`seg-run c-${colorKey(tl.top, r.app)} ${hl && groupOf(r.app) === hl ? 'hl' : ''}`} />
      ))}
    </>
  );
});

export default function DayBar({ label, tl, range, axis, total }) {
  const [pos, setPos] = useState(null);       // godzina pod wskaznikiem
  const [hl, setHl] = useState(null);         // aplikacja z legendy albo OTHER
  const rowRef = useRef(null);
  const trackRef = useRef(null);
  const drag = useRef(null);
  const frame = useRef(0);
  const nextPos = useRef(null);

  const groupOf = useCallback((app) => (tl.top.includes(app) ? app : OTHER), [tl]);
  const tolHours = () => {
    const w = trackRef.current?.getBoundingClientRect().width || 300;
    return (TAP_PX / w) * (range.end - range.start);
  };
  const hourAt = (clientX) => {
    const r = trackRef.current.getBoundingClientRect();
    return pctToHour(((clientX - r.left) / r.width) * 100, range);
  };
  const schedule = (h) => {
    nextPos.current = h;
    if (!frame.current) {
      frame.current = requestAnimationFrame(() => {
        frame.current = 0;
        setPos(nextPos.current);
      });
    }
  };
  useEffect(() => () => cancelAnimationFrame(frame.current), []);

  const toggleAt = (h, tol) => {
    const app = whatAt(tl, h, tol, hl === OTHER ? null : hl).apps[0];
    const group = app ? groupOf(app) : null;
    if (app) setPos(snapTo(tl, h, app));
    setHl((cur) => (group == null || cur === group ? null : group));
  };

  // Dotkniecie poza wierszem: reset wskaznika i podswietlenia.
  useEffect(() => {
    if (pos == null && hl == null) return undefined;
    const outside = (e) => {
      if (rowRef.current && !rowRef.current.contains(e.target)) {
        setPos(null);
        setHl(null);
      }
    };
    document.addEventListener('pointerdown', outside);
    return () => document.removeEventListener('pointerdown', outside);
  }, [pos, hl]);

  const onPointerDown = (e) => {
    if (e.pointerType === 'mouse' && e.button !== 0) return;
    drag.current = { x: e.clientX, moved: false };
    if (e.pointerType !== 'mouse') {
      try { e.currentTarget.setPointerCapture(e.pointerId); } catch { /* starsze Safari */ }
    }
    schedule(hourAt(e.clientX));
  };
  const onPointerMove = (e) => {
    const d = drag.current;
    if (d && Math.abs(e.clientX - d.x) > DRAG_PX) d.moved = true;
    if (d || e.pointerType === 'mouse') schedule(hourAt(e.clientX));
  };
  const onPointerUp = (e) => {
    const d = drag.current;
    drag.current = null;
    if (d && !d.moved) {
      cancelAnimationFrame(frame.current);
      frame.current = 0;
      const h = hourAt(e.clientX);
      setPos(h);
      toggleAt(h, tolHours());
    }
  };
  const onPointerCancel = () => {
    // Przegladarka przejela gest (przewijanie w pionie) - wskaznik znika.
    drag.current = null;
    schedule(null);
  };
  const onPointerLeave = (e) => {
    if (e.pointerType === 'mouse') schedule(null);
  };

  const lastEnd = tl.sessions.length ? Math.max(...tl.sessions.map((s) => s.end)) : range.start;
  const onKeyDown = (e) => {
    const cur = pos ?? lastEnd;
    const step = (e.shiftKey ? 30 : 5) / 60;
    const clamp = (h) => Math.min(range.end, Math.max(range.start, h));
    const keys = {
      ArrowLeft: () => setPos(clamp(cur - step)),
      ArrowDown: () => setPos(clamp(cur - step)),
      ArrowRight: () => setPos(clamp(cur + step)),
      ArrowUp: () => setPos(clamp(cur + step)),
      Home: () => setPos(range.start),
      End: () => setPos(range.end),
      Enter: () => toggleAt(cur, 0),
      ' ': () => toggleAt(cur, 0),
      Escape: () => { setPos(null); setHl(null); },
    };
    if (keys[e.key]) {
      e.preventDefault();
      keys[e.key]();
    }
  };

  const hlTotal = hl == null ? null
    : hl === OTHER ? tl.other : (tl.totals.find((t) => t.app === hl)?.minutes ?? 0);
  const tipText = pos == null ? null : describeAt(tl, pos, 0, hl === OTHER ? null : hl);
  const tipPct = pos == null ? 0 : hourToPct(pos, range);
  const legend = tl.top.map((app, i) => ({ key: app, label: app, color: i, minutes: tl.totals[i].minutes }));
  if (tl.other > 0) legend.push({ key: OTHER, label: 'inne', color: OTHER, minutes: tl.other });

  return (
    <div className="st-bar" ref={rowRef}>
      <div ref={trackRef}
           className={`st-track day ${hl ? 'has-hl' : ''}`}
           role="slider" tabIndex={0}
           aria-label={`${label}: oś dnia ${fmtClock(range.start)}–${fmtClock(range.end)}, łącznie ${minutes(total)}`}
           aria-valuemin={range.start} aria-valuemax={range.end}
           aria-valuenow={Math.round((pos ?? lastEnd) * 60) / 60}
           aria-valuetext={describeAt(tl, pos ?? lastEnd, 0, hl === OTHER ? null : hl)}
           onPointerDown={onPointerDown} onPointerMove={onPointerMove} onPointerUp={onPointerUp}
           onPointerCancel={onPointerCancel} onPointerLeave={onPointerLeave}
           onKeyDown={onKeyDown} onBlur={() => setPos(null)}>
        {axis.ticks.map((h) => (
          <span key={h} className="st-tick" style={{ left: `${hourToPct(h, range)}%` }} />
        ))}
        <Segments tl={tl} range={range} hl={hl} />
        {pos != null && (
          <>
            <span className="st-cursor" style={{ left: `${tipPct}%` }} />
            <span className={`st-tip ${tipPct < 18 ? 'edge-l' : tipPct > 82 ? 'edge-r' : ''}`}
                  style={{ left: `${tipPct}%` }} aria-hidden="true">
              {tipText}
            </span>
          </>
        )}
      </div>
      <div className="st-hours" aria-hidden="true">
        {axis.labels.map((h) => (
          <span key={h} style={{ left: `${hourToPct(h, range)}%` }}
                className={h <= range.start ? 'first' : h >= range.end ? 'last' : ''}>
            {fmtClock(h).replace(':00', '')}
          </span>
        ))}
      </div>
      {legend.length > 0 && (
        <div className="st-apps" role="group" aria-label="Aplikacje dziś - dotknij, aby podświetlić">
          {legend.map((l) => (
            <button key={l.key} type="button" aria-pressed={hl === l.key}
                    className={`st-app c-${l.color} ${hl === l.key ? 'on' : hl ? 'off' : ''}`}
                    onClick={() => setHl((cur) => (cur === l.key ? null : l.key))}>
              {l.label}
              <span className="st-app-min">{minutes(l.minutes)}</span>
            </button>
          ))}
        </div>
      )}
      <span className="sr-only" aria-live="polite">
        {hl ? `${hl === OTHER ? 'inne aplikacje' : hl} · ${minutes(hlTotal)} dziś` : ''}
      </span>
    </div>
  );
}
