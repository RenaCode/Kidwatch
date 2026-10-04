import React, { useEffect, useState } from 'react';
import { get, qs } from '../utils/api';
import { KINDS, kindOf, hhmm, dayLabel } from '../utils/format';
import NoteBody from './NoteBody';
import ErrorBoundary from './ErrorBoundary';

const PAGE = 100;

export default function Notifications({ devices, child }) {
  const [filters, setFilters] = useState({ device: '', kind: '', day: '' });
  const [items, setItems] = useState([]);
  const [hasMore, setHasMore] = useState(false);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);

  // Nowe filtry = lista od zera. Co 30 s dociagamy tylko pierwsza strone,
  // zeby nowe pushe pojawialy sie na gorze bez przewijania.
  useEffect(() => {
    let alive = true;
    const load = async (initial) => {
      try {
        const res = await get(`/api/notifications${qs({ ...filters, child, limit: PAGE })}`);
        if (!alive) return;
        setItems((prev) => {
          // Pierwsza strona podmienia gore listy; starsze strony dociagniete
          // przyciskiem zostaja, bez duplikatow.
          const ids = new Set(res.items.map((n) => n.id));
          const oldest = res.items.at(-1)?.cursor;
          const tail = oldest ? prev.filter((n) => !ids.has(n.id) && n.cursor < oldest) : [];
          return [...res.items, ...tail];
        });
        // Odswiezenie w tle nie rusza stronicowania dociagnietego przyciskiem.
        if (initial) setHasMore(res.has_more);
        setError(null);
      } catch (e) {
        if (alive) setError(e.message);
      } finally {
        if (alive) setLoading(false);
      }
    };
    setItems([]);
    setLoading(true);
    load(true);
    const id = setInterval(() => load(false), 30000);
    return () => { alive = false; clearInterval(id); };
  }, [filters, child]);

  const more = async () => {
    try {
      const res = await get(`/api/notifications${qs({ ...filters, child, limit: PAGE, before: items.at(-1)?.cursor })}`);
      setItems((prev) => [...prev, ...res.items]);
      setHasMore(res.has_more);
    } catch (e) { setError(e.message); }
  };

  const set = (k) => (e) => setFilters((f) => ({ ...f, [k]: e.target.value }));

  // Naglowek dnia miedzy wierszami - lista z kilku dni bez niego sie zlewa.
  let lastDay = null;

  return (
    <div className="glass-card">
      <div className="card-title">
        <span>Historia powiadomień</span>
        <span className="hint">{items.length} na liście</span>
      </div>

      <div className="filters">
        <select className="input-field" value={filters.device} onChange={set('device')} aria-label="Dziecko">
          {/* Lista przychodzi juz zawezona do wybranego dziecka - tu wybiera
              sie urzadzenie, gdy dziecko ma ich kilka albo jest TV. */}
          <option value="">{child ? 'Wszystkie urządzenia' : 'Wszystkie dzieci'}</option>
          {devices.map((d) => (
            <option key={d.name} value={d.name}>{d.child ? `${d.child} · ${d.name}` : d.name}</option>
          ))}
        </select>
        <select className="input-field" value={filters.kind} onChange={set('kind')} aria-label="Rodzaj">
          <option value="">Wszystkie rodzaje</option>
          {Object.entries(KINDS).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
        </select>
        <input className="input-field" type="date" value={filters.day} onChange={set('day')} aria-label="Dzień" />
        {(filters.device || filters.kind || filters.day) && (
          <button className="btn-ghost" onClick={() => setFilters({ device: '', kind: '', day: '' })}>Wyczyść</button>
        )}
      </div>

      {error && <div className="notice" style={{ marginBottom: 12 }}>Błąd odczytu: {error}</div>}

      {loading && !items.length ? (
        <div className="empty loading-pulse">Wczytywanie…</div>
      ) : !items.length ? (
        <div className="empty">Brak powiadomień dla tych filtrów.</div>
      ) : (
        <div className="row-list no-fade" style={{ maxHeight: 'none' }}>
          {items.map((n) => {
            const k = kindOf(n.kind);
            const day = n.ts.slice(0, 10);
            const header = day !== lastDay ? (lastDay = day, (
              <div key={`d-${day}`} className="stat-label" style={{ margin: '10px 2px 2px' }}>{dayLabel(n.ts)}</div>
            )) : null;
            const failed = Object.entries(n.channels).filter(([, ok]) => !ok).map(([c]) => c);
            return (
              <React.Fragment key={n.id}>
                {header}
                <div className="row-item note-row">
                  <span className="kind-icon" aria-hidden>{k.icon}</span>
                  <div className="note-main">
                    <div className="row-head">
                      <span className="row-title">{n.title}</span>
                      <span className="mono dim" style={{ fontSize: '0.78rem' }}>{hhmm(n.ts)}</span>
                    </div>
                    <ErrorBoundary fallback={<div className="row-body note-text" style={{ marginTop: 4 }}>{n.text}</div>}>
                      <NoteBody note={n} />
                    </ErrorBoundary>
                    <div className="row-meta">
                      <span className={`badge ${k.badge}`}>{k.label}</span>
                      {n.child && <span className="badge">{n.child}</span>}
                      {n.app && <span className="badge info">{n.app}</span>}
                      {!n.delivered && <span className="badge bad">nie dotarło</span>}
                      {n.delivered && failed.length > 0 && <span className="badge warn">bez: {failed.join(', ')}</span>}
                    </div>
                  </div>
                </div>
              </React.Fragment>
            );
          })}
        </div>
      )}

      {hasMore && <button className="btn-ghost btn-more" onClick={more}>Pokaż starsze</button>}
    </div>
  );
}
