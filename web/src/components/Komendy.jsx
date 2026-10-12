/* Komendy z WhatsAppa: dziennik (administrator - wszystkie wiadomosci
   z awaryjnym wylacznikiem; opiekun domu - komendy swojego domu). Numery
   sa zamaskowane juz na serwerze. */
import React, { useCallback, useEffect, useState } from 'react';
import { get, post } from '../utils/api';
import { kiedy, opisAkcji, stanWylacznika, wynikLabel } from '../utils/komendy';

function Wpisy({ wpisy }) {
  if (!wpisy?.length) return <div className="empty">Brak wpisów.</div>;
  return wpisy.slice(0, 100).map((w) => {
    const [etykieta, klasa] = wynikLabel(w.wynik);
    return (
      <div key={w.id} style={{ display: 'flex', gap: 10, flexWrap: 'wrap', fontSize: '0.84rem', padding: '4px 0' }}>
        <span className="dim">{kiedy(w.ts)}</span>
        <strong>{w.login || w.numer}</strong>
        <span className={`badge ${klasa}`}>{etykieta}</span>
        {w.akcja && <span>{opisAkcji(w)}</span>}
        {w.llm && <span className="badge info" title="rozpoznane przez LLM">LLM</span>}
        {w.szczegol && <span className="dim">{w.szczegol}</span>}
      </div>
    );
  });
}

/* Administrator instalacji: stan, wylacznik dla wszystkich, caly dziennik. */
export function KomendyAdmin() {
  const [stan, setStan] = useState(null);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);
  const load = useCallback(() => get('/api/whatsapp/komendy').then(setStan, (e) => setError(e.message)), []);
  useEffect(() => { load(); }, [load]);

  const przelacz = async () => {
    const wylacz = !stan.wylaczone;
    if (wylacz && !window.confirm('Wyłączyć komendy z WhatsAppa dla wszystkich domów?')) return;
    setBusy(true);
    try {
      await post('/api/whatsapp/komendy/wylacznik', { wylaczone: wylacz });
      await load();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  if (error) return <div className="glass-card"><div className="form-error">{error}</div></div>;
  if (!stan) return <div className="glass-card"><div className="empty loading-pulse">Wczytywanie…</div></div>;
  return (
    <div className="glass-card">
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap', marginBottom: 10 }}>
        <span>{stanWylacznika(stan)}</span>
        {stan.wlaczone && (
          <button className={stan.wylaczone ? 'btn-primary' : 'btn-ghost'} disabled={busy} onClick={przelacz}>
            {stan.wylaczone ? 'Włącz komendy' : 'Wyłącz komendy dla wszystkich'}
          </button>
        )}
      </div>
      {stan.llm && (
        <div className="dim" style={{ fontSize: '0.84rem', marginBottom: 8 }}>
          LLM: {stan.llm.dostawcy.length ? stan.llm.dostawcy.join(', ') : 'brak kluczy (tylko dokładne komendy)'}
          {' · '}dziś {stan.llm.wywolania_dzis}/{stan.llm.limit} wywołań
          {' · '}luzowanie: {stan.limity.luzowanie_minut} min i {stan.limity.odblokowania} odblokowań na dziecko dziennie
        </div>
      )}
      <Wpisy wpisy={stan.wpisy} />
    </div>
  );
}

/* Opiekun domu (zarzadzanie kontami): komendy wydane w tym domu. */
export function KomendyDomu() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  useEffect(() => { get('/api/komendy').then(setData, (e) => setError(e.message)); }, []);
  if (error) return <div className="glass-card"><div className="form-error">{error}</div></div>;
  if (!data) return <div className="glass-card"><div className="empty loading-pulse">Wczytywanie…</div></div>;
  if (!data.wlaczone) return <div className="glass-card"><div className="empty">Komendy z WhatsAppa są wyłączone.</div></div>;
  return (
    <div className="glass-card">
      {data.wylaczone && <div className="form-error">Administrator wyłączył komendy z WhatsAppa.</div>}
      <Wpisy wpisy={data.wpisy} />
    </div>
  );
}
