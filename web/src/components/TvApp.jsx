/* Aplikacja Kidwatch TV na telewizorze: tytuly bez ADB. Instalacja idzie
   przez dzialajace jeszcze ADB (APK z obrazu Kidwatch), potem parowanie
   6 cyframi z ekranu aplikacji. Serwer czeka na telewizor - przyciski
   blokujemy do wyniku (instalacja do 3 min). */
import React, { useState } from 'react';
import { post, useApi } from '../utils/api';

export function TvAppControl() {
  const { data, reload } = useApi('/api/tv/aplikacja', [], { refreshMs: 30000 });
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(null);
  const [error, setError] = useState(null);
  const [message, setMessage] = useState(null);
  if (!data?.available) return null;

  const call = async (what, path, body) => {
    setBusy(what);
    setError(null);
    setMessage(null);
    try {
      const res = await post(path, body);
      if (res?.message) setMessage(res.message);
      setCode('');
      reload?.();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(null);
    }
  };

  const working = data.paired && data.last_read && !data.error;
  let status;
  if (working) status = <span className="badge">aplikacja TV {data.version || ''} · działa</span>;
  else if (data.paired) status = <span className="badge warn">aplikacja TV: {data.error || 'brak odczytu'}</span>;
  else status = <span className="badge warn">aplikacja TV niesparowana</span>;

  return (
    <div className="row-body" style={{ marginBottom: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        {status}
        {data.adb && (
          <button className="btn-ghost" disabled={!!busy}
                  onClick={() => call('install', '/api/tv/aplikacja/instaluj', {})}>
            📲 {data.version ? 'Aktualizuj' : 'Zainstaluj'} aplikację na TV
          </button>
        )}
        {busy === 'install' && <span className="badge loading-pulse">instaluję przez ADB…</span>}
      </div>
      {!working && (
        <fieldset className="tv-pause-form">
          <legend className="dim">Kod parowania z ekranu aplikacji Kidwatch TV (6 cyfr)</legend>
          <input className="input-field" value={code} maxLength={6} inputMode="numeric"
                 autoComplete="off" aria-label="Kod z aplikacji Kidwatch TV"
                 onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))} />
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn-ghost" disabled={!!busy || code.length !== 6}
                    onClick={() => call('pair', '/api/tv/aplikacja/paruj', { kod: code })}>Sparuj</button>
            {busy === 'pair' && <span className="badge loading-pulse">łączę z telewizorem…</span>}
          </div>
        </fieldset>
      )}
      {message && <div className="notice">{message}</div>}
      {error && <div className="notice">{error}</div>}
    </div>
  );
}
