/* Pilot Google TV (Android TV Remote v2): zasilanie i aplikacja bez ADB.
   Parowanie raz: "Sparuj" - telewizor pokazuje 6 znakow - wpisujemy je tutaj.
   Serwer czeka na odpowiedz telewizora, wiec przyciski blokujemy do wyniku. */
import React, { useState } from 'react';
import { post, useApi } from '../utils/api';

export function TvPilotControl() {
  const { data, reload } = useApi('/api/tv/pilot', [], { refreshMs: 30000 });
  const [step, setStep] = useState('idle'); // idle | code
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  if (!data?.available) return null;

  const call = async (path, body, next) => {
    setBusy(true);
    setError(null);
    try {
      await post(path, body);
      setStep(next);
      setCode('');
      reload?.();
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  let status;
  if (!data.paired) status = <span className="badge warn">pilot niesparowany</span>;
  else if (!data.connected) status = <span className="badge">pilot: brak połączenia</span>;
  else status = (
    <span className="badge">
      pilot: {data.on ? `włączony${data.app ? ` · ${data.app}` : ''}` : 'wyłączony'}
    </span>
  );

  return (
    <div className="row-body" style={{ marginBottom: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        {status}
        {step === 'idle' && !(data.paired && data.connected) && (
          <button className="btn-ghost" disabled={busy}
                  onClick={() => call('/api/tv/pilot/start', {}, 'code')}>
            📺 Sparuj pilota TV
          </button>
        )}
        {busy && <span className="badge loading-pulse">czekam na telewizor…</span>}
      </div>
      {step === 'code' && (
        <fieldset className="tv-pause-form">
          <legend className="dim">Wpisz kod z ekranu telewizora (6 znaków)</legend>
          <input className="input-field" value={code} maxLength={6} autoFocus
                 autoCapitalize="characters" autoComplete="off" aria-label="Kod z telewizora"
                 onChange={(e) => setCode(e.target.value.toUpperCase())} />
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn-ghost" disabled={busy || code.length !== 6}
                    onClick={() => call('/api/tv/pilot/kod', { kod: code }, 'idle')}>Potwierdź</button>
            <button className="btn-ghost" disabled={busy} onClick={() => setStep('idle')}>Anuluj</button>
          </div>
        </fieldset>
      )}
      {error && <div className="notice">{error}</div>}
    </div>
  );
}
