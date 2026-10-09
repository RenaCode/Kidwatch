/* Pauza monitoringu TV: wyjazd z dziecmi, w domu ogladaja inni. Przyciski
   tylko ZLECAJA zmiane (kolejka w panel-auth.db, jak czas gry) - wykonuje
   ja tik petli serwisu co 30 s, wiec po kliknieciu odswiezamy stan kilka
   razy, az zadanie przestanie byc "oczekujace". iPady sa monitorowane
   normalnie - jada z dziecmi. */
import React, { useState } from 'react';
import { post } from '../utils/api';
import Icon from './Icons';
import { defaultPauseUntil, localInputValue, pauseUntil } from '../utils/format';

const REFRESH_AFTER_MS = [1000, 5000, 15000, 32000];

function usePauseAction(onChanged) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const run = async (path, body) => {
    setBusy(true);
    setError(null);
    try {
      await post(path, body);
      REFRESH_AFTER_MS.forEach((ms) => setTimeout(() => onChanged?.(), ms));
      return true;
    } catch (e) {
      setError(e.message);
      return false;
    } finally {
      setBusy(false);
    }
  };
  return { busy, error, run };
}

function failedRequest(pause) {
  const r = pause?.request;
  return r && r.ok === false ? r.error : null;
}

// Baner nad cala zawartoscia panelu - widoczny przy kazdym dziecku i kazdej
// zakladce, bo zero minut TV w tym czasie ma nie wygladac na brak ogladania.
export function TvPauseBanner({ pause, onChanged }) {
  const { busy, error, run } = usePauseAction(onChanged);
  if (!pause?.available || !pause.active) return null;
  const pending = busy || pause.request?.pending;
  return (
    <div className="notice tv-pause-banner" role="status">
      <span>
        ⏸️ <strong>Monitoring TV wstrzymany {pauseUntil(pause.active.until)}</strong>
        <span className="dim"> · {pause.name} bez powiadomień i bez liczenia czasu; iPady bez zmian
          {pause.active.by ? ` · włączone przez ${pause.active.by}` : ''}</span>
      </span>
      <span style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        {pending && <span className="badge loading-pulse">wysyłanie…</span>}
        <button className="btn-ghost" disabled={pending}
                onClick={() => run('/api/tv/resume', {})}>Wznów teraz</button>
      </span>
      {(error || failedRequest(pause)) && (
        <span className="tv-pause-error">{error || failedRequest(pause)}</span>
      )}
    </div>
  );
}

// Przycisk otwiera wybor konca pauzy - termin (domyslnie za tydzien) albo
// "do odwolania". `hero`: duza pigulka na karcie szybkiej kontroli w Pulpicie;
// w Ustawieniach zwykly przycisk. Logika ta sama.
export function TvPauseControl({ pause, onChanged, hero = false }) {
  const { busy, error, run } = usePauseAction(onChanged);
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState('until');
  const [until, setUntil] = useState(defaultPauseUntil);
  if (!pause?.available) return null;
  const pending = busy || pause.request?.pending;
  const failed = error || failedRequest(pause);

  if (pause.active && hero) {
    return (
      <div className="tv-hero-action">
        <button className="btn-pill" disabled={pending}
                onClick={() => run('/api/tv/resume', {})}>
          <Icon name="play" size={18} /> Wznów monitoring TV
        </button>
        <span className="dim">wstrzymany {pauseUntil(pause.active.until)}</span>
        {pending && <span className="badge loading-pulse">wysyłanie…</span>}
        {failed && <div className="notice">{failed}</div>}
      </div>
    );
  }

  if (pause.active) {
    return (
      <div className="row-body" style={{ marginBottom: 12, display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <span className="badge warn">⏸️ monitoring wstrzymany {pauseUntil(pause.active.until)}</span>
        {pending && <span className="badge loading-pulse">wysyłanie…</span>}
        <button className="btn-ghost" disabled={pending}
                onClick={() => run('/api/tv/resume', {})}>Wznów teraz</button>
        {failed && <div className="notice" style={{ width: '100%' }}>{failed}</div>}
      </div>
    );
  }

  const submit = async () => {
    const ok = await run('/api/tv/pause', { until: mode === 'until' ? until : null });
    if (ok) setOpen(false);
  };

  return (
    <div className={hero ? 'tv-hero' : 'row-body'} style={{ marginBottom: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
      {!open && hero ? (
        <div className="tv-hero-action">
          <button className="btn-pill" disabled={pending}
                  onClick={() => { setUntil(defaultPauseUntil()); setOpen(true); }}>
            <Icon name="pause" size={18} /> Wstrzymaj monitoring TV
          </button>
          {pending && <span className="badge loading-pulse">wysyłanie…</span>}
        </div>
      ) : !open ? (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <button className="btn-ghost" disabled={pending}
                  onClick={() => { setUntil(defaultPauseUntil()); setOpen(true); }}>
            ⏸️ Wstrzymaj monitoring TV
          </button>
          {pending && <span className="badge loading-pulse">wysyłanie…</span>}
        </div>
      ) : (
        <fieldset className="tv-pause-form">
          <legend className="dim">Wstrzymaj monitoring TV (np. wyjazd, w domu oglądają inni)</legend>
          <label className="tv-pause-option">
            <input type="radio" name="tv-pause-mode" checked={mode === 'until'}
                   onChange={() => setMode('until')} />
            do
            <input className="input-field" type="datetime-local" value={until}
                   min={localInputValue(new Date())}
                   onChange={(e) => { setUntil(e.target.value); setMode('until'); }}
                   aria-label="Koniec pauzy" />
          </label>
          <label className="tv-pause-option">
            <input type="radio" name="tv-pause-mode" checked={mode === 'forever'}
                   onChange={() => setMode('forever')} />
            do odwołania
          </label>
          <span className="dim">
            Telewizor nie będzie odpytywany: zero powiadomień o TV i zero minut TV w raportach.
            iPady dalej monitorowane.
          </span>
          <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
            <button className="btn-ghost" disabled={pending || (mode === 'until' && !until)}
                    onClick={submit}>Wstrzymaj</button>
            <button className="btn-ghost" disabled={busy} onClick={() => setOpen(false)}>Anuluj</button>
          </div>
        </fieldset>
      )}
      {failed && <div className="notice">{failed}</div>}
    </div>
  );
}
