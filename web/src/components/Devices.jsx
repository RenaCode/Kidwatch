import React, { useState } from 'react';
import { post } from '../utils/api';
import { ago, hhmm, minutes } from '../utils/format';
import { TvPauseControl } from './TvPause';
import { TvPilotControl } from './TvPilot';

const GAME_STATE = {
  blocked: { label: 'gry zablokowane', badge: 'warn' },
  allowed: { label: 'gry dozwolone', badge: 'ok' },
  bonus: { label: 'bonus', badge: 'info' },
  mixed: { label: 'gry częściowo (zmiana w NextDNS)', badge: 'warn' },
};

// Czas gry: przyciski tylko ZLECAJA zmiane - wykonuje ja petla serwisu
// (kolejka w panel-auth.db), wiec po kliknieciu odswiezamy karte kilka razy,
// az zadanie zniknie z "oczekujacych". Stan w odznace to stan potwierdzony
// odczytem z NextDNS, nie to, co kliknieto.
function GameControl({ child, game, onChanged }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const pending = busy || game.request?.pending;
  const state = GAME_STATE[game.mode] || { label: 'stan gier nieznany', badge: '' };
  const failed = game.request && game.request.ok === false ? game.request.error : null;

  const act = async (action) => {
    setBusy(true);
    setError(null);
    try {
      await post('/api/game', action === 'bonus'
        ? { child, action, minutes: game.default_bonus_minutes }
        : { child, action });
      [500, 2500, 6000].forEach((ms) => setTimeout(() => onChanged?.(), ms));
    } catch (e) {
      setError(e.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="row-body" style={{ marginBottom: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <span className={`badge ${state.badge}`}>
          🎮 {state.label}{game.mode === 'bonus' && game.bonus_until ? ` do ${hhmm(game.bonus_until)}` : ''}
        </span>
        <span className="dim" title={game.confirmed_at || ''}>
          {game.confirmed_at ? `potwierdzone w NextDNS ${ago(game.confirmed_at)}` : 'jeszcze nie odczytane z NextDNS'}
        </span>
        {pending && <span className="badge loading-pulse">wysyłanie…</span>}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button className="btn-ghost" disabled={pending} onClick={() => act('block')}>Zablokuj gry</button>
        <button className="btn-ghost" disabled={pending} onClick={() => act('allow')}>Odblokuj</button>
        <button className="btn-ghost" disabled={pending} onClick={() => act('bonus')}>
          +{game.default_bonus_minutes} min
        </button>
      </div>
      {game.shared_with?.length > 0 && (
        <span className="dim">Wspólny profil NextDNS z: {game.shared_with.join(', ')} — zmiana dotyczy wszystkich.</span>
      )}
      {(error || failed || game.error) && (
        <div className="notice">
          {error || failed || game.error}{game.retrying ? ' · ponawiam co minutę' : ''}
        </div>
      )}
    </div>
  );
}

// Karta na urzadzenie: czy teraz trwa sesja, ostatni push i ostatni udany
// odczyt wprost z urzadzenia. "Brak odczytu" przy spiacym iPadzie albo
// wylaczonym telewizorze jest normalne. Telewizor (child: null) pokazuje
// zamiast dziecka co leci; iPad - czy jest w domowym Wi-Fi (UniFi).
export default function Devices({ devices, onChanged, tvPause, onTvPauseChanged }) {
  if (!devices) return <div className="empty loading-pulse">Wczytywanie urządzeń…</div>;
  return (
    <div className="grid grid-2">
      {devices.map((d) => (
        <div key={d.name} className="glass-card device-card">
          <div className="card-title">
            <span>
              {d.kind === 'tv' ? '📺 ' : ''}{d.child ?? d.name}{' '}
              {d.child && <span className="hint">· {d.name}</span>}
            </span>
            <span style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {/* Brak informacji (UniFi wylaczone albo dawno bez odczytu) to
                  brak odznaki - nie zgadujemy "poza domem". */}
              {d.presence && (
                <span className={`badge ${d.presence.home ? 'info' : ''}`}
                      title={`od ${hhmm(d.presence.since)}${d.presence.essid ? ` · ${d.presence.essid}` : ''}`}>
                  {d.presence.home ? 'w domu' : 'poza domem'}
                </span>
              )}
              {d.session
                ? <span className="badge ok"><span className="live-dot" /> {d.kind === 'tv' ? 'gra' : 'aktywny'} od {hhmm(d.session.started_at)}</span>
                : <span className="badge">{d.kind === 'tv' ? 'nic nie gra' : 'bezczynny'}</span>}
            </span>
          </div>
          {d.now_playing && (
            <div className="row-body" style={{ marginBottom: 12 }}>
              <strong>{d.now_playing.title || d.now_playing.app}</strong>
              {d.now_playing.channel && <span className="dim"> · {d.now_playing.channel}</span>}
              {d.now_playing.title && <span className="dim"> · {d.now_playing.app}</span>}
              <span className="dim"> · od {hhmm(d.now_playing.since)}</span>
            </div>
          )}
          {d.game && <GameControl child={d.child} game={d.game} onChanged={onChanged} />}
          {d.kind === 'tv' && <TvPauseControl pause={tvPause} onChanged={onTvPauseChanged} />}
          {d.kind === 'tv' && <TvPilotControl />}
          <div className="grid grid-3">
            <div className="stat">
              <span className="stat-label">Ostatnia aktywność</span>
              <span className="stat-value sm">{d.session ? ago(d.session.last_activity_at) : '—'}</span>
            </div>
            <div className="stat">
              <span className="stat-label">Ostatni push</span>
              <span className="stat-value sm">{ago(d.last_notification?.ts)}</span>
              {d.last_notification && <span className="stat-sub">{d.last_notification.title}</span>}
            </div>
            {/* Odczyt wprost z urzadzenia tylko tam, gdzie jest wlaczony -
                "Odczyt z iPada: nigdy" przy wylaczonej warstwie nic nie mowi. */}
            {d.reads_device ? (
              <div className="stat">
                <span className="stat-label">Odczyt z {d.kind === 'tv' ? 'TV' : 'iPada'}</span>
                <span className="stat-value sm">{ago(d.last_device_read)}</span>
              </div>
            ) : (
              <div className="stat">
                <span className="stat-label">Dziś</span>
                <span className="stat-value sm">{d.today ? minutes(d.today.minutes) : '—'}</span>
                {d.today?.top_app && (
                  <span className="stat-sub">najwięcej: {d.today.top_app.app} ~{minutes(d.today.top_app.minutes)}</span>
                )}
              </div>
            )}
          </div>
        </div>
      ))}
    </div>
  );
}
