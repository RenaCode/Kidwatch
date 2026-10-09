import React, { useState } from 'react';
import { post } from '../utils/api';
import { ago, hhmm, minutes } from '../utils/format';
import Icon from './Icons';

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
    <div className="game-control">
      <div className="game-status">
        <span className={`badge ${state.badge}`}>
          <Icon name="gamepad" size={14} />
          {state.label}{game.mode === 'bonus' && game.bonus_until ? ` do ${hhmm(game.bonus_until)}` : ''}
        </span>
        <span className="dim" title={game.confirmed_at || ''}>
          {game.confirmed_at ? `potwierdzone w NextDNS ${ago(game.confirmed_at)}` : 'jeszcze nie odczytane z NextDNS'}
        </span>
        {pending && <span className="badge loading-pulse">wysyłanie…</span>}
      </div>
      <div className="segmented" role="group" aria-label={`Czas gry: ${child}`}>
        <button disabled={pending} onClick={() => act('block')}>Zablokuj gry</button>
        <button disabled={pending} onClick={() => act('allow')}>Odblokuj</button>
        <button disabled={pending} onClick={() => act('bonus')}>
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
function DeviceCard({ d, onChanged }) {
  const [open, setOpen] = useState(false);
  const tv = d.kind === 'tv';
  const live = !!d.session;
  const detailsId = `dev-details-${d.name.replace(/\W+/g, '-')}`;
  return (
    <article className={`glass-card device-card ${live ? 'live' : ''}`}>
      <div className="dev-head">
        <span className="dev-icon"><Icon name={tv ? 'tv' : 'tablet'} size={26} /></span>
        <div className="dev-id">
          <h3 className="dev-name">
            {d.child ?? d.name}
            {d.child && <span className="dev-sub"> · {d.name}</span>}
          </h3>
          <span className={`dev-status ${live ? 'on' : ''}`}>
            <span className={live ? 'live-dot' : 'idle-dot'} />
            {live
              ? `${tv ? 'gra' : 'aktywny'} od ${hhmm(d.session.started_at)}`
              : (tv ? 'nic nie gra' : 'bezczynny')}
          </span>
        </div>
      </div>

      <div className="dev-figure">
        <span className="dev-time">{d.today ? minutes(d.today.minutes) : '—'}</span>
        <span className="dev-time-label">
          dziś{d.today ? ` · ${d.today.sessions} ${d.today.sessions === 1 ? 'sesja' : 'sesji'}` : ''}
        </span>
        {/* W miejscu baterii z makiety: obecnosc w domowym Wi-Fi. Brak
            informacji (UniFi wylaczone albo dawno bez odczytu) to brak
            odznaki - nie zgadujemy "poza domem". */}
        {d.presence && (
          <span className={`badge presence ${d.presence.home ? 'info' : ''}`}
                title={`od ${hhmm(d.presence.since)}${d.presence.essid ? ` · ${d.presence.essid}` : ''}`}>
            <Icon name="home" size={13} />{d.presence.home ? 'w domu' : 'poza domem'}
          </span>
        )}
      </div>

      {d.now_playing && (
        <div className="row-body now-playing">
          <strong>{d.now_playing.title || d.now_playing.app}</strong>
          {d.now_playing.channel && <span className="dim"> · {d.now_playing.channel}</span>}
          {d.now_playing.title && <span className="dim"> · {d.now_playing.app}</span>}
          <span className="dim"> · od {hhmm(d.now_playing.since)}</span>
        </div>
      )}
      {d.game && <GameControl child={d.child} game={d.game} onChanged={onChanged} />}

      {open && (
        <div className="dev-details" id={detailsId}>
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
              <span className="stat-label">Odczyt z {tv ? 'TV' : 'iPada'}</span>
              <span className="stat-value sm">{ago(d.last_device_read)}</span>
            </div>
          ) : (
            <div className="stat">
              <span className="stat-label">Najwięcej dziś</span>
              <span className="stat-value sm">{d.today?.top_app ? d.today.top_app.app : '—'}</span>
              {d.today?.top_app && <span className="stat-sub">~{minutes(d.today.top_app.minutes)}</span>}
            </div>
          )}
        </div>
      )}

      <button className="dev-more" aria-expanded={open} aria-controls={detailsId}
              aria-label={`${open ? 'Zwiń' : 'Pokaż'} szczegóły: ${d.name}`}
              onClick={() => setOpen((v) => !v)}>
        <Icon name="more" size={18} />
      </button>
    </article>
  );
}

// Karty w siatce - na telefonie jedna kolumna, od 720 px dwie.
export default function Devices({ devices, onChanged }) {
  if (!devices) return <div className="empty loading-pulse">Wczytywanie urządzeń…</div>;
  if (!devices.length) return <div className="empty">Brak urządzeń dla tego wyboru.</div>;
  return (
    <div className="device-grid">
      {devices.map((d) => <DeviceCard key={d.name} d={d} onChanged={onChanged} />)}
    </div>
  );
}
