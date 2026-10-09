/* Zakladka MDM: stan iPadow w wlasnym serwerze MDM (kidwatch-mdm) i akcje.
   Panel jest tylko posrednikiem - polityka (blokady, DNS) zyje w serwerze MDM
   i jest wgrywana sama. Tu: podglad, odswiezenie, blokada ekranu, restart,
   wymuszona aktualizacja systemu i link do zapisu nowego iPada. */
import React, { useState } from 'react';
import { post, useApi } from '../utils/api';
import { ago } from '../utils/format';
import { eventTone, isMeaningfulEvent } from '../utils/mdm';
import Icon from './Icons';

const EVENT_LABELS = {
  enrolled: 'zapisany do MDM',
  authenticate: 'uwierzytelnienie',
  checkout: 'PROFIL ZDJĘTY',
  profile_missing: 'zniknął profil',
  apps_installed: 'nowa aplikacja',
  apps_removed: 'usunięta aplikacja',
  command_error: 'błąd komendy',
  push_token_dead: 'push odrzucony',
  os_update_failed: 'aktualizacja nieudana',
  os_update_set: 'ustawiono aktualizację',
  supervision_changed: 'zmiana nadzoru',
  enrollment_created: 'nowe zaproszenie',
  signature_rejected: 'odrzucony podpis',
  cert_mismatch: 'próba podszycia',
};

function Action({ label, onRun, disabled }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    try { await onRun(); } catch (e) { setError(e.message); } finally { setBusy(false); }
  };
  return (
    <>
      <button className="btn-ghost" disabled={busy || disabled} onClick={run}>
        {busy ? '…' : label}
      </button>
      {error && <span className="badge warn" title={error}>błąd: {error}</span>}
    </>
  );
}

function DeviceCard({ d, onChanged }) {
  const [open, setOpen] = useState(false);
  const detail = useApi(open ? `/api/mdm/devices/${d.udid}` : null, [open]);
  const later = () => [1500, 6000, 15000].forEach((ms) => setTimeout(() => onChanged?.(), ms));
  const lock = async () => {
    const message = window.prompt('Komunikat na ekranie blokady (opcjonalnie):', '');
    if (message === null) return;
    await post('/api/mdm/command', { udid: d.udid, request_type: 'DeviceLock', Message: message });
    later();
  };
  const restart = async () => {
    if (!window.confirm(`Zrestartować ${d.name}?`)) return;
    await post('/api/mdm/command', { udid: d.udid, request_type: 'RestartDevice' });
    later();
  };
  const apps = detail.data?.apps || [];
  const detailsId = `mdm-details-${d.udid}`;
  return (
    <article className="glass-card mdm-device">
      <div className="dev-head">
        <span className="dev-icon"><Icon name="tablet" size={26} /></span>
        <div className="dev-id">
          <h3 className="dev-name">{d.name}</h3>
          <span className="dim">{d.product || '?'} · iPadOS {d.os_version || '?'}</span>
        </div>
      </div>
      <div className="mdm-row">
        {d.checked_out_at
          ? <span className="badge warn">profil zdjęty {ago(d.checked_out_at)}</span>
          : d.supervised === true
            ? <span className="badge ok">nadzorowany</span>
            : d.supervised === false
              ? <span className="badge warn" title="iOS ignoruje blokady VPN, DNS i usuwania profilu">bez nadzoru</span>
              : <span className="badge">nadzór: ?</span>}
        {!d.ddm_synced && !d.checked_out_at && <span className="badge info">polityka w drodze</span>}
        {d.push_error && <span className="badge warn" title={d.push_error_at}>push: {d.push_error}</span>}
      </div>
      <span className="dim" title={d.last_seen_at}>Kontakt z MDM {ago(d.last_seen_at)}</span>
      {!d.checked_out_at && (
        <div className="mdm-row">
          <Action label="Odśwież" onRun={async () => { await post('/api/mdm/refresh', { udid: d.udid }); later(); }} />
          <Action label="Zablokuj ekran" onRun={lock} />
          <Action label="Restart" onRun={restart} disabled={d.supervised !== true} />
          <button className="btn-ghost" aria-expanded={open} aria-controls={detailsId}
                  onClick={() => setOpen((v) => !v)}>
            {open ? 'Ukryj szczegóły' : 'Szczegóły'}
          </button>
        </div>
      )}
      {open && detail.data && (
        <div className="dev-details" id={detailsId}>
          <div className="stat">
            <span className="stat-label">Bateria</span>
            <span className="stat-value sm">
              {detail.data.info?.BatteryLevel != null ? `${Math.round(detail.data.info.BatteryLevel * 100)}%` : '—'}
            </span>
          </div>
          <div className="stat">
            <span className="stat-label">Wolne miejsce</span>
            <span className="stat-value sm">
              {detail.data.info?.AvailableDeviceCapacity != null ? `${detail.data.info.AvailableDeviceCapacity.toFixed(1)} GB` : '—'}
            </span>
            <span className="stat-sub">nr seryjny {d.serial || '?'}</span>
          </div>
          <div className="stat">
            <span className="stat-label">Profile od MDM</span>
            <span className="stat-sub">
              {(detail.data.profiles_installed || []).map((p) => (
                `${p.identifier.split('.').pop()} ${p.installed_at ? '✓' : p.failures ? `✗ (${p.failures})` : '…'}`
              )).join(', ') || 'brak'}
            </span>
          </div>
          <div className="stat">
            <span className="stat-label">Aplikacje ({apps.length})</span>
            <span className="stat-sub">{apps.map((a) => a.name || a.id).join(', ') || '—'}</span>
          </div>
        </div>
      )}
      {open && detail.error && <div className="notice">{detail.error}</div>}
    </article>
  );
}

function OsUpdate({ state, onChanged }) {
  const effective = state?.effective;
  const [version, setVersion] = useState('');
  const [deadline, setDeadline] = useState('');
  const [error, setError] = useState(null);
  const save = async (body) => {
    setError(null);
    try { await post('/api/mdm/os-update', body); onChanged?.(); } catch (e) { setError(e.message); }
  };
  return (
    <section className="glass-card mdm-form">
      <div className="card-title"><span>Wymuszona aktualizacja iPadOS</span></div>
      <span>
        {effective
          ? <>Do <strong>{effective.deadline.replace('T', ' ')}</strong> (czas iPada) wersja <strong>{effective.target_version}</strong>.</>
          : 'Brak wymuszenia — nadzorowane iPady instalują aktualizacje automatycznie.'}
      </span>
      <div className="mdm-row">
        <input className="input-field" placeholder="np. 27.1" value={version} style={{ maxWidth: 110 }}
               aria-label="Wersja iPadOS" onChange={(e) => setVersion(e.target.value.trim())} />
        <input className="input-field" type="datetime-local" value={deadline} style={{ maxWidth: 230 }}
               aria-label="Termin" onChange={(e) => setDeadline(e.target.value)} />
        <button className="btn-ghost" disabled={!version || !deadline}
                onClick={() => save({ target_version: version, deadline: deadline.length === 16 ? `${deadline}:00` : deadline })}>
          Ustaw
        </button>
        {state?.override && <button className="btn-ghost" onClick={() => save({ clear: true })}>Wróć do polityki</button>}
      </div>
      {error && <div className="notice">{error}</div>}
    </section>
  );
}

function Enroll() {
  const [label, setLabel] = useState('');
  const [link, setLink] = useState(null);
  const [error, setError] = useState(null);
  const create = async () => {
    setError(null);
    setLink(null);
    try { setLink((await post('/api/mdm/enroll', { label })).url); } catch (e) { setError(e.message); }
  };
  return (
    <section className="glass-card mdm-form">
      <div className="card-title"><span>Zapis nowego iPada</span></div>
      <span className="dim">Etykieta z polityki serwera MDM (np. dziecko1). Link działa 24 h i tylko dla jednego iPada.</span>
      <div className="mdm-row">
        <input className="input-field" value={label} style={{ maxWidth: 200 }} aria-label="Etykieta"
               onChange={(e) => setLabel(e.target.value.toLowerCase().trim())} />
        <button className="btn-ghost" disabled={!label} onClick={create}>Utwórz link</button>
      </div>
      {link && (
        <div className="mdm-row">
          <code style={{ wordBreak: 'break-all' }}>{link}</code>
          <button className="btn-ghost" onClick={() => navigator.clipboard?.writeText(link)}>Kopiuj</button>
        </div>
      )}
      {error && <div className="notice">{error}</div>}
    </section>
  );
}

export default function Mdm() {
  const { data, error, reload } = useApi('/api/mdm', [], { refreshMs: 30000 });
  if (error && !data) return <div className="notice">Serwer MDM: {error}</div>;
  if (!data) return <div className="loading-pulse dim">Ładowanie…</div>;
  if (!data.available) {
    return <div className="notice">Integracja MDM jest wyłączona ({data.error}).</div>;
  }
  const apns = data.health?.apns || {};
  const events = [...data.events].reverse().filter(isMeaningfulEvent).slice(0, 30);
  return (
    <div className="mdm-stack">
      <div className="mdm-row">
        {apns.configured
          ? <span className={`badge ${apns.days_left <= 30 ? 'warn' : 'ok'}`} title={apns.topic}>
              certyfikat APNs: {apns.days_left} dni
            </span>
          : <span className="badge warn">brak certyfikatu APNs — zapis iPadów zablokowany</span>}
        {error && <span className="badge warn">odświeżanie: {error}</span>}
      </div>

      {data.devices.length === 0
        ? <div className="glass-card empty">Żaden iPad nie jest jeszcze zapisany.</div>
        : (
          <div className="device-grid">
            {data.devices.map((d) => <DeviceCard key={d.udid} d={d} onChanged={reload} />)}
          </div>
        )}

      <div className="device-grid">
        <OsUpdate state={data.os_update} onChanged={reload} />
        <Enroll />
      </div>

      <section className="glass-card">
        <div className="card-title"><span>Ostatnie zdarzenia</span><span className="hint">serwer MDM</span></div>
        {events.length === 0
          ? <div className="empty">Brak zdarzeń.</div>
          : (
            <div className="row-list">
              {events.map((e) => {
                const dev = data.devices.find((d) => d.udid === e.udid);
                return (
                  <div key={e.id} className="row-item mdm-event">
                    <span className={`badge ${eventTone(e)}`}>{EVENT_LABELS[e.kind] || e.kind}</span>
                    <span>{dev?.name || ''}</span>
                    <span className="dim" title={e.at}>{ago(e.at)}</span>
                  </div>
                );
              })}
            </div>
          )}
      </section>
    </div>
  );
}
