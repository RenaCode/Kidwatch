/* Zakladka MDM: stan iPadow w wlasnym serwerze MDM (kidwatch-mdm) i akcje.
   Panel jest tylko posrednikiem - polityka (blokady, DNS) zyje w serwerze MDM
   i jest wgrywana sama. Tu: podglad, odswiezenie, blokada ekranu, restart,
   wymuszona aktualizacja systemu i link do zapisu nowego iPada. */
import React, { useState } from 'react';
import { post, useApi } from '../utils/api';
import { ago } from '../utils/format';

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
const ALARM = new Set(['checkout', 'profile_missing', 'push_token_dead', 'cert_mismatch',
  'supervision_changed', 'os_update_failed']);

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
  return (
    <div className="row-body" style={{ marginBottom: 12, display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
        <strong>{d.name}</strong>
        <span className="dim">{d.product || '?'} · iPadOS {d.os_version || '?'}</span>
        {d.checked_out_at
          ? <span className="badge warn">profil zdjęty {ago(d.checked_out_at)}</span>
          : d.supervised === true
            ? <span className="badge ok">nadzorowany</span>
            : d.supervised === false
              ? <span className="badge warn" title="iOS ignoruje blokady VPN, DNS i usuwania profilu">bez nadzoru</span>
              : <span className="badge">nadzór: ?</span>}
        <span className="dim" title={d.last_seen_at}>kontakt {ago(d.last_seen_at)}</span>
        {!d.ddm_synced && !d.checked_out_at && <span className="badge info">polityka w drodze</span>}
        {d.push_error && <span className="badge warn" title={d.push_error_at}>push: {d.push_error}</span>}
      </div>
      {!d.checked_out_at && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <Action label="Odśwież" onRun={async () => { await post('/api/mdm/refresh', { udid: d.udid }); later(); }} />
          <Action label="Zablokuj ekran" onRun={lock} />
          <Action label="Restart" onRun={restart} disabled={d.supervised !== true} />
          <button className="btn-ghost" onClick={() => setOpen((v) => !v)}>
            {open ? 'Ukryj szczegóły' : 'Szczegóły'}
          </button>
        </div>
      )}
      {open && detail.data && (
        <div className="dim" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          <span>
            Bateria: {detail.data.info?.BatteryLevel != null ? `${Math.round(detail.data.info.BatteryLevel * 100)}%` : '?'}
            {' · '}Wolne: {detail.data.info?.AvailableDeviceCapacity != null ? `${detail.data.info.AvailableDeviceCapacity.toFixed(1)} GB` : '?'}
            {' · '}Numer seryjny: {d.serial || '?'}
          </span>
          <span>
            Profile od MDM: {(detail.data.profiles_installed || []).map((p) => (
              `${p.identifier.split('.').pop()} ${p.installed_at ? '✓' : p.failures ? `✗ (${p.failures})` : '…'}`
            )).join(', ') || 'brak'}
          </span>
          <span>Aplikacje ({apps.length}): {apps.map((a) => a.name || a.id).join(', ') || '—'}</span>
        </div>
      )}
      {open && detail.error && <div className="notice">{detail.error}</div>}
    </div>
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
    <fieldset className="tv-pause-form" style={{ marginBottom: 16 }}>
      <legend className="dim">Wymuszona aktualizacja iPadOS</legend>
      <span>
        {effective
          ? <>Do <strong>{effective.deadline.replace('T', ' ')}</strong> (czas iPada) wersja <strong>{effective.target_version}</strong>.</>
          : 'Brak wymuszenia — nadzorowane iPady instalują aktualizacje automatycznie.'}
      </span>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
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
    </fieldset>
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
    <fieldset className="tv-pause-form" style={{ marginBottom: 16 }}>
      <legend className="dim">Zapis nowego iPada</legend>
      <span className="dim">Etykieta z polityki serwera MDM (np. dziecko1). Link działa 24 h i tylko dla jednego iPada.</span>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <input className="input-field" value={label} style={{ maxWidth: 200 }} aria-label="Etykieta"
               onChange={(e) => setLabel(e.target.value.toLowerCase().trim())} />
        <button className="btn-ghost" disabled={!label} onClick={create}>Utwórz link</button>
      </div>
      {link && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center' }}>
          <code style={{ wordBreak: 'break-all' }}>{link}</code>
          <button className="btn-ghost" onClick={() => navigator.clipboard?.writeText(link)}>Kopiuj</button>
        </div>
      )}
      {error && <div className="notice">{error}</div>}
    </fieldset>
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
  return (
    <div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', marginBottom: 16 }}>
        {apns.configured
          ? <span className={`badge ${apns.days_left <= 30 ? 'warn' : 'ok'}`} title={apns.topic}>
              certyfikat APNs: {apns.days_left} dni
            </span>
          : <span className="badge warn">brak certyfikatu APNs — zapis iPadów zablokowany</span>}
        {error && <span className="badge warn">odświeżanie: {error}</span>}
      </div>

      {data.devices.length === 0 && <div className="dim" style={{ marginBottom: 16 }}>Żaden iPad nie jest jeszcze zapisany.</div>}
      {data.devices.map((d) => <DeviceCard key={d.udid} d={d} onChanged={reload} />)}

      <OsUpdate state={data.os_update} onChanged={reload} />
      <Enroll />

      <h3 className="dim" style={{ margin: '8px 0' }}>Ostatnie zdarzenia</h3>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
        {[...data.events].reverse().slice(0, 30).map((e) => {
          const dev = data.devices.find((d) => d.udid === e.udid);
          return (
            <div key={e.id} className="dim">
              <span className={`badge ${ALARM.has(e.kind) ? 'warn' : ''}`}>{EVENT_LABELS[e.kind] || e.kind}</span>
              {' '}{dev?.name || ''} <span title={e.at}>{ago(e.at)}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
