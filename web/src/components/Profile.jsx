/* Profil konta: bezpieczenstwo (2FA, zmiana hasla) i powiadomienia (kanaly
   bramki, polaczenie WhatsAppa, lista odbiorcow). Panel nie zna klucza
   bramki - kazda akcja idzie przez /api/profile/* z sesja i CSRF, a bramke
   woła serwer. */
import React, { useCallback, useEffect, useState } from 'react';
import { TvPauseControl } from './TvPause';
import { TvAppControl } from './TvApp';
import { get, post } from '../utils/api';
import {
  MAX_LABEL, MAX_RECIPIENTS, SOURCES_ALL, SOURCES_FAMILY, getsEverything, newRecipient,
  partialFailure, recipientsFromState, recipientsPayload, sameRecipients, sourcesKey,
  sourcesLabel, testSummary, validateRecipients,
} from '../utils/recipients';
import TwoFactor from './TwoFactor';

const STATUS = {
  WORKING: { label: 'połączony', badge: 'ok' },
  SCAN_QR_CODE: { label: 'czeka na skan QR', badge: 'warn' },
  STARTING: { label: 'uruchamia się…', badge: 'info' },
  STOPPED: { label: 'zatrzymany', badge: '' },
  BRAK_SESJI: { label: 'nie połączony', badge: '' },
  FAILED: { label: 'błąd sesji', badge: 'bad' },
  NIEOSIAGALNY: { label: 'WAHA nie odpowiada', badge: 'bad' },
  NIESKONFIGUROWANY: { label: 'WAHA nieskonfigurowana', badge: 'bad' },
};
const statusOf = (s) => STATUS[s] || { label: s || 'nieznany', badge: 'warn' };
const QR_REFRESH_MS = 20000;
const botNumber = (me) => (me?.id ? me.id.split('@')[0] : null);

function PasswordForm() {
  const [form, setForm] = useState({ old: '', new: '', repeat: '' });
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const set = (k) => (e) => setForm((f) => ({ ...f, [k]: e.target.value }));
  const mismatch = form.repeat && form.new !== form.repeat;

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      const r = await post('/api/auth/password', { old: form.old, new: form.new });
      setForm({ old: '', new: '', repeat: '' });
      setMsg({ ok: true, text: `Hasło zmienione. Wylogowano innych sesji: ${r.closed_sessions}.` });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="glass-card">
      <div className="card-title"><span>Zmiana hasła</span></div>
      <form onSubmit={submit} noValidate style={{ maxWidth: 380 }}>
        <label className="field">
          <span className="field-label">Obecne hasło</span>
          <input className="input-field" type="password" autoComplete="current-password"
                 value={form.old} onChange={set('old')} />
        </label>
        <label className="field">
          <span className="field-label">Nowe hasło (min. 12 znaków)</span>
          <input className="input-field" type="password" autoComplete="new-password"
                 value={form.new} onChange={set('new')} />
        </label>
        <label className="field">
          <span className="field-label">Powtórz nowe hasło</span>
          <input className="input-field" type="password" autoComplete="new-password"
                 value={form.repeat} onChange={set('repeat')} />
        </label>
        {mismatch && <div className="form-error">Hasła się różnią.</div>}
        {msg && <div className={msg.ok ? 'notice info' : 'form-error'} role="alert">{msg.text}</div>}
        <button className="btn-ghost" type="submit"
                disabled={busy || !form.old || form.new.length < 12 || form.new !== form.repeat}>
          {busy ? 'Zmieniam…' : 'Zmień hasło'}
        </button>
        <p className="dim" style={{ fontSize: '0.76rem', marginTop: 10 }}>
          Po zmianie wszystkie inne zalogowane urządzenia zostaną wylogowane.
        </p>
      </form>
    </div>
  );
}

/* Co dostaje odbiorca (trasy w bramce). Dwa gotowe wybory; trasy ustawione
   inaczej (API bramki) widac jako trzecia pozycje i zostaja bez zmian. */
function SourcesSelect({ i, sources, apps, onChange }) {
  if (!Array.isArray(sources)) {
    return <span className="dim" title="Bramka bez tras wysyła wszystko do wszystkich">wszystko</span>;
  }
  const others = apps.filter((a) => a !== 'kidwatch');
  const key = sourcesKey(sources);
  const presets = [sourcesKey(SOURCES_ALL), sourcesKey(SOURCES_FAMILY)];
  return (
    <select className="input-field" aria-label={`Co dostaje odbiorca ${i + 1}`} value={key}
            onChange={(e) => onChange(e.target.value.split(','))}>
      <option value={sourcesKey(SOURCES_ALL)}>
        Wszystko{others.length ? ` (kidwatch, ${others.join(', ')}, testy)` : ''}
      </option>
      <option value={sourcesKey(SOURCES_FAMILY)}>Tylko sesje dzieci (bez alarmów)</option>
      {!presets.includes(key) && <option value={key}>Inne: {sourcesLabel(sources)}</option>}
    </select>
  );
}

/* Odbiorcy WhatsApp: cala lista edytowana lokalnie i zapisywana jednym
   POST. Lista jest wspolna dla wszystkich aplikacji RenaCode - serwer zada
   hasla albo kodu 2FA (sama sesja nie wystarcza). */
function Recipients({ state, onSaved, busy, setBusy }) {
  const saved = recipientsFromState(state);
  const [draft, setDraft] = useState(saved);
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState(null);
  const max = state.max_odbiorcow || MAX_RECIPIENTS;
  const maxLabel = state.max_etykieta || MAX_LABEL;
  const dirty = !sameRecipients(draft, saved);
  const problem = validateRecipients(draft, max, maxLabel);
  const activeSaved = saved.filter((r) => r.active).length;
  const testTargets = saved.filter((r) => r.active && getsEverything(r)).length;
  const apps = Array.isArray(state.aplikacje) ? state.aplikacje : [];

  // Odswiezenie stanu (np. co 20 s przy QR) nie nadpisuje edycji w toku.
  const savedKey = JSON.stringify(recipientsPayload(saved));
  useEffect(() => {
    if (!dirty) setDraft(recipientsFromState(state));
  }, [savedKey]);

  const edit = (i, patch) => setDraft((d) => d.map((r, j) => (j === i ? { ...r, ...patch } : r)));

  const save = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      const r = await post('/api/profile/whatsapp/recipients',
        { recipients: recipientsPayload(draft), confirm });
      setDraft(recipientsFromState(r));
      onSaved(r);
      setMsg({ ok: true, text: 'Lista odbiorców zapisana.' });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setConfirm('');
      setBusy(false);
    }
  };

  const sendTest = async () => {
    setBusy(true); setMsg(null);
    try {
      const r = await post('/api/profile/test', { channel: 'whatsapp' });
      setMsg({ ok: !partialFailure(r), text: testSummary(r) });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={save} noValidate>
      <div className="card-title" style={{ marginBottom: 8 }}>
        <span>Odbiorcy WhatsApp</span>
        <span className="hint">
          aktywni: {activeSaved} z {saved.length}
          {state.odbiorcy_zrodlo === 'sekret' ? ' · z sekretu bramki' : ''}
        </span>
      </div>
      {draft.length === 0 && (
        <div className="notice" style={{ marginBottom: 10 }}>
          Brak odbiorców — powiadomienia idą e-mailem.
        </div>
      )}
      {draft.length > 0 && (
        <div className="table-scroll" style={{ marginBottom: 10 }}>
          <table className="table">
            <thead>
              <tr><th>Numer (z kierunkowym)</th><th>Etykieta</th><th>Dostaje</th><th>Aktywny</th><th aria-label="Usuń" /></tr>
            </thead>
            <tbody>
              {draft.map((r, i) => (
                <tr key={i}>
                  <td>
                    <input className="input-field mono" inputMode="tel" placeholder="48…"
                           aria-label={`Numer odbiorcy ${i + 1}`} value={r.number}
                           onChange={(e) => edit(i, { number: e.target.value })} />
                  </td>
                  <td>
                    <input className="input-field" maxLength={maxLabel} placeholder="np. Mama"
                           aria-label={`Etykieta odbiorcy ${i + 1}`} value={r.label}
                           onChange={(e) => edit(i, { label: e.target.value })} />
                  </td>
                  <td>
                    <SourcesSelect i={i} sources={r.sources} apps={apps}
                                   onChange={(sources) => edit(i, { sources })} />
                  </td>
                  <td>
                    <label className="switch" title={r.active ? 'dostaje powiadomienia' : 'wyłączony'}>
                      <input type="checkbox" checked={r.active} aria-label={`Odbiorca ${i + 1} aktywny`}
                             onChange={(e) => edit(i, { active: e.target.checked })} />
                      <span className="slider" />
                    </label>
                  </td>
                  <td>
                    <button type="button" className="btn-link" aria-label={`Usuń odbiorcę ${i + 1}`}
                            onClick={() => setDraft((d) => d.filter((_, j) => j !== i))}>Usuń</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {draft.some((r) => Array.isArray(r.sources)) && (
        <p className="dim" style={{ fontSize: '0.76rem', margin: '0 0 10px' }}>
          „Wszystko” — kidwatch, alarmy techniczne czujki, trader, monitoring, wiadomość
          próbna i każda nowa aplikacja. „Tylko kidwatch” — powiadomienia o dzieciach.
          Alarm, którego nikt nie dostaje WhatsAppem, idzie e-mailem do właściciela bramki.
        </p>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
        <button type="button" className="btn-ghost" disabled={busy || draft.length >= max}
                onClick={() => setDraft((d) => [...d, newRecipient(state)])}>
          + Dodaj odbiorcę
        </button>
        {dirty && (
          <button type="button" className="btn-link" disabled={busy}
                  onClick={() => { setDraft(saved); setMsg(null); }}>Cofnij zmiany</button>
        )}
        <button type="button" className="btn-ghost" disabled={busy || dirty || testTargets === 0}
                title={dirty ? 'Najpierw zapisz listę' : 'Test dostają tylko aktywni z „Wszystko”'}
                onClick={sendTest}>
          Wyślij test ({testTargets})
        </button>
      </div>

      {dirty && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', maxWidth: 460 }}>
          <label className="field" style={{ flex: 1, marginBottom: 0 }}>
            <span className="field-label">Hasło albo kod z aplikacji 2FA</span>
            <input className="input-field" type="password" autoComplete="current-password"
                   value={confirm} onChange={(e) => setConfirm(e.target.value)} />
          </label>
          <button className="btn-ghost" type="submit" disabled={busy || !!problem || !confirm}>
            Zapisz listę
          </button>
        </div>
      )}
      {dirty && problem && <div className="form-error" style={{ marginTop: 8 }}>{problem}</div>}
      {msg && <div className={msg.ok ? 'notice info' : 'form-error'} style={{ marginTop: 12 }} role="alert">{msg.text}</div>}
      <p className="dim" style={{ fontSize: '0.76rem', marginTop: 10 }}>
        Wiadomość idzie do wszystkich aktywnych (najwyżej {max}). Gdy nie dojdzie do nikogo,
        bramka wyśle e-mail. Lista jest wspólna dla wszystkich aplikacji RenaCode.
      </p>
    </form>
  );
}

function WhatsApp() {
  const [state, setState] = useState(null);
  const [qr, setQr] = useState(null);
  // QR wymaga swiezego potwierdzenia haslem (serwer: 403 po 5 min albo bez
  // "Polacz") - wtedy zamiast cichej przerwy mowimy rodzicowi, co zrobic.
  const [qrNeedsConfirm, setQrNeedsConfirm] = useState(false);
  // Po "Polacz" pobieramy QR od razu, nie dopiero przy nastepnym odswiezeniu.
  const [qrKick, setQrKick] = useState(0);
  const [sessionConfirm, setSessionConfirm] = useState('');
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const s = await get('/api/profile/notify');
      setState(s);
      return s;
    } catch (e) {
      setMsg({ ok: false, text: e.message });
      return null;
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // QR wygasa po kilkudziesieciu sekundach - odswiezamy go razem ze stanem,
  // az sesja przejdzie na WORKING (telefon zeskanowal kod).
  const waiting = state?.status === 'SCAN_QR_CODE' || state?.status === 'STARTING';
  useEffect(() => {
    if (!waiting) { setQr(null); setQrNeedsConfirm(false); return undefined; }
    let alive = true;
    const tick = async () => {
      const s = await load();
      if (!alive || !s) return;
      if (s.status === 'SCAN_QR_CODE') {
        try {
          const q = await get('/api/profile/whatsapp/qr');
          if (alive) { setQr(q); setQrNeedsConfirm(false); }
        } catch (e) {
          if (alive && e.status === 403) { setQr(null); setQrNeedsConfirm(true); }
          /* inne bledy: za chwile kolejna proba */
        }
      }
    };
    tick();
    const id = setInterval(tick, QR_REFRESH_MS);
    return () => { alive = false; clearInterval(id); };
  }, [waiting, load, qrKick]);

  const act = async (path, body, okText) => {
    setBusy(true); setMsg(null);
    try {
      const r = await post(path, body);
      if (r && r.status) setState((s) => ({ ...s, ...r }));
      setMsg({ ok: true, text: typeof okText === 'function' ? okText(r) : okText });
      await load();
      return true;
    } catch (e) {
      setMsg({ ok: false, text: e.message });
      return false;
    } finally {
      setBusy(false);
    }
  };

  if (!state) return <div className="glass-card"><div className="empty loading-pulse">Wczytywanie…</div></div>;
  if (!state.available) {
    return (
      <div className="glass-card">
        <div className="card-title"><span>Powiadomienia</span></div>
        <div className="notice">Bramka powiadomień nie jest skonfigurowana (notifiers.bramka albo BRAMKA_KLUCZ).</div>
      </div>
    );
  }

  const st = statusOf(state.status);
  const bot = botNumber(state.me);
  return (
    <div className="glass-card">
      <div className="card-title">
        <span>Powiadomienia</span>
        <span className="hint">teraz idą: {state.kanal_auto === 'whatsapp' ? 'WhatsApp' : 'e-mail'}</span>
      </div>
      {state.error && <div className="notice" style={{ marginBottom: 12 }}>Bramka: {state.error}</div>}

      <div className="grid grid-3" style={{ marginBottom: 16 }}>
        <div className="stat">
          <span className="stat-label">E-mail</span>
          <span className={`badge ${state.email ? 'ok' : 'bad'}`}>{state.email ? 'skonfigurowany' : 'brak'}</span>
        </div>
        <div className="stat">
          <span className="stat-label">WhatsApp (WAHA)</span>
          <span className={`badge ${st.badge}`}>{st.label}</span>
          {bot && <span className="stat-sub">numer bota: +{bot}{state.me?.nazwa ? ` · ${state.me.nazwa}` : ''}</span>}
        </div>
        <div className="stat">
          <span className="stat-label">Odbiorcy</span>
          <span className="stat-value sm">
            {recipientsFromState(state).filter((r) => r.active).length} aktywnych
          </span>
          <span className="stat-sub">lista niżej</span>
        </div>
      </div>

      {qrNeedsConfirm && !qr && (
        <div className="notice" style={{ marginBottom: 16 }}>
          Kliknij „Połącz WhatsApp” i potwierdź hasłem albo kodem 2FA — wtedy pojawi się kod QR.
        </div>
      )}

      {qr && (
        <div style={{ display: 'flex', gap: 16, alignItems: 'center', flexWrap: 'wrap', marginBottom: 16 }}>
          <img src={`data:${qr.mimetype};base64,${qr.data}`} alt="Kod QR WhatsApp"
               style={{ width: 220, background: '#fff', padding: 10, borderRadius: 'var(--radius-md)' }} />
          <div className="dim" style={{ fontSize: '0.82rem', maxWidth: 360 }}>
            Na telefonie z numerem bota: WhatsApp → Ustawienia → Połączone urządzenia →
            Połącz urządzenie i zeskanuj kod. Kod odświeża się co 20 s.
          </div>
        </div>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 16 }}>
        <label className="field" style={{ marginBottom: 0, minWidth: 220 }}>
          <span className="field-label">Hasło albo kod 2FA (połącz / rozłącz)</span>
          <input className="input-field" type="password" autoComplete="current-password"
                 value={sessionConfirm} onChange={(e) => setSessionConfirm(e.target.value)} />
        </label>
        {state.status !== 'WORKING' && (
          <button className="btn-ghost" disabled={busy || !sessionConfirm}
                  onClick={() => act('/api/profile/whatsapp/start', { confirm: sessionConfirm }, 'Sesja uruchomiona — zeskanuj kod QR.')
                    .then((ok) => { if (ok) { setSessionConfirm(''); setQrKick((k) => k + 1); } })}>
            Połącz WhatsApp
          </button>
        )}
        <button className="btn-ghost" disabled={busy}
                onClick={() => act('/api/profile/test', {}, testSummary)}>
          Wyślij test
        </button>
        {state.status === 'WORKING' && (
          <button className="btn-ghost" disabled={busy || !sessionConfirm}
                  onClick={() => {
                    if (window.confirm('Rozłączyć numer bota? Powiadomienia pójdą mailem do ponownego skanu QR.')) {
                      act('/api/profile/whatsapp/logout', { confirm: sessionConfirm }, 'Rozłączono. Do ponownego połączenia potrzebny skan QR.')
                        .then((ok) => ok && setSessionConfirm(''));
                    }
                  }}>
            Rozłącz
          </button>
        )}
      </div>

      {msg && <div className={msg.ok ? 'notice info' : 'form-error'} style={{ marginBottom: 12 }} role="alert">{msg.text}</div>}

      <Recipients state={state} busy={busy} setBusy={setBusy}
                  onSaved={(r) => setState((s) => ({ ...s, ...r }))} />
    </div>
  );
}

// Telewizor: wstrzymanie monitoringu i aplikacja Kidwatch TV.
// Do 2026-10-09 te przyciski siedzialy na karcie TV w widoku urzadzen.
function TvSettings({ tvPause, onTvPauseChanged }) {
  return (
    <div className="card">
      <div className="card-title"><span>Telewizor</span></div>
      <TvPauseControl pause={tvPause} onChanged={onTvPauseChanged} />
      <TvAppControl />
    </div>
  );
}

export default function Profile({ user, onChanged, onClose, tvPause, onTvPauseChanged }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, marginBottom: 22 }}>
      <div className="card-title" style={{ marginBottom: 0 }}>
        <span>Ustawienia · {user?.login}</span>
        <button className="btn-ghost" onClick={onClose}>← Wróć do panelu</button>
      </div>
      <div className="stat-label">Bezpieczeństwo</div>
      <div className="grid grid-2">
        <TwoFactor user={user} onChanged={onChanged} />
        <PasswordForm />
      </div>
      <div className="stat-label">Powiadomienia / WhatsApp</div>
      <WhatsApp />
      <div className="stat-label">Telewizor</div>
      <TvSettings tvPause={tvPause} onTvPauseChanged={onTvPauseChanged} />
    </div>
  );
}
