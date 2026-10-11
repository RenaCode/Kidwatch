/* Powiadomienia per konto: wlasny profil (kazde konto) i zarzadzanie kontami
   (uprawnienie konta.zarzadzanie). Serwer: /api/konto/* i /api/konta/*
   (panel_konta.py). Pelne numery i adresy nigdy nie wracaja z serwera -
   pokazujemy maski, a zmiana to wpisanie nowej wartosci z haslem albo 2FA. */
import React, { useCallback, useEffect, useState } from 'react';
import { get, post } from '../utils/api';
import {
  CHANNEL_LABEL, channelsSummary, modeNotice, permissionChange, prefsFromProfile, prefsPayload,
  quietProblem, samePrefs, toggle, toggleChild,
} from '../utils/konta';

function Msg({ msg }) {
  if (!msg) return null;
  return <div className={msg.ok ? 'notice info' : 'form-error'} style={{ marginTop: 10 }} role="alert">{msg.text}</div>;
}

function ConfirmField({ value, onChange, label = 'Hasło albo kod z aplikacji 2FA' }) {
  return (
    <label className="field" style={{ flex: 1, minWidth: 200, marginBottom: 0 }}>
      <span className="field-label">{label}</span>
      <input className="input-field" type="password" autoComplete="current-password"
             value={value} onChange={(e) => onChange(e.target.value)} />
    </label>
  );
}

/* Kategorie, cisza, dzieci, wlaczone. `confirm` - tylko gdy edytuje
   zarzadca (cudze konto); wlasne preferencje wystarczy sesja. */
export function PrefsForm({ profil, katalog, onSave, needConfirm = false }) {
  const saved = prefsFromProfile(profil);
  const [form, setForm] = useState(saved);
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const order = katalog.kategorie.map((k) => k.id);
  const allowed = new Set(profil.dozwolone || []);
  const dirty = !samePrefs(form, saved);
  const problem = quietProblem(form.cisza_od, form.cisza_do);
  const set = (patch) => setForm((f) => ({ ...f, ...patch }));

  useEffect(() => { if (!dirty) setForm(prefsFromProfile(profil)); }, [JSON.stringify(profil)]);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      await onSave({ ...prefsPayload(form), ...(needConfirm ? { confirm } : {}) });
      setMsg({ ok: true, text: 'Zapisano.' });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setConfirm(''); setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} noValidate>
      <label className="switch-row" style={{ display: 'flex', gap: 10, alignItems: 'center', marginBottom: 12 }}>
        <span className="switch">
          <input type="checkbox" checked={form.aktywne} aria-label="Powiadomienia włączone"
                 onChange={(e) => set({ aktywne: e.target.checked })} />
          <span className="slider" />
        </span>
        <span>{form.aktywne ? 'Powiadomienia włączone' : 'Powiadomienia wyłączone'}</span>
      </label>

      <div className="field-label">Co dostawać</div>
      <ul style={{ listStyle: 'none', padding: 0, margin: '6px 0 14px', display: 'grid', gap: 6 }}>
        {katalog.kategorie.map((k) => (
          <li key={k.id}>
            <label style={{ display: 'flex', gap: 8, alignItems: 'baseline', opacity: allowed.has(k.id) ? 1 : 0.55 }}>
              <input type="checkbox" disabled={!allowed.has(k.id)}
                     checked={form.kategorie.includes(k.id)}
                     onChange={(e) => set({ kategorie: toggle(form.kategorie, k.id, e.target.checked, order) })} />
              <span>{k.opis}</span>
              {!allowed.has(k.id) && <span className="dim" style={{ fontSize: '0.74rem' }}>wymaga uprawnienia {k.wymaga}</span>}
            </label>
          </li>
        ))}
      </ul>

      <div className="field-label">Godziny ciszy</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'center', margin: '6px 0 6px' }}>
        <input className="input-field mono" style={{ width: 90 }} placeholder="22:00" aria-label="Cisza od"
               value={form.cisza_od} onChange={(e) => set({ cisza_od: e.target.value })} />
        <span>–</span>
        <input className="input-field mono" style={{ width: 90 }} placeholder="07:00" aria-label="Cisza do"
               value={form.cisza_do} onChange={(e) => set({ cisza_do: e.target.value })} />
        <label style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <input type="checkbox" checked={form.cisza_alarmy}
                 onChange={(e) => set({ cisza_alarmy: e.target.checked })} />
          <span>alarmy przebijają ciszę</span>
        </label>
      </div>
      <p className="dim" style={{ fontSize: '0.76rem', margin: '0 0 14px' }}>
        W ciszy informacje o sesjach przepadają, raporty i alarmy techniczne czekają do jej końca,
        a alarm (np. iPad w nocy) przychodzi od razu, jeśli zaznaczone wyżej.
      </p>

      {katalog.dzieci.length > 1 && (
        <>
          <div className="field-label">Których dzieci dotyczy</div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', margin: '6px 0 6px' }}>
            {katalog.dzieci.map((c) => (
              <label key={c} style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                <input type="checkbox" checked={form.dzieci == null || form.dzieci.includes(c)}
                       onChange={(e) => set({ dzieci: toggleChild(form.dzieci, c, e.target.checked, katalog.dzieci) })} />
                <span>{c}</span>
              </label>
            ))}
          </div>
          <p className="dim" style={{ fontSize: '0.76rem', margin: '0 0 14px' }}>
            Telewizor, raporty zbiorcze i alarmy techniczne dotyczą całego domu i przychodzą zawsze.
          </p>
        </>
      )}

      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        {needConfirm && dirty && <ConfirmField value={confirm} onChange={setConfirm} />}
        <button className="btn-ghost" type="submit"
                disabled={busy || !dirty || !!problem || (needConfirm && !confirm)}>
          {busy ? 'Zapisuję…' : 'Zapisz preferencje'}
        </button>
        {dirty && (
          <button type="button" className="btn-link" disabled={busy}
                  onClick={() => { setForm(saved); setMsg(null); }}>Cofnij</button>
        )}
      </div>
      {dirty && problem && <div className="form-error" style={{ marginTop: 8 }}>{problem}</div>}
      <Msg msg={msg} />
    </form>
  );
}

/* Kanaly: zawsze z haslem albo kodem 2FA wykonujacego. Puste pole = bez
   zmiany; "Usuń" wysyla pusty kanal jawnie. */
export function ChannelsForm({ profil, onSave }) {
  const [whatsapp, setWhatsapp] = useState('');
  const [email, setEmail] = useState('');
  const [kanal, setKanal] = useState(profil.kanal || 'auto');
  const [clear, setClear] = useState({ whatsapp: false, email: false });
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const dirty = whatsapp || email || clear.whatsapp || clear.email || kanal !== (profil.kanal || 'auto');

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      // Pole pominiete (undefined znika z JSON) = bez zmiany; pusty napis
      // = usun kanal. Przegladarka zna tylko maske, starego numeru nie odesle.
      await onSave({
        whatsapp: clear.whatsapp ? '' : whatsapp || undefined,
        email: clear.email ? '' : email || undefined,
        kanal,
        confirm,
      });
      setWhatsapp(''); setEmail(''); setClear({ whatsapp: false, email: false });
      setMsg({ ok: true, text: 'Kanały zapisane.' });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setConfirm(''); setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} noValidate>
      <div className="dim" style={{ marginBottom: 10 }}>Teraz: {channelsSummary(profil)}</div>
      <div className="grid grid-2" style={{ gap: 10 }}>
        <label className="field" style={{ marginBottom: 0 }}>
          <span className="field-label">Nowy numer WhatsApp (z kierunkowym)</span>
          <input className="input-field mono" inputMode="tel" placeholder="48…" disabled={clear.whatsapp}
                 value={whatsapp} onChange={(e) => setWhatsapp(e.target.value)} />
          {profil.whatsapp && (
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 4, fontSize: '0.8rem' }}>
              <input type="checkbox" checked={clear.whatsapp}
                     onChange={(e) => setClear((c) => ({ ...c, whatsapp: e.target.checked }))} />
              usuń numer
            </label>
          )}
        </label>
        <label className="field" style={{ marginBottom: 0 }}>
          <span className="field-label">Nowy adres e-mail</span>
          <input className="input-field" type="email" autoComplete="email" disabled={clear.email}
                 value={email} onChange={(e) => setEmail(e.target.value)} />
          {profil.email && (
            <label style={{ display: 'flex', gap: 6, alignItems: 'center', marginTop: 4, fontSize: '0.8rem' }}>
              <input type="checkbox" checked={clear.email}
                     onChange={(e) => setClear((c) => ({ ...c, email: e.target.checked }))} />
              usuń adres
            </label>
          )}
        </label>
      </div>
      <label className="field" style={{ maxWidth: 360, marginTop: 10 }}>
        <span className="field-label">Którędy</span>
        <select className="input-field" value={kanal} onChange={(e) => setKanal(e.target.value)}>
          {Object.entries(CHANNEL_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
        </select>
      </label>
      {dirty && (
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', maxWidth: 460 }}>
          <ConfirmField value={confirm} onChange={setConfirm} />
          <button className="btn-ghost" type="submit" disabled={busy || !confirm}>Zapisz kanały</button>
        </div>
      )}
      <Msg msg={msg} />
    </form>
  );
}

export function MyNotifications() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const load = useCallback(async () => {
    try { setData(await get('/api/konto/powiadomienia')); setError(null); } catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (error && !data) return <div className="glass-card"><div className="form-error">{error}</div></div>;
  if (!data) return <div className="glass-card"><div className="empty loading-pulse">Wczytywanie…</div></div>;
  const notice = modeNotice(data.tryb);
  return (
    <div className="glass-card">
      <div className="card-title">
        <span>Moje powiadomienia</span>
        <span className="hint">{data.profil.ma_kanal ? channelsSummary(data.profil) : 'brak kanału — nic nie przychodzi'}</span>
      </div>
      {notice && <div className="notice" style={{ marginBottom: 12 }}>{notice}</div>}
      <div className="grid grid-2">
        <div>
          <div className="stat-label" style={{ marginBottom: 8 }}>Kanały</div>
          <ChannelsForm profil={data.profil}
                        onSave={async (b) => { const r = await post('/api/konto/kanaly', b); setData(r); }} />
        </div>
        <div>
          <div className="stat-label" style={{ marginBottom: 8 }}>Preferencje</div>
          <PrefsForm profil={data.profil} katalog={data}
                     onSave={async (b) => { const r = await post('/api/konto/powiadomienia', b); setData(r); }} />
        </div>
      </div>
    </div>
  );
}

/* ---------------------------------------------------------------- konta */
function AddAccount({ confirm, onDone }) {
  const [login, setLogin] = useState('');
  const [rola, setRola] = useState('podglad');
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e) => {
    e.preventDefault();
    setBusy(true); setMsg(null);
    try {
      const r = await post('/api/konta/dodaj', { login: login.trim(), rola, confirm });
      setMsg({ ok: true, text: `Konto ${r.login} założone. Hasło (pokazane tylko raz): ${r.haslo}` });
      setLogin('');
      onDone();
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setBusy(false);
    }
  };
  return (
    <form onSubmit={submit} noValidate>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <label className="field" style={{ marginBottom: 0 }}>
          <span className="field-label">Login (a-z, 0-9, . _ -)</span>
          <input className="input-field" autoComplete="off" value={login}
                 onChange={(e) => setLogin(e.target.value)} />
        </label>
        <label className="field" style={{ marginBottom: 0 }}>
          <span className="field-label">Rola</span>
          <select className="input-field" value={rola} onChange={(e) => setRola(e.target.value)}>
            <option value="podglad">podgląd</option>
            <option value="wlasciciel">właściciel</option>
          </select>
        </label>
        <button className="btn-ghost" type="submit" disabled={busy || !login.trim() || !confirm}>
          + Dodaj konto
        </button>
      </div>
      <Msg msg={msg} />
    </form>
  );
}

function AccountRow({ konto, katalog, confirm, onChanged }) {
  const [open, setOpen] = useState(false);
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const p = konto.powiadomienia || {};
  const roleDefaults = katalog.role_uprawnienia[konto.rola] || [];

  const act = async (path, body, okText) => {
    setBusy(true); setMsg(null);
    try {
      await post(path, { login: konto.login, confirm, ...body });
      setMsg({ ok: true, text: okText });
      onChanged();
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setBusy(false);
    }
  };

  return (
    <div style={{ borderTop: '1px solid var(--border, rgba(255,255,255,0.08))', padding: '12px 0' }}>
      <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
        <strong>{konto.login}</strong>{konto.ja && <span className="dim">(ty)</span>}
        <select className="input-field" style={{ width: 'auto' }} value={konto.rola}
                disabled={busy || !confirm} aria-label={`Rola konta ${konto.login}`}
                onChange={(e) => act('/api/konta/rola', { rola: e.target.value }, 'Rola zmieniona.')}>
          {katalog.role.map((r) => <option key={r} value={r}>{r === 'podglad' ? 'podgląd' : 'właściciel'}</option>)}
        </select>
        {konto.totp ? <span className="badge ok">2FA</span> : <span className="badge">bez 2FA</span>}
        <span className="dim">{channelsSummary(p)}{p.aktywne === false ? ' · wyłączone' : ''}</span>
        <span style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          <button type="button" className="btn-link" onClick={() => setOpen((o) => !o)}>
            {open ? 'Zwiń' : 'Edytuj'}
          </button>
          {!konto.ja && (
            <button type="button" className="btn-link" disabled={busy || !confirm}
                    onClick={() => window.confirm(`Usunąć konto ${konto.login}?`)
                      && act('/api/konta/usun', {}, 'Konto usunięte.')}>
              Usuń
            </button>
          )}
        </span>
      </div>
      <Msg msg={msg} />
      {open && (
        <div className="grid" style={{ gap: 16, paddingTop: 12, gridTemplateColumns: 'repeat(auto-fit, minmax(min(260px, 100%), 1fr))' }}>
          <div>
            <div className="stat-label" style={{ marginBottom: 6 }}>Uprawnienia</div>
            {katalog.uprawnienia.map((u) => (
              <label key={u.id} style={{ display: 'flex', gap: 6, alignItems: 'baseline', fontSize: '0.84rem' }}>
                <input type="checkbox" disabled={busy || u.stale || !confirm}
                       checked={konto.uprawnienia.includes(u.id)}
                       onChange={(e) => act('/api/konta/uprawnienia',
                         { zmiany: permissionChange(roleDefaults, u.id, e.target.checked) },
                         'Uprawnienia zmienione.')} />
                <span>{u.opis}</span>
              </label>
            ))}
          </div>
          <div>
            <div className="stat-label" style={{ marginBottom: 6 }}>Kanały</div>
            <ChannelsForm profil={p} onSave={async (b) => {
              await post('/api/konta/kanaly', { login: konto.login, ...b }); onChanged();
            }} />
          </div>
          <div>
            <div className="stat-label" style={{ marginBottom: 6 }}>Powiadomienia</div>
            <PrefsForm profil={p} katalog={katalog} needConfirm onSave={async (b) => {
              await post('/api/konta/powiadomienia', { login: konto.login, ...b }); onChanged();
            }} />
          </div>
        </div>
      )}
    </div>
  );
}

export function Accounts() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [confirm, setConfirm] = useState('');
  const [msg, setMsg] = useState(null);
  const load = useCallback(async () => {
    try { setData(await get('/api/konta')); setError(null); } catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  if (error && !data) return <div className="glass-card"><div className="form-error">{error}</div></div>;
  if (!data) return <div className="glass-card"><div className="empty loading-pulse">Wczytywanie…</div></div>;

  const setMode = async (tryb) => {
    setMsg(null);
    try {
      await post('/api/konta/tryb', { tryb, confirm });
      setMsg({ ok: true, text: tryb === 'konta' ? 'Kidwatch wysyła teraz do kont.' : 'Powrót do listy odbiorców bramki.' });
      load();
    } catch (e) {
      setMsg({ ok: false, text: e.message });
    }
  };

  return (
    <div className="glass-card">
      <div className="card-title">
        <span>Konta i ich powiadomienia</span>
        <span className="hint">tryb: {data.tryb === 'konta' ? 'per konto' : 'lista bramki (tryb tras)'}</span>
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end', marginBottom: 12, maxWidth: 560 }}>
        <ConfirmField value={confirm} onChange={setConfirm}
                      label="Twoje hasło albo kod 2FA — potwierdza każdą zmianę niżej" />
        <button className="btn-ghost" disabled={!confirm}
                onClick={() => setMode(data.tryb === 'konta' ? 'trasy' : 'konta')}>
          {data.tryb === 'konta' ? 'Wróć do listy bramki' : 'Przełącz na powiadomienia per konto'}
        </button>
      </div>
      <Msg msg={msg} />
      <div style={{ margin: '12px 0' }}>
        {data.konta.map((k) => (
          <AccountRow key={k.login} konto={k} katalog={data} confirm={confirm} onChanged={load} />
        ))}
      </div>
      <AddAccount confirm={confirm} onDone={load} />
      <p className="dim" style={{ fontSize: '0.76rem', marginTop: 10 }}>
        Przed przełączeniem na tryb kont uzupełnij kanały (albo przenieś listę bramki:
        <code> kidwatch konta-migruj</code>). Wspólne dla domu zostają: bot WhatsApp, MDM,
        UniFi, telewizor, NextDNS.
      </p>
    </div>
  );
}
