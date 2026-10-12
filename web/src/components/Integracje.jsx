/* Integracje wybranego domu - ekran administratora instalacji (decyzja
   wlasciciela 2026-10-12). Serwer: /api/domy/<id>/integracje*
   (panel_integracje.py), prefiks domu dokleja api.js. Sekrety tylko do
   zapisu: pole hasla z maska w placeholderze, puste = bez zmian, usuniecie
   osobnym przyciskiem. Kazdy zapis potwierdzony haslem albo kodem 2FA. */
import React, { useCallback, useEffect, useState } from 'react';
import { get, post } from '../utils/api';
import {
  POLL_LIMIT, POLL_MS, applySaved, applyState, formFromIntegration, isDirty, reloadNotice,
  savePayload, secretPlaceholder, waitingForReload,
} from '../utils/integracje';

const NOTICE_CLASS = { ok: 'notice info', info: 'notice info', warn: 'notice', bad: 'form-error' };

function Notice({ notice }) {
  if (!notice) return null;
  return <div className={NOTICE_CLASS[notice.kind] || 'notice'} role="status">{notice.text}</div>;
}

function Msg({ msg }) {
  if (!msg) return null;
  return (
    <div className={msg.ok ? 'notice info' : 'form-error'} style={{ marginTop: 10 }} role="alert">
      {msg.text}
    </div>
  );
}

function SettingField({ pole, value, onChange }) {
  const id = `int-${pole.pole}`;
  if (pole.rodzaj === 'bool') {
    return (
      <label className="field" style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <input id={id} type="checkbox" checked={!!value} onChange={(e) => onChange(e.target.checked)} />
        <span className="field-label" style={{ margin: 0 }}>{pole.pole}</span>
      </label>
    );
  }
  const hint = pole.rodzaj === 'lista' ? 'po przecinku' : pole.rodzaj === 'slownik' ? 'klucz=wartość, po linii' : '';
  return (
    <label className="field">
      <span className="field-label">
        {pole.pole}{pole.wymagane ? ' *' : ''}{hint ? <span className="dim"> · {hint}</span> : null}
      </span>
      {pole.rodzaj === 'slownik' ? (
        <textarea id={id} className="input-field" rows={3} value={value}
                  onChange={(e) => onChange(e.target.value)} />
      ) : (
        <input id={id} className="input-field" value={value} autoComplete="off"
               inputMode={pole.rodzaj === 'int' || pole.rodzaj === 'float' ? 'decimal' : undefined}
               placeholder={pole.domyslna == null ? '' : `domyślnie: ${pole.domyslna}`}
               onChange={(e) => onChange(e.target.value)} />
      )}
    </label>
  );
}

function SecretField({ sekret, value, onChange, onRemove, disabled }) {
  return (
    <div className="field">
      <span className="field-label">
        {sekret.opis} <span className="dim">({sekret.pole})</span>
        {sekret.ustawiony
          ? <span className="badge ok" style={{ marginLeft: 6 }}>ustawiony</span>
          : <span className="badge" style={{ marginLeft: 6 }}>brak</span>}
      </span>
      <div style={{ display: 'flex', gap: 8, alignItems: 'flex-start' }}>
        {sekret.wielolinijkowy ? (
          <textarea className="input-field" rows={3} value={value} autoComplete="off" spellCheck={false}
                    placeholder={secretPlaceholder(sekret)} aria-label={sekret.opis}
                    onChange={(e) => onChange(e.target.value)} />
        ) : (
          <input className="input-field" type="password" value={value} autoComplete="new-password"
                 placeholder={secretPlaceholder(sekret)} aria-label={sekret.opis}
                 onChange={(e) => onChange(e.target.value)} />
        )}
        {sekret.ustawiony && (
          <button type="button" className="btn-link" disabled={disabled} onClick={onRemove}>Usuń</button>
        )}
      </div>
    </div>
  );
}

function IntegrationCard({ integ, confirm, wersja, onUsed, onSaved }) {
  const [form, setForm] = useState(() => formFromIntegration(integ));
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  const dirty = isDirty(integ, form);

  // Nowe dane z serwera (po zapisie albo odswiezeniu) - formularz za nimi,
  // chyba ze administrator wlasnie cos wpisuje.
  useEffect(() => { if (!dirty) setForm(formFromIntegration(integ)); }, [JSON.stringify(integ)]);

  const send = async (path, body, okText) => {
    setBusy(true); setMsg(null);
    try {
      // `wersja`: serwer odrzuci zapis (409), gdy ktos zmienil dom od wczytania.
      const r = await post(path, { ...body, wersja, confirm });
      if (r.integracja) setForm(formFromIntegration(r.integracja));
      setMsg(r.ostrzezenie ? { ok: false, text: r.ostrzezenie } : { ok: true, text: okText });
      onSaved(r);
    } catch (e) {
      setMsg({ ok: false, text: e.message });
    } finally {
      onUsed(); setBusy(false);
    }
  };

  const save = (e) => {
    e.preventDefault();
    const r = savePayload(integ, form);
    if (r.error) { setMsg({ ok: false, text: r.error }); return; }
    send('/api/integracje/zapisz', r.body, 'Zapisano.');
  };

  const remove = (pole) => {
    if (!window.confirm(`Usunąć sekret ${pole} integracji ${integ.nazwa}?`)) return;
    send('/api/integracje/usun-sekret', { typ: integ.typ, pole }, `Usunięto sekret ${pole}.`);
  };

  const setPole = (pole, v) => setForm((f) => ({ ...f, pola: { ...f.pola, [pole]: v } }));
  const setSekret = (pole, v) => setForm((f) => ({ ...f, sekrety: { ...f.sekrety, [pole]: v } }));

  return (
    <form className="glass-card" onSubmit={save} noValidate>
      <div className="card-title">
        <span>{integ.nazwa}</span>
        <label className="switch" title={form.wlaczona ? 'włączona' : 'wyłączona'}>
          <input type="checkbox" checked={form.wlaczona} aria-label={`${integ.nazwa} włączona`}
                 onChange={(e) => setForm((f) => ({ ...f, wlaczona: e.target.checked }))} />
          <span className="slider" />
        </label>
      </div>
      <p className="dim" style={{ fontSize: '0.76rem', marginTop: 0 }}>
        {integ.skonfigurowana
          ? `Zmienione: ${integ.zmienione_przez || '—'}${integ.zmienione_at ? `, ${new Date(integ.zmienione_at).toLocaleString('pl-PL')}` : ''}`
          : 'Jeszcze nie skonfigurowana.'}
      </p>
      {integ.uwaga && <p className="dim" style={{ fontSize: '0.76rem' }}>{integ.uwaga}</p>}
      <div className="grid grid-2" style={{ gap: '0 16px' }}>
        {integ.pola.map((p) => (
          <SettingField key={p.pole} pole={p} value={form.pola[p.pole]} onChange={(v) => setPole(p.pole, v)} />
        ))}
      </div>
      {integ.sekrety.length > 0 && <div className="stat-label" style={{ margin: '8px 0' }}>Sekrety</div>}
      {integ.sekrety.map((s) => (
        <SecretField key={s.pole} sekret={s} value={form.sekrety[s.pole] || ''} disabled={busy || !confirm}
                     onChange={(v) => setSekret(s.pole, v)} onRemove={() => remove(s.pole)} />
      ))}
      <button className="btn-ghost" type="submit" disabled={busy || !dirty || !confirm}>
        Zapisz {integ.nazwa}
      </button>
      {dirty && !confirm && <span className="dim" style={{ marginLeft: 8, fontSize: '0.76rem' }}>wpisz hasło albo kod u góry</span>}
      <Msg msg={msg} />
    </form>
  );
}

export default function Integrations() {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  /* Potwierdzenie na JEDNA zmiane (jak w Kontach): kod TOTP jest jednorazowy,
     a haslo nie zostaje w stanie strony. */
  const [confirm, setConfirm] = useState('');
  const load = useCallback(async () => {
    try { setData(await get('/api/integracje')); setError(null); } catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  /* Po zapisie: sam stan przeladowania (bez masek i bez wpisu w dzienniku),
     az nadzorca przelaczy dom, zglosi blad albo minie limit czasu. */
  const [polls, setPolls] = useState(0);
  const waiting = waitingForReload(data?.przeladowanie) && polls < POLL_LIMIT;
  useEffect(() => {
    if (!waiting) return undefined;
    const id = setInterval(async () => {
      setPolls((n) => n + 1);
      try {
        const st = await get('/api/integracje/stan');
        setData((d) => applyState(d, st));
      } catch { /* nastepna proba za chwile */ }
    }, POLL_MS);
    return () => clearInterval(id);
  }, [waiting]);

  if (error && !data) return <div className="glass-card"><div className="form-error">{error}</div></div>;
  if (!data) return <div className="glass-card"><div className="empty loading-pulse">Wczytywanie…</div></div>;

  const onSaved = (r) => {
    setPolls(0);
    if (r.ostrzezenie) { load(); return; }
    setData((d) => applySaved(d, r));
  };
  const timedOut = waitingForReload(data.przeladowanie) && polls >= POLL_LIMIT;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div className="glass-card">
        <div className="card-title">
          <span>{data.dom.nazwa}</span>
          <span className="hint">wersja konfiguracji {data.dom.wersja}</span>
        </div>
        <Notice notice={reloadNotice(data.przeladowanie)} />
        {timedOut && (
          <div className="notice" style={{ marginTop: 10 }} role="status">
            Nie potwierdzono przełączenia domu w ciągu 2 minut — odśwież ekran albo sprawdź log.
          </div>
        )}
        {data.start && (
          <div className="notice" style={{ marginTop: 10 }} role="alert">
            Na obecnej konfiguracji dom nie wystartuje: {data.start}
          </div>
        )}
        <p className="dim" style={{ fontSize: '0.76rem' }}>
          Sieci domu: {data.sieci.length ? data.sieci.join(', ') : 'brak (tylko adresy publiczne)'}
          {data.hosty.length ? ` · hosty API: ${data.hosty.join(', ')}` : ''}. Zmienia je administrator
          z CLI (<code>kidwatch dom-sieci</code>). Wartości sekretów nigdy nie wracają do przeglądarki —
          widać tylko maskę; puste pole zostawia sekret bez zmian.
        </p>
        <label className="field" style={{ maxWidth: 420, marginBottom: 0 }}>
          <span className="field-label">Twoje hasło albo kod 2FA — potwierdza jedną zmianę niżej</span>
          <input className="input-field" type="password" autoComplete="current-password"
                 value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </label>
      </div>
      {data.integracje.map((i) => (
        <IntegrationCard key={i.typ} integ={i} confirm={confirm} wersja={data.dom.wersja}
                         onUsed={() => setConfirm('')} onSaved={onSaved} />
      ))}
    </div>
  );
}
