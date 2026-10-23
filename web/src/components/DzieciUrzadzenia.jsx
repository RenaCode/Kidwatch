/* Dzieci i urzadzenia wybranego domu - wlasciciel domu i zarzadca
   (uprawnienie dom.urzadzenia), administrator instalacji w kazdym domu.
   Serwer: /api/domy/<id>/urzadzenia* (panel_urzadzenia.py), prefiks domu
   dokleja api.js. UDID, adres i MAC ustawia administrator - rola domu widzi
   je jako „ustawione przez administratora”, a zapis ich nie zmienia.
   Kazdy zapis potwierdzony haslem albo kodem 2FA. */
import React, { useCallback, useEffect, useState } from 'react';
import { get, post } from '../utils/api';
import { POLL_LIMIT, POLL_MS, reloadNotice, waitingForReload } from '../utils/integracje';
import {
  OPISY_ADMINA, POLA_ADMINA, RODZAJ_ANDROID, cialoZapisu, czyZmieniony, formZEkranu,
  hostPrywatnegoDns, nazwyNextdns, noweDziecko, noweUrzadzenie, profilUrzadzenia,
  ustawionePrzezAdmina, walidujFormularz, zablokowaneUsuniecie,
} from '../utils/urzadzenia';

const NOTICE_CLASS = { ok: 'notice info', info: 'notice info', warn: 'notice', bad: 'form-error' };

function HostAndroida({ urz, profilDomu }) {
  const r = hostPrywatnegoDns(nazwyNextdns(urz.nextdns)[0], profilUrzadzenia(urz, profilDomu));
  if (r.error) return <p className="dim" style={{ fontSize: '0.76rem' }}>Prywatny DNS: {r.error}</p>;
  const kopiuj = () => { navigator.clipboard?.writeText(r.host).catch(() => {}); };
  return (
    <div className="field">
      <span className="field-label">Host Prywatnego DNS — wpisz na telefonie (Ustawienia → Sieć i internet → Prywatny DNS)</span>
      <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
        <code style={{ wordBreak: 'break-all' }}>{r.host}</code>
        <button type="button" className="btn-link" onClick={kopiuj}>Kopiuj</button>
      </div>
    </div>
  );
}

function Urzadzenie({ urz, dzieci, rodzaje, administrator, profilDomu, onChange, onRemove }) {
  const set = (k) => (e) => onChange({ ...urz, [k]: e.target.value });
  const setTech = (k) => (e) => onChange({ ...urz, techniczne: { ...urz.techniczne, [k]: e.target.value } });
  const adminowe = ustawionePrzezAdmina(urz);
  const zablokowane = zablokowaneUsuniecie(urz, administrator);
  return (
    <div className="glass-card" style={{ padding: 12 }}>
      <div className="grid grid-2" style={{ gap: '0 16px' }}>
        <label className="field">
          <span className="field-label">Nazwa urządzenia</span>
          <input className="input-field" value={urz.nazwa} onChange={set('nazwa')} maxLength={64} />
        </label>
        <label className="field">
          <span className="field-label">Dziecko</span>
          <select className="input-field" value={urz.dziecko} onChange={set('dziecko')}>
            {dzieci.map((d) => <option key={d.klucz} value={d.klucz}>{d.nazwa || '(bez imienia)'}</option>)}
          </select>
        </label>
        <label className="field">
          <span className="field-label">Rodzaj</span>
          <select className="input-field" value={urz.rodzaj} onChange={set('rodzaj')}>
            {rodzaje.map((r) => <option key={r.rodzaj} value={r.rodzaj}>{r.nazwa}</option>)}
          </select>
        </label>
        <label className="field">
          <span className="field-label">Nazwa w NextDNS <span className="dim">· jak w logach NextDNS, kilka po przecinku</span></span>
          <input className="input-field" value={urz.nextdns} onChange={set('nextdns')} autoComplete="off" />
        </label>
        <label className="field">
          <span className="field-label">Profil NextDNS <span className="dim">· puste = profil domu{profilDomu ? ` (${profilDomu})` : ''}</span></span>
          <input className="input-field" value={urz.nextdns_profile} onChange={set('nextdns_profile')}
                 placeholder={profilDomu || ''} autoComplete="off" />
        </label>
      </div>
      {urz.rodzaj === RODZAJ_ANDROID && <HostAndroida urz={urz} profilDomu={profilDomu} />}
      {administrator ? (
        <div className="grid grid-2" style={{ gap: '0 16px' }}>
          {POLA_ADMINA.map((p) => (
            <label key={p} className="field">
              <span className="field-label">{OPISY_ADMINA[p]} <span className="dim">· administrator</span></span>
              <input className="input-field" value={urz.techniczne[p]} onChange={setTech(p)} autoComplete="off" />
            </label>
          ))}
        </div>
      ) : adminowe.length > 0 && (
        <p className="dim" style={{ fontSize: '0.76rem' }}>
          Ustawione przez administratora: {adminowe.join(', ')} — zapis tego ekranu ich nie zmienia.
        </p>
      )}
      {urz.id != null && (
        <p className="dim" style={{ fontSize: '0.76rem' }}>
          Zmiana nazwy zaczyna nową historię urządzenia (dotychczasowa zostaje pod starą nazwą).
        </p>
      )}
      <button type="button" className="btn-link" disabled={zablokowane} onClick={onRemove}
              title={zablokowane ? 'Urządzenie z ustawieniami administratora usuwa administrator instalacji' : ''}>
        Usuń urządzenie
      </button>
    </div>
  );
}

export default function DzieciUrzadzenia() {
  const [ekran, setEkran] = useState(null);
  const [form, setForm] = useState(null);
  const [error, setError] = useState(null);
  const [msg, setMsg] = useState(null);
  const [busy, setBusy] = useState(false);
  /* Potwierdzenie na jedna zmiane (jak w Integracjach i Kontach). */
  const [confirm, setConfirm] = useState('');
  const pokaz = (e) => { setEkran(e); setForm(formZEkranu(e)); };
  const load = useCallback(async () => {
    try { pokaz(await get('/api/urzadzenia')); setError(null); } catch (e) { setError(e.message); }
  }, []);
  useEffect(() => { load(); }, [load]);

  /* Po zapisie: odswiezac stan przeladowania, az nadzorca przelaczy dom.
     Formularza nie ruszamy - bierzemy tylko stan domu. */
  const [polls, setPolls] = useState(0);
  const waiting = waitingForReload(ekran?.przeladowanie) && polls < POLL_LIMIT;
  useEffect(() => {
    if (!waiting) return undefined;
    const id = setInterval(async () => {
      setPolls((n) => n + 1);
      try {
        const st = await get('/api/urzadzenia');
        setEkran((e) => e && ({
          ...e, start: st.start, przeladowanie: st.przeladowanie,
          obcaZmiana: e.obcaZmiana || st.dom.wersja > e.dom.wersja,
        }));
      } catch { /* nastepna proba za chwile */ }
    }, POLL_MS);
    return () => clearInterval(id);
  }, [waiting]);

  if (error && !ekran) return <div className="glass-card"><div className="form-error">{error}</div></div>;
  if (!ekran || !form) return <div className="glass-card"><div className="empty loading-pulse">Wczytywanie…</div></div>;

  const zmieniony = czyZmieniony(ekran, form);
  const notice = reloadNotice(ekran.przeladowanie);
  const setUrz = (klucz, u) => setForm((f) => ({ ...f, urzadzenia: f.urzadzenia.map((x) => (x.klucz === klucz ? u : x)) }));
  const usunUrz = (klucz) => setForm((f) => ({ ...f, urzadzenia: f.urzadzenia.filter((x) => x.klucz !== klucz) }));
  const setDziecko = (klucz, nazwa) => setForm((f) => ({ ...f, dzieci: f.dzieci.map((d) => (d.klucz === klucz ? { ...d, nazwa } : d)) }));
  const usunDziecko = (klucz) => setForm((f) => ({
    dzieci: f.dzieci.filter((d) => d.klucz !== klucz),
    urzadzenia: f.urzadzenia.filter((u) => u.dziecko !== klucz),
  }));
  const dodajDziecko = () => setForm((f) => {
    const d = noweDziecko();
    return { dzieci: [...f.dzieci, d], urzadzenia: [...f.urzadzenia, noweUrzadzenie(d.klucz)] };
  });
  const dodajUrz = (kluczDziecka) => setForm((f) => ({ ...f, urzadzenia: [...f.urzadzenia, noweUrzadzenie(kluczDziecka)] }));

  const zapisz = async (e) => {
    e.preventDefault();
    const blad = walidujFormularz(form, { rodzaje: ekran.rodzaje });
    if (blad) { setMsg({ ok: false, text: blad }); return; }
    setBusy(true); setMsg(null);
    try {
      const body = cialoZapisu(form, { wersja: ekran.dom.wersja, administrator: ekran.administrator });
      const r = await post('/api/urzadzenia/zapisz', { ...body, confirm });
      setPolls(0);
      if (r.ostrzezenie) { setMsg({ ok: false, text: r.ostrzezenie }); load(); return; }
      pokaz(r);
      setMsg({ ok: true, text: 'Zapisano.' });
    } catch (err) {
      setMsg({ ok: false, text: err.message });
    } finally {
      setConfirm(''); setBusy(false);
    }
  };

  return (
    <form style={{ display: 'flex', flexDirection: 'column', gap: 16 }} onSubmit={zapisz} noValidate>
      <div className="glass-card">
        <div className="card-title">
          <span>{ekran.dom.nazwa}</span>
          <span className="hint">wersja konfiguracji {ekran.dom.wersja}</span>
        </div>
        {notice && <div className={NOTICE_CLASS[notice.kind] || 'notice'} role="status">{notice.text}</div>}
        {ekran.obcaZmiana && (
          <div className="notice" style={{ marginTop: 10 }} role="alert">
            Ten dom zmienił w międzyczasie ktoś inny.{' '}
            <button type="button" className="btn-link" onClick={load}>Odśwież ekran</button>{' '}
            przed kolejną zmianą — inaczej zapis zostanie odrzucony.
          </div>
        )}
        {ekran.start && (
          <div className="notice" style={{ marginTop: 10 }} role="alert">
            Na obecnej konfiguracji dom nie wystartuje: {ekran.start}
          </div>
        )}
        <p className="dim" style={{ fontSize: '0.76rem' }}>
          Nazwa w NextDNS musi się zgadzać z nazwą urządzenia w logach NextDNS — po niej Kidwatch
          rozpoznaje, czyje są zapytania. Telewizor i integracje (NextDNS, UniFi…) ustawia
          administrator na osobnym ekranie.
        </p>
      </div>
      {form.dzieci.map((d) => (
        <div key={d.klucz} className="glass-card">
          <div className="card-title" style={{ gap: 8 }}>
            <input className="input-field" value={d.nazwa} placeholder="Imię dziecka" maxLength={64}
                   aria-label="Imię dziecka" onChange={(e) => setDziecko(d.klucz, e.target.value)} />
            <button type="button" className="btn-link"
                    disabled={form.urzadzenia.some((u) => u.dziecko === d.klucz && zablokowaneUsuniecie(u, ekran.administrator))}
                    onClick={() => usunDziecko(d.klucz)}>Usuń dziecko</button>
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {form.urzadzenia.filter((u) => u.dziecko === d.klucz).map((u) => (
              <Urzadzenie key={u.klucz} urz={u} dzieci={form.dzieci} rodzaje={ekran.rodzaje}
                          administrator={ekran.administrator} profilDomu={ekran.profil_nextdns}
                          onChange={(nowe) => setUrz(u.klucz, nowe)} onRemove={() => usunUrz(u.klucz)} />
            ))}
          </div>
          <button type="button" className="btn-ghost" style={{ marginTop: 10 }} onClick={() => dodajUrz(d.klucz)}>
            + Urządzenie
          </button>
        </div>
      ))}
      <div className="glass-card">
        <button type="button" className="btn-ghost" onClick={dodajDziecko}>+ Dziecko</button>
        <label className="field" style={{ maxWidth: 420, marginTop: 12 }}>
          <span className="field-label">Twoje hasło albo kod 2FA — potwierdza zapis</span>
          <input className="input-field" type="password" autoComplete="current-password"
                 value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        </label>
        <button className="btn-ghost" type="submit" disabled={busy || !zmieniony || !confirm}>
          {busy ? 'Zapisuję…' : 'Zapisz dzieci i urządzenia'}
        </button>
        {zmieniony && (
          <button type="button" className="btn-link" style={{ marginLeft: 8 }} disabled={busy}
                  onClick={() => { setForm(formZEkranu(ekran)); setMsg(null); }}>Cofnij zmiany</button>
        )}
        {msg && (
          <div className={msg.ok ? 'notice info' : 'form-error'} style={{ marginTop: 10 }} role="alert">{msg.text}</div>
        )}
      </div>
    </form>
  );
}
