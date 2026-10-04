/* Karta "Weryfikacja dwuetapowa" otwierana z menu konta. Wzor: TotpPanel
   w Trader-AI (Settings.jsx), plus wylaczanie, ktorego Trader w panelu nie ma.

   Wlaczanie: QR + sekret do przepisania -> kod -> kody zapasowe pokazane RAZ.
   Wylaczanie: haslo + kod (albo kod zapasowy) - sama sesja nie wystarcza.
   401 z tych POST-ow to "zle dane", nie wygasla sesja (patrz isLoginFlow). */
import React, { useState } from 'react';
import { post } from '../utils/api';

const box = { background: 'var(--bg-inset)', padding: '10px 12px',
              borderRadius: 'var(--radius-sm)', fontSize: '0.82rem' };

export default function TwoFactor({ user, onChanged, onClose }) {
  const [setup, setSetup] = useState(null);
  const [codes, setCodes] = useState(null);
  const [code, setCode] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const run = async (fn) => {
    setBusy(true); setError('');
    try { await fn(); }
    catch (e) { setError(e.message); }
    finally { setBusy(false); }
  };

  const start = () => run(async () => { setSetup(await post('/api/auth/totp/setup')); });

  const confirm = (e) => {
    e.preventDefault();
    run(async () => {
      const r = await post('/api/auth/totp/confirm', { code });
      setCodes(r.backup_codes);
      setSetup(null);
      setCode('');
      onChanged();
    });
  };

  const disable = (e) => {
    e.preventDefault();
    run(async () => {
      await post('/api/auth/totp/disable', { password, code });
      setPassword(''); setCode('');
      onChanged();
    });
  };

  let body;
  if (codes) {
    body = (
      <>
        <div className="notice" style={{ marginBottom: 12 }}>
          <strong>Zapisz te kody teraz</strong>, najlepiej w menedżerze haseł. Każdy działa
          raz zamiast kodu z aplikacji, gdy stracisz do niej dostęp. W bazie są wyłącznie
          ich skróty — nie da się ich odzyskać. Pozostałe sesje tego konta zostały wylogowane.
        </div>
        <div className="mono" style={{ display: 'grid', gap: 8,
                                       gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))' }}>
          {codes.map((c) => <span key={c} style={{ ...box, textAlign: 'center' }}>{c}</span>)}
        </div>
        <button className="btn-ghost" style={{ marginTop: 14 }} onClick={() => { setCodes(null); onClose?.(); }}>
          Zapisałem kody
        </button>
      </>
    );
  } else if (user.totp_enabled) {
    body = (
      <form onSubmit={disable} noValidate style={{ maxWidth: 380 }}>
        <p className="dim" style={{ marginBottom: 14 }}>
          Weryfikacja dwuetapowa jest włączona. Pozostało kodów zapasowych:{' '}
          <strong>{user.backup_codes_left}</strong>. Żeby ją wyłączyć, podaj hasło
          i aktualny kod (albo kod zapasowy).
        </p>
        <label className="field">
          <span className="field-label">Hasło</span>
          <input className="input-field" type="password" value={password}
                 autoComplete="current-password" onChange={(e) => setPassword(e.target.value)} />
        </label>
        <label className="field">
          <span className="field-label">Kod</span>
          <input className="input-field code-input" value={code} inputMode="numeric"
                 maxLength={14} autoComplete="one-time-code" onChange={(e) => setCode(e.target.value)} />
        </label>
        {error && <div className="form-error" role="alert">{error}</div>}
        <button className="btn-ghost" type="submit" disabled={busy || !password || code.length < 6}>
          {busy ? 'Sprawdzam…' : 'Wyłącz weryfikację dwuetapową'}
        </button>
      </form>
    );
  } else if (setup) {
    body = (
      <div className="grid grid-2" style={{ alignItems: 'center' }}>
        {/* QR liczy serwer lokalnie (qrcode) - URI zawiera sekret, wiec nie
            moze trafic do zadnej zewnetrznej uslugi. */}
        <img src={`data:image/png;base64,${setup.qr_png_base64}`}
             alt="Kod QR do konfiguracji weryfikacji dwuetapowej"
             style={{ width: 190, background: '#fff', padding: 10, borderRadius: 'var(--radius-md)' }} />
        <form onSubmit={confirm} noValidate>
          <p className="dim" style={{ marginTop: 0 }}>
            Zeskanuj kod w aplikacji uwierzytelniającej (Google Authenticator, 1Password,
            Bitwarden…), a jeśli nie możesz — wpisz sekret ręcznie:
          </p>
          <div className="mono" style={{ ...box, margin: '10px 0', wordBreak: 'break-all',
                                         userSelect: 'all' }}>
            {setup.secret}
          </div>
          <label className="field">
            <span className="field-label">Kod z aplikacji</span>
            <input className="input-field code-input" value={code} inputMode="numeric"
                   maxLength={6} autoComplete="one-time-code" onChange={(e) => setCode(e.target.value)} />
          </label>
          {error && <div className="form-error" role="alert">{error}</div>}
          <button className="btn-primary" type="submit" disabled={busy || code.length < 6}
                  style={{ width: 'auto', padding: '12px 26px' }}>
            {busy ? 'Sprawdzam…' : 'Potwierdź i włącz'}
          </button>
        </form>
      </div>
    );
  } else if (!user.totp_available) {
    body = (
      <div className="notice">
        Weryfikacja dwuetapowa jest niedostępna: panel nie ma klucza szyfrującego
        (<code>PANEL_TOTP_KEY</code>). Administrator musi dodać go do sekretu
        <code> kidwatch-secrets</code> i zrestartować poda. Logowanie hasłem działa normalnie.
      </div>
    );
  } else {
    body = (
      <>
        <p className="dim" style={{ marginBottom: 12 }}>
          Weryfikacja dwuetapowa jest wyłączona — do panelu wystarcza samo hasło.
          Po włączeniu logowanie będzie wymagało też kodu z aplikacji w telefonie.
        </p>
        {error && <div className="form-error" role="alert">{error}</div>}
        <button className="btn-ghost" onClick={start} disabled={busy}>
          {busy ? 'Przygotowuję…' : 'Włącz weryfikację dwuetapową'}
        </button>
      </>
    );
  }

  return (
    <div className="glass-card" style={{ marginBottom: 18 }}>
      <div className="card-title">
        <span>Weryfikacja dwuetapowa</span>
        {!codes && onClose && <button className="btn-ghost" onClick={onClose}>Zamknij</button>}
      </div>
      {body}
    </div>
  );
}
