/* Ekran przyjecia zaproszenia: https://<panel>/zaproszenie#<token>
   (src/kidwatch/zaproszenia.py, docs/architektura-domy.md §7 E4).

   Token z fragmentu adresu trafia do pamieci karty (sessionStorage - odswiezenie
   strony nie gubi go) i od razu znika z paska adresu i historii. Serwer mowi,
   kto przyjmuje (`tryb`):
     - `sso`   - zalogowany przez Authelie; konto w Kidwatchu powstanie samo,
     - `sesja` - zalogowane konto panelu (haslem: wymaga wlaczonego 2FA),
     - `haslo` - bez SSO: nowe konto z wlasnym haslem; dane domu dopiero
                 po wlaczeniu 2FA (App pokazuje to zaraz po zalogowaniu).
   Przed przyjeciem informacja o prywatnosci (decyzja 5, §8): przyjecie jest
   potwierdzeniem jej przeczytania. */
import React, { useEffect, useState } from 'react';
import { post } from '../utils/api';
import { roleLabel } from '../utils/domy';
import { newAccountProblem, tokenFromHash } from '../utils/zaproszenia';

const TOKEN_KEY = 'kidwatch.zaproszenie';
/* Pierwsze wejscie przez Authelie: przekierowanie na portal i z powrotem
   gubi koncowke adresu (#token) zanim ta strona sie zaladuje - sessionStorage
   nie pomoze (strona nie zdazyla ruszyc). Stad prosba o ponowne otwarcie
   linku: drugi raz Authelia juz nie przekierowuje. */
const NO_TOKEN = 'W adresie nie ma tokenu zaproszenia. Jeśli przed chwilą logowałeś(-aś) się '
  + 'w SSO, logowanie zgubiło końcówkę linku — otwórz link z zaproszenia jeszcze raz '
  + '(teraz już bez logowania). Inaczej skopiuj link ponownie w całości.';
const HOME_KEY = 'kidwatch.dom';

function readToken() {
  const fromHash = tokenFromHash(window.location.hash);
  try {
    if (fromHash) {
      window.sessionStorage.setItem(TOKEN_KEY, fromHash);
    }
    // Token nie zostaje w pasku adresu ani w historii przegladarki.
    if (window.location.hash) window.history.replaceState(null, '', window.location.pathname);
    return fromHash || window.sessionStorage.getItem(TOKEN_KEY);
  } catch {
    return fromHash;
  }
}

function forgetToken() {
  try { window.sessionStorage.removeItem(TOKEN_KEY); } catch { /* trudno */ }
}

function goHome(domId) {
  try { window.localStorage.setItem(HOME_KEY, String(domId)); } catch { /* trudno */ }
  window.location.assign('/');
}

export default function Zaproszenie() {
  const [token] = useState(readToken);
  const [info, setInfo] = useState(null);
  const [error, setError] = useState(token ? null : NO_TOKEN);
  const [read, setRead] = useState(false);
  const [form, setForm] = useState({ login: '', haslo: '', haslo2: '' });
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(null);

  useEffect(() => {
    if (!token) return;
    post('/api/zaproszenia/sprawdz', { token }).then((r) => {
      setInfo(r);
      if (r.dla) setForm((f) => ({ ...f, login: r.dla }));
    }, (e) => setError(e.message));
  }, [token]);

  const problem = info?.tryb === 'haslo' ? newAccountProblem(form, info.min_haslo) : null;

  const accept = async (e) => {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const body = { token, potwierdzam: true };
      if (info.tryb === 'haslo') Object.assign(body, { login: form.login.trim(), haslo: form.haslo });
      const r = await post('/api/zaproszenia/przyjmij', body);
      forgetToken();
      if (info.tryb === 'haslo') {
        // Nowe konto bez 2FA: logowanie haslem i od razu ekran wlaczenia 2FA.
        await post('/api/auth/login', { login: r.login, password: form.haslo });
        goHome(r.dom_id);
        return;
      }
      if (r.zaloguj_ponownie) { setDone(r); return; }
      goHome(r.dom_id);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login-shell">
      <div className="login-card glass-card" style={{ maxWidth: 520 }}>
        <div className="login-card-head">
          <h1>Zaproszenie do Kidwatcha</h1>
          {info && (
            <p>
              Dom <strong>{info.dom}</strong>, rola <strong>{roleLabel(info.rola)}</strong>.
              Ważne do {new Date(info.wygasa_at).toLocaleString('pl-PL')}.
            </p>
          )}
        </div>
        {error && <div className="form-error" role="alert">{error}</div>}
        {!info && !error && <div className="loading-pulse dim">Sprawdzanie zaproszenia…</div>}
        {done && (
          <>
            <div className="notice info" role="status">
              Dołączono do domu. Zaloguj się ponownie, żeby go zobaczyć.
            </div>
            <a className="btn-primary" href="/">Przejdź do logowania</a>
          </>
        )}
        {info && !done && (
          <form onSubmit={accept} noValidate>
            <div className="notice" style={{ marginBottom: 12 }}>
              <strong>Prywatność.</strong> {info.informacja}
            </div>
            {info.tryb === 'sso' && (
              <p className="dim">
                Przyjmujesz jako <strong>{info.login}</strong> (konto z logowania SSO).
                {info.konto_istnieje === false && ' Konto w Kidwatchu zostanie założone.'}
              </p>
            )}
            {info.tryb === 'sesja' && (
              <p className="dim">Przyjmujesz jako <strong>{info.login}</strong>.</p>
            )}
            {info.tryb === 'haslo' && (
              <>
                <label className="field">
                  <span className="field-label">Login (a-z, 0-9, . _ -)</span>
                  <input className="input-field" autoComplete="username" value={form.login}
                         readOnly={!!info.dla}
                         onChange={(e) => setForm((f) => ({ ...f, login: e.target.value }))} />
                </label>
                <label className="field">
                  <span className="field-label">Hasło (co najmniej {info.min_haslo} znaków)</span>
                  <input className="input-field" type="password" autoComplete="new-password"
                         value={form.haslo}
                         onChange={(e) => setForm((f) => ({ ...f, haslo: e.target.value }))} />
                </label>
                <label className="field">
                  <span className="field-label">Powtórz hasło</span>
                  <input className="input-field" type="password" autoComplete="new-password"
                         value={form.haslo2}
                         onChange={(e) => setForm((f) => ({ ...f, haslo2: e.target.value }))} />
                </label>
                <p className="dim" style={{ fontSize: '0.8rem' }}>
                  Po przyjęciu włączysz weryfikację dwuetapową (aplikacja z kodami) — bez niej
                  dane domu się nie otworzą.
                </p>
              </>
            )}
            <label style={{ display: 'flex', gap: 8, alignItems: 'baseline', margin: '10px 0 14px' }}>
              <input type="checkbox" checked={read} onChange={(e) => setRead(e.target.checked)} />
              <span>Przeczytałem(-am) informację o prywatności i ją akceptuję.</span>
            </label>
            {problem && (form.login || form.haslo) && (
              <div className="form-error" style={{ marginBottom: 10 }}>{problem}</div>
            )}
            <button className="btn-primary" type="submit" disabled={busy || !read || !!problem}>
              {busy ? 'Przyjmuję…' : 'Przyjmij zaproszenie'}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
