import React, { useCallback, useEffect, useRef, useState } from 'react';
import Login from './components/Login';
import Devices from './components/Devices';
import Day from './components/Day';
import Notifications from './components/Notifications';
import Profile from './components/Profile';
import Usage from './components/Usage';
import Screens from './components/Screens';
import Trends from './components/Trends';
import Mdm from './components/Mdm';
import ErrorBoundary from './components/ErrorBoundary';
import { TvPauseBanner } from './components/TvPause';
import { get, post, qs, useApi, setSessionExpiredHandler } from './utils/api';

const SECTIONS = [
  { key: 'notifications', label: 'Powiadomienia', Component: Notifications },
  { key: 'screens',       label: 'Wszystkie ekrany', Component: Screens },
  { key: 'usage',         label: 'Użycie',        Component: Usage },
  { key: 'trends',        label: 'Trendy',        Component: Trends },
  { key: 'day',           label: 'Dzień',         Component: Day },
  { key: 'mdm',           label: 'MDM',           Component: Mdm },
];

/* Wybrane dziecko przezywa odswiezenie strony. localStorage w try/catch:
   tryb prywatny Safari i zablokowane dane witryny rzucaja przy samym
   dostepie, a panel ma wtedy dzialac jak bez pamieci, nie bialym ekranem. */
const CHILD_KEY = 'kidwatch.child';
function readChild() {
  try { return window.localStorage.getItem(CHILD_KEY) || ''; } catch { return ''; }
}
function saveChild(child) {
  try {
    if (child) window.localStorage.setItem(CHILD_KEY, child);
    else window.localStorage.removeItem(CHILD_KEY);
  } catch { /* bez pamieci wyboru - trudno */ }
}

export default function App() {
  // 'checking' zapobiega mignieciu ekranu logowania u zalogowanego uzytkownika
  // przy odswiezeniu strony - dopiero odpowiedz /api/auth/me rozstrzyga.
  const [authState, setAuthState] = useState('checking');
  const [user, setUser] = useState(null);

  const checkSession = useCallback(async () => {
    try {
      setUser(await get('/api/auth/me'));
      setAuthState('in');
    } catch {
      setUser(null);
      setAuthState('out');
    }
  }, []);

  useEffect(() => { checkSession(); }, [checkSession]);

  const signOut = useCallback(async () => {
    try { await post('/api/auth/logout'); } catch { /* sesja i tak przepada */ }
    setUser(null);
    setAuthState('out');
  }, []);

  // Sesja moze wygasnac w trakcie ogladania. Kazde 401 spoza logowania konczy
  // sie tutaj, niezaleznie od tego, ktory komponent wyslal zapytanie.
  useEffect(() => {
    setSessionExpiredHandler(() => { setUser(null); setAuthState('out'); });
    return () => setSessionExpiredHandler(null);
  }, []);

  if (authState === 'checking') {
    return <div className="login-shell"><div className="loading-pulse dim">Sprawdzanie sesji…</div></div>;
  }
  if (authState === 'out') {
    return <Login onSuccess={checkSession} />;
  }
  return <Panel user={user} onSignOut={signOut} onUserChanged={checkSession} />;
}

// Konto jako avatar z menu (Ustawienia, Wyloguj). Kropka na avatarze mowi o 2FA:
// zielona = wlaczone, pomaranczowa = wylaczone albo malo kodow zapasowych.
function AccountMenu({ user, onProfile, onSignOut }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const esc = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('mousedown', close);
    document.addEventListener('touchstart', close);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('mousedown', close);
      document.removeEventListener('touchstart', close);
      document.removeEventListener('keydown', esc);
    };
  }, [open]);
  const secure = user?.totp_enabled && user.backup_codes_left > 2;
  return (
    <div className="account" ref={ref}>
      <button className="account-btn" aria-haspopup="menu" aria-expanded={open}
              title={`${user?.login} · ${user?.totp_enabled ? '2FA włączone' : 'bez 2FA'}`}
              onClick={() => setOpen((v) => !v)}>
        <span className="avatar">{(user?.login || '?').slice(0, 1).toUpperCase()}</span>
        <span className={`account-dot ${secure ? 'ok' : 'warn'}`} />
      </button>
      {open && (
        <div className="account-menu" role="menu">
          <div className="account-head">
            <strong>{user?.login}</strong>
            <span className={`badge ${user?.totp_enabled ? 'ok' : 'warn'}`}>
              {user?.totp_enabled ? '2FA' : 'bez 2FA'}
            </span>
          </div>
          <button role="menuitem" onClick={() => { setOpen(false); onProfile(); }}>Ustawienia</button>
          <button role="menuitem" onClick={() => { setOpen(false); onSignOut(); }}>Wyloguj</button>
        </div>
      )}
    </div>
  );
}

// Osobny komponent, zeby odswiezanie co 30 s startowalo dopiero po zalogowaniu
// i znikalo razem z panelem - bez warunkow w hookach App.
function Panel({ user, onSignOut, onUserChanged }) {
  const [section, setSection] = useState('notifications');
  const [profile, setProfile] = useState(false);
  const meta = useApi('/api/meta');
  const [child, setChildState] = useState(readChild);
  const setChild = (c) => { setChildState(c); saveChild(c); };

  // Zapamietane dziecko, ktorego nie ma juz w konfiguracji, wraca do
  // "Wszyscy" - inaczej kazdy widok dostawalby 400 az do recznego klikniecia.
  useEffect(() => {
    if (child && meta.data && !meta.data.children.includes(child)) setChild('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [meta.data, child]);
  const known = !child || meta.data?.children.includes(child);

  const devices = useApi(known ? `/api/devices${qs({ child })}` : null, [], { refreshMs: 30000 });
  // Pauza monitoringu TV osobno od kart: baner ma byc takze przy wybranym
  // dziecku, gdy karty telewizora nie widac.
  const tvPause = useApi('/api/tv/pause', [], { refreshMs: 30000 });
  const tvPauseChanged = () => { tvPause.reload(); devices.reload(); };
  const Active = SECTIONS.find((s) => s.key === section)?.Component || Notifications;
  const children = meta.data?.children || [];

  return (
    <div className="app-container">
      <header className="app-header compact">
        <div className="logo-container">
          <div className="logo-icon">👀</div>
          <div className="hide-narrow">
            <div className="logo-text">Kidwatch</div>
            <div style={{ display: 'flex', gap: 6, marginTop: 3 }}>
              <span className={`logo-badge ${devices.error ? 'bad' : ''}`}
                    title={devices.error ? `Panel nie odpowiada: ${devices.error}` : 'Odświeżane co 30 s'}>
                {devices.error ? 'API ✗' : devices.data ? 'na żywo' : 'API …'}
              </span>
            </div>
          </div>
        </div>

        {/* Przelacznik dzieci: jeden rzad, przewijany w poziomie - na telefonie
            pigulki, chip konta i przyciski rozjezdzaly sie na trzy rzedy. */}
        {(children.length > 1 || meta.data?.devices.some((d) => d.child == null)) ? (
          <div className="engine-tabs child-tabs" role="tablist" aria-label="Dziecko">
            {['', ...children].map((c) => (
              <button key={c || '*'} role="tab" aria-selected={child === c}
                      className={`engine-tab ${child === c ? 'active' : ''}`}
                      onClick={() => setChild(c)}>
                {c || 'Wszyscy'}
              </button>
            ))}
          </div>
        ) : <div style={{ flex: 1 }} />}

        <AccountMenu user={user} onProfile={() => setProfile(true)} onSignOut={onSignOut} />
      </header>

      <TvPauseBanner pause={tvPause.data} onChanged={tvPauseChanged} />

      {profile && (
        <Profile user={user} onChanged={onUserChanged} onClose={() => setProfile(false)}
                 tvPause={tvPause.data} onTvPauseChanged={tvPauseChanged} />
      )}

      {devices.error && !devices.data && (
        <div className="notice" style={{ marginBottom: 16 }}>
          Nie udało się pobrać stanu: {devices.error}
        </div>
      )}

      {!profile && <Devices devices={devices.data} onChanged={devices.reload}
                            tvPause={tvPause.data} onTvPauseChanged={tvPauseChanged} />}

      {!profile && <nav className="nav-tabs" role="tablist" style={{ marginTop: 22 }}>
        {SECTIONS.map((s) => (
          <button key={s.key} role="tab" aria-selected={section === s.key}
                  className={`nav-tab ${section === s.key ? 'active' : ''}`}
                  onClick={() => setSection(s.key)}>
            {s.label}
          </button>
        ))}
      </nav>}

      {/* key: zmiana dziecka montuje widok od nowa - filtry i stronicowanie
          poprzedniego dziecka nie maja sensu dla nastepnego. */}
      {known && !profile && (
        <ErrorBoundary key={`${section}-${child}`}>
          <Active child={child} meta={meta.data} devices={devices.data || []} />
        </ErrorBoundary>
      )}

      <footer className="app-footer">
        Kidwatch · liczby minut to dolne oszacowanie z zapytań DNS, nie czas przed ekranem ·{' '}
        <a href="https://renacode.com" target="_blank" rel="noopener noreferrer">RenaCode</a>
      </footer>
    </div>
  );
}
