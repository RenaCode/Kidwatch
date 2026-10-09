import React, { useCallback, useEffect, useRef, useState } from 'react';
import Login from './components/Login';
import Day from './components/Day';
import Notifications from './components/Notifications';
import Profile from './components/Profile';
import Usage from './components/Usage';
import Screens from './components/Screens';
import Trends from './components/Trends';
import Mdm from './components/Mdm';
import Dashboard from './components/Dashboard';
import Icon from './components/Icons';
import ErrorBoundary from './components/ErrorBoundary';
import { TvPauseBanner } from './components/TvPause';
import { get, post, qs, useApi, setSessionExpiredHandler } from './utils/api';
import { localToday } from './utils/format';

// Pulpit renderuje Panel sam (potrzebuje pauzy TV i nawigacji), reszta
// dostaje wspolne propsy. `short`: etykieta w dolnym pasku telefonu.
const SECTIONS = [
  { key: 'pulpit',        label: 'Pulpit',           icon: 'pulpit',  Component: null },
  { key: 'notifications', label: 'Powiadomienia',    icon: 'bell',    Component: Notifications, short: 'Powiad.' },
  { key: 'screens',       label: 'Wszystkie ekrany', icon: 'screens', Component: Screens, short: 'Ekrany' },
  { key: 'usage',         label: 'Użycie',           icon: 'usage',   Component: Usage },
  { key: 'trends',        label: 'Trendy',           icon: 'trends',  Component: Trends },
  { key: 'day',           label: 'Dzień',            icon: 'day',     Component: Day },
  { key: 'mdm',           label: 'MDM',              icon: 'mdm',     Component: Mdm },
];
// Na telefonie w dolnym pasku miesci sie piec pozycji: cztery sekcje
// i "Wiecej" z reszta (oraz Ustawieniami).
const BOTTOM = ['pulpit', 'notifications', 'screens', 'usage'];

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

/* Podglad UI bez backendu - WYLACZNIE w `npm run dev` (import.meta.env.DEV).
   W buildzie produkcyjnym Vite podstawia false i caly kod podgladu znika:
   na produkcji nie ma przycisku, falszywego konta ani zmyslonych danych. */
function readPreview() {
  if (!import.meta.env.DEV) return false;
  try {
    return window.location.search.includes('preview')
      || window.localStorage.getItem('kidwatch_preview') === 'true';
  } catch { return false; }
}
const PREVIEW_META = {
  children: ['Jan', 'Anna'],
  devices: [
    { name: 'iPad Jan', child: 'Jan', icon: 'tablet' },
    { name: 'iPad Anna', child: 'Anna', icon: 'tablet' },
    { name: 'Telewizor', child: null, icon: 'tv' },
  ],
};

export default function App() {
  // 'checking' zapobiega mignieciu ekranu logowania u zalogowanego uzytkownika
  // przy odswiezeniu strony - dopiero odpowiedz /api/auth/me rozstrzyga.
  const [authState, setAuthState] = useState('checking');
  const [user, setUser] = useState(null);

  const isPreview = import.meta.env.DEV && readPreview();

  const checkSession = useCallback(async () => {
    if (isPreview) {
      setUser({ login: 'admin', role: 'admin', totp_enabled: true, backup_codes_left: 5 });
      setAuthState('in');
      return;
    }
    try {
      setUser(await get('/api/auth/me'));
      setAuthState('in');
    } catch {
      setUser(null);
      setAuthState('out');
    }
  }, [isPreview]);

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
  const close = useCallback(() => setOpen(false), []);
  const ref = useDismiss(open, close);
  const secure = user?.totp_enabled && user.backup_codes_left > 2;
  return (
    <div className="account" ref={ref}>
      <button className="account-btn" aria-haspopup="menu" aria-expanded={open}
              aria-label={`Konto ${user?.login}, ${user?.totp_enabled ? '2FA włączone' : 'bez 2FA'}`}
              onClick={() => setOpen((v) => !v)}>
        <span className="avatar-wrap">
          <span className="avatar">{(user?.login || '?').slice(0, 1).toUpperCase()}</span>
          <span className={`account-dot ${secure ? 'ok' : 'warn'}`} />
        </span>
        <span className="account-id">
          <strong>{user?.login}</strong>
          <span>{user?.role === 'admin' ? 'administrator' : (user?.role || '')}</span>
        </span>
        <Icon name="chevron" size={16} className="account-chev" />
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

// Zamykanie wysuwanego menu: klik poza nim albo Escape.
function useDismiss(open, close) {
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const outside = (e) => { if (ref.current && !ref.current.contains(e.target)) close(); };
    const esc = (e) => { if (e.key === 'Escape') close(); };
    document.addEventListener('mousedown', outside);
    document.addEventListener('touchstart', outside);
    document.addEventListener('keydown', esc);
    return () => {
      document.removeEventListener('mousedown', outside);
      document.removeEventListener('touchstart', outside);
      document.removeEventListener('keydown', esc);
    };
  }, [open, close]);
  return ref;
}

function ChildTabs({ items, child, onPick, className = '' }) {
  return (
    <div className={`child-tabs ${className}`} role="tablist" aria-label="Dziecko">
      {items.map((c) => (
        <button key={c || '*'} role="tab" aria-selected={child === c}
                className={`child-tab ${child === c ? 'active' : ''}`}
                onClick={() => onPick(c)}>
          {c ? <span className="child-initial" aria-hidden="true">{c.slice(0, 1).toUpperCase()}</span> : null}
          {c || 'Wszyscy'}
        </button>
      ))}
    </div>
  );
}

// Dolny pasek telefonu: cztery sekcje i "Wiecej" (reszta + Ustawienia).
function BottomNav({ section, profile, go, openProfile }) {
  const [open, setOpen] = useState(false);
  const close = useCallback(() => setOpen(false), []);
  const ref = useDismiss(open, close);
  const rest = SECTIONS.filter((s) => !BOTTOM.includes(s.key));
  const restActive = profile || rest.some((s) => s.key === section);
  return (
    <nav className="bottom-nav" aria-label="Sekcje" ref={ref}>
      {BOTTOM.map((k) => {
        const s = SECTIONS.find((x) => x.key === k);
        const active = !profile && section === k;
        return (
          <button key={k} className={`bottom-item ${active ? 'active' : ''}`}
                  aria-current={active ? 'page' : undefined} onClick={() => go(k)}>
            <Icon name={s.icon} size={22} />
            <span>{s.short || s.label}</span>
          </button>
        );
      })}
      <button className={`bottom-item ${restActive ? 'active' : ''}`} aria-haspopup="menu"
              aria-expanded={open} onClick={() => setOpen((v) => !v)}>
        <Icon name="more" size={22} />
        <span>Więcej</span>
      </button>
      {open && (
        <div className="bottom-sheet" role="menu">
          {rest.map((s) => (
            <button key={s.key} role="menuitem"
                    className={!profile && section === s.key ? 'active' : ''}
                    onClick={() => { close(); go(s.key); }}>
              <Icon name={s.icon} size={20} />{s.label}
            </button>
          ))}
          <button role="menuitem" className={profile ? 'active' : ''}
                  onClick={() => { close(); openProfile(); }}>
            <Icon name="settings" size={20} />Ustawienia
          </button>
        </div>
      )}
    </nav>
  );
}

function greeting(now = new Date()) {
  const h = now.getHours();
  if (h < 5 || h >= 18) return 'Dobry wieczór';
  return 'Dzień dobry';
}

// Osobny komponent, zeby odswiezanie co 30 s startowalo dopiero po zalogowaniu
// i znikalo razem z panelem - bez warunkow w hookach App.
function Panel({ user, onSignOut, onUserChanged }) {
  const [section, setSection] = useState('pulpit');
  const [profile, setProfile] = useState(false);
  const meta = useApi('/api/meta');
  const [child, setChildState] = useState(readChild);
  const setChild = (c) => { setChildState(c); saveChild(c); };

  // Zapamietane dziecko, ktorego nie ma juz w konfiguracji, wraca do
  // "Wszyscy" - inaczej kazdy widok dostawalby 400 az do recznego klikniecia.
  const activeMeta = meta.data || (import.meta.env.DEV && readPreview() ? PREVIEW_META : { children: [], devices: [] });

  useEffect(() => {
    if (child && activeMeta.children && !activeMeta.children.includes(child)) setChild('');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeMeta, child]);
  const known = !child || activeMeta.children.includes(child);

  const devices = useApi(known ? `/api/devices${qs({ child })}` : null, [], { refreshMs: 30000 });
  // Pauza monitoringu TV osobno od kart: baner ma byc takze przy wybranym
  // dziecku, gdy karty telewizora nie widac.
  const tvPause = useApi('/api/tv/pause', [], { refreshMs: 30000 });
  const tvPauseChanged = () => { tvPause.reload(); devices.reload(); };
  // Licznik przy dzwonku: powiadomienia z dzisiaj (do 100). Alarm czujki
  // albo zdjety profil DNS barwi plakietke na czerwono.
  const notesToday = useApi(known ? `/api/notifications${qs({ child, day: localToday(), limit: 100 })}` : null,
                            [], { refreshMs: 60000 });
  const notes = notesToday.data ? {
    count: notesToday.data.items.length,
    more: notesToday.data.has_more,
    critical: notesToday.data.items.some((n) => n.kind === 'watchdog' || n.kind === 'dns_profile'),
  } : null;

  const current = SECTIONS.find((s) => s.key === section) || SECTIONS[0];
  const Active = current.Component;
  const children = activeMeta.children || [];
  const showChildren = children.length > 1 || meta.data?.devices.some((d) => d.child == null);
  const childItems = ['', ...children];
  const go = (key) => { setSection(key); setProfile(false); window.scrollTo?.(0, 0); };
  const openProfile = () => { setProfile(true); window.scrollTo?.(0, 0); };
  const today = new Date().toLocaleDateString('pl-PL', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric' });
  const apiState = devices.error ? 'bad' : devices.data ? 'ok' : 'wait';

  return (
    <div className="shell">
      <aside className="sidebar" aria-label="Nawigacja">
        <div className="brand">
          <span className="brand-mark"><Icon name="logo" size={26} /></span>
          <span className="brand-name">Kidwatch</span>
        </div>
        {showChildren && <ChildTabs items={childItems} child={child} onPick={setChild} className="vertical" />}
        <nav className="side-nav" aria-label="Sekcje">
          {SECTIONS.map((s) => {
            const active = !profile && section === s.key;
            return (
              <button key={s.key} className={`side-item ${active ? 'active' : ''}`}
                      aria-current={active ? 'page' : undefined} onClick={() => go(s.key)}>
                <Icon name={s.icon} />{s.label}
                {s.key === 'notifications' && notes?.count > 0 && (
                  <span className={`side-count ${notes.critical ? 'critical' : ''}`}>
                    {notes.more ? '99+' : notes.count}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
        <div className="side-foot">
          <button className={`side-item ${profile ? 'active' : ''}`}
                  aria-current={profile ? 'page' : undefined} onClick={openProfile}>
            <Icon name="settings" />Ustawienia
          </button>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <span className="brand-mark mobile-only"><Icon name="logo" size={22} /></span>
          <div className="crumbs">
            <span className="crumb-brand hide-narrow">Kidwatch</span>
            <h1 className="crumb-title">{profile ? 'Ustawienia' : current.label}</h1>
            <span className="crumb-meta hide-mid">{today}</span>
            <span className="crumb-meta hide-mid">{greeting()}, {user?.login}!</span>
          </div>
          <div className="top-actions">
            <span className={`api-state ${apiState}`} role="status"
                  title={devices.error ? `Panel nie odpowiada: ${devices.error}` : 'Odświeżane co 30 s'}>
              <span className="api-dot" />
              <span className="hide-narrow">{apiState === 'bad' ? 'brak połączenia' : apiState === 'ok' ? 'na żywo' : 'łączenie…'}</span>
            </span>
            <button className="icon-btn" onClick={() => go('notifications')}
                    aria-label={notes ? `Powiadomienia: ${notes.more ? 'ponad ' : ''}${notes.count} dziś` : 'Powiadomienia'}>
              <Icon name="bell" />
              {notes?.count > 0 && (
                <span className={`bell-badge ${notes.critical ? 'critical' : ''}`} aria-hidden="true">
                  {notes.more ? '99+' : notes.count}
                </span>
              )}
            </button>
            <AccountMenu user={user} onProfile={openProfile} onSignOut={onSignOut} />
          </div>
        </header>

        {showChildren && <ChildTabs items={childItems} child={child} onPick={setChild} className="mobile-only" />}

        <TvPauseBanner pause={tvPause.data} onChanged={tvPauseChanged} />

        {devices.error && !devices.data && (
          <div className="notice" style={{ marginBottom: 16 }}>
            Nie udało się pobrać stanu: {devices.error}
          </div>
        )}

        {profile && (
          <Profile user={user} onChanged={onUserChanged} onClose={() => setProfile(false)}
                   tvPause={tvPause.data} onTvPauseChanged={tvPauseChanged} />
        )}

        {/* key: zmiana dziecka montuje widok od nowa - filtry i stronicowanie
            poprzedniego dziecka nie maja sensu dla nastepnego. */}
        {known && !profile && (
          <ErrorBoundary key={`${section}-${child}`}>
            {Active ? (
              <Active child={child} meta={meta.data} devices={devices.data || []} />
            ) : (
              <Dashboard child={child} devices={devices.data} onDevicesChanged={devices.reload}
                         tvPause={tvPause.data} onTvPauseChanged={tvPauseChanged}
                         notes={notes} onOpenSection={go} onOpenSettings={openProfile} />
            )}
          </ErrorBoundary>
        )}

        <footer className="app-footer">
          Kidwatch · liczby minut to dolne oszacowanie z zapytań DNS, nie czas przed ekranem ·{' '}
          <a href="https://renacode.com" target="_blank" rel="noopener noreferrer">RenaCode</a>
        </footer>
      </div>

      <BottomNav section={section} profile={profile} go={go} openProfile={openProfile} />
    </div>
  );
}
