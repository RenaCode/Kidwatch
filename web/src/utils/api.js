import { useCallback, useEffect, useRef, useState } from 'react';

/* Warstwa HTTP, ten sam model co w Trader-AI.

   Ciasteczko sesji jest HttpOnly, wiec JS go nie widzi i nie moze wyciec przez
   XSS. Token CSRF jest w osobnym, czytelnym ciasteczku i doklejamy go do kazdego
   POST - serwer porownuje go z tokenem zapisanym przy sesji. */
export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

function csrfToken() {
  const m = document.cookie.match(/(?:^|;\s*)kidwatch_csrf=([^;]+)/);
  return m ? decodeURIComponent(m[1]) : '';
}

/* Wygasniecie sesji obslugujemy w JEDNYM miejscu - tutaj - a nie propem
   przez cale drzewo. Odswiezanie w tle (useApi co 30 s) dostaje 401 tak samo
   jak klikniecie, i w obu przypadkach App ma wrocic do ekranu logowania. */
let sessionExpired = null;
export function setSessionExpiredHandler(fn) { sessionExpired = fn; }

/* 401 z POST /api/auth/* znaczy "zle dane" (zle haslo), nie "sesja wygasla".
   Ten blad nalezy do formularza logowania - wyrzucenie na ekran logowania
   zabraloby komunikat sprzed oczu. O stanie sesji rozstrzyga /api/auth/me. */
function isLoginFlow(path, method) {
  if (!path.startsWith('/api/auth/')) return false;
  return method !== 'GET' || path.startsWith('/api/auth/me');
}

async function request(path, { method = 'GET', body } = {}) {
  const headers = { Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (method !== 'GET' && method !== 'HEAD') headers['X-CSRF-Token'] = csrfToken();

  const res = await fetch(path, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  let payload = null;
  try { payload = await res.json(); } catch { /* np. 502 z Traefika */ }

  if (!res.ok) {
    if (res.status === 401 && !isLoginFlow(path, method)) sessionExpired?.();
    throw new ApiError(res.status, payload?.error || `HTTP ${res.status}`);
  }
  return payload;
}

export const get = (path) => request(path);
export const post = (path, body = {}) => request(path, { method: 'POST', body });

export function qs(params) {
  const q = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => { if (v !== '' && v != null) q.set(k, v); });
  const s = q.toString();
  return s ? `?${s}` : '';
}

// Odswiezanie w tle NIE czysci danych - przy chwilowym bledzie zostaje ostatni
// dobry stan, a blad jest widoczny obok, zamiast migajacego pustego ekranu.
// ZMIANA SCIEZKI (np. inne dziecko w przelaczniku) czysci - dane Kuby pod
// naglowkiem "Zosia", nawet przez pol sekundy, to klamstwo, nie ciaglosc.
// 401 obsluguje warstwa nizej (setSessionExpiredHandler).
export function useApi(path, deps = [], { refreshMs } = {}) {
  const [state, setState] = useState({ data: null, error: null, loading: !!path });
  // Straznik pokolenia jak w Traderze: odpowiedz na zapytanie, ktore zdazylo
  // sie zdezaktualizowac (szybkie przelaczanie dzieci), jest odrzucana -
  // inaczej spozniona odpowiedz poprzedniego dziecka nadpisalaby biezaca.
  const generation = useRef(0);

  const load = useCallback(async () => {
    if (!path) return;
    const mine = (generation.current += 1);
    try {
      const data = await get(path);
      if (mine === generation.current) setState({ data, error: null, loading: false });
    } catch (e) {
      if (mine === generation.current) setState((s) => ({ ...s, error: e.message, loading: false }));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, ...deps]);

  useEffect(() => {
    setState({ data: null, error: null, loading: !!path });
  }, [path]);

  useEffect(() => {
    load();
    if (!refreshMs) return undefined;
    const id = setInterval(load, refreshMs);
    return () => clearInterval(id);
  }, [load, refreshMs, path]);

  return { ...state, reload: load };
}
