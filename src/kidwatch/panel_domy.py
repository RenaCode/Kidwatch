"""Panel: kontekst domu zadania — kto widzi ktory dom i z jakimi uprawnieniami.

docs/architektura-domy.md §2.3, §4.1. Kazda trasa danych domu ma dom
w SCIEZCE (`/api/domy/<id>/...`), nigdy w ciasteczku ani w ciele zadania.
Ten modul rozstrzyga, czy sesja ma do niego dostep:

  1. czlonkostwo w domu -> uprawnienia z roli w domu i odstepstw
     (`uprawnienia.w_domu` — zakres `dom` i `konto`);
  2. bez czlonkostwa — tylko AKTYWNY administrator instalacji: flaga
     `users.admin_instancji` z bazy (nigdy z naglowka) ORAZ przy zadaniu
     przez Authelie grupa `admins` w `Remote-Groups`, a przy sesji z hasla
     (droga awaryjna, port-forward) wlaczony TOTP. Dostaje pelny zestaw
     uprawnien domu, a kazde wejscie idzie do `audyt` (GET: `admin.wglad`
     najwyzej raz na sesje i dom na 15 min, kazdy POST: `admin.<akcja>`);
  3. inaczej 404 „nie ma takiego domu” — tak samo dla domu, ktorego nie
     ma, i dla cudzego: odpowiedz nie zdradza, ze cudzy dom istnieje.

Stare trasy bez domu (`/api/day`) sa przez E3 aliasem domu, ale tylko gdy
konto widzi DOKLADNIE jeden dom; przy wiekszej liczbie 409 „wybierz dom”
zamiast cichego zgadywania.

`PanelQueries` per dom: kazdy dom ma wlasna baze zdarzen (§2.1), a obiekt
zapytan domu otwiera tylko ja — nie ma funkcji, ktora dostaje dom i czyta
plik innego domu.
"""

from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from zoneinfo import ZoneInfo

from . import domy as d
from . import uprawnienia as u
from .config import GameTimeConfig, TvConfig
from .panel_auth import AuthError, Session
from .panel_sso import GRUPA_ADMINOW

log = logging.getLogger(__name__)

#: Wglad (GET) administratora: jeden wpis na sesje i dom w tym oknie.
WGLAD_OKNO_SECONDS = 15 * 60

NIE_MA_DOMU = "Nie ma takiego domu"
#: Prefiks tras domu w tablicach panelu (panel.py: POST_TRASY, GET_TRASY).
PREFIKS_DOMU = "/api/domy/<id>"


@dataclass(frozen=True)
class WidokDomu:
    """Dom widoczny dla sesji (przelacznik w panelu, /api/auth/me)."""

    dom: d.Dom
    #: Rola w domu; None = wglad administratora bez czlonkostwa.
    rola: str | None
    uprawnienia: frozenset[str]

    @property
    def administracja(self) -> bool:
        return self.rola is None


@dataclass(frozen=True)
class KontekstDomu:
    """Dom zadania po sprawdzeniu dostepu."""

    dom_id: int
    nazwa: str
    #: Uprawnienia sesji W TYM domu (zakres `dom` i `konto`).
    uprawnienia: frozenset[str]
    #: Wejscie administratora bez czlonkostwa (kazde do `audyt`).
    administracja: bool
    #: Aktywny administrator instalacji (niezaleznie od czlonkostwa).
    admin: bool
    queries: object = field(repr=False, default=None)


@dataclass(frozen=True)
class BezKonfiguracji:
    """Dom bez konfiguracji w tym obrazie (zrodlo `baza` przed E2): panel
    pokazuje go bez urzadzen. Te same pola, ktore czyta PanelQueries."""

    timezone: str = "Europe/Warsaw"
    game_time: GameTimeConfig = field(default_factory=GameTimeConfig)
    tv: TvConfig = field(default_factory=TvConfig)
    devices: tuple = ()

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def watched(self) -> list:
        return []

    def child_profiles(self) -> dict[str, str]:
        return {}


def admin_aktywny(session: Session, grupy: tuple[str, ...] | None) -> bool:
    """Rola administratora instalacji dla TEGO zadania (§2.3).

    `grupy`: `Remote-Groups` zadania przez Authelie, None = zadanie bez
    naglowka SSO (haslo panelu). Flaga z bazy jest warunkiem koniecznym;
    grupa `admins` (SSO) albo TOTP (haslo) — drugim. Flaga omylkowo nadana
    prywatnemu kontu (grupa `wlasciciel`) nic wiec nie otwiera."""
    if not session.admin_instancji:
        return False
    if grupy is not None:
        return GRUPA_ADMINOW in grupy
    return session.kind == "haslo" and session.totp


def uprawnienia_sesji(session: Session, admin: bool) -> frozenset[str]:
    """Uprawnienia poza domem: konto + instancja (bot WhatsApp)."""
    return session.uprawnienia | (u.UPRAWNIENIA_INSTANCJI if admin else frozenset())


class DomyPanelu:
    """Rejestr domow panelu: dostep sesji, aliasy, audyt wejsc
    administratora i `PanelQueries` per dom (budowane leniwie)."""

    def __init__(
        self,
        auth_path: str,
        queries_domu: Callable[[d.Dom], object],
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.rejestr = d.RejestrDomow(auth_path)
        self._queries_domu = queries_domu
        self._queries: dict[int, object] = {}
        self._lock = threading.Lock()
        self._wglad: dict[tuple[str, int], float] = {}
        self.clock = clock

    # ------------------------------------------------------------- odczyt
    def queries(self, dom: d.Dom):
        with self._lock:
            q = self._queries.get(dom.id)
            if q is None:
                q = self._queries[dom.id] = self._queries_domu(dom)
            return q

    def widoczne(self, session: Session, admin: bool) -> list[WidokDomu]:
        """Domy sesji: jej czlonkostwa, a aktywnemu administratorowi takze
        reszta (oznaczona `administracja`). Kolejnosc: po id."""
        czl = {c.dom_id: c for c in self.rejestr.czlonkostwa(session.user_id)}
        out = []
        for dom in self.rejestr.domy():
            c = czl.get(dom.id)
            if c is not None:
                out.append(WidokDomu(dom, c.rola, u.w_domu(c.uprawnienia)))
            elif admin:
                out.append(WidokDomu(dom, None, u.UPRAWNIENIA_DOMU | u.STALE))
        return out

    def dostep(self, session: Session, dom_id: int, admin: bool) -> KontekstDomu:
        """Kontekst domu albo AuthError 404 (brak domu i cudzy dom wygladaja
        tak samo)."""
        dom = self.rejestr.dom(dom_id)
        if dom is None:
            raise AuthError(404, NIE_MA_DOMU)
        c = self.rejestr.czlonkostwo(session.user_id, dom_id)
        if c is not None:
            upr, administracja = u.w_domu(c.uprawnienia), False
        elif admin:
            upr, administracja = u.UPRAWNIENIA_DOMU | u.STALE, True
        else:
            log.warning("panel: %r bez dostepu do domu %d", session.login, dom_id)
            raise AuthError(404, NIE_MA_DOMU)
        return KontekstDomu(dom.id, dom.nazwa, upr, administracja, admin, self.queries(dom))

    def alias(self, session: Session, admin: bool) -> int:
        """Dom dla starej trasy bez domu: jedyny widoczny. Dwa i wiecej —
        409, zeby stary front nie dzialal po cichu na zlym domu."""
        widoczne = self.widoczne(session, admin)
        if not widoczne:
            raise AuthError(404, NIE_MA_DOMU)
        if len(widoczne) > 1:
            raise AuthError(409, "To konto widzi więcej niż jeden dom — wybierz dom "
                                 "(adres /api/domy/<id>/…).")
        return widoczne[0].dom.id

    # ------------------------------------------------------------- audyt
    def audytuj(self, session: Session, ctx: KontekstDomu, metoda: str, klucz: str) -> None:
        """Wejscie administratora do domu bez czlonkostwa. Blad zapisu
        przerywa zadanie (fail-closed): wglad bez sladu w dzienniku nie
        moze sie zdarzyc."""
        if not ctx.administracja:
            return
        akcja_trasy = klucz.removeprefix(PREFIKS_DOMU).strip("/").replace("/", ".") or "dom"
        if metoda == "GET":
            teraz = self.clock()
            key = (session.token_hash, ctx.dom_id)
            with self._lock:
                for k in [k for k, t in self._wglad.items() if teraz - t >= WGLAD_OKNO_SECONDS]:
                    del self._wglad[k]
                if key in self._wglad:
                    return
                self._wglad[key] = teraz
            akcja, opis = "admin.wglad", f"wgląd administratora (pierwszy: {akcja_trasy})"
        else:
            akcja, opis = f"admin.{akcja_trasy}", f"{metoda} {akcja_trasy}"
        try:
            self.rejestr.zapisz_audyt(ctx.dom_id, session.login, akcja, opis)
        except Exception as exc:
            if metoda == "GET":
                with self._lock:
                    self._wglad.pop((session.token_hash, ctx.dom_id), None)
            log.exception("panel: nie zapisano audytu wejscia administratora")
            raise AuthError(503, "Nie udało się zapisać wpisu w dzienniku domu") from exc
        log.info("panel: administrator %r w domu %d: %s", session.login, ctx.dom_id, akcja)
