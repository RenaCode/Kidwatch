"""Domy (gospodarstwa): model w panel-auth.db, migracja do Domu 1, srodowisko domu.

Projekt: docs/architektura-domy.md. Ten modul to etap E1 — model i migracja
bez zmiany zachowania. Instalacja ma dalej jeden dom (Dom 1) z konfiguracja
z config.yaml, ale:

  * w panel-auth.db sa tabele domow (§2.2) i Dom 1 z czlonkami;
  * monitoring Domu 1 chodzi w `HomeRuntime` pod `Nadzorca` — tym samym
    ukladem, w ktorym pozniej pojda kolejne domy;
  * baza zdarzen Domu 1 to dalej /data/kidwatch.db, bez kopiowania.

KONTRAKT DLA KOLEJNYCH ETAPOW (zamrozony w E1; zmiana = osobny PR z opisem):

  Stale:     DOM_1, NAZWA_DOMU_1, ZRODLO_YAML, ZRODLO_BAZA
  Sciezki:   sciezka_bazy_domu(dom_id, baza_domu_1), katalog_domu(...)
  Odczyt:    RejestrDomow(auth_path).domy() / .dom(id) / .czlonkowie(dom_id) /
             .czlonkostwa(user_id) / .czlonkostwo(user_id, dom_id) /
             .uprawnienia(user_id, dom_id) / .konta_bez_domu()
  Zapis:     RejestrDomow.ustaw_czlonkostwo(dom_id, user_id, rola, nadane, odebrane)
             (w Domu 1 takze lustro w users.rola + user_uprawnienia)
             ustaw_czlonkostwo_conn / uzgodnij_konto_conn — to samo na
             polaczeniu wolajacego, w jego transakcji (panel_auth.py)
  Migracja:  RejestrDomow.migruj(strefa=...) -> RaportMigracji (idempotentna)
  Srodowisko: HomeRuntime(dom_id, home, store, engine, outbox, source)
             + dodaj_petle(nazwa, fabryka) / dodaj_sprzatanie(fn) / start() /
             zamknij(); Nadzorca([HomeRuntime...]).run(stop) / zamknij()

ROZSZERZENIA E2 (addytywne; nic z kontraktu E1 nie znika):

  Model:     Dom + ustawienia, dozwolone_sieci, dozwolone_hosty, kek_id, ma_dek;
             Integracja (bez wartosci sekretow), SekretyDomu (dostawca sekretow
             domu dla HomeConfig), PlanDomu/DaneDomu (konfiguracja_domu.py)
  Stale:     TYPY_INTEGRACJI, POLA_SEKRETOW
  Odczyt:    RejestrDomow.integracje(dom_id) / .integracja(dom_id, typ) /
             .sekrety_domu(dom_id, sejf) / .dane_domu(dom_id) /
             .sprawdz(sejf) / .sprawdz_raport(sejf) / .straznik(dom_id)
  Zapis:     RejestrDomow.zapisz_integracje(dom_id, typ, sejf=..., ...) (sekrety
             tylko do zapisu: panel nigdy ich nie odczytuje) / .ustaw_zrodlo /
             .ustaw_sieci / .dodaj_dom / .rotuj_kek / .rotuj_dek /
             .zapisz_dane_domu (dom-importuj)
  Sciezki:   katalog_sekretow_domu(dom_id) — pliki z sekretow (klucz ADB,
             token aplikacji TV) w pamieci poda, nie na /data

Sekrety: sejf.py (KEK/DEK, AAD). Siec: straznik.py (SSRF, §3.6).

`uprawnienia(user_id, dom_id)` liczy WYLACZNIE z czlonkostwa: bez wiersza
pusty zbior. Wyjatek administratora instalacji (§2.3: flaga + grupa SSO
`admins` + wpis w `audyt`) zalezy od sesji i dochodzi w panelu, nad ta
funkcja.

ZRODLO PRAWDY O ROLACH W DOMU 1 (od E3a). Prawda sa `czlonkostwa`: panel
liczy z nich uprawnienia, a kazda zmiana idzie przez `ustaw_czlonkostwo_conn`
albo `usun_czlonkostwo_conn`, ktore w tej samej transakcji przepisuja
lustro do `users.rola` + `user_uprawnienia` (obraz sprzed domow czyta role
stamtad; lustro zyje do E4, §6 p. 7). Konto BEZ czlonkostwa w Domu 1 (konto
administracyjne, gosc innego domu z E4) ma w lustrze role `BEZ_DOMU` —
stary obraz nie zna jej i daje takiemu kontu tylko `konto.wlasne`.

Start (`uzgodnij_konto_conn`) nie nadaje juz czlonkostwa kazdemu kontu.
Lustro rozne od czlonkostwa oznacza zmiane zrobiona POZA tym kodem —
starym obrazem po wycofaniu albo reczna edycja bazy — i tylko taka zmiana
wraca do `czlonkostwa` (degradacja konta zrobiona w czasie wycofania nie
moze sie po powrocie cofnac). Konto z `BEZ_DOMU` zostaje bez domu.

Dopisane w E3a (addytywnie, kontrakt E1 bez zmian): `BEZ_DOMU`,
`zapisz_audyt`, `admin_instancji`, `ustaw_admin_instancji_conn`,
`usun_czlonkostwo_conn`, `czlonkostwo_conn`, `OstatniZarzadzajacy`
i odpowiedniki w `RejestrDomow` (`usun_czlonkostwo`,
`ustaw_admin_instancji`, `admin_instancji`, `zapisz_audyt`, `audyt`).

Dopisane w E3b (addytywnie): `RejestrDomow.dom_udidu(udid)` (druga bariera
MDM w panelu), `HomeRuntime.tetno` / `okres_tiku` / `dotknij_tetna()` (tetno
domu) i izolacja awarii w `Nadzorca(..., odbuduj=...)`: wyjatek w petli domu
albo tik stojacy dluzej niz 3x okres zatrzymuje TYLKO ten dom i uruchamia go
ponownie z narastajacym odstepem (1, 2, 4... do 30 min), z alarmem instancji
i czujka domu; plik tetna procesu (liveness) dotyka nadzorca. Bez `odbuduj`
— zachowanie E1 (koniec zadania = koniec procesu).
"""

from __future__ import annotations

import asyncio
import contextlib
import dataclasses
import json
import logging
import os
import sqlite3
import threading
import time
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import uprawnienia as upr
from .models import Notification, NotifyKind

if TYPE_CHECKING:
    from .config import HomeConfig
    from .engine import Engine
    from .notifiers.base import Outbox
    from .sejf import Sejf
    from .store import Store
    from .straznik import Straznik

log = logging.getLogger(__name__)

DOM_1 = 1
NAZWA_DOMU_1 = "Dom 1"
#: domy.zrodlo_konfiguracji: 'yaml' = config.yaml + zmienne srodowiskowe
#: (tylko Dom 1, etap przejsciowy), 'baza' = tabele ponizej (od E2).
ZRODLO_YAML = "yaml"
ZRODLO_BAZA = "baza"

#: Lustro `users.rola` konta, ktore NIE jest czlonkiem Domu 1. Obraz sprzed
#: domow nie zna tej roli: konto dostaje w nim tylko `konto.wlasne`.
BEZ_DOMU = "bez-domu"

#: Rola konta (users.rola) -> rola w Domu 1 i z powrotem.
ROLA_DOMU_Z_KONTA = {
    upr.ROLE_OWNER: upr.ROLA_WLASCICIEL_DOMU,
    upr.ROLE_VIEWER: upr.ROLA_PODGLAD,
}

SCHEMAT = """
-- Dom (gospodarstwo). id=1 to dom wlasciciela, zakladany przy migracji.
CREATE TABLE IF NOT EXISTS domy (
    id                  INTEGER PRIMARY KEY,
    nazwa               TEXT NOT NULL,
    strefa              TEXT NOT NULL DEFAULT 'Europe/Warsaw',
    -- 'yaml' = config.yaml (tylko dom 1, etap przejsciowy), 'baza' = tabele.
    zrodlo_konfiguracji TEXT NOT NULL DEFAULT 'baza',
    -- Ustawienia domu niebedace sekretami ani urzadzeniami (JSON, HomeConfig).
    ustawienia          TEXT NOT NULL DEFAULT '{}',
    -- Klucz danych domu zaszyfrowany kluczem z Sekretu (od E2).
    dek_zaszyfrowany    BLOB,
    kek_id              TEXT,
    -- Sieci, do ktorych integracje domu moga sie laczyc (CIDR, JSON).
    dozwolone_sieci     TEXT NOT NULL DEFAULT '[]',
    -- Hosty API spoza listy wbudowanej (nextdns.base_url, ntfy.server), JSON.
    -- Jak dozwolone_sieci: ustawia wylacznie administrator instancji (CLI).
    dozwolone_hosty     TEXT NOT NULL DEFAULT '[]',
    -- +1 przy kazdej zmianie: sygnal przeladowania srodowiska domu.
    wersja              INTEGER NOT NULL DEFAULT 1,
    zawieszony          INTEGER NOT NULL DEFAULT 0,
    utworzony_at        REAL NOT NULL
);

-- Konto <-> dom. Brak wiersza = konto nie widzi domu w ogole.
CREATE TABLE IF NOT EXISTS czlonkostwa (
    dom_id         INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    user_id        INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    rola           TEXT NOT NULL,     -- 'wlasciciel-domu' | 'zarzadca' | 'podglad'
    od             REAL NOT NULL,
    zaproszenie_id INTEGER,
    PRIMARY KEY (dom_id, user_id)
);
CREATE INDEX IF NOT EXISTS ix_czlonkostwa_user ON czlonkostwa (user_id);

-- Odstepstwa od roli W DOMU (nastepca user_uprawnienia).
CREATE TABLE IF NOT EXISTS czlonkostwa_uprawnienia (
    dom_id      INTEGER NOT NULL,
    user_id     INTEGER NOT NULL,
    uprawnienie TEXT NOT NULL,
    nadane      INTEGER NOT NULL,
    PRIMARY KEY (dom_id, user_id, uprawnienie),
    FOREIGN KEY (dom_id, user_id) REFERENCES czlonkostwa (dom_id, user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS dzieci (
    id        INTEGER PRIMARY KEY,
    dom_id    INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    nazwa     TEXT NOT NULL,
    kolejnosc INTEGER NOT NULL DEFAULT 0,
    UNIQUE (dom_id, nazwa)
);

CREATE TABLE IF NOT EXISTS urzadzenia (
    id              INTEGER PRIMARY KEY,
    dom_id          INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    dziecko_id      INTEGER REFERENCES dzieci (id),  -- NULL = wspolne (TV)
    rodzaj          TEXT NOT NULL,     -- 'ipad' | 'iphone' | 'phone-android' | 'tv'
    nazwa           TEXT NOT NULL,     -- = DeviceConfig.display_name = klucz w bazie domu
    source_ids      TEXT NOT NULL DEFAULT '[]',
    nextdns_profile TEXT,
    unifi_mac       TEXT,
    unifi_ip        TEXT,
    udid            TEXT,
    host            TEXT,
    mdm             INTEGER NOT NULL DEFAULT 0,
    ustawienia      TEXT NOT NULL DEFAULT '{}',
    UNIQUE (dom_id, nazwa)
);
-- UDID jest globalnie jednoznaczny: jedno urzadzenie nalezy do jednego domu.
CREATE UNIQUE INDEX IF NOT EXISTS ux_urzadzenia_udid ON urzadzenia (udid)
    WHERE udid IS NOT NULL;

-- Integracja domu: jawne ustawienia osobno, sekrety zaszyfrowane osobno (E2).
CREATE TABLE IF NOT EXISTS integracje (
    dom_id          INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    typ             TEXT NOT NULL,
    wlaczona        INTEGER NOT NULL DEFAULT 0,
    ustawienia      TEXT NOT NULL DEFAULT '{}',
    sekrety         BLOB,
    sekrety_pola    TEXT NOT NULL DEFAULT '[]',
    zmienione_przez TEXT,
    zmienione_at    REAL,
    PRIMARY KEY (dom_id, typ)
);

-- Ostatnia konfiguracja domu, na ktorej srodowisko WSTALO (nadzorca, `run`):
-- dom, dzieci, urzadzenia i integracje z sekretami nadal ZASZYFROWANYMI
-- kluczem domu. Start na niej, gdy biezaca wersja nie wstaje (§5.1).
CREATE TABLE IF NOT EXISTS domy_kopia (
    dom_id  INTEGER PRIMARY KEY REFERENCES domy (id) ON DELETE CASCADE,
    wersja  INTEGER NOT NULL,
    dane    TEXT NOT NULL,
    ts      REAL NOT NULL
);

-- Kto co zrobil w domu. Bez wartosci sekretow.
CREATE TABLE IF NOT EXISTS audyt (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      REAL NOT NULL,
    dom_id  INTEGER,                  -- NULL = zdarzenie instancji
    login   TEXT,
    akcja   TEXT NOT NULL,
    opis    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_audyt_dom ON audyt (dom_id, ts);
"""


# ===================================================================== model
@dataclass(frozen=True, slots=True)
class Dom:
    id: int
    nazwa: str
    strefa: str
    zrodlo_konfiguracji: str
    wersja: int
    zawieszony: bool
    # --- E2 (addytywnie, z wartosciami domyslnymi)
    #: Ustawienia domu niebedace integracjami (engine, watchdog, game_time...).
    ustawienia: dict = field(default_factory=dict, compare=False)
    #: CIDR-y, do ktorych integracje domu moga sie laczyc (straznik.py).
    dozwolone_sieci: tuple[str, ...] = ()
    #: Hosty API spoza listy wbudowanej (straznik.HOSTY_API).
    dozwolone_hosty: tuple[str, ...] = ()
    #: Ktorym kluczem KEK zapakowano DEK domu (None = dom bez DEK).
    kek_id: str | None = None
    ma_dek: bool = False


@dataclass(frozen=True, slots=True)
class Czlonkostwo:
    dom_id: int
    user_id: int
    login: str
    rola: str
    nadane: frozenset[str] = frozenset()
    odebrane: frozenset[str] = frozenset()

    @property
    def uprawnienia(self) -> frozenset[str]:
        return upr.efektywne(self.rola, self.nadane, self.odebrane,
                             role=upr.ROLE_DOMU_UPRAWNIENIA)


@dataclass(frozen=True, slots=True)
class RaportMigracji:
    """Co zmienil jeden przebieg migracji. Pusty = nic (drugi start)."""

    dom_1_zalozony: bool = False
    #: Loginy, ktorym dopisano albo poprawiono czlonkostwo w Domu 1.
    uzgodnione: tuple[str, ...] = ()
    #: Kolumny dodane do istniejacych tabel.
    kolumny: tuple[str, ...] = ()

    @property
    def zmiany(self) -> bool:
        return self.dom_1_zalozony or bool(self.uzgodnione) or bool(self.kolumny)


# ==================================================================== sciezki
def sciezka_bazy_domu(dom_id: int, baza_domu_1: str | Path) -> Path:
    """Baza zdarzen domu. Dom 1: dotychczasowa baza (store.path), bez
    przenoszenia. Kolejne: <katalog bazy Domu 1>/domy/<id>/kidwatch.db."""
    baza = Path(baza_domu_1).expanduser()
    if dom_id == DOM_1:
        return baza
    return baza.parent / "domy" / str(int(dom_id)) / "kidwatch.db"


def katalog_domu(dom_id: int, baza_domu_1: str | Path) -> Path:
    """Katalog plikow domu obok jego bazy (np. `tv-app/` z tokenem aplikacji
    TV). Dla Domu 1 to katalog bazy, jak przed domami."""
    return sciezka_bazy_domu(dom_id, baza_domu_1).parent


# ===================================================================== lustro
def _jest_tabela(conn: sqlite3.Connection, nazwa: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (nazwa,)
    ).fetchone() is not None


def _odstepstwa(rows) -> tuple[frozenset[str], frozenset[str]]:
    nadane, odebrane = set(), set()
    for r in rows:
        (nadane if r[1] else odebrane).add(r[0])
    return frozenset(nadane), frozenset(odebrane)


Stan = tuple[str, frozenset[str], frozenset[str]]


def _stan_konta(conn: sqlite3.Connection, user_id: int) -> Stan | None:
    if conn.execute("SELECT 1 FROM users WHERE id = ?", (user_id,)).fetchone() is None:
        return None
    # Baza sprzed rol (#44) nie ma kolumny `rola` ani tabeli odstepstw;
    # PanelAuth doda je z wartoscia 'wlasciciel' — tak samo liczymy tutaj.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    rola = upr.ROLE_OWNER
    if "rola" in cols:
        rola = conn.execute("SELECT rola FROM users WHERE id = ?", (user_id,)).fetchone()[0]
    nadane: frozenset[str] = frozenset()
    odebrane: frozenset[str] = frozenset()
    if _jest_tabela(conn, "user_uprawnienia"):
        nadane, odebrane = _odstepstwa(conn.execute(
            "SELECT uprawnienie, nadane FROM user_uprawnienia WHERE user_id = ?", (user_id,)
        ))
    return rola, nadane, odebrane


def _stan_czlonkostwa(conn: sqlite3.Connection, dom_id: int, user_id: int) -> Stan | None:
    row = conn.execute(
        "SELECT rola FROM czlonkostwa WHERE dom_id = ? AND user_id = ?", (dom_id, user_id)
    ).fetchone()
    if row is None:
        return None
    nadane, odebrane = _odstepstwa(conn.execute(
        "SELECT uprawnienie, nadane FROM czlonkostwa_uprawnienia "
        "WHERE dom_id = ? AND user_id = ?", (dom_id, user_id)
    ))
    return row[0], nadane, odebrane


def czlonkostwo_conn(conn: sqlite3.Connection, user_id: int,
                     dom_id: int) -> tuple[str, frozenset[str], frozenset[str]] | None:
    """(rola, nadane, odebrane) konta w domu albo None — na polaczeniu
    wolajacego (PanelAuth liczy z tego uprawnienia sesji)."""
    if not _jest_tabela(conn, "czlonkostwa"):
        return None
    return _stan_czlonkostwa(conn, dom_id, user_id)


#: Uprawnienia dodane w E3a — obraz E1 i starsze ich nie znaja.
_NOWE_E3A = frozenset({upr.DOM_URZADZENIA, upr.DOM_INTEGRACJE, upr.DOM_ZAPROSZENIA})


def lustro_konta(stan: Stan) -> Stan:
    """Rola w Domu 1 -> to, co ma zobaczyc obraz sprzed domow w `users`.

    `wlasciciel-domu` i `podglad` przechodza wprost (z odstepstwami).
    `zarzadca` nie ma odpowiednika: zapisujemy `podglad` z nadaniami
    i odebraniami, ktore daja dokladnie te same uprawnienia efektywne.
    Nieznana rola idzie bez zmian (efektywnie: tylko STALE, jak dzis)."""
    rola, nadane, odebrane = stan
    wprost = {v: k for k, v in ROLA_DOMU_Z_KONTA.items()}
    if rola in wprost:
        return wprost[rola], nadane, odebrane
    if rola in upr.ROLE_DOMU_UPRAWNIENIA:
        # Bez uprawnien, ktorych obraz sprzed E3a nie zna: on liczy to samo
        # lustro bez nich i przy roznicy nadpisalby czlonkostwo (zarzadca
        # po wycofaniu i powrocie stalby sie `podglad` z nadaniami).
        cel = upr.efektywne(rola, nadane, odebrane, role=upr.ROLE_DOMU_UPRAWNIENIA) - _NOWE_E3A
        baza = upr.ROLE_UPRAWNIENIA[upr.ROLE_VIEWER]
        return upr.ROLE_VIEWER, frozenset(cel - baza), frozenset(baza - cel - upr.STALE)
    return stan


def rola_z_konta(stan: Stan) -> Stan:
    """`users` -> rola w Domu 1 (odwrotnosc lustra dla rol kont)."""
    rola, nadane, odebrane = stan
    return ROLA_DOMU_Z_KONTA.get(rola, rola), nadane, odebrane


def _zapisz_czlonkostwo(conn: sqlite3.Connection, dom_id: int, user_id: int, stan: Stan,
                        teraz: float) -> None:
    rola, nadane, odebrane = stan
    conn.execute(
        "INSERT INTO czlonkostwa (dom_id, user_id, rola, od) VALUES (?, ?, ?, ?) "
        "ON CONFLICT (dom_id, user_id) DO UPDATE SET rola = excluded.rola",
        (dom_id, user_id, rola, teraz),
    )
    conn.execute("DELETE FROM czlonkostwa_uprawnienia WHERE dom_id = ? AND user_id = ?",
                 (dom_id, user_id))
    conn.executemany(
        "INSERT INTO czlonkostwa_uprawnienia (dom_id, user_id, uprawnienie, nadane) "
        "VALUES (?, ?, ?, ?)",
        [(dom_id, user_id, n, 1) for n in sorted(nadane)]
        + [(dom_id, user_id, n, 0) for n in sorted(odebrane)],
    )


def _zapisz_konto(conn: sqlite3.Connection, user_id: int, stan: Stan) -> None:
    rola, nadane, odebrane = stan
    conn.execute("UPDATE users SET rola = ? WHERE id = ?", (rola, user_id))
    conn.execute("DELETE FROM user_uprawnienia WHERE user_id = ?", (user_id,))
    conn.executemany(
        "INSERT INTO user_uprawnienia (user_id, uprawnienie, nadane) VALUES (?, ?, ?)",
        [(user_id, n, 1) for n in sorted(nadane)] + [(user_id, n, 0) for n in sorted(odebrane)],
    )


def _dom_istnieje(conn: sqlite3.Connection, dom_id: int) -> bool:
    return _jest_tabela(conn, "domy") and conn.execute(
        "SELECT 1 FROM domy WHERE id = ?", (dom_id,)
    ).fetchone() is not None


def uzgodnij_konto_conn(conn: sqlite3.Connection, user_id: int,
                        teraz: float | None = None) -> bool:
    """Start: czlonkostwo w Domu 1 a lustro w `users` (od E3a prawda jest
    czlonkostwo, docstring modulu).

    - lustro zgodne z czlonkostwem — nic (takze `zarzadca` zapisany jako
      `podglad` + nadania);
    - lustro rozne — zmiana zrobiona starym obrazem albo recznie: wraca do
      czlonkostwa (`users.rola = BEZ_DOMU` = konto wypisane z Domu 1);
    - konto bez czlonkostwa z lustrem `BEZ_DOMU` — zostaje bez domu;
    - konto bez czlonkostwa z rola konta (zalozone starym obrazem po
      wycofaniu) — czlonek Domu 1 z ta rola, jak przed domami; konto
      z flaga `admin_instancji` zamiast tego dostaje lustro `BEZ_DOMU`.

    Na polaczeniu i w transakcji wolajacego. Zwraca, czy cos zapisano."""
    if not _dom_istnieje(conn, DOM_1):
        return False
    konto = _stan_konta(conn, user_id)
    if konto is None:
        return False
    obecne = _stan_czlonkostwa(conn, DOM_1, user_id)
    if obecne is not None:
        if obecne[0] == BEZ_DOMU or (konto[0] == BEZ_DOMU and obecne[0] not in upr.ROLE_DOMU):
            # Obraz z E1 dopisuje czlonkostwo kazdemu kontu, takze z lustrem
            # BEZ_DOMU (rola przechodzi bez zmian) — sprzatamy je.
            _usun_wiersz_czlonkostwa(conn, DOM_1, user_id)
            return True
        if lustro_konta(obecne) == konto:
            return False
        if konto[0] == BEZ_DOMU:
            _usun_wiersz_czlonkostwa(conn, DOM_1, user_id)
            return True
        _zapisz_czlonkostwo(conn, DOM_1, user_id, rola_z_konta(konto),
                            time.time() if teraz is None else teraz)
        return True
    if konto[0] == BEZ_DOMU:
        return False
    if admin_instancji(conn, user_id):
        _zapisz_konto(conn, user_id, (BEZ_DOMU, frozenset(), frozenset()))
        return True
    _zapisz_czlonkostwo(conn, DOM_1, user_id, rola_z_konta(konto),
                        time.time() if teraz is None else teraz)
    return True


def _usun_wiersz_czlonkostwa(conn: sqlite3.Connection, dom_id: int, user_id: int) -> None:
    # czlonkostwa_uprawnienia i czlonkostwa_powiadomienia znikaja kaskada (FK).
    conn.execute("DELETE FROM czlonkostwa WHERE dom_id = ? AND user_id = ?", (dom_id, user_id))


def admin_instancji(conn: sqlite3.Connection, user_id: int) -> bool:
    """Flaga administratora instalacji z bazy (§2.3). Sama flaga niczego nie
    otwiera — panel wymaga jeszcze grupy `admins` (SSO) albo TOTP (haslo)."""
    try:
        row = conn.execute("SELECT admin_instancji FROM users WHERE id = ?",
                           (user_id,)).fetchone()
    except sqlite3.OperationalError:
        return False
    return bool(row and row[0])


#: Nazwa z E1, zostawiona dla zgodnosci.
_admin_instancji = admin_instancji

#: Wartosci `users.admin_instancji`: 0 — nie; 1 — administrator (przez
#: Authelie z grupa `admins` albo haslem z TOTP); 2 — administrator TYLKO
#: przez Authelie: sesja z hasla nigdy nie daje roli, nawet z TOTP (przeglad
#: E3a, B-2). Obraz sprzed E3a czyta kolumne jako prawde/falsz i roli
#: administratora nie zna — 2 nic w nim nie otwiera.
ADMIN = 1
ADMIN_TYLKO_SSO = 2


def tryb_admina(conn: sqlite3.Connection, user_id: int) -> int:
    """0, ADMIN albo ADMIN_TYLKO_SSO. Nieznana wartosc (reczna edycja) =
    ADMIN_TYLKO_SSO: wezsza droga, nie szersza."""
    try:
        row = conn.execute("SELECT admin_instancji FROM users WHERE id = ?",
                           (user_id,)).fetchone()
    except sqlite3.OperationalError:
        return 0
    if not row or not row[0]:
        return 0
    return ADMIN if row[0] == ADMIN else ADMIN_TYLKO_SSO


def ustaw_admin_instancji_conn(conn: sqlite3.Connection, user_id: int, wlaczona: bool,
                               teraz: float | None = None, *, tylko_sso: bool = False) -> bool:
    """Flaga `admin_instancji` (tylko CLI `user-admin`); `tylko_sso` —
    rola wylacznie przez Authelie. Zwraca, czy sie zmienila; zmiana idzie do
    `audyt` jako zdarzenie instancji."""
    row = conn.execute("SELECT login, admin_instancji FROM users WHERE id = ?",
                       (user_id,)).fetchone()
    if row is None:
        raise LookupError(f"nie ma konta {user_id}")
    nowa = (ADMIN_TYLKO_SSO if tylko_sso else ADMIN) if wlaczona else 0
    if tryb_admina(conn, user_id) == nowa:
        return False
    conn.execute("UPDATE users SET admin_instancji = ? WHERE id = ?", (nowa, user_id))
    opis = {0: "odebrany", ADMIN: "nadany", ADMIN_TYLKO_SSO: "nadany (tylko przez Authelie)"}
    zapisz_audyt(conn, None, row[0], "instancja.admin",
                 f"administrator instalacji: {opis[nowa]}", teraz)
    return True


class ZmianaWersji(Exception):
    """Zapis z nieaktualnej wersji konfiguracji domu (kontrola wspolbieznosci)."""


class OstatniZarzadzajacy(ValueError):
    """Zmiana zostawilaby dom bez czlonka z `konta.zarzadzanie` (§2.3)."""


def _zarzadzajacy(conn: sqlite3.Connection, dom_id: int) -> set[int]:
    out = set()
    for (uid,) in conn.execute("SELECT user_id FROM czlonkostwa WHERE dom_id = ?", (dom_id,)):
        stan = _stan_czlonkostwa(conn, dom_id, uid)
        if stan and upr.KONTA in upr.efektywne(*stan, role=upr.ROLE_DOMU_UPRAWNIENIA):
            out.add(uid)
    return out


def _pilnuj_zarzadzajacego(conn: sqlite3.Connection, dom_id: int, przed: set[int]) -> None:
    """Dom, ktory mial kogos z `konta.zarzadzanie`, nie moze go stracic —
    zostaloby tylko CLI. Dom bez takiego czlonka (swiezy) moze rosnac."""
    if przed and not _zarzadzajacy(conn, dom_id):
        raise OstatniZarzadzajacy(
            "w domu musi zostać co najmniej jedno konto z zarządzaniem kontami"
        )


def _wyloguj(conn: sqlite3.Connection, user_id: int) -> None:
    """Sesje i bilety konta po zmianie jego czlonkostwa — jak PanelAuth.set_role:
    front rysuje przyciski i domy z /api/auth/me, a po odebraniu uprawnien
    mialby je na ekranie do odswiezenia (uprawnienia serwer i tak czyta przy
    kazdym zadaniu)."""
    for tabela in ("sessions", "tickets"):
        if _jest_tabela(conn, tabela):
            conn.execute(f"DELETE FROM {tabela} WHERE user_id = ?", (user_id,))  # noqa: S608


def ustaw_czlonkostwo_conn(conn: sqlite3.Connection, dom_id: int, user_id: int, rola: str,
                           nadane: frozenset[str] = frozenset(),
                           odebrane: frozenset[str] = frozenset(),
                           teraz: float | None = None) -> None:
    """Rola konta w domu. W Domu 1 takze lustro w `users` (obraz sprzed
    domow czyta role stamtad). Sesje konta sa uniewazniane. Na polaczeniu
    i w transakcji wolajacego.
    `OstatniZarzadzajacy`, gdy dom stracilby ostatniego zarzadzajacego —
    wolajacy wycofuje transakcje."""
    if rola not in upr.ROLE_DOMU:
        raise ValueError(f"nieznana rola w domu {rola!r} (dozwolone: {', '.join(upr.ROLE_DOMU)})")
    zle = (set(nadane) | set(odebrane)) - set(upr.UPRAWNIENIA)
    if zle or set(odebrane) & upr.STALE:
        raise ValueError(f"niedozwolone odstepstwa: {sorted(zle or set(odebrane) & upr.STALE)}")
    if not _dom_istnieje(conn, dom_id):
        raise LookupError(f"nie ma domu {dom_id}")
    przed = _zarzadzajacy(conn, dom_id)
    stan = (rola, frozenset(nadane), frozenset(odebrane))
    _zapisz_czlonkostwo(conn, dom_id, user_id, stan, time.time() if teraz is None else teraz)
    if dom_id == DOM_1:
        _zapisz_konto(conn, user_id, lustro_konta(stan))
    _pilnuj_zarzadzajacego(conn, dom_id, przed)
    _wyloguj(conn, user_id)


def usun_czlonkostwo_conn(conn: sqlite3.Connection, dom_id: int, user_id: int) -> bool:
    """Wypisuje konto z domu (z odstepstwami i preferencjami powiadomien
    w tym domu). W Domu 1 lustro `BEZ_DOMU`. Konto zostaje — o jego
    usunieciu decyduje wolajacy. Zwraca, czy czlonkostwo bylo."""
    if _stan_czlonkostwa(conn, dom_id, user_id) is None:
        return False
    przed = _zarzadzajacy(conn, dom_id)
    _usun_wiersz_czlonkostwa(conn, dom_id, user_id)
    if dom_id == DOM_1:
        _zapisz_konto(conn, user_id, (BEZ_DOMU, frozenset(), frozenset()))
    _pilnuj_zarzadzajacego(conn, dom_id, przed)
    _wyloguj(conn, user_id)
    return True


# =================================================================== migracja
def _dodaj_kolumne(conn: sqlite3.Connection, tabela: str, kolumna: str, ddl: str) -> bool:
    if not _jest_tabela(conn, tabela):
        return False
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({tabela})")}
    if kolumna in cols:
        return False
    conn.execute(f"ALTER TABLE {tabela} ADD COLUMN {kolumna} {ddl}")
    return True


def migruj_conn(conn: sqlite3.Connection, *, strefa: str | None = None,
                teraz: float | None = None) -> RaportMigracji:
    """Schemat domow + Dom 1 + uzgodnienie czlonkostw z `users` (§6 p. 2).

    Idempotentna: drugi przebieg niczego nie zapisuje. Tylko nowe tabele
    i kolumny z wartosciami domyslnymi — obraz sprzed domow ich nie czyta.
    `admin_instancji` nie jest nadawana nikomu. Wlasna transakcja."""
    teraz = time.time() if teraz is None else teraz
    conn.executescript(SCHEMAT)
    conn.execute("BEGIN IMMEDIATE")
    try:
        kolumny = []
        if _dodaj_kolumne(conn, "users", "admin_instancji", "INTEGER NOT NULL DEFAULT 0"):
            kolumny.append("users.admin_instancji")
        # E2: baza zalozona przez E1 nie ma tej kolumny (stary obraz jej nie czyta).
        if _dodaj_kolumne(conn, "domy", "dozwolone_hosty", "TEXT NOT NULL DEFAULT '[]'"):
            kolumny.append("domy.dozwolone_hosty")
        zalozony = False
        if conn.execute("SELECT 1 FROM domy LIMIT 1").fetchone() is None:
            conn.execute(
                "INSERT INTO domy (id, nazwa, strefa, zrodlo_konfiguracji, utworzony_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (DOM_1, NAZWA_DOMU_1, strefa or "Europe/Warsaw", ZRODLO_YAML, teraz),
            )
            _audyt(conn, teraz, DOM_1, None, "migracja.dom1",
                   "Dom 1 założony z konfiguracji config.yaml")
            zalozony = True
        uzgodnione = []
        if _dom_istnieje(conn, DOM_1) and _jest_tabela(conn, "users"):
            # Sieroty po koncie usunietym bez kluczy obcych (reczna edycja).
            conn.execute("DELETE FROM czlonkostwa WHERE user_id NOT IN (SELECT id FROM users)")
            conn.execute(
                "DELETE FROM czlonkostwa_uprawnienia WHERE NOT EXISTS (SELECT 1 FROM czlonkostwa c "
                "WHERE c.dom_id = czlonkostwa_uprawnienia.dom_id "
                "AND c.user_id = czlonkostwa_uprawnienia.user_id)"
            )
            for uid, login in conn.execute("SELECT id, login FROM users ORDER BY id").fetchall():
                if uzgodnij_konto_conn(conn, uid, teraz):
                    rola = _stan_czlonkostwa(conn, DOM_1, uid)
                    _audyt(conn, teraz, DOM_1, login, "migracja.czlonkostwo",
                           f"rola w Domu 1 z roli konta: {rola[0]}" if rola
                           else "konto wypisane z Domu 1 (lustro bez domu)")
                    uzgodnione.append(login)
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    return RaportMigracji(zalozony, tuple(uzgodnione), tuple(kolumny))


def _audyt(conn: sqlite3.Connection, ts: float, dom_id: int | None, login: str | None,
           akcja: str, opis: str) -> None:
    conn.execute("INSERT INTO audyt (ts, dom_id, login, akcja, opis) VALUES (?, ?, ?, ?, ?)",
                 (ts, dom_id, login, akcja, opis))


def zapisz_audyt(conn: sqlite3.Connection, dom_id: int | None, login: str | None, akcja: str,
                 opis: str, ts: float | None = None) -> None:
    """Wiersz dziennika (§2.2 `audyt`). `opis` bez wartosci sekretow."""
    _audyt(conn, time.time() if ts is None else ts, dom_id, login, akcja, opis[:500])


# ================================================================ integracje (E2)
TYPY_INTEGRACJI = ("nextdns", "adguard", "unifi", "tv", "mdm", "ntfy", "homeassistant")
#: Pola sekretow integracji — wszystko inne w integracji jest jawne.
POLA_SEKRETOW: dict[str, tuple[str, ...]] = {
    "nextdns": ("api_key",),
    "adguard": ("password",),
    "unifi": ("api_key",),
    # Klucz ADB (PEM) i token aplikacji TV sa czytane z pliku: srodowisko
    # domu zapisuje je przy starcie do katalogu w pamieci poda (§3.1).
    "tv": ("sony_psk", "adb_key", "adb_key_pub", "app_token"),
    "mdm": ("token",),
    # Nazwa tematu ntfy.sh JEST haslem (config.NtfyConfig).
    "ntfy": ("topic", "token"),
    "homeassistant": ("webhook_id",),
}
#: Katalog plikow z sekretami domow (emptyDir medium: Memory w chartcie).
KATALOG_SEKRETOW_ENV = "KIDWATCH_KATALOG_SEKRETOW"
KATALOG_SEKRETOW = "/run/kidwatch"


def katalog_sekretow_domu(dom_id: int, baza: str | Path | None = None) -> Path:
    """Pliki z sekretow domu (adb/adbkey, tv-app/token) — w pamieci poda,
    nie na wolumenie /data: na dysku leza tylko szyfrogramy."""
    korzen = Path(baza or os.environ.get(KATALOG_SEKRETOW_ENV) or KATALOG_SEKRETOW)
    return korzen / "domy" / str(int(dom_id))


@dataclass(frozen=True, slots=True)
class Integracja:
    """Integracja domu BEZ wartosci sekretow (panel, CLI): jakie pola sa
    ustawione, kto i kiedy zmienil."""

    dom_id: int
    typ: str
    wlaczona: bool
    ustawienia: dict = field(default_factory=dict, compare=False)
    sekrety_pola: tuple[str, ...] = ()
    zmienione_przez: str | None = None
    zmienione_at: float | None = None


class SekretyDomu:
    """Odszyfrowane sekrety JEDNEGO domu w pamieci srodowiska domu —
    dostawca dla `HomeConfig.ustaw_srodowisko` (config.DostawcaSekretow).

    repr/str pokazuja tylko nazwy pol, nigdy wartosci. `zapisz` (token
    aplikacji TV po sparowaniu) idzie do bazy przez `zapisywacz`."""

    def __init__(self, dom_id: int, wartosci: Mapping[str, Mapping[str, str]] | None = None,
                 zapisywacz: Callable[[str, dict[str, str | None]], None] | None = None) -> None:
        self.dom_id = dom_id
        self._w = {typ: dict(p) for typ, p in (wartosci or {}).items()}
        self._zapisywacz = zapisywacz

    def get(self, typ: str, pole: str) -> str | None:
        return self._w.get(typ, {}).get(pole)

    def typu(self, typ: str) -> dict[str, str]:
        return dict(self._w.get(typ, {}))

    def pola(self) -> dict[str, tuple[str, ...]]:
        return {typ: tuple(sorted(p)) for typ, p in sorted(self._w.items()) if p}

    def zapisz(self, typ: str, pole: str, wartosc: str) -> None:
        if self._zapisywacz is None:
            raise RuntimeError(f"dom {self.dom_id}: sekrety tylko do odczytu")
        self._zapisywacz(typ, {pole: wartosc})
        self._w.setdefault(typ, {})[pole] = wartosc

    def __repr__(self) -> str:
        return f"SekretyDomu(dom={self.dom_id}, pola={self.pola()})"

    __str__ = __repr__


@dataclass
class PlanDomu:
    """Konfiguracja domu w ksztalcie tabel (konfiguracja_domu.plan_z_home):
    to, co `dom-importuj` zapisuje, i to, z czego powstaje HomeConfig."""

    strefa: str
    ustawienia: dict
    dzieci: list[str]
    #: Wiersze `urzadzenia`: nazwa, dziecko (nazwa albo None), rodzaj,
    #: source_ids, nextdns_profile, unifi_mac, unifi_ip, udid, host, ustawienia.
    urzadzenia: list[dict]
    #: typ -> (wlaczona, jawne ustawienia)
    integracje: dict[str, tuple[bool, dict]]
    #: typ -> {pole: wartosc}; poza `dozwolone_*` jedyne miejsce z sekretami.
    sekrety: dict[str, dict[str, str]] = field(default_factory=dict, repr=False)
    dozwolone_sieci: list[str] = field(default_factory=list)
    dozwolone_hosty: list[str] = field(default_factory=list)


@dataclass
class RaportSprawdzenia:
    """Wynik testu odtworzenia: bledy oraz ile naprawde odszyfrowano."""

    bledy: list[tuple[int, str | None, str]] = field(default_factory=list)
    #: Domy, ktorych DEK sie odpakowal (dowod, ze klucz pasuje).
    klucze_domow: int = 0
    integracje: int = 0
    #: Integracje z kopii ostatniej dobrej konfiguracji (domy_kopia), ktore
    #: sie odszyfrowaly.
    kopie: int = 0
    #: dom -> kek_id, ktorym zapakowano jego DEK (tylko odpakowane).
    kek_id_domow: dict[int, str | None] = field(default_factory=dict)

    @property
    def potwierdzone(self) -> bool:
        return not self.bledy and self.klucze_domow > 0


@dataclass
class DaneDomu:
    """Wszystko z bazy panelu o jednym domu (bez odszyfrowania)."""

    dom: Dom
    dzieci: list[str]
    urzadzenia: list[dict]
    integracje: list[Integracja]


def _transakcja(conn: sqlite3.Connection) -> contextlib.AbstractContextManager:
    @contextlib.contextmanager
    def tx():
        conn.execute("BEGIN IMMEDIATE")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
    return tx()


def _wiersz_domu(conn: sqlite3.Connection, dom_id: int) -> sqlite3.Row:
    row = conn.execute("SELECT * FROM domy WHERE id = ?", (dom_id,)).fetchone()
    if row is None:
        raise LookupError(f"nie ma domu {dom_id}")
    return row


def _dek_conn(conn: sqlite3.Connection, dom_id: int, sejf: Sejf, *, utworz: bool) -> bytes:
    row = _wiersz_domu(conn, dom_id)
    if row["dek_zaszyfrowany"] is None:
        if not utworz:
            from .sejf import SejfError  # noqa: PLC0415

            raise SejfError(f"dom {dom_id} nie ma klucza danych (DEK)")
        dek, blob, kid = sejf.nowy_dek(dom_id)
        conn.execute("UPDATE domy SET dek_zaszyfrowany = ?, kek_id = ? WHERE id = ?",
                     (blob, kid, dom_id))
        return dek
    return sejf.odpakuj_dek(dom_id, row["dek_zaszyfrowany"], row["kek_id"])


def _podbij_wersje(conn: sqlite3.Connection, dom_id: int) -> None:
    conn.execute("UPDATE domy SET wersja = wersja + 1 WHERE id = ?", (dom_id,))


def _integracja(row: sqlite3.Row) -> Integracja:
    return Integracja(row["dom_id"], row["typ"], bool(row["wlaczona"]),
                      _json(row["ustawienia"], {}), tuple(_json(row["sekrety_pola"], [])),
                      row["zmienione_przez"], row["zmienione_at"])


def _sprawdz_pola(typ: str, pola: Sequence[str]) -> None:
    if typ not in POLA_SEKRETOW:
        raise ValueError(f"nieznany typ integracji {typ!r} "
                         f"(dozwolone: {', '.join(TYPY_INTEGRACJI)})")
    zle = sorted(set(pola) - set(POLA_SEKRETOW[typ]))
    if zle:
        raise ValueError(f"integracja {typ}: nieznane pola sekretow {zle} "
                         f"(dozwolone: {', '.join(POLA_SEKRETOW[typ])})")


def zapisz_integracje_conn(conn: sqlite3.Connection, dom_id: int, typ: str, *, sejf: Sejf,
                           wlaczona: bool | None = None, ustawienia: dict | None = None,
                           sekrety: Mapping[str, str | None] | None = None,
                           kto: str | None = None, teraz: float | None = None,
                           podbij_wersje: bool = True) -> None:
    """Upsert integracji w transakcji wolajacego. `sekrety`: pole -> wartosc
    (None = usun pole); pola nie wymienione zostaja. Bez walidacji ustawien
    i adresow — robi ja RejestrDomow.zapisz_integracje (panel) i porownanie
    w dom-importuj. Audyt bez wartosci: nazwy zmienionych ustawien i pol
    sekretow. `podbij_wersje=False` — zapis srodowiska domu o sobie samym
    (token aplikacji TV po sparowaniu): to, co juz ma w pamieci, nie jest
    powodem do przeladowania (§5.1)."""
    sekrety = dict(sekrety or {})
    _sprawdz_pola(typ, list(sekrety))
    teraz = time.time() if teraz is None else teraz
    stary = conn.execute("SELECT * FROM integracje WHERE dom_id = ? AND typ = ?",
                         (dom_id, typ)).fetchone()
    blob = stary["sekrety"] if stary else None
    pola = list(_json(stary["sekrety_pola"], [])) if stary else []
    if sekrety:
        from .sejf import odszyfruj_sekrety, zaszyfruj_sekrety  # noqa: PLC0415

        dek = _dek_conn(conn, dom_id, sejf, utworz=True)
        biezace = odszyfruj_sekrety(dek, dom_id, typ, blob)
        for pole, wartosc in sekrety.items():
            if wartosc is None or not str(wartosc).strip():
                biezace.pop(pole, None)
            else:
                biezace[pole] = str(wartosc)
        blob = zaszyfruj_sekrety(dek, dom_id, typ, biezace) if biezace else None
        pola = sorted(biezace)
    nowe_wlaczona = bool(stary["wlaczona"]) if (wlaczona is None and stary) else bool(wlaczona)
    nowe_ustawienia = (ustawienia if ustawienia is not None
                       else (_json(stary["ustawienia"], {}) if stary else {}))
    conn.execute(
        "INSERT INTO integracje (dom_id, typ, wlaczona, ustawienia, sekrety, sekrety_pola, "
        "zmienione_przez, zmienione_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (dom_id, typ) DO UPDATE SET wlaczona = excluded.wlaczona, "
        "ustawienia = excluded.ustawienia, sekrety = excluded.sekrety, "
        "sekrety_pola = excluded.sekrety_pola, zmienione_przez = excluded.zmienione_przez, "
        "zmienione_at = excluded.zmienione_at",
        (dom_id, typ, int(nowe_wlaczona), json.dumps(nowe_ustawienia, ensure_ascii=False,
                                                     sort_keys=True),
         blob, json.dumps(pola), kto, teraz),
    )
    if podbij_wersje:
        _podbij_wersje(conn, dom_id)
    opis = [f"integracja {typ}: {'wlaczona' if nowe_wlaczona else 'wylaczona'}"]
    if ustawienia is not None:
        przed = _json(stary["ustawienia"], {}) if stary else {}
        zmienione = sorted(k for k in set(przed) | set(ustawienia)
                           if przed.get(k, ...) != ustawienia.get(k, ...))
        opis.append(f"ustawienia zmienione: {', '.join(zmienione) or '-'}")
    if sekrety:
        opis.append(f"sekrety zmienione: {', '.join(sorted(sekrety))}")
    _audyt(conn, teraz, dom_id, kto, "integracja.zapis", "; ".join(opis))


def sekrety_domu_conn(conn: sqlite3.Connection, dom_id: int, sejf: Sejf) -> SekretyDomu:
    """Odszyfrowane sekrety wszystkich integracji domu. SejfError, gdy
    ktoras sie nie odszyfrowuje — dom nie startuje z polowa sekretow."""
    from .sejf import odszyfruj_sekrety  # noqa: PLC0415

    rows = conn.execute("SELECT typ, sekrety FROM integracje WHERE dom_id = ? ORDER BY typ",
                        (dom_id,)).fetchall()
    if not any(r["sekrety"] for r in rows):
        return SekretyDomu(dom_id, {})
    dek = _dek_conn(conn, dom_id, sejf, utworz=False)
    return SekretyDomu(dom_id, {r["typ"]: odszyfruj_sekrety(dek, dom_id, r["typ"], r["sekrety"])
                                for r in rows if r["sekrety"]})


def dane_domu_conn(conn: sqlite3.Connection, dom_id: int) -> DaneDomu:
    dom = _dom(_wiersz_domu(conn, dom_id))
    dzieci = {r["id"]: r["nazwa"] for r in conn.execute(
        "SELECT id, nazwa FROM dzieci WHERE dom_id = ? ORDER BY kolejnosc, id", (dom_id,))}
    urzadzenia = []
    for r in conn.execute("SELECT * FROM urzadzenia WHERE dom_id = ? ORDER BY id", (dom_id,)):
        urzadzenia.append({
            "nazwa": r["nazwa"], "dziecko": dzieci.get(r["dziecko_id"]), "rodzaj": r["rodzaj"],
            "source_ids": _json(r["source_ids"], []), "nextdns_profile": r["nextdns_profile"],
            "unifi_mac": r["unifi_mac"], "unifi_ip": r["unifi_ip"], "udid": r["udid"],
            "host": r["host"], "mdm": bool(r["mdm"]), "ustawienia": _json(r["ustawienia"], {}),
        })
    integracje = [_integracja(r) for r in conn.execute(
        "SELECT * FROM integracje WHERE dom_id = ? ORDER BY typ", (dom_id,))]
    return DaneDomu(dom, list(dzieci.values()), urzadzenia, integracje)


def zapisz_dane_domu_conn(conn: sqlite3.Connection, dom_id: int, plan: PlanDomu, *,
                          sejf: Sejf, kto: str | None = None,
                          teraz: float | None = None) -> None:
    """Zastepuje dzieci, urzadzenia i integracje domu planem (dom-importuj).
    W transakcji wolajacego — wolajacy porownuje wynik i dopiero commituje."""
    from .devicekind import RODZAJ_W_BAZIE  # noqa: PLC0415

    teraz = time.time() if teraz is None else teraz
    _wiersz_domu(conn, dom_id)
    obce = sorted(set(plan.sekrety) - set(plan.integracje))
    if obce:
        raise ValueError(f"sekrety dla integracji {obce}, ktorych nie ma w planie")
    conn.execute("DELETE FROM integracje WHERE dom_id = ?", (dom_id,))
    conn.execute("DELETE FROM urzadzenia WHERE dom_id = ?", (dom_id,))
    conn.execute("DELETE FROM dzieci WHERE dom_id = ?", (dom_id,))
    id_dziecka = {}
    for i, nazwa in enumerate(plan.dzieci):
        cur = conn.execute("INSERT INTO dzieci (dom_id, nazwa, kolejnosc) VALUES (?, ?, ?)",
                           (dom_id, nazwa, i))
        id_dziecka[nazwa] = cur.lastrowid
    for u in plan.urzadzenia:
        conn.execute(
            "INSERT INTO urzadzenia (dom_id, dziecko_id, rodzaj, nazwa, source_ids, "
            "nextdns_profile, unifi_mac, unifi_ip, udid, host, mdm, ustawienia) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (dom_id, id_dziecka.get(u.get("dziecko")) if u.get("dziecko") else None,
             RODZAJ_W_BAZIE.get(u["rodzaj"], u["rodzaj"]), u["nazwa"],
             json.dumps(u.get("source_ids") or []), u.get("nextdns_profile"),
             u.get("unifi_mac"), u.get("unifi_ip"), u.get("udid"), u.get("host"),
             int(bool(u.get("mdm"))),
             json.dumps(u.get("ustawienia") or {}, ensure_ascii=False, sort_keys=True)),
        )
    for typ, (wlaczona, ustawienia) in plan.integracje.items():
        zapisz_integracje_conn(conn, dom_id, typ, sejf=sejf, wlaczona=wlaczona,
                               ustawienia=ustawienia, sekrety=plan.sekrety.get(typ),
                               kto=kto, teraz=teraz)
    conn.execute(
        "UPDATE domy SET strefa = ?, ustawienia = ?, dozwolone_sieci = ?, dozwolone_hosty = ? "
        "WHERE id = ?",
        (plan.strefa, json.dumps(plan.ustawienia, ensure_ascii=False, sort_keys=True),
         json.dumps(plan.dozwolone_sieci), json.dumps(plan.dozwolone_hosty), dom_id),
    )
    _podbij_wersje(conn, dom_id)
    _audyt(conn, teraz, dom_id, kto, "dom.import",
           f"dzieci: {len(plan.dzieci)}, urzadzenia: {len(plan.urzadzenia)}, integracje: "
           f"{', '.join(sorted(plan.integracje)) or '-'}, sieci: "
           f"{', '.join(plan.dozwolone_sieci) or '-'}")


# ==================================================================== rejestr
class RejestrDomow:
    """Domy i czlonkostwa w panel-auth.db. Kazda operacja na wlasnym
    polaczeniu (jak PanelAuth): wola ja panel z wielu watkow i CLI."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        new = not Path(self.path).exists()
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        if new:
            # `run` i `domy` zakladaja plik przed PanelAuth, a ten nadaje 0600
            # tylko nowemu plikowi — hashe hasel nie dla innych uzytkownikow.
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def migruj(self, *, strefa: str | None = None) -> RaportMigracji:
        with self._conn() as conn:
            return migruj_conn(conn, strefa=strefa)

    def dom_udidu(self, udid: str) -> int | None:
        """Dom, do ktorego nalezy UDID (tabela `urzadzenia`, UDID globalnie
        jednoznaczny), albo None. Druga bariera MDM w panelu (E3b)."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT dom_id FROM urzadzenia WHERE upper(udid) = ? LIMIT 1",
                (udid.strip().upper(),)).fetchone()
        return int(row["dom_id"]) if row else None

    def domy(self) -> list[Dom]:
        with self._conn() as conn:
            if not _jest_tabela(conn, "domy"):
                return []
            return [_dom(r) for r in conn.execute("SELECT * FROM domy ORDER BY id")]

    def dom(self, dom_id: int) -> Dom | None:
        with self._conn() as conn:
            if not _jest_tabela(conn, "domy"):
                return None
            row = conn.execute("SELECT * FROM domy WHERE id = ?", (dom_id,)).fetchone()
        return _dom(row) if row else None

    def _czlonkostwa(self, where: str, args: tuple) -> list[Czlonkostwo]:
        with self._conn() as conn:
            if not _jest_tabela(conn, "czlonkostwa"):
                return []
            rows = conn.execute(
                "SELECT c.dom_id, c.user_id, u.login, c.rola FROM czlonkostwa c "
                f"JOIN users u ON u.id = c.user_id WHERE {where} ORDER BY c.dom_id, u.login",
                args,
            ).fetchall()
            out = []
            for r in rows:
                nadane, odebrane = _odstepstwa(conn.execute(
                    "SELECT uprawnienie, nadane FROM czlonkostwa_uprawnienia "
                    "WHERE dom_id = ? AND user_id = ?", (r["dom_id"], r["user_id"])
                ))
                out.append(Czlonkostwo(r["dom_id"], r["user_id"], r["login"], r["rola"],
                                       nadane, odebrane))
        return out

    def czlonkowie(self, dom_id: int) -> list[Czlonkostwo]:
        return self._czlonkostwa("c.dom_id = ?", (dom_id,))

    def czlonkostwa(self, user_id: int) -> list[Czlonkostwo]:
        """Domy konta (przelacznik domow, /api/auth/me)."""
        return self._czlonkostwa("c.user_id = ?", (user_id,))

    def czlonkostwo(self, user_id: int, dom_id: int) -> Czlonkostwo | None:
        found = self._czlonkostwa("c.user_id = ? AND c.dom_id = ?", (user_id, dom_id))
        return found[0] if found else None

    def uprawnienia(self, user_id: int, dom_id: int) -> frozenset[str]:
        """Uprawnienia konta W DOMU. Bez czlonkostwa: pusty zbior."""
        c = self.czlonkostwo(user_id, dom_id)
        return c.uprawnienia if c else frozenset()

    def konta_bez_domu(self) -> list[str]:
        with self._conn() as conn:
            if not (_jest_tabela(conn, "users") and _jest_tabela(conn, "czlonkostwa")):
                return []
            return [r[0] for r in conn.execute(
                "SELECT login FROM users WHERE id NOT IN (SELECT user_id FROM czlonkostwa) "
                "ORDER BY login"
            )]

    def ustaw_czlonkostwo(self, dom_id: int, user_id: int, rola: str,
                          nadane: frozenset[str] = frozenset(),
                          odebrane: frozenset[str] = frozenset()) -> None:
        self._w_transakcji(ustaw_czlonkostwo_conn, dom_id, user_id, rola, nadane, odebrane)

    def _w_transakcji(self, fn, *args, **kwargs):
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                wynik = fn(conn, *args, **kwargs)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return wynik

    def usun_czlonkostwo(self, dom_id: int, user_id: int) -> bool:
        return self._w_transakcji(usun_czlonkostwo_conn, dom_id, user_id)

    def admin_instancji(self, user_id: int) -> bool:
        with self._conn() as conn:
            return admin_instancji(conn, user_id)

    def ustaw_admin_instancji(self, user_id: int, wlaczona: bool, *,
                              tylko_sso: bool = False) -> bool:
        return self._w_transakcji(ustaw_admin_instancji_conn, user_id, wlaczona,
                                  tylko_sso=tylko_sso)

    def zapisz_audyt(self, dom_id: int | None, login: str | None, akcja: str, opis: str) -> None:
        with self._conn() as conn:
            zapisz_audyt(conn, dom_id, login, akcja, opis)

    def audyt(self, dom_id: int, limit: int = 100) -> list[dict]:
        """Dziennik domu, najnowsze pierwsze (panel: Dom -> Dziennik)."""
        with self._conn() as conn:
            if not _jest_tabela(conn, "audyt"):
                return []
            return [dict(r) for r in conn.execute(
                "SELECT ts, login, akcja, opis FROM audyt WHERE dom_id = ? "
                "ORDER BY ts DESC, id DESC LIMIT ?", (dom_id, limit))]

    # ------------------------------------------------------------ E2: domy
    def dodaj_dom(self, nazwa: str, *, strefa: str = "Europe/Warsaw",
                  kto: str | None = None) -> int:
        """Nowy dom z konfiguracja w bazie (`baza`). Bez czlonkow — zaklada
        go administrator instancji (CLI `dom-dodaj` w E6)."""
        teraz = time.time()
        with self._conn() as conn, _transakcja(conn):
            cur = conn.execute(
                "INSERT INTO domy (nazwa, strefa, zrodlo_konfiguracji, utworzony_at) "
                "VALUES (?, ?, ?, ?)", (nazwa, strefa, ZRODLO_BAZA, teraz))
            dom_id = int(cur.lastrowid)
            _audyt(conn, teraz, dom_id, kto, "dom.dodaj", f"dom {dom_id} zalozony")
        return dom_id

    def ustaw_zrodlo(self, dom_id: int, zrodlo: str, *, kto: str | None = None) -> None:
        """`yaml` tylko dla Domu 1 (§6 p. 4: powrot `dom-zrodlo 1 yaml`)."""
        if zrodlo not in (ZRODLO_YAML, ZRODLO_BAZA):
            raise ValueError(f"zrodlo {zrodlo!r}: dozwolone {ZRODLO_YAML}, {ZRODLO_BAZA}")
        if zrodlo == ZRODLO_YAML and dom_id != DOM_1:
            raise ValueError("konfiguracje z config.yaml moze miec tylko Dom 1")
        with self._conn() as conn, _transakcja(conn):
            _wiersz_domu(conn, dom_id)
            conn.execute("UPDATE domy SET zrodlo_konfiguracji = ? WHERE id = ?",
                         (zrodlo, dom_id))
            _podbij_wersje(conn, dom_id)
            _audyt(conn, time.time(), dom_id, kto, "dom.zrodlo",
                   f"konfiguracja domu: {zrodlo}")

    def ustaw_sieci(self, dom_id: int, *, sieci: Sequence[str] | None = None,
                    hosty: Sequence[str] | None = None, kto: str | None = None) -> Dom:
        """Sieci i hosty, do ktorych integracje domu moga sie laczyc (§3.6).
        WYLACZNIE administrator instancji (CLI `dom-sieci`), nigdy panel."""
        from .straznik import sieci_z_tekstu  # noqa: PLC0415

        with self._conn() as conn, _transakcja(conn):
            _wiersz_domu(conn, dom_id)
            opis = []
            if sieci is not None:
                znormalizowane = [str(n) for n in sieci_z_tekstu(sieci)]
                conn.execute("UPDATE domy SET dozwolone_sieci = ? WHERE id = ?",
                             (json.dumps(list(dict.fromkeys(znormalizowane))), dom_id))
                opis.append(f"sieci: {', '.join(znormalizowane) or '-'}")
            if hosty is not None:
                czyste = list(dict.fromkeys(h.strip().lower() for h in hosty if h.strip()))
                conn.execute("UPDATE domy SET dozwolone_hosty = ? WHERE id = ?",
                             (json.dumps(czyste), dom_id))
                opis.append(f"hosty: {', '.join(czyste) or '-'}")
            _podbij_wersje(conn, dom_id)
            _audyt(conn, time.time(), dom_id, kto, "dom.sieci", "; ".join(opis) or "bez zmian")
        dom = self.dom(dom_id)
        assert dom is not None
        return dom

    def straznik(self, dom_id: int,
                 resolver: Callable[[str, int], list[str]] | None = None) -> Straznik:
        from .straznik import Straznik  # noqa: PLC0415

        dom = self.dom(dom_id)
        if dom is None:
            raise LookupError(f"nie ma domu {dom_id}")
        return Straznik(dom_id, dom.dozwolone_sieci, dom.dozwolone_hosty, resolver=resolver)

    # ------------------------------------------------------ E2: integracje
    def integracje(self, dom_id: int) -> list[Integracja]:
        with self._conn() as conn:
            if not _jest_tabela(conn, "integracje"):
                return []
            return [_integracja(r) for r in conn.execute(
                "SELECT * FROM integracje WHERE dom_id = ? ORDER BY typ", (dom_id,))]

    def integracja(self, dom_id: int, typ: str) -> Integracja | None:
        found = [i for i in self.integracje(dom_id) if i.typ == typ]
        return found[0] if found else None

    def zapisz_integracje(self, dom_id: int, typ: str, *, sejf: Sejf,
                          wlaczona: bool | None = None, ustawienia: dict | None = None,
                          sekrety: Mapping[str, str | None] | None = None,
                          kto: str | None = None,
                          resolver: Callable[[str, int], list[str]] | None = None,
                          sprawdz_dom: Callable[[sqlite3.Connection], str | None] | None = None,
                          wylacz: Sequence[str] = (),
                          oczekiwana_wersja: int | None = None,
                          ) -> Integracja:
        """Zapis integracji z panelu (E3a): walidacja ustawien modelem
        konfiguracji, adresy przez straznika sieci domu (odmowa = ValueError
        z opisem, bez wartosci sekretow), sekrety tylko do zapisu.

        `sprawdz_dom(conn)` — opis, dlaczego dom nie wystartowalby na
        konfiguracji widocznej na `conn`, albo None (konfiguracja_domu.
        blad_startu_conn). Wolane przed i po zapisie w TEJ SAMEJ transakcji:
        zmiana, po ktorej dzialajacy dom przestalby startowac, jest wycofywana
        (ValueError). Dom juz niedzialajacy (np. swiezy, bez zrodla DNS) mozna
        uzupelniac w dowolnej kolejnosci.

        `wylacz` — inne integracje wylaczane w tej samej transakcji
        (przelaczenie zrodla DNS NextDNS <-> AdGuard: dom ma dokladnie jedno).
        `oczekiwana_wersja` — `domy.wersja`, ktora widzial wolajacy; inna
        w chwili zapisu = ZmianaWersji (ktos zmienil dom w miedzyczasie)."""
        from .konfiguracja_domu import waliduj_integracje  # noqa: PLC0415

        _sprawdz_pola(typ, list(sekrety or {}))
        obecna = self.integracja(dom_id, typ)
        do_walidacji = ustawienia if ustawienia is not None else (
            obecna.ustawienia if obecna else {})
        skutecznie = wlaczona if wlaczona is not None else bool(obecna and obecna.wlaczona)
        waliduj_integracje(typ, do_walidacji, self.straznik(dom_id, resolver),
                           wlaczona=skutecznie)
        with self._conn() as conn, _transakcja(conn):
            if oczekiwana_wersja is not None and \
                    _wiersz_domu(conn, dom_id)["wersja"] != oczekiwana_wersja:
                raise ZmianaWersji("konfiguracja domu zmienila sie od wczytania — odswiez")
            przed = sprawdz_dom(conn) if sprawdz_dom is not None else None
            zapisz_integracje_conn(conn, dom_id, typ, sejf=sejf, wlaczona=wlaczona,
                                   ustawienia=ustawienia, sekrety=sekrety, kto=kto)
            for inny in wylacz:
                _sprawdz_pola(inny, [])
                if conn.execute("SELECT 1 FROM integracje WHERE dom_id = ? AND typ = ? "
                                "AND wlaczona = 1", (dom_id, inny)).fetchone():
                    zapisz_integracje_conn(conn, dom_id, inny, sejf=sejf, wlaczona=False,
                                           kto=kto)
            po = sprawdz_dom(conn) if sprawdz_dom is not None else None
            if po is not None and przed is None:
                raise ValueError(f"po tej zmianie dom nie wystartuje — {po}")
        wynik = self.integracja(dom_id, typ)
        assert wynik is not None
        return wynik

    def sekrety_domu(self, dom_id: int, sejf: Sejf) -> SekretyDomu:
        """Tylko dla srodowiska domu i testu polaczenia — nigdy do odpowiedzi
        panelu. Zwrocony obiekt zapisuje zmiany (token aplikacji TV) do bazy."""
        with self._conn() as conn:
            wynik = sekrety_domu_conn(conn, dom_id, sejf)

        def zapisz(typ: str, sekrety: dict[str, str | None]) -> None:
            # Srodowisko domu zapisuje to, co juz ma w pamieci — bez
            # podbicia wersji, inaczej nadzorca przeladowalby dom po kazdym
            # sparowaniu aplikacji TV.
            with self._conn() as conn, _transakcja(conn):
                zapisz_integracje_conn(conn, dom_id, typ, sejf=sejf, sekrety=sekrety,
                                       kto=f"dom-{dom_id}", podbij_wersje=False)

        return SekretyDomu(dom_id, {t: wynik.typu(t) for t in wynik.pola()}, zapisz)

    def maski(self, dom_id: int, sejf: Sejf) -> dict[str, dict[str, str]]:
        """typ -> {pole: maska} do panelu i CLI (sejf.maska), bez wartosci."""
        from .sejf import maska  # noqa: PLC0415

        sekrety = self.sekrety_domu(dom_id, sejf)
        return {typ: {p: maska(sekrety.get(typ, p) or "") for p in pola}
                for typ, pola in sekrety.pola().items()}

    def dane_domu(self, dom_id: int) -> DaneDomu:
        with self._conn() as conn:
            return dane_domu_conn(conn, dom_id)

    def sprawdz(self, sejf: Sejf) -> list[tuple[int, str | None, str]]:
        """Test odtworzenia (§3.3): odszyfrowanie DEK i KAZDEJ integracji
        kazdego domu. Lista (dom, typ albo None dla DEK, opis bledu).
        Pusta lista NIE znaczy, ze klucz jest dobry — patrz sprawdz_raport."""
        return self.sprawdz_raport(sejf).bledy

    def sprawdz_raport(self, sejf: Sejf) -> RaportSprawdzenia:
        """Jak `sprawdz`, plus ile kluczy domow i integracji naprawde sie
        odszyfrowalo. Zero = nic nie potwierdzono (baza bez DEK przechodzi
        z KAZDYM kluczem)."""
        from .sejf import SejfError, odszyfruj_sekrety  # noqa: PLC0415

        raport = RaportSprawdzenia()
        with self._conn() as conn:
            for dom in self.domy():
                rows = conn.execute(
                    "SELECT typ, sekrety FROM integracje WHERE dom_id = ? AND sekrety IS NOT NULL "
                    "ORDER BY typ", (dom.id,)).fetchall()
                if not rows and not dom.ma_dek:
                    continue
                try:
                    dek = _dek_conn(conn, dom.id, sejf, utworz=False)
                except SejfError as exc:
                    raport.bledy.append((dom.id, None, str(exc)))
                    continue
                raport.klucze_domow += 1
                raport.kek_id_domow[dom.id] = dom.kek_id
                for r in rows:
                    try:
                        odszyfruj_sekrety(dek, dom.id, r["typ"], r["sekrety"])
                    except SejfError as exc:
                        raport.bledy.append((dom.id, r["typ"], str(exc)))
                    else:
                        raport.integracje += 1
                # Kopia ostatniej dobrej konfiguracji (§5.1): start na niej
                # musi sie odszyfrowac tym samym kluczem.
                kopia = conn.execute("SELECT dane FROM domy_kopia WHERE dom_id = ?",
                                     (dom.id,)).fetchone() \
                    if _jest_tabela(conn, "domy_kopia") else None
                try:
                    integracje_kopii = json.loads(kopia["dane"])["integracje"] if kopia else []
                except (ValueError, KeyError, TypeError) as exc:
                    raport.bledy.append((dom.id, "kopia:-", f"kopia nieczytelna: {exc}"))
                    integracje_kopii = []
                for i in integracje_kopii:
                    if not i["sekrety"]:
                        continue
                    try:
                        odszyfruj_sekrety(dek, dom.id, i["typ"], bytes.fromhex(i["sekrety"]))
                    except (SejfError, ValueError) as exc:
                        raport.bledy.append((dom.id, f"kopia:{i['typ']}", str(exc)))
                    else:
                        raport.kopie += 1
        return raport

    def czas_zmiany_sekretu(self, dom_id: int, typ: str, pole: str) -> float | None:
        """Kiedy ostatnio zapisano TO pole sekretu (z audytu `integracja.zapis`,
        ktory podaje nazwy zmienionych pol) — nie cala integracja. None, gdy
        audyt go nie zna."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT MAX(ts) FROM audyt WHERE dom_id = ? AND akcja = 'integracja.zapis' "
                "AND opis LIKE ? AND opis LIKE ?",
                (dom_id, f"integracja {typ}:%", f"%sekrety zmienione:%{pole}%"),
            ).fetchone()
        return row[0] if row and row[0] is not None else None

    # ------------------------------------------- przeladowanie (§5.1, nadzorca)
    def zapamietaj_dobra(self, dom_id: int, wersja: int) -> bool:
        """Srodowisko domu wstalo na wersji `wersja`: kopia tej konfiguracji
        (sekrety dalej zaszyfrowane) i wpis `dom.przeladowanie`. Gdy wersja
        w bazie jest juz inna (zmiana w trakcie budowy), kopii nie ma — nie
        wiadomo, ktore wiersze wstaly. Zwraca, czy zapisano."""
        teraz = time.time()
        with self._conn() as conn, _transakcja(conn):
            row = _wiersz_domu(conn, dom_id)
            if row["wersja"] != wersja:
                return False
            dane = dane_domu_conn(conn, dom_id)
            integracje = [{
                "typ": r["typ"], "wlaczona": bool(r["wlaczona"]),
                "ustawienia": _json(r["ustawienia"], {}),
                "sekrety_pola": _json(r["sekrety_pola"], []),
                "sekrety": r["sekrety"].hex() if r["sekrety"] else None,
            } for r in conn.execute("SELECT * FROM integracje WHERE dom_id = ? ORDER BY typ",
                                    (dom_id,))]
            kopia = {
                "strefa": dane.dom.strefa, "ustawienia": dane.dom.ustawienia,
                "dozwolone_sieci": list(dane.dom.dozwolone_sieci),
                "dozwolone_hosty": list(dane.dom.dozwolone_hosty),
                "dzieci": dane.dzieci, "urzadzenia": dane.urzadzenia, "integracje": integracje,
            }
            poprzednia = conn.execute("SELECT wersja FROM domy_kopia WHERE dom_id = ?",
                                      (dom_id,)).fetchone()
            conn.execute(
                "INSERT INTO domy_kopia (dom_id, wersja, dane, ts) VALUES (?, ?, ?, ?) "
                "ON CONFLICT (dom_id) DO UPDATE SET wersja = excluded.wersja, "
                "dane = excluded.dane, ts = excluded.ts",
                (dom_id, wersja, json.dumps(kopia, ensure_ascii=False, sort_keys=True), teraz))
            if poprzednia is None or poprzednia[0] != wersja:
                _audyt(conn, teraz, dom_id, None, "dom.przeladowanie",
                       f"dom dziala na konfiguracji w wersji {wersja}")
        return True

    def zapisz_blad_przeladowania(self, dom_id: int, wersja: int, blad: str) -> None:
        """Wersja nie wstala — trwale (dziennik domu), widoczne po restarcie."""
        with self._conn() as conn:
            zapisz_audyt(conn, dom_id, None, "dom.przeladowanie.blad",
                         f"wersja {wersja} nie wystartowala: {blad}")

    def blad_przeladowania(self, dom_id: int, wersja: int) -> str | None:
        """Opis bledu wersji `wersja` z dziennika albo None."""
        prefiks = f"wersja {wersja} nie wystartowala: "
        with self._conn() as conn:
            if not _jest_tabela(conn, "audyt"):
                return None
            row = conn.execute(
                "SELECT opis FROM audyt WHERE dom_id = ? AND akcja = 'dom.przeladowanie.blad' "
                "AND opis LIKE ? ORDER BY id DESC LIMIT 1", (dom_id, prefiks + "%")).fetchone()
        return row[0].removeprefix(prefiks) if row else None

    def alarm_startu(self, dom_id: int, teraz: float | None = None) -> float | None:
        """Czy wyslac alarm startu domu (start bez kopii — kod 2 — albo start
        na kopii): odstep do NASTEPNEGO alarmu w sekundach albo None (jeszcze
        nie). Pod w CrashLoop startuje co kilka minut — bez tej bramki kazdy
        restart to kolejny alarm. Ten sam rosnacy odstep co w nadzorcy (1 h,
        2 h, 4 h…, najwyzej doba), liczony z dziennika domu, bo pamieci procesu
        restart nie przezywa.

        Nowa awaria (alarm od razu, odstep od 1 h): brak poprzedniego alarmu,
        udany start PO nim (`dom.start.ok`, zapisz_start_ok) albo przerwa
        dluzsza niz dwie doby. Sama ta funkcja NICZEGO nie zapisuje — wpis
        robi zapisz_alarm_startu dopiero po udanej wysylce, wiec bramka,
        ktora lezy, nie blokuje alarmu na pelny odstep. Blad bazy = wyslac
        (glosno zamiast cicho)."""
        teraz = time.time() if teraz is None else teraz
        try:
            with self._conn() as conn:
                alarm = conn.execute(
                    "SELECT id, ts, opis FROM audyt WHERE dom_id = ? AND akcja = "
                    "'dom.start.alarm' ORDER BY id DESC LIMIT 1", (dom_id,)).fetchone()
                if alarm is None:
                    return ALARM_PIERWSZY_ODSTEP
                ok = conn.execute(
                    "SELECT 1 FROM audyt WHERE dom_id = ? AND akcja = 'dom.start.ok' "
                    "AND id > ?", (dom_id, alarm["id"])).fetchone()
        except sqlite3.Error:
            log.exception("dom %d: bramka alarmu startu niedostepna — wysylam", dom_id)
            return ALARM_PIERWSZY_ODSTEP
        if ok is not None:
            return ALARM_PIERWSZY_ODSTEP
        try:
            poprzedni = float(alarm["opis"].rsplit("po ", 1)[1].split(" s")[0])
        except (IndexError, ValueError):
            poprzedni = ALARM_PIERWSZY_ODSTEP
        minelo = teraz - alarm["ts"]
        if minelo >= 2 * ALARM_MAX_ODSTEP:
            return ALARM_PIERWSZY_ODSTEP
        if minelo < poprzedni:
            return None
        return min(poprzedni * 2, ALARM_MAX_ODSTEP)

    def zapisz_alarm_startu(self, dom_id: int, odstep: float, tytul: str,
                            teraz: float | None = None) -> None:
        """Alarm startu WYSLANY — wpis `dom.start.alarm` z odstepem do nastepnego."""
        with self._conn() as conn:
            zapisz_audyt(conn, dom_id, None, "dom.start.alarm",
                         f"alarm: {tytul}; nastepny najwczesniej po {odstep:.0f} s",
                         teraz)

    def zapisz_start_ok(self, dom_id: int, wersja: int | None,
                        teraz: float | None = None) -> bool:
        """Dom wstal na biezacej konfiguracji. Wpis `dom.start.ok` tylko, gdy
        jest otwarta awaria startu (alarm bez pozniejszego udanego startu) —
        konczy ja, wiec pierwszy alarm nastepnej awarii idzie od razu. Bez
        awarii nic (dziennik nie puchnie od restartow poda)."""
        with self._conn() as conn:
            alarm = conn.execute(
                "SELECT id FROM audyt WHERE dom_id = ? AND akcja = 'dom.start.alarm' "
                "ORDER BY id DESC LIMIT 1", (dom_id,)).fetchone()
            if alarm is None or conn.execute(
                    "SELECT 1 FROM audyt WHERE dom_id = ? AND akcja = 'dom.start.ok' AND id > ?",
                    (dom_id, alarm["id"])).fetchone() is not None:
                return False
            zapisz_audyt(conn, dom_id, None, "dom.start.ok",
                         f"dom wstal na konfiguracji w wersji {wersja} — koniec awarii startu",
                         teraz)
        return True

    def kopia_domu(self, dom_id: int, sejf: Sejf) -> tuple[int, DaneDomu, SekretyDomu] | None:
        """Ostatnia dobra konfiguracja (zapamietaj_dobra): wersja, wiersze
        i sekrety odszyfrowane BIEZACYM kluczem domu. None = brak kopii.
        SejfError, gdy klucz domu zmieniono po kopii (dom-klucz-rotuj)."""
        from .sejf import odszyfruj_sekrety  # noqa: PLC0415

        with self._conn() as conn:
            if not _jest_tabela(conn, "domy_kopia"):
                return None
            row = conn.execute("SELECT wersja, dane FROM domy_kopia WHERE dom_id = ?",
                               (dom_id,)).fetchone()
            if row is None:
                return None
            k = json.loads(row["dane"])
            dom = dataclasses.replace(
                _dom(_wiersz_domu(conn, dom_id)), strefa=k["strefa"], ustawienia=k["ustawienia"],
                dozwolone_sieci=tuple(k["dozwolone_sieci"]),
                dozwolone_hosty=tuple(k["dozwolone_hosty"]), wersja=row["wersja"])
            integracje, wartosci = [], {}
            zaszyfrowane = [i for i in k["integracje"] if i["sekrety"]]
            dek = _dek_conn(conn, dom_id, sejf, utworz=False) if zaszyfrowane else b""
            for i in k["integracje"]:
                integracje.append(Integracja(dom_id, i["typ"], i["wlaczona"], i["ustawienia"],
                                             tuple(i["sekrety_pola"])))
                if i["sekrety"]:
                    wartosci[i["typ"]] = odszyfruj_sekrety(dek, dom_id, i["typ"],
                                                           bytes.fromhex(i["sekrety"]))

        def zapisz(typ: str, sekrety: dict[str, str | None]) -> None:
            # Token aplikacji TV sparowanej w czasie pracy na kopii — do bazy, jak
            # w sekrety_domu (bez podbicia wersji).
            with self._conn() as conn, _transakcja(conn):
                zapisz_integracje_conn(conn, dom_id, typ, sejf=sejf, sekrety=sekrety,
                                       kto=f"dom-{dom_id}", podbij_wersje=False)

        return (row["wersja"], DaneDomu(dom, k["dzieci"], k["urzadzenia"], integracje),
                SekretyDomu(dom_id, wartosci, zapisz))

    # ---------------------------------------------------------- E2: klucze
    def ostatnia_rotacja_kek(self) -> str | None:
        """Data (UTC) ostatniego `klucze-rotuj` albo None. Kopie bazy sprzed
        niej otwiera tylko poprzedni klucz."""
        with self._conn() as conn:
            row = conn.execute("SELECT MAX(ts) FROM audyt WHERE akcja = 'klucze.rotacja'"
                               ).fetchone()
        if not row or row[0] is None:
            return None
        return time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(row[0]))

    def zapisz_potwierdzenie_kek(self, kid: str, klucze_domow: int, integracje: int, *,
                                 kto: str | None = None) -> None:
        with self._conn() as conn, _transakcja(conn):
            _audyt(conn, time.time(), None, kto, "klucze.potwierdzenie",
                   f"klucz {kid} z menedzera hasel otwiera {klucze_domow} kluczy domow "
                   f"i {integracje} integracji")

    def rotuj_kek(self, sejf: Sejf, *, kto: str | None = None) -> list[int]:
        """Przepakowanie DEK-ow biezacym KEK (sekrety integracji bez zmian).
        Wszystko albo nic. Zwraca domy, ktorych DEK przepakowano."""
        zmienione = []
        with self._conn() as conn, _transakcja(conn):
            for row in conn.execute("SELECT id, dek_zaszyfrowany, kek_id FROM domy "
                                    "WHERE dek_zaszyfrowany IS NOT NULL ORDER BY id").fetchall():
                nowy = sejf.przepakuj_dek(row["id"], row["dek_zaszyfrowany"], row["kek_id"])
                if nowy is None:
                    continue
                conn.execute("UPDATE domy SET dek_zaszyfrowany = ?, kek_id = ? WHERE id = ?",
                             (nowy[0], nowy[1], row["id"]))
                _audyt(conn, time.time(), row["id"], kto, "klucze.rotacja",
                       f"DEK przepakowany: {row['kek_id']} -> {nowy[1]}")
                zmienione.append(int(row["id"]))
        return zmienione

    def rotuj_dek(self, dom_id: int, sejf: Sejf, *, kto: str | None = None) -> list[str]:
        """Nowy DEK domu i przeszyfrowanie jego integracji (np. po usunieciu
        zarzadcy). Wszystko albo nic. Zwraca przeszyfrowane typy."""
        from .sejf import odszyfruj_sekrety, zaszyfruj_sekrety  # noqa: PLC0415

        with self._conn() as conn, _transakcja(conn):
            row = _wiersz_domu(conn, dom_id)
            stary = (sejf.odpakuj_dek(dom_id, row["dek_zaszyfrowany"], row["kek_id"])
                     if row["dek_zaszyfrowany"] is not None else None)
            dek, blob, kid = sejf.nowy_dek(dom_id)
            typy = []
            for r in conn.execute("SELECT typ, sekrety FROM integracje WHERE dom_id = ? "
                                  "AND sekrety IS NOT NULL ORDER BY typ", (dom_id,)).fetchall():
                if stary is None:
                    from .sejf import SejfError  # noqa: PLC0415

                    raise SejfError(f"dom {dom_id}: sekrety bez klucza danych (DEK)")
                jawne = odszyfruj_sekrety(stary, dom_id, r["typ"], r["sekrety"])
                conn.execute("UPDATE integracje SET sekrety = ? WHERE dom_id = ? AND typ = ?",
                             (zaszyfruj_sekrety(dek, dom_id, r["typ"], jawne), dom_id, r["typ"]))
                typy.append(r["typ"])
            # Kopia ostatniej dobrej konfiguracji tez przechodzi na nowy klucz —
            # inaczej start na kopii (§5.1) skonczylby sie bledem sejfu.
            kopia = conn.execute("SELECT dane FROM domy_kopia WHERE dom_id = ?",
                                 (dom_id,)).fetchone() if _jest_tabela(conn, "domy_kopia") \
                else None
            if kopia is not None:
                # Kopia, ktorej nie da sie odszyfrowac (uszkodzona, sprzed
                # innego klucza), nie moze wycofac calej rotacji: usuwamy ja
                # z wpisem — nastepny udany start zapisze nowa.
                from .sejf import SejfError  # noqa: PLC0415

                try:
                    k = json.loads(kopia["dane"])
                    for i in k["integracje"]:
                        if not i["sekrety"]:
                            continue
                        if stary is None:
                            raise SejfError(f"dom {dom_id}: kopia z sekretami bez klucza danych")
                        jawne = odszyfruj_sekrety(stary, dom_id, i["typ"],
                                                  bytes.fromhex(i["sekrety"]))
                        i["sekrety"] = zaszyfruj_sekrety(dek, dom_id, i["typ"], jawne).hex()
                except (SejfError, ValueError, KeyError, TypeError) as exc:
                    conn.execute("DELETE FROM domy_kopia WHERE dom_id = ?", (dom_id,))
                    _audyt(conn, time.time(), dom_id, kto, "dom.kopia.usunieta",
                           f"kopia ostatniej dobrej konfiguracji usunieta przy rotacji klucza "
                           f"domu: {exc}")
                else:
                    conn.execute("UPDATE domy_kopia SET dane = ? WHERE dom_id = ?",
                                 (json.dumps(k, ensure_ascii=False, sort_keys=True), dom_id))
            conn.execute("UPDATE domy SET dek_zaszyfrowany = ?, kek_id = ? WHERE id = ?",
                         (blob, kid, dom_id))
            _podbij_wersje(conn, dom_id)
            _audyt(conn, time.time(), dom_id, kto, "klucze.dom",
                   f"nowy DEK, przeszyfrowane: {', '.join(typy) or '-'}")
        return typy


def _json(tekst: str | None, domyslnie: Any) -> Any:
    try:
        return json.loads(tekst) if tekst else domyslnie
    except ValueError:
        return domyslnie


def _dom(row: sqlite3.Row) -> Dom:
    kolumny = set(row.keys())

    def kol(nazwa: str, domyslnie: Any = None) -> Any:
        return row[nazwa] if nazwa in kolumny else domyslnie

    return Dom(row["id"], row["nazwa"], row["strefa"], row["zrodlo_konfiguracji"],
               row["wersja"], bool(row["zawieszony"]),
               ustawienia=_json(kol("ustawienia"), {}),
               dozwolone_sieci=tuple(_json(kol("dozwolone_sieci"), [])),
               dozwolone_hosty=tuple(_json(kol("dozwolone_hosty"), [])),
               kek_id=kol("kek_id"),
               ma_dek=kol("dek_zaszyfrowany") is not None)


# ============================================================== srodowisko domu
@dataclass
class HomeRuntime:
    """Wszystko, co pracuje dla JEDNEGO domu: jego konfiguracja, baza
    zdarzen, silnik, kolejka wyjsciowa (z `dom_id`), zrodlo DNS i petle
    (device, tv, unifi, mdm, game). Buduje je __main__.build_home_runtime;
    tu jest tylko cykl zycia."""

    dom_id: int
    home: HomeConfig
    store: Store
    engine: Engine
    outbox: Outbox
    source: Any
    #: (nazwa zadania, fabryka korutyny) w kolejnosci startu. Pierwsze trzy
    #: to zawsze source, tick, outbox.
    petle: list[tuple[str, Callable[[], Coroutine[Any, Any, Any]]]] = field(
        default_factory=list
    )
    #: Zamkniecie sond i klientow — przed oproznieniem kolejki.
    sprzatanie: list[Callable[[], Awaitable[None]]] = field(default_factory=list)
    #: `domy.wersja`, z ktorej zbudowano konfiguracje (odczytana PRZED budowa);
    #: None = nieznana (tryb `yaml` albo starszy wolajacy) — nadzorca czyta sam.
    wersja: int | None = None
    #: Tetno domu (E3b): czas monotoniczny ostatniego udanego tiku. Nadzorca
    #: z izolacja restartuje dom, gdy tik stoi dluzej niz 3x `okres_tiku`.
    tetno: float = field(default_factory=time.monotonic)
    okres_tiku: float = 30.0

    def dotknij_tetna(self) -> None:
        self.tetno = time.monotonic()

    def dodaj_petle(self, nazwa: str, fabryka: Callable[[], Coroutine[Any, Any, Any]]) -> None:
        self.petle.append((nazwa, fabryka))

    def dodaj_sprzatanie(self, fn: Callable[[], Awaitable[None]]) -> None:
        self.sprzatanie.append(fn)

    def start(self) -> list[asyncio.Task]:
        return [asyncio.create_task(fabryka(), name=nazwa) for nazwa, fabryka in self.petle]

    async def zamknij(self, flush_seconds: float) -> None:
        """Kazdy krok osobno: blad jednej sondy nie moze zostawic otwartej
        kolejki ani bazy (przy przeladowaniu nowe srodowisko otwiera je znowu)."""
        for fn in self.sprzatanie:
            try:
                await fn()
            except Exception:
                log.exception("dom %d: blad przy zamykaniu sondy", self.dom_id)
        # Co zostalo w kolejce, probujemy wyslac przed zamknieciem — reszta i tak
        # wyjdzie po starcie. Krocej niz terminationGracePeriodSeconds (30 s).
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.outbox.flush(), timeout=flush_seconds)
        for nazwa, krok in (("kolejka", self.outbox.aclose), ("zrodlo", self.source.aclose)):
            try:
                await krok()
            except Exception:
                log.exception("dom %d: blad przy zamykaniu (%s)", self.dom_id, nazwa)
        try:
            self.store.close()
        except Exception:
            log.exception("dom %d: blad przy zamykaniu bazy domu", self.dom_id)


#: Co ile sekund nadzorca porownuje `domy.wersja` (§5.1).
OKRES_PRZELADOWANIA = 10.0
#: Ponowienia po bledzie PRZEJSCIOWYM (baza zajeta, DNS, siec): 1, 5, 30 min,
#: potem co 30 min. Blad konfiguracji czeka na nastepna zmiane.
PONOWIENIA = (60.0, 300.0, 1800.0)
#: Alarm instancji o domu bez nowej konfiguracji: od razu, potem co 1 h,
#: 2 h, 4 h... najwyzej co dobe — liczone od awarii domu, nie od komunikatu.
ALARM_PIERWSZY_ODSTEP = 3600.0
ALARM_MAX_ODSTEP = 24 * 3600.0


def blad_przejsciowy(exc: BaseException) -> bool:
    """Czy blad przeladowania moze minac sam (ponawiac z odstepem). Bledy
    konfiguracji — model, brak sekretu, odmowa straznika, sejf, brak domu —
    nie mijaja bez zmiany w panelu, wiec nie sa ponawiane."""
    from .config import MissingSecretError  # noqa: PLC0415
    from .sejf import SejfError  # noqa: PLC0415
    from .straznik import OdmowaSieci  # noqa: PLC0415

    if isinstance(exc, (ValueError, LookupError, MissingSecretError, SejfError, OdmowaSieci)):
        return False
    return isinstance(exc, (sqlite3.Error, OSError, TimeoutError, ConnectionError))


#: Izolacja awarii (E3b, §5.1): restart domu po 1, 2, 4... min, najwyzej co 30 min.
RESTART_PIERWSZY = 60.0
RESTART_MAX = 1800.0
#: Dom dzialajacy tyle po restarcie konczy serie awarii (odstep od nowa).
RESTART_STABILNY = 1800.0
#: Tik stojacy dluzej niz tyle okresow = awaria domu (najmniej MIN_TETNO s).
TETNO_OKRESY = 3
MIN_TETNO = 90.0
#: Co ile nadzorca z izolacja sprawdza tetna, restarty i dotyka tetna procesu.
OKRES_NADZORU = 10.0


#: Tresc alarmu, gdy opisu bezpiecznego do wysylki nie ma — nigdy surowy blad.
BEZ_OPISU = "szczegoly w panelu (Ustawienia -> Integracje) i w logu"


def opis_bledu(exc: BaseException) -> str:
    """Tresc bledu do ALARMU (bramka, poza instalacja): pelny komunikat tylko
    dla bledow, ktorych komunikaty sa z zalozenia bez wartosci sekretow
    (walidacja, brak sekretu, straznik, sejf); dla reszty sam typ wyjatku —
    nieznany wyjatek moze powtorzyc w tresci dane wejscia."""
    from .config import MissingSecretError  # noqa: PLC0415
    from .sejf import SejfError  # noqa: PLC0415
    from .straznik import OdmowaSieci  # noqa: PLC0415

    # Dokladnie ValueError/LookupError (nasze komunikaty), nie podklasy:
    # pydantic ValidationError i KeyError potrafia powtorzyc wartosci wejscia.
    if type(exc) in (ValueError, LookupError) or isinstance(
            exc, (MissingSecretError, SejfError, OdmowaSieci)):
        return str(exc) or type(exc).__name__
    return f"{type(exc).__name__} (szczegoly w logu)"


@dataclass(frozen=True, slots=True)
class StanDomu:
    """Na jakiej konfiguracji chodzi srodowisko domu — dla panelu."""

    #: `domy.wersja`, z ktorej zbudowano dzialajace srodowisko.
    wersja: int | None
    #: Ostatnia wersja, ktorej NIE udalo sie uruchomic, i dlaczego (bez
    #: wartosci sekretow: komunikaty sejfu, straznika i walidacji ich nie maja).
    nieudana: int | None = None
    blad: str | None = None
    ts: float = field(default=0.0, compare=False)
    #: Blad przejsciowy — nadzorca sam ponowi probe.
    ponowienie: bool = False
    #: Opis bledu do ALARMU (opis_bledu) — `blad` idzie tylko do panelu i logu.
    opis_alarmu: str | None = None


class StanyDomow:
    """Wspolny dla watku panelu i petli nadzorcy: dom -> StanDomu. Brak
    wpisu = dom bez automatycznego przeladowania (np. tryb `yaml`)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stany: dict[int, StanDomu] = {}

    def ustaw(self, dom_id: int, stan: StanDomu) -> None:
        with self._lock:
            self._stany[dom_id] = stan

    def get(self, dom_id: int) -> StanDomu | None:
        with self._lock:
            return self._stany.get(dom_id)


def _nic(*_args) -> None:
    return None


@dataclass
class Przeladowanie:
    """Jak nadzorca przebudowuje dom po zmianie `domy.wersja` (§5.1).

    `wersja(dom_id)` — biezaca wersja domu, gdy dom ma byc przeladowywany,
    inaczej None (tryb `yaml`, wymuszenie `KIDWATCH_DOM_1_ZRODLO`).
    `konfiguracja(dom_id)` — HomeConfig z bazy BEZ zapisu plikow (blokujace:
    baza, DNS — idzie w watku). `materializuj(dom_id, home)` — pliki z
    sekretow (klucz ADB, token TV) w pamieci poda; wolane dopiero po
    zatrzymaniu starego srodowiska, zeby nieudana proba nie podmienila mu
    plikow. `runtime(dom_id, home)` — nowe HomeRuntime (w petli: Store
    i polaczenia SQLite naleza do watku petli). `po_zmianie(dom_id, rt)` —
    np. panel bierze konfiguracje nowego srodowiska.

    Trwalosc i alarmy: `zapamietaj(dom_id, wersja)` — wersja wstala (kopia
    „ostatniej dobrej” + dziennik), `zapisz_blad(dom_id, wersja, blad)` —
    nie wstala (dziennik, widoczny po restarcie), `ostatnia_dobra(dom_id)` —
    (wersja, HomeConfig) z kopii albo None, `alarm(tytul, tresc)` — kanal
    instancji (bramka). Wszystkie poza `alarm` blokujace (w watku)."""

    wersja: Callable[[int], int | None]
    konfiguracja: Callable[[int], HomeConfig]
    runtime: Callable[[int, HomeConfig], HomeRuntime]
    po_zmianie: Callable[[int, HomeRuntime], None] = _nic
    stany: StanyDomow = field(default_factory=StanyDomow)
    okres: float = OKRES_PRZELADOWANIA
    materializuj: Callable[[int, HomeConfig], None] = _nic
    zapamietaj: Callable[[int, int], None] = _nic
    zapisz_blad: Callable[[int, int, str], None] = _nic
    #: Dom znow dziala na biezacej wersji — konczy awarie startu w dzienniku
    #: (RejestrDomow.zapisz_start_ok), zeby alarm nastepnej szedl od razu.
    start_ok: Callable[[int, int], Any] = _nic
    ostatnia_dobra: Callable[[int], tuple[int, HomeConfig] | None] = _nic
    alarm: Callable[[str, str], Awaitable[None]] | None = None
    przejsciowy: Callable[[BaseException], bool] = blad_przejsciowy
    zegar: Callable[[], float] = time.monotonic


@dataclass
class _SeriaAwarii:
    """Kolejne awarie jednego domu: numer proby i rytm alarmow."""

    proba: int
    nastepny_alarm: float
    odstep_alarmu: float


class Nadzorca:
    """Uruchamia srodowiska domow i czeka na koniec.

    Bez `odbuduj` (E1): kazde zadanie domu jest nieskonczone, wiec jego koniec
    — z bledem czy bez — konczy proces kodem 1 (k8s restartuje poda).

    Z `odbuduj(dom_id, home) -> HomeRuntime` (E3b, izolacja awarii, §5.1):
    koniec zadania domu albo tik stojacy dluzej niz 3x okres zatrzymuje caly
    `HomeRuntime` TEGO domu (z oproznieniem kolejki), a nadzorca buduje go od
    nowa po 1, 2, 4... min (najwyzej co 30 min; seria konczy sie po 30 min
    spokoju). Kazda awaria: alarm instancji i czujka domu (notka w kolejce
    domu) — pierwsza od razu, kolejne z serii co 1 h, 2 h... najwyzej co dobe.
    Pozostale domy chodza dalej. Proces konczy sie tylko po `stop` albo przy
    awarii samego nadzorcy; tetno procesu (`tetno_procesu`, liveness) dotyka
    nadzorca, a nie tik ktoregos domu.

    Z `przeladowanie` (§5.1) nadzorca co `okres` sekund porownuje
    `domy.wersja` z wersja dzialajacego srodowiska i przy roznicy restartuje
    TYLKO ten dom: najpierw buduje nowa konfiguracje (blad = stary dom
    chodzi dalej), potem zatrzymuje stare srodowisko (z oproznieniem
    kolejki), zapisuje pliki z sekretow i uruchamia nowe. Kursory, sesje
    i dedup sa w bazie domu — jak przy restarcie poda.

    Nieudana wersja: wpis w dzienniku domu, stan dla panelu i alarm
    instancji z rosnacym odstepem (od awarii, nie od komunikatu). Blad
    konfiguracji czeka na nastepna zmiane; blad przejsciowy jest ponawiany
    po 1, 5, 30 min. Gdy nie wstaje ani nowa, ani poprzednia konfiguracja —
    ostatnia dobra z kopii w bazie; dopiero bez niej koniec procesu."""

    def __init__(self, domy: Sequence[HomeRuntime],
                 przeladowanie: Przeladowanie | None = None,
                 flush_seconds: float = 10.0,
                 odbuduj: Callable[[int, HomeConfig], HomeRuntime] | None = None,
                 alarm: Callable[[str, str], Awaitable[None]] | None = None,
                 tetno_procesu: Callable[[], None] | None = None,
                 zegar: Callable[[], float] = time.monotonic,
                 okres_nadzoru: float = OKRES_NADZORU) -> None:
        self.domy = list(domy)
        self.przeladowanie = przeladowanie
        self.flush_seconds = flush_seconds
        #: Izolacja awarii (E3b): fabryka srodowiska domu; None = jak w E1.
        self.odbuduj = odbuduj
        #: Kanal alarmow instancji; None = z `przeladowanie.alarm` (albo log).
        self.alarm = alarm
        self.tetno_procesu = tetno_procesu
        self.zegar = zegar
        self.okres_nadzoru = okres_nadzoru
        #: dom -> (kiedy, HomeConfig, wersja) — dom czekajacy na restart.
        self._restarty: dict[int, tuple[float, HomeConfig, int | None]] = {}
        self._serie: dict[int, _SeriaAwarii] = {}
        #: dom -> kiedy (zegar) ostatnio wystartowal — do konca serii awarii.
        self._starty: dict[int, float] = {}
        self._wersje: dict[int, int | None] = {}
        self._nieudane: dict[int, int] = {}
        #: dom -> (wersja, numer proby, kiedy ponowic) po bledzie przejsciowym.
        self._ponow: dict[int, tuple[int, int, float]] = {}
        #: dom -> (kiedy nastepny alarm, odstep) w czasie awarii przeladowania.
        self._alarmy: dict[int, tuple[float, float]] = {}
        self._zadania: dict[asyncio.Task, HomeRuntime] = {}
        self._alarmy_w_tle: set[asyncio.Task] = set()
        #: dom -> tresc bledu do alarmu (opis_bledu), osobno od stanu dla panelu.
        self._opisy_alarmu: dict[int, str] = {}
        self._awaria = False

    @property
    def izolacja(self) -> bool:
        return self.odbuduj is not None

    def _uruchom(self, rt: HomeRuntime) -> None:
        if self.izolacja:
            # Tetno od startu srodowiska — czas budowy nie liczy sie do ciszy tiku.
            rt.tetno = self.zegar()
            self._starty[rt.dom_id] = self.zegar()
        for task in rt.start():
            self._zadania[task] = rt

    async def run(self, stop: asyncio.Event) -> int:
        p = self.przeladowanie
        if p is not None:
            for rt in self.domy:
                await self._wersja_startowa(rt)
        for rt in self.domy:
            self._uruchom(rt)
        stop_task = asyncio.create_task(stop.wait(), name="stop")
        timeout = p.okres if p is not None else None
        if self.izolacja:
            timeout = min(timeout, self.okres_nadzoru) if timeout else self.okres_nadzoru
        while True:
            done, _ = await asyncio.wait(
                {*self._zadania, stop_task}, timeout=timeout,
                return_when=asyncio.FIRST_COMPLETED)
            if stop_task in done or self._awaria or (done and not self.izolacja):
                break
            if self.izolacja:
                for task in done:
                    await self._awaria_zadania(task)
                self._dotknij_tetna_procesu()
                await self._sprawdz_tetna()
                await self._restartuj_gotowe()
            if p is not None and not done:
                await self._sprawdz_wersje()
            if self._awaria:
                break
        if self._alarmy_w_tle:
            # Alarm „monitoring zatrzymany” ma szanse wyjsc przed koncem procesu.
            await asyncio.wait(self._alarmy_w_tle, timeout=self.flush_seconds)
        pending = [t for t in (*self._zadania, *self._alarmy_w_tle, stop_task) if not t.done()]
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        # Kod 0 udawal w k8s czyste zatrzymanie i ginal w statystyce restartow;
        # niezerowy widac w `kubectl describe` jako Error. Z izolacja koniec
        # zadania domu obsluzyl juz restart domu — liczy sie tylko stop.
        failed = [] if self.izolacja else [task for task in done if task is not stop_task]
        for task in failed:
            if task.cancelled():
                log.error("zadanie %s anulowane", task.get_name())
            elif task.exception() is not None:
                log.error("zadanie %s zakonczylo sie bledem", task.get_name(),
                          exc_info=task.exception())
            else:
                log.error("zadanie %s zakonczylo sie bez bledu, a nie powinno", task.get_name())
        return 1 if failed or self._awaria else 0

    async def _wersja_startowa(self, rt: HomeRuntime) -> None:
        """Wersja dzialajaca: podana przez `run` (odczytana PRZED budowa —
        zmiana w trakcie startu da najwyzej jedno zbedne przeladowanie), a bez
        niej odczyt teraz. Blad odczytu = wersja nieznana: pierwszy udany
        odczyt przeladuje dom (zbedne przeladowanie zamiast zgubionej zmiany)."""
        p = self.przeladowanie
        assert p is not None
        stan = p.stany.get(rt.dom_id)
        w = rt.wersja
        if w is None:
            try:
                w = await asyncio.to_thread(p.wersja, rt.dom_id)
            except Exception:
                log.exception("dom %d: nie odczytano wersji konfiguracji przy starcie",
                              rt.dom_id)
                self._wersje[rt.dom_id] = None
                return
        self._wersje[rt.dom_id] = w
        if stan is not None and stan.nieudana is not None:
            # `run` wystartowal dom na ostatniej dobrej wersji, bo biezaca nie wstala.
            self._nieudane[rt.dom_id] = stan.nieudana
            self._opisy_alarmu[rt.dom_id] = stan.opis_alarmu or BEZ_OPISU
            self._alarmy[rt.dom_id] = (p.zegar() + ALARM_PIERWSZY_ODSTEP, ALARM_PIERWSZY_ODSTEP)
            if stan.ponowienie:
                self._ponow[rt.dom_id] = (stan.nieudana, 1, p.zegar() + PONOWIENIA[0])
        elif w is not None:
            p.stany.ustaw(rt.dom_id, StanDomu(w, ts=time.time()))

    async def _sprawdz_wersje(self) -> None:
        p = self.przeladowanie
        assert p is not None
        for i, rt in enumerate(list(self.domy)):
            dom_id = rt.dom_id
            try:
                w = await asyncio.to_thread(p.wersja, dom_id)
            except Exception:
                log.exception("dom %d: nie odczytano wersji konfiguracji", dom_id)
                continue
            if w is not None and w != self._wersje.get(dom_id) and self._czas_na_probe(dom_id, w):
                await self._przeladuj(i, rt, w)
            await self._alarm_powtorka(dom_id)

    def _czas_na_probe(self, dom_id: int, w: int) -> bool:
        p = self.przeladowanie
        assert p is not None
        if self._nieudane.get(dom_id) != w:
            return True
        ponow = self._ponow.get(dom_id)
        return ponow is not None and ponow[0] == w and p.zegar() >= ponow[2]

    # ------------------------------------------------------------ alarmy
    async def _alarm(self, tytul: str, tresc: str) -> None:
        """W tle: bramka ponawia wysylke, a nadzorca w tym czasie pilnuje
        pozostalych domow. Zawsze tez w logu."""
        p = self.przeladowanie
        log.error("alarm instancji: %s — %s", tytul, tresc)
        kanal = self.alarm if self.alarm is not None else (p.alarm if p is not None else None)
        if kanal is None:
            return

        async def wyslij() -> None:
            try:
                await kanal(tytul, tresc)
            except Exception:
                log.exception("alarm instancji nie wyszedl: %s", tytul)

        zadanie = asyncio.create_task(wyslij(), name="alarm instancji")
        self._alarmy_w_tle.add(zadanie)
        zadanie.add_done_callback(self._alarmy_w_tle.discard)

    async def _awaria_domu(self, dom_id: int, w: int, stara: int | None, blad: str,
                           przejsciowy: bool, opis_alarmu: str | None = None) -> None:
        """Wersja `w` nie wstala: stan dla panelu, dziennik (raz na wersje),
        ponowienie (blad przejsciowy) i alarm (od razu, potem z odstepem)."""
        p = self.przeladowanie
        assert p is not None
        pierwszy_raz = self._nieudane.get(dom_id) != w
        self._nieudane[dom_id] = w
        if przejsciowy:
            proba = self._ponow[dom_id][1] + 1 if dom_id in self._ponow and \
                self._ponow[dom_id][0] == w else 1
            odstep = PONOWIENIA[min(proba, len(PONOWIENIA)) - 1]
            self._ponow[dom_id] = (w, proba, p.zegar() + odstep)
        else:
            self._ponow.pop(dom_id, None)
        p.stany.ustaw(dom_id, StanDomu(stara, w, blad, time.time(), przejsciowy,
                                       opis_alarmu))
        self._opisy_alarmu[dom_id] = opis_alarmu if opis_alarmu is not None else BEZ_OPISU
        if pierwszy_raz:
            try:
                await asyncio.to_thread(p.zapisz_blad, dom_id, w, blad)
            except Exception:
                log.exception("dom %d: nie zapisano bledu przeladowania w dzienniku", dom_id)
        if dom_id not in self._alarmy:
            self._alarmy[dom_id] = (p.zegar() + ALARM_PIERWSZY_ODSTEP, ALARM_PIERWSZY_ODSTEP)
            await self._alarm(
                f"Dom {dom_id}: nowa konfiguracja nie wystartowala",
                f"Wersja {w}: {self._opisy_alarmu[dom_id]}. Dom dziala dalej na wersji {stara}. "
                + ("Kidwatch ponowi probe sam." if przejsciowy
                   else "Popraw integracje w panelu (Ustawienia -> Integracje)."))

    async def _alarm_powtorka(self, dom_id: int) -> None:
        p = self.przeladowanie
        assert p is not None
        nastepny = self._alarmy.get(dom_id)
        stan = p.stany.get(dom_id)
        if nastepny is None or stan is None or stan.nieudana is None or p.zegar() < nastepny[0]:
            return
        odstep = min(nastepny[1] * 2, ALARM_MAX_ODSTEP)
        self._alarmy[dom_id] = (p.zegar() + odstep, odstep)
        await self._alarm(f"Dom {dom_id}: nadal bez nowej konfiguracji",
                          f"Wersja {stan.nieudana}: "
                          f"{self._opisy_alarmu.get(dom_id, stan.opis_alarmu or BEZ_OPISU)}. "
                          f"Dom dziala na wersji "
                          f"{stan.wersja}.")

    async def _naprawiony(self, dom_id: int, w: int) -> None:
        p = self.przeladowanie
        assert p is not None
        self._wersje[dom_id] = w
        self._nieudane.pop(dom_id, None)
        self._ponow.pop(dom_id, None)
        p.stany.ustaw(dom_id, StanDomu(w, ts=time.time()))
        log.info("dom %d: dziala na konfiguracji w wersji %d", dom_id, w)
        try:
            await asyncio.to_thread(p.zapamietaj, dom_id, w)
        except Exception:
            log.exception("dom %d: nie zapisano kopii dzialajacej konfiguracji", dom_id)
        try:
            # Naprawa po starcie z kopii konczy awarie startu (dom.start.ok).
            await asyncio.to_thread(p.start_ok, dom_id, w)
        except Exception:
            log.exception("dom %d: nie zapisano udanego startu w dzienniku", dom_id)
        if self._alarmy.pop(dom_id, None) is not None:
            await self._alarm(f"Dom {dom_id}: konfiguracja znow dziala",
                              f"Dom dziala na konfiguracji w wersji {w}.")

    # ------------------------------------------------------- przeladowanie
    async def _przeladuj(self, i: int, rt: HomeRuntime, w: int) -> None:
        p = self.przeladowanie
        assert p is not None
        dom_id = rt.dom_id
        stara = self._wersje.get(dom_id)
        log.info("dom %d: konfiguracja zmieniona (wersja %s -> %d), przeladowanie",
                 dom_id, stara, w)
        try:
            home = await asyncio.to_thread(p.konfiguracja, dom_id)
        except Exception as exc:
            # Stary dom chodzi dalej na swojej konfiguracji.
            log.error("dom %d: nowa konfiguracja (wersja %d) nie wystartuje — %s; "
                      "dom dziala dalej na wersji %s", dom_id, w, exc, stara)
            await self._awaria_domu(dom_id, w, stara, str(exc), p.przejsciowy(exc),
                                    opis_bledu(exc))
            return
        await self._zatrzymaj(rt)
        try:
            await asyncio.to_thread(p.materializuj, dom_id, home)
            nowy = p.runtime(dom_id, home)
        except Exception as exc:
            log.error("dom %d: srodowisko z wersji %d nie wystartowalo — %s; powrot do "
                      "poprzedniej konfiguracji", dom_id, w, exc)
            await self._awaria_domu(dom_id, w, stara, str(exc), p.przejsciowy(exc),
                                    opis_bledu(exc))
            nowy = await self._odtworz(dom_id, rt.home, stara)
            if nowy is None:
                self._awaria = True
                self.domy.pop(i)
                return
        else:
            nowy.wersja = w
            await self._naprawiony(dom_id, w)
        self.domy[i] = nowy
        self._uruchom(nowy)
        try:
            p.po_zmianie(dom_id, nowy)
        except Exception:
            log.exception("dom %d: blad po przeladowaniu (panel)", dom_id)

    async def _odtworz(self, dom_id: int, home: HomeConfig,
                       wersja: int | None) -> HomeRuntime | None:
        """Po nieudanym starcie nowego srodowiska: poprzednia konfiguracja,
        a gdy i ona nie wstaje — ostatnia dobra z kopii w bazie. None = nic
        nie wstalo (alarm, koniec procesu, k8s zrestartuje poda)."""
        p = self.przeladowanie
        assert p is not None
        try:
            await asyncio.to_thread(p.materializuj, dom_id, home)
            rt = p.runtime(dom_id, home)
            rt.wersja = wersja
            return rt
        except Exception as exc:
            log.error("dom %d: poprzednia konfiguracja tez nie wstaje — %s", dom_id, exc)
        try:
            kopia = await asyncio.to_thread(p.ostatnia_dobra, dom_id)
            if kopia is not None:
                await asyncio.to_thread(p.materializuj, dom_id, kopia[1])
                rt = p.runtime(dom_id, kopia[1])
                rt.wersja = kopia[0]
                self._wersje[dom_id] = kopia[0]
                stan = p.stany.get(dom_id)
                p.stany.ustaw(dom_id, dataclasses.replace(stan, wersja=kopia[0]) if stan
                              else StanDomu(kopia[0], ts=time.time()))
                log.warning("dom %d: dziala na ostatniej dobrej konfiguracji (wersja %d)",
                            dom_id, kopia[0])
                return rt
        except Exception as exc:
            log.error("dom %d: ostatnia dobra konfiguracja tez nie wstaje — %s", dom_id, exc)
        log.error("dom %d: zadna konfiguracja nie wstaje — koniec procesu (k8s "
                  "zrestartuje poda)", dom_id)
        await self._alarm(f"Dom {dom_id}: monitoring zatrzymany",
                          "Ani nowa, ani poprzednia, ani ostatnia dobra konfiguracja domu nie "
                          "wstaje. Proces konczy sie; sprawdz log i docs/sejf-domow.md.")
        return None

    async def _zatrzymaj(self, rt: HomeRuntime) -> None:
        zadania = [t for t, r in self._zadania.items() if r is rt]
        for t in zadania:
            t.cancel()
        await asyncio.gather(*zadania, return_exceptions=True)
        for t in zadania:
            self._zadania.pop(t, None)
        try:
            await rt.zamknij(self.flush_seconds)
        except Exception:
            log.exception("dom %d: blad przy zamykaniu starego srodowiska", rt.dom_id)

    # ---------------------------------------------------- izolacja awarii
    def _dotknij_tetna_procesu(self) -> None:
        if self.tetno_procesu is None:
            return
        try:
            self.tetno_procesu()
        except Exception:
            log.exception("nie zapisano tetna procesu")

    async def _awaria_zadania(self, task: asyncio.Task) -> None:
        """Zadanie domu sie skonczylo (petle sa nieskonczone, wiec to awaria)."""
        rt = self._zadania.pop(task, None)
        if rt is None:
            return  # zadanie srodowiska zatrzymanego w tym samym obiegu
        if task.cancelled():
            powod = f"petla {task.get_name()} anulowana"
            log.error("dom %d: zadanie %s anulowane", rt.dom_id, task.get_name())
        elif task.exception() is not None:
            exc = task.exception()
            powod = f"petla {task.get_name()}: {opis_bledu(exc)}"
            log.error("dom %d: zadanie %s zakonczylo sie bledem", rt.dom_id, task.get_name(),
                      exc_info=exc)
        else:
            powod = f"petla {task.get_name()} zakonczyla sie bez bledu"
            log.error("dom %d: zadanie %s zakonczylo sie bez bledu, a nie powinno",
                      rt.dom_id, task.get_name())
        await self._restart_domu(rt, powod)

    async def _sprawdz_tetna(self) -> None:
        teraz = self.zegar()
        for rt in list(self.domy):
            limit = max(TETNO_OKRESY * rt.okres_tiku, MIN_TETNO)
            cisza = teraz - rt.tetno
            if cisza > limit:
                log.error("dom %d: tik stoi od %.0f s (limit %.0f s)", rt.dom_id, cisza, limit)
                await self._restart_domu(rt, f"tik stoi od {int(cisza)} s")

    async def _restart_domu(self, rt: HomeRuntime, powod: str) -> None:
        """Zatrzymuje srodowisko domu i planuje jego ponowne zbudowanie.
        Czujka domu idzie do JEGO kolejki przed zamknieciem (zapis w bazie
        domu — wysle ja kolejka nowego srodowiska)."""
        dom_id = rt.dom_id
        alarm = self._seria(dom_id)
        if alarm is not None:
            note = Notification(
                kind=NotifyKind.WATCHDOG, title="Kidwatch: przerwa w monitoringu domu",
                text=(f"Monitoring tego domu zatrzymal sie ({powod}) i zostanie uruchomiony "
                      f"ponownie za {_czas(alarm)}. Do tego czasu powiadomienia moga nie "
                      "przychodzic."),
                dedup_key=f"nadzorca:awaria:{dom_id}:{int(time.time())}",
                ts=_teraz_utc(), priority=4)
            try:
                await rt.outbox.send_all([note])
            except Exception:
                log.exception("dom %d: nie zapisano czujki awarii w kolejce domu", dom_id)
        if rt in self.domy:
            self.domy.remove(rt)
        await self._zatrzymaj(rt)
        await self._zaplanuj_restart(dom_id, rt.home, rt.wersja, powod, alarm)

    def _seria(self, dom_id: int) -> float | None:
        """Kolejna awaria domu: numer proby, odstep restartu i czy pora na
        alarm. Zwraca odstep restartu, gdy alarm ma wyjsc, inaczej None."""
        teraz = self.zegar()
        seria = self._serie.get(dom_id)
        start = self._starty.get(dom_id)
        if seria is not None and start is not None and teraz - start >= RESTART_STABILNY:
            seria = None  # dom chodzil dlugo — nowa seria, odstep od nowa
        proba = 1 if seria is None else seria.proba + 1
        odstep = min(RESTART_PIERWSZY * 2 ** (proba - 1), RESTART_MAX)
        if seria is None:
            self._serie[dom_id] = _SeriaAwarii(proba, teraz + ALARM_PIERWSZY_ODSTEP,
                                               ALARM_PIERWSZY_ODSTEP)
            return odstep
        seria.proba = proba
        if teraz < seria.nastepny_alarm:
            return None
        seria.odstep_alarmu = min(seria.odstep_alarmu * 2, ALARM_MAX_ODSTEP)
        seria.nastepny_alarm = teraz + seria.odstep_alarmu
        return odstep

    def _odstep(self, dom_id: int) -> float:
        seria = self._serie.get(dom_id)
        proba = seria.proba if seria is not None else 1
        return min(RESTART_PIERWSZY * 2 ** (proba - 1), RESTART_MAX)

    async def _zaplanuj_restart(self, dom_id: int, home: HomeConfig, wersja: int | None,
                                powod: str, alarm: float | None) -> None:
        odstep = self._odstep(dom_id)
        self._restarty[dom_id] = (self.zegar() + odstep, home, wersja)
        proba = self._serie[dom_id].proba if dom_id in self._serie else 1
        log.error("dom %d: awaria (%s) — restart domu za %s (proba %d); pozostale domy "
                  "dzialaja", dom_id, powod, _czas(odstep), proba)
        if alarm is not None:
            await self._alarm(f"Dom {dom_id}: awaria monitoringu",
                              f"{powod}. Restart domu za {_czas(odstep)} (proba {proba}); "
                              "pozostale domy dzialaja. Kolejne awarie z tej serii — alarm "
                              "najwyzej co 1 h, 2 h... (log: kubectl logs).")

    async def _restartuj_gotowe(self) -> None:
        p = self.przeladowanie
        for dom_id, (kiedy, home, wersja) in sorted(self._restarty.items()):
            if self.zegar() < kiedy:
                continue
            del self._restarty[dom_id]
            assert self.odbuduj is not None
            try:
                if p is not None:
                    await asyncio.to_thread(p.materializuj, dom_id, home)
                nowy = self.odbuduj(dom_id, home)
            except Exception as exc:
                log.exception("dom %d: srodowisko nie wstalo przy restarcie", dom_id)
                await self._zaplanuj_restart(dom_id, home, wersja,
                                             f"restart nieudany: {opis_bledu(exc)}",
                                             self._seria(dom_id))
                continue
            nowy.wersja = wersja
            self.domy.append(nowy)
            self.domy.sort(key=lambda r: r.dom_id)
            self._uruchom(nowy)
            log.warning("dom %d: srodowisko uruchomione ponownie po awarii (proba %d)",
                        dom_id, self._serie[dom_id].proba if dom_id in self._serie else 1)
            if p is not None:
                try:
                    p.po_zmianie(dom_id, nowy)
                except Exception:
                    log.exception("dom %d: blad po restarcie (panel)", dom_id)

    async def zamknij(self, flush_seconds: float) -> None:
        for rt in self.domy:
            await rt.zamknij(flush_seconds)


def _czas(sekundy: float) -> str:
    return f"{int(sekundy // 60)} min" if sekundy >= 60 else f"{int(sekundy)} s"


def _teraz_utc():
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.now(UTC)
