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
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import sqlite3
import time
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import uprawnienia as upr

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


def ustaw_admin_instancji_conn(conn: sqlite3.Connection, user_id: int, wlaczona: bool,
                               teraz: float | None = None) -> bool:
    """Flaga `admin_instancji` (tylko CLI `user-admin`). Zwraca, czy sie
    zmienila; zmiana idzie do `audyt` jako zdarzenie instancji."""
    row = conn.execute("SELECT login, admin_instancji FROM users WHERE id = ?",
                       (user_id,)).fetchone()
    if row is None:
        raise LookupError(f"nie ma konta {user_id}")
    if bool(row[1]) == wlaczona:
        return False
    conn.execute("UPDATE users SET admin_instancji = ? WHERE id = ?", (int(wlaczona), user_id))
    zapisz_audyt(conn, None, row[0], "instancja.admin",
                 "administrator instalacji: " + ("nadany" if wlaczona else "odebrany"), teraz)
    return True


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
                           kto: str | None = None, teraz: float | None = None) -> None:
    """Upsert integracji w transakcji wolajacego. `sekrety`: pole -> wartosc
    (None = usun pole); pola nie wymienione zostaja. Bez walidacji ustawien
    i adresow — robi ja RejestrDomow.zapisz_integracje (panel) i porownanie
    w dom-importuj. Audyt bez wartosci."""
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
    _podbij_wersje(conn, dom_id)
    opis = [f"integracja {typ}: {'wlaczona' if nowe_wlaczona else 'wylaczona'}"]
    if ustawienia is not None:
        opis.append(f"ustawienia: {', '.join(sorted(ustawienia)) or '-'}")
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

    def ustaw_admin_instancji(self, user_id: int, wlaczona: bool) -> bool:
        return self._w_transakcji(ustaw_admin_instancji_conn, user_id, wlaczona)

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
                          resolver: Callable[[str, int], list[str]] | None = None
                          ) -> Integracja:
        """Zapis integracji z panelu (E3a): walidacja ustawien modelem
        konfiguracji, adresy przez straznika sieci domu (odmowa = ValueError
        z opisem, bez wartosci sekretow), sekrety tylko do zapisu."""
        from .konfiguracja_domu import waliduj_integracje  # noqa: PLC0415

        _sprawdz_pola(typ, list(sekrety or {}))
        obecna = self.integracja(dom_id, typ)
        do_walidacji = ustawienia if ustawienia is not None else (
            obecna.ustawienia if obecna else {})
        skutecznie = wlaczona if wlaczona is not None else bool(obecna and obecna.wlaczona)
        waliduj_integracje(typ, do_walidacji, self.straznik(dom_id, resolver),
                           wlaczona=skutecznie)
        with self._conn() as conn, _transakcja(conn):
            zapisz_integracje_conn(conn, dom_id, typ, sejf=sejf, wlaczona=wlaczona,
                                   ustawienia=ustawienia, sekrety=sekrety, kto=kto)
        wynik = self.integracja(dom_id, typ)
        assert wynik is not None
        return wynik

    def sekrety_domu(self, dom_id: int, sejf: Sejf) -> SekretyDomu:
        """Tylko dla srodowiska domu i testu polaczenia — nigdy do odpowiedzi
        panelu. Zwrocony obiekt zapisuje zmiany (token aplikacji TV) do bazy."""
        with self._conn() as conn:
            wynik = sekrety_domu_conn(conn, dom_id, sejf)

        def zapisz(typ: str, sekrety: dict[str, str | None]) -> None:
            with self._conn() as conn, _transakcja(conn):
                zapisz_integracje_conn(conn, dom_id, typ, sejf=sejf, sekrety=sekrety,
                                       kto=f"dom-{dom_id}")

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
        return raport

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

    def dodaj_petle(self, nazwa: str, fabryka: Callable[[], Coroutine[Any, Any, Any]]) -> None:
        self.petle.append((nazwa, fabryka))

    def dodaj_sprzatanie(self, fn: Callable[[], Awaitable[None]]) -> None:
        self.sprzatanie.append(fn)

    def start(self) -> list[asyncio.Task]:
        return [asyncio.create_task(fabryka(), name=nazwa) for nazwa, fabryka in self.petle]

    async def zamknij(self, flush_seconds: float) -> None:
        for fn in self.sprzatanie:
            await fn()
        # Co zostalo w kolejce, probujemy wyslac przed zamknieciem — reszta i tak
        # wyjdzie po starcie. Krocej niz terminationGracePeriodSeconds (30 s).
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.outbox.flush(), timeout=flush_seconds)
        await self.outbox.aclose()
        await self.source.aclose()
        self.store.close()


class Nadzorca:
    """Uruchamia srodowiska domow i czeka na koniec.

    E1 zachowuje regule sprzed domow: kazde zadanie domu jest nieskonczone,
    wiec jego koniec — z bledem czy bez — konczy proces kodem 1 (k8s
    restartuje poda). Izolacja awarii miedzy domami to etap E3b."""

    def __init__(self, domy: Sequence[HomeRuntime]) -> None:
        self.domy = list(domy)

    async def run(self, stop: asyncio.Event) -> int:
        tasks = [t for rt in self.domy for t in rt.start()]
        tasks.append(asyncio.create_task(stop.wait(), name="stop"))
        done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)
        # Kod 0 udawal w k8s czyste zatrzymanie i ginal w statystyce restartow;
        # niezerowy widac w `kubectl describe` jako Error.
        failed = [task for task in done if task.get_name() != "stop"]
        for task in failed:
            if task.exception() is not None:
                log.error("zadanie %s zakonczylo sie bledem", task.get_name(),
                          exc_info=task.exception())
            else:
                log.error("zadanie %s zakonczylo sie bez bledu, a nie powinno", task.get_name())
        return 1 if failed else 0

    async def zamknij(self, flush_seconds: float) -> None:
        for rt in self.domy:
            await rt.zamknij(flush_seconds)
