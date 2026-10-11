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

`uprawnienia(user_id, dom_id)` liczy WYLACZNIE z czlonkostwa: bez wiersza
pusty zbior. Wyjatek administratora instalacji (§2.3: flaga + grupa SSO
`admins` + wpis w `audyt`) zalezy od sesji i dochodzi w panelu, nad ta
funkcja.

ZRODLO PRAWDY O ROLACH W DOMU 1. Do E4 (§6 p. 7) `users.rola`
i `user_uprawnienia` sa lustrem roli w Domu 1, zeby obraz sprzed domow
dzialal na tej samej bazie. W E1 panel liczy uprawnienia jak dotad
(z `users`), a kazda zmiana konta przepisuje rola do `czlonkostwa`
(`uzgodnij_konto_conn`). Start uzgadnia oba miejsca: role zmienione przez
stary obraz po wycofaniu wracaja do `czlonkostwa`. E3a, przelaczajac
odczyt na `czlonkostwa`, odwraca kierunek uzgadniania przy starcie;
lustro w `users` usuwa E4.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sqlite3
import time
from collections.abc import Awaitable, Callable, Coroutine, Iterator, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from . import uprawnienia as upr

if TYPE_CHECKING:
    from .config import HomeConfig
    from .engine import Engine
    from .notifiers.base import Outbox
    from .store import Store

log = logging.getLogger(__name__)

DOM_1 = 1
NAZWA_DOMU_1 = "Dom 1"
#: domy.zrodlo_konfiguracji: 'yaml' = config.yaml + zmienne srodowiskowe
#: (tylko Dom 1, etap przejsciowy), 'baza' = tabele ponizej (od E2).
ZRODLO_YAML = "yaml"
ZRODLO_BAZA = "baza"

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
        cel = upr.efektywne(rola, nadane, odebrane, role=upr.ROLE_DOMU_UPRAWNIENIA)
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
    """Czlonkostwo konta w Domu 1 := rola z `users` (E1: `users` jest prawda).

    Bez zmiany, gdy lustro czlonkostwa juz zgadza sie z `users` — dzieki temu
    `zarzadca` zapisany lustrem jako `podglad` + nadania nie spada do
    `podglad`. Konto z flaga `admin_instancji` nie dostaje czlonkostwa
    (konto administracyjne bez domow, §2.3). Na polaczeniu i w transakcji
    wolajacego. Zwraca, czy cos zapisano."""
    if not _dom_istnieje(conn, DOM_1):
        return False
    konto = _stan_konta(conn, user_id)
    if konto is None:
        return False
    obecne = _stan_czlonkostwa(conn, DOM_1, user_id)
    if obecne is None and _admin_instancji(conn, user_id):
        return False
    if obecne is not None and lustro_konta(obecne) == konto:
        return False
    _zapisz_czlonkostwo(conn, DOM_1, user_id, rola_z_konta(konto),
                        time.time() if teraz is None else teraz)
    return True


def _admin_instancji(conn: sqlite3.Connection, user_id: int) -> bool:
    try:
        row = conn.execute("SELECT admin_instancji FROM users WHERE id = ?",
                           (user_id,)).fetchone()
    except sqlite3.OperationalError:
        return False
    return bool(row and row[0])


def ustaw_czlonkostwo_conn(conn: sqlite3.Connection, dom_id: int, user_id: int, rola: str,
                           nadane: frozenset[str] = frozenset(),
                           odebrane: frozenset[str] = frozenset(),
                           teraz: float | None = None) -> None:
    """Rola konta w domu. W Domu 1 takze lustro w `users` (obraz sprzed
    domow czyta role stamtad). Na polaczeniu i w transakcji wolajacego."""
    if rola not in upr.ROLE_DOMU:
        raise ValueError(f"nieznana rola w domu {rola!r} (dozwolone: {', '.join(upr.ROLE_DOMU)})")
    zle = (set(nadane) | set(odebrane)) - set(upr.UPRAWNIENIA)
    if zle or set(odebrane) & upr.STALE:
        raise ValueError(f"niedozwolone odstepstwa: {sorted(zle or set(odebrane) & upr.STALE)}")
    if not _dom_istnieje(conn, dom_id):
        raise LookupError(f"nie ma domu {dom_id}")
    stan = (rola, frozenset(nadane), frozenset(odebrane))
    _zapisz_czlonkostwo(conn, dom_id, user_id, stan, time.time() if teraz is None else teraz)
    if dom_id == DOM_1:
        _zapisz_konto(conn, user_id, lustro_konta(stan))


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
                           f"rola w Domu 1 z roli konta: {rola[0] if rola else '?'}")
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
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                ustaw_czlonkostwo_conn(conn, dom_id, user_id, rola, nadane, odebrane)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise


def _dom(row: sqlite3.Row) -> Dom:
    return Dom(row["id"], row["nazwa"], row["strefa"], row["zrodlo_konfiguracji"],
               row["wersja"], bool(row["zawieszony"]))


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
