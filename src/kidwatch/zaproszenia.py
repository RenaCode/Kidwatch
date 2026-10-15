"""Zaproszenia do domu (etap E4, docs/architektura-domy.md §7 E4).

PRZEPLYW. Osoba z `dom.zaproszenia` w domu (domyslnie `wlasciciel-domu`,
takze aktywny administrator instalacji) tworzy zaproszenie: rola, waznosc
(domyslnie 72 h, najwyzej 7 dni) i opcjonalnie oczekiwany login SSO (`dla`).
Panel pokazuje RAZ link `https://<panel>/zaproszenie#<token>` — token we
fragmencie adresu nie trafia do logow Traefika ani do naglowka `Referer`.

Zaproszony otwiera link:
  * przez Authelie (SSO, droga podstawowa): login = `Remote-User`. Konto
    panelu o tym loginie, jesli go nie ma, powstaje W TEJ CHWILI — jedyny
    przypadek zakladania konta z SSO w locie, i tylko z waznym tokenem —
    z losowym haslem awaryjnym, ktorego nikt nie widzi;
  * bez SSO: ekran „ustaw haslo” (MIN_PASSWORD_LEN, Argon2id), a dostep do
    danych domu dopiero po wlaczeniu TOTP (`wymaga_totp`);
  * z istniejaca sesja panelu (konto z innego domu): przyjecie dopisuje
    czlonkostwo temu kontu; sesja z hasla musi miec wlaczony TOTP.

Przyjecie = potwierdzenie przeczytania informacji o prywatnosci
(INFORMACJA_O_PRYWATNOSCI, decyzja 5 w §8): administrator instalacji ma
wglad we wszystkie dane domu, operator klastra — techniczny dostep do bazy.

ZABEZPIECZENIA
  * token 32 B z `secrets.token_urlsafe`; w bazie WYLACZNIE SHA-256 — wyciek
    pliku bazy nie daje dzialajacego linku; token nie trafia do logu ani do
    `audyt` (tam numer zaproszenia);
  * jednorazowe: zuzycie warunkowym UPDATE-em w tej samej transakcji co
    czlonkostwo — z dwoch rownoleglych przyjec przechodzi jedno;
  * wygasa, mozna je odwolac w kazdej chwili; wygasle i odwolane znikaja po
    30 dniach (`sprzataj`);
  * limit MAX_PROB nieudanych prob na token (zly login wzgledem `dla` na
    ekranie bez SSO, proba na zuzytym/odwolanym/wygaslym — NIE zly login
    zalogowanego w SSO: to nie zgadywanie) i limit per adres (IP_MAX_FAILED w oknie,
    jak `ip_failures` logowania) — takze dla tokenow, ktorych nie ma;
  * sufit roli: zaproszenie nie nadaje roli wyzszej niz rola zapraszajacego
    (`wlasciciel-domu` i administrator — dowolna); nie podnosi roli
    istniejacego czlonka (tylko nowy czlonek) i nie przyjmuje go konto
    administracyjne (§2.3: bez czlonkostw);
  * prawo zapraszajacego sprawdzane takze przy PRZYJECIU (`zapraszajacy_moze`):
    wypisanie z domu albo degradacja zamyka jego oczekujace linki;
  * utworzenie wymaga swiezego potwierdzenia haslem albo kodem 2FA;
  * przyjecie daje czlonkostwo WYLACZNIE w domu zaproszenia — inne domy
    zapraszajacego zostaja nieznane (404).

Modul bez HTTP: panel.py dopina trasy, logika i walidacja sa tutaj
(`PanelZaproszenia`), testowane takze bez serwera.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import logging
import secrets
import sqlite3
import threading
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from . import domy as dm
from . import panel_auth
from . import uprawnienia as u
from .panel_auth import (
    MIN_PASSWORD_LEN,
    AuthError,
    PanelAuth,
    Session,
    check_password_policy,
    generate_password,
    hash_password,
)
from .panel_sso import GRUPA_GOSCI, login_ok

log = logging.getLogger(__name__)

WAZNOSC_DOMYSLNA_H = 72
WAZNOSC_MIN_H = 1
WAZNOSC_MAX_H = 7 * 24
#: Nieudane proby na JEDEN token, po ktorych jest martwy.
MAX_PROB = 5
#: Nieudane proby z jednego adresu w oknie (takze nieistniejace tokeny).
IP_MAX_FAILED = 10
IP_WINDOW_SECONDS = 15 * 60
#: Wygasle i odwolane zaproszenia znikaja po tym czasie.
SPRZATANIE_PO_SECONDS = 30 * 24 * 3600
#: token_urlsafe(32) ma 43 znaki; dluzszego nie ma po co hashowac.
MAX_TOKEN = 128

#: Kolejnosc rol do sufitu (§2.3): zaproszenie nie nadaje wyzszej.
RANGA = {u.ROLA_PODGLAD: 0, u.ROLA_ZARZADCA: 1, u.ROLA_WLASCICIEL_DOMU: 2}

#: Pokazywane na ekranie przyjecia PRZED utworzeniem czlonkostwa (decyzja 5,
#: §8). Przyjecie = potwierdzenie przeczytania (pole `potwierdzam`).
INFORMACJA_O_PRYWATNOSCI = (
    "Kidwatch prowadzi jeden operator (właściciel instalacji). Administrator "
    "instalacji ma w panelu wgląd we wszystkie dane tego domu — historię, "
    "urządzenia, integracje i członków; każde jego wejście jest zapisywane "
    "w dzienniku domu, który widzi właściciel domu. Operator klastra ma "
    "ponadto techniczny dostęp do bazy danych i klucza szyfrującego. "
    "Izolacja między domami jest w aplikacji: inni członkowie innych domów "
    "nie widzą danych tego domu."
)

#: Instrukcja dla zapraszajacego przy SSO (§7 E4 p. 2): konto w Authelii
#: zaklada administrator instalacji w renacode-infra.
INSTRUKCJA_SSO = (
    "Panel stoi za Authelią. Zanim zaproszony otworzy link, administrator "
    "instalacji musi założyć mu konto w Authelii (renacode-infra, Sekret "
    f"authelia-uzytkownicy) w grupie „{GRUPA_GOSCI}” — z tym samym loginem, "
    "który wpisano jako oczekiwany. Konto w Kidwatchu powstanie samo przy "
    "przyjęciu zaproszenia."
)

SCHEMAT = """
-- Zaproszenia do domu (§2.2). Sam token nigdzie nie lezy — tylko SHA-256.
-- utworzone_przez / przyjete_przez: konto moze zniknac (ostatni dom), wiec
-- SET NULL, a login zostaje w kolumnach *_login (dziennik).
CREATE TABLE IF NOT EXISTS zaproszenia (
    id                    INTEGER PRIMARY KEY,
    dom_id                INTEGER NOT NULL REFERENCES domy (id) ON DELETE CASCADE,
    token_hash            TEXT NOT NULL UNIQUE,
    rola                  TEXT NOT NULL,
    dla                   TEXT,
    utworzone_przez       INTEGER REFERENCES users (id) ON DELETE SET NULL,
    utworzone_przez_login TEXT,
    utworzone_at          REAL NOT NULL,
    wygasa_at             REAL NOT NULL,
    przyjete_przez        INTEGER REFERENCES users (id) ON DELETE SET NULL,
    przyjete_przez_login  TEXT,
    przyjete_at           REAL,
    odwolane_at           REAL,
    proby                 INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_zaproszenia_dom ON zaproszenia (dom_id, utworzone_at);

-- Nieudane proby per SAM adres (tokeny, ktorych nie ma, zly login).
CREATE TABLE IF NOT EXISTS zaproszenia_ip (
    ip           TEXT PRIMARY KEY,
    failures     INTEGER NOT NULL DEFAULT 0,
    locked_until REAL,
    updated_at   REAL NOT NULL
);
"""

OCZEKUJE, PRZYJETE, ODWOLANE, WYGASLE, ZABLOKOWANE = (
    "oczekuje", "przyjete", "odwolane", "wygasle", "zablokowane")


def nowy_token() -> str:
    return secrets.token_urlsafe(32)


def hash_tokenu(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _iso(ts: float | None) -> str | None:
    return None if ts is None else datetime.fromtimestamp(ts, UTC).isoformat()


@dataclass(frozen=True)
class Zaproszenie:
    """Wiersz `zaproszenia` bez hasha tokenu (do panelu i dziennika)."""

    id: int
    dom_id: int
    rola: str
    dla: str | None
    utworzone_przez: int | None
    utworzone_przez_login: str | None
    utworzone_at: float
    wygasa_at: float
    przyjete_przez_login: str | None
    przyjete_at: float | None
    odwolane_at: float | None
    proby: int

    def stan(self, teraz: float) -> str:
        if self.przyjete_at is not None:
            return PRZYJETE
        if self.odwolane_at is not None:
            return ODWOLANE
        if self.wygasa_at <= teraz:
            return WYGASLE
        if self.proby >= MAX_PROB:
            return ZABLOKOWANE
        return OCZEKUJE

    def publiczne(self, teraz: float) -> dict:
        return {
            "id": self.id,
            "rola": self.rola,
            "dla": self.dla,
            "stan": self.stan(teraz),
            "utworzone_przez": self.utworzone_przez_login,
            "utworzone_at": _iso(self.utworzone_at),
            "wygasa_at": _iso(self.wygasa_at),
            "przyjete_przez": self.przyjete_przez_login,
            "przyjete_at": _iso(self.przyjete_at),
            "odwolane_at": _iso(self.odwolane_at),
        }


def _zaproszenie(r: sqlite3.Row) -> Zaproszenie:
    return Zaproszenie(r["id"], r["dom_id"], r["rola"], r["dla"], r["utworzone_przez"],
                       r["utworzone_przez_login"], r["utworzone_at"], r["wygasa_at"],
                       r["przyjete_przez_login"], r["przyjete_at"], r["odwolane_at"],
                       r["proby"])


def dozwolone_role(rola_zapraszajacego: str | None, upr_zapraszajacego: frozenset[str], *,
                   admin: bool) -> list[str]:
    """Role, ktore zapraszajacy moze nadac (sufit, §2.3). `wlasciciel-domu`
    i aktywny administrator instalacji — kazda. Inni (np. zarzadca z nadanym
    `dom.zaproszenia`) — rola nie wyzsza od wlasnej i taka, ktorej
    uprawnienia sam ma w tym domu."""
    if admin or rola_zapraszajacego == u.ROLA_WLASCICIEL_DOMU:
        return list(u.ROLE_DOMU)
    if rola_zapraszajacego not in RANGA:
        return []
    return [r for r in u.ROLE_DOMU
            if RANGA[r] <= RANGA[rola_zapraszajacego]
            and u.ROLE_DOMU_UPRAWNIENIA[r] <= upr_zapraszajacego]


NIEWAZNE_BEZ_PRAWA = ("To zaproszenie straciło ważność: osoba, która je wysłała, nie może "
                      "już zapraszać do tego domu z tą rolą. Poproś o nowe.")


def zapraszajacy_moze(conn: sqlite3.Connection, z: Zaproszenie) -> bool:
    """Czy zapraszajacy NADAL moze wydac to zaproszenie (przeglad #72, 2).

    Link zyje do 7 dni; prawo sprawdzone tylko przy tworzeniu zostawialoby
    dzialajace linki osoby wypisanej z domu albo zdegradowanej. Teraz:
    konto istnieje i (a) jest czlonkiem domu z `dom.zaproszenia`, a rola
    zaproszenia miesci sie pod jej obecnym sufitem, albo (b) bez czlonkostwa
    ma flage administratora instalacji (grupy `admins` z naglowka tu nie ma —
    flaga to warunek konieczny, sufitu administrator nie ma)."""
    if z.utworzone_przez is None:
        return False
    stan = dm.czlonkostwo_conn(conn, z.utworzone_przez, z.dom_id)
    if stan is None:
        return dm.admin_instancji(conn, z.utworzone_przez)
    upr = u.efektywne(*stan, role=u.ROLE_DOMU_UPRAWNIENIA)
    if dm.admin_instancji(conn, z.utworzone_przez):
        return True
    return u.DOM_ZAPROSZENIA in upr and z.rola in dozwolone_role(stan[0], upr, admin=False)


@dataclass(frozen=True)
class Przyjecie:
    """Wynik przyjecia zaproszenia."""

    zaproszenie_id: int
    dom_id: int
    rola: str
    user_id: int
    login: str
    konto_zalozone: bool
    #: Kto zaprosil (powiadomienie) — None, gdy konta juz nie ma.
    zapraszajacy: str | None


def _hash_hasla(haslo: str) -> str:
    """Argon2id w tym samym JEDNYM slocie co logowanie (panel_auth: 64 MiB
    na weryfikacje, limit poda 384 Mi) — rownolegle przyjecia nie zabija
    procesu OOM-em."""
    if not panel_auth._verify_slot.acquire(timeout=panel_auth.VERIFY_WAIT_SECONDS):
        raise AuthError(503, "Serwer jest zajęty. Spróbuj za chwilę.")
    try:
        return hash_password(haslo)
    finally:
        panel_auth._verify_slot.release()


class Zaproszenia:
    """Zaproszenia w panel-auth.db. Kazda operacja na wlasnym polaczeniu
    (jak PanelAuth): wola ja panel z wielu watkow."""

    def __init__(self, path: str | Path, *, clock: Callable[[], float] = time.time) -> None:
        self.path = str(path)
        self.clock = clock
        with self._conn() as conn:
            conn.executescript(SCHEMAT)

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------ zapis
    def utworz(self, dom_id: int, *, kto_id: int | None, kto_login: str, rola: str,
               waznosc_h: int = WAZNOSC_DOMYSLNA_H, dla: str | None = None,
               ) -> tuple[str, Zaproszenie]:
        """Nowe zaproszenie. Zwraca (token, zaproszenie) — token pokazywany
        RAZ, w bazie tylko jego SHA-256. Sufit roli sprawdza wolajacy
        (PanelZaproszenia), tu tylko poprawnosc wartosci."""
        if rola not in u.ROLE_DOMU:
            raise ValueError(f"nieznana rola w domu {rola!r}")
        if not WAZNOSC_MIN_H <= waznosc_h <= WAZNOSC_MAX_H:
            raise ValueError(f"waznosc od {WAZNOSC_MIN_H} do {WAZNOSC_MAX_H} h")
        if dla is not None and not login_ok(dla):
            raise ValueError("oczekiwany login: małe litery a-z, cyfry, '.', '_', '-'")
        token = nowy_token()
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if not dm._dom_istnieje(conn, dom_id):
                    raise LookupError(f"nie ma domu {dom_id}")
                cur = conn.execute(
                    "INSERT INTO zaproszenia (dom_id, token_hash, rola, dla, utworzone_przez, "
                    "utworzone_przez_login, utworzone_at, wygasa_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (dom_id, hash_tokenu(token), rola, dla, kto_id, kto_login, teraz,
                     teraz + waznosc_h * 3600),
                )
                zid = int(cur.lastrowid)
                dm.zapisz_audyt(conn, dom_id, kto_login, "zaproszenie.utworz",
                                f"zaproszenie #{zid}: rola {rola}, ważne {waznosc_h} h"
                                + (f", dla {dla}" if dla else ""), teraz)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        log.info("zaproszenia: %r utworzyl zaproszenie #%d do domu %d (rola %s)", kto_login,
                 zid, dom_id, rola)
        z = self.zaproszenie(dom_id, zid)
        assert z is not None
        return token, z

    def odwolaj(self, dom_id: int, zid: int, *, kto_login: str) -> Zaproszenie:
        """Odwolanie oczekujacego zaproszenia. Zaproszenie innego domu = jak
        nieistniejace (LookupError -> 404)."""
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM zaproszenia WHERE id = ? AND dom_id = ?",
                                   (zid, dom_id)).fetchone()
                if row is None:
                    raise LookupError(zid)
                z = _zaproszenie(row)
                if z.przyjete_at is not None:
                    raise ValueError("Zaproszenie zostało już przyjęte — członka usuniesz "
                                     "w Kontach.")
                if z.odwolane_at is None:
                    conn.execute("UPDATE zaproszenia SET odwolane_at = ? WHERE id = ?",
                                 (teraz, zid))
                    dm.zapisz_audyt(conn, dom_id, kto_login, "zaproszenie.odwolaj",
                                    f"zaproszenie #{zid} odwołane", teraz)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        log.info("zaproszenia: %r odwolal zaproszenie #%d domu %d", kto_login, zid, dom_id)
        z = self.zaproszenie(dom_id, zid)
        assert z is not None
        return z

    def sprzataj(self) -> int:
        """Wygasle (nieprzyjete) i odwolane starsze niz 30 dni."""
        granica = self.clock() - SPRZATANIE_PO_SECONDS
        with self._conn() as conn:
            n = conn.execute(
                "DELETE FROM zaproszenia WHERE przyjete_at IS NULL AND "
                "(wygasa_at < ? OR (odwolane_at IS NOT NULL AND odwolane_at < ?))",
                (granica, granica)).rowcount
            conn.execute("DELETE FROM zaproszenia_ip WHERE updated_at < ?",
                         (self.clock() - 24 * 3600,))
        return n

    # ------------------------------------------------------------ odczyt
    def zaproszenie(self, dom_id: int, zid: int) -> Zaproszenie | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM zaproszenia WHERE id = ? AND dom_id = ?",
                               (zid, dom_id)).fetchone()
        return _zaproszenie(row) if row else None

    def lista(self, dom_id: int) -> list[Zaproszenie]:
        with self._conn() as conn:
            return [_zaproszenie(r) for r in conn.execute(
                "SELECT * FROM zaproszenia WHERE dom_id = ? ORDER BY utworzone_at DESC, id DESC",
                (dom_id,))]

    def wymaga_totp(self, user_id: int, dom_id: int | None = None) -> bool:
        """Czlonkostwo z zaproszenia (w `dom_id` albo w dowolnym domu).
        Sesja z hasla bez TOTP nie dostaje danych takiego domu."""
        sql = "SELECT 1 FROM czlonkostwa WHERE user_id = ? AND zaproszenie_id IS NOT NULL"
        args: tuple = (user_id,)
        if dom_id is not None:
            sql += " AND dom_id = ?"
            args += (dom_id,)
        with self._conn() as conn:
            if not dm._jest_tabela(conn, "czlonkostwa"):
                return False
            return conn.execute(sql + " LIMIT 1", args).fetchone() is not None

    # ------------------------------------------------------------ proby
    def _sprawdz_adres(self, ip: str) -> None:
        with self._conn() as conn:
            row = conn.execute("SELECT locked_until FROM zaproszenia_ip WHERE ip = ?",
                               (ip,)).fetchone()
        teraz = self.clock()
        if row is not None and row["locked_until"] and row["locked_until"] > teraz:
            raise AuthError(429, f"Zbyt wiele nieudanych prób. Spróbuj za "
                                 f"{int(row['locked_until'] - teraz) + 1} s.")

    def _porazka(self, ip: str, zid: int | None = None) -> None:
        """Nieudana proba: licznik adresu i (gdy token istnieje) tokenu.
        Wlasne polaczenie w trybie autocommit — licznik zostaje, choc
        zadanie konczy sie bledem."""
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO zaproszenia_ip (ip, failures, locked_until, updated_at) "
                "VALUES (?, 1, NULL, ?) "
                "ON CONFLICT (ip) DO UPDATE SET "
                "failures = CASE WHEN (locked_until IS NOT NULL AND locked_until <= ?) "
                "OR updated_at < ? THEN 1 ELSE failures + 1 END, "
                "locked_until = CASE "
                "WHEN (locked_until IS NOT NULL AND locked_until <= ?) OR updated_at < ? "
                "THEN NULL WHEN failures + 1 >= ? THEN ? ELSE locked_until END, "
                "updated_at = excluded.updated_at",
                (ip, teraz, teraz, teraz - IP_WINDOW_SECONDS, teraz, teraz - IP_WINDOW_SECONDS,
                 IP_MAX_FAILED, teraz + IP_WINDOW_SECONDS),
            )
            if zid is not None:
                conn.execute("UPDATE zaproszenia SET proby = proby + 1 WHERE id = ?", (zid,))

    def _token(self, token: str, ip: str, login: str | None,
               uwierzytelniony: bool = True) -> Zaproszenie:
        """Zaproszenie z tokenu, ktore jeszcze mozna przyjac — inaczej
        AuthError (i licznik prob). `login` = None: bez sprawdzenia `dla`
        (ekran bez SSO, login wpisze zaproszony).

        `uwierzytelniony`: login pochodzi z Authelii albo z sesji panelu.
        Wtedy `dla` != login NIE zjada prob tokenu ani adresu — to nie
        zgadywanie (token jest wazny, a tozsamosc potwierdzona), a inaczej
        kazdy z linkiem i kontem SSO spalilby zaproszenie wlasciwej osobie
        (przeglad #72, 3c). Licza sie proby nieuwierzytelnione (ekran
        „ustaw haslo”) i kazdy zly albo martwy token."""
        self._sprawdz_adres(ip)
        if not isinstance(token, str) or not token or len(token) > MAX_TOKEN:
            self._porazka(ip)
            raise AuthError(404, "Zaproszenie nie istnieje albo link jest niepełny.")
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM zaproszenia WHERE token_hash = ?",
                               (hash_tokenu(token),)).fetchone()
        if row is None:
            self._porazka(ip)
            log.warning("zaproszenia: nieznany token z %s", ip)
            raise AuthError(404, "Zaproszenie nie istnieje albo link jest niepełny.")
        z = _zaproszenie(row)
        stan = z.stan(self.clock())
        if stan != OCZEKUJE:
            self._porazka(ip, z.id)
            log.warning("zaproszenia: proba na zaproszeniu #%d (%s) z %s", z.id, stan, ip)
            raise AuthError(410, {
                PRZYJETE: "To zaproszenie zostało już wykorzystane.",
                ODWOLANE: "To zaproszenie zostało odwołane.",
                WYGASLE: "To zaproszenie wygasło — poproś o nowe.",
                ZABLOKOWANE: "To zaproszenie zablokowano po nieudanych próbach — poproś o nowe.",
            }[stan])
        if login is not None and z.dla is not None and z.dla != login:
            if not uwierzytelniony:
                self._porazka(ip, z.id)
            log.warning("zaproszenia: zaproszenie #%d dla innego konta (proba %r z %s)", z.id,
                        login, ip)
            raise AuthError(403, "To zaproszenie jest dla innego konta. Zaloguj się w SSO "
                                 "jako osoba, którą zaproszono.")
        with self._conn() as conn:
            if not zapraszajacy_moze(conn, z):
                log.warning("zaproszenia: zaproszenie #%d bez prawa zapraszajacego", z.id)
                raise AuthError(410, NIEWAZNE_BEZ_PRAWA)
        return z

    def sprawdz(self, token: str, *, ip: str, login: str | None,
                uwierzytelniony: bool = True) -> Zaproszenie:
        """Podglad przed przyjeciem (dom, rola, waznosc). Te same bariery
        i liczniki co przyjecie — podglad nie jest wyrocznia bez limitu."""
        return self._token(token, ip, login, uwierzytelniony)

    # ------------------------------------------------------------ przyjecie
    def przyjmij(self, token: str, *, ip: str, login: str, sso: bool,
                 haslo: str | None = None, zaloz: bool = False,
                 uwierzytelniony: bool = True) -> Przyjecie:
        """Przyjecie zaproszenia przez `login`.

        `zaloz`=True: konta moze nie byc — powstaje w tej transakcji (SSO:
        losowe haslo awaryjne, nikomu niepokazane; bez SSO: `haslo`
        zaproszonego). `zaloz`=False: konto musi istniec (sesja panelu).
        Wszystko albo nic: zuzycie tokenu, konto, czlonkostwo i wpis
        w dzienniku w jednej transakcji."""
        z = self._token(token, ip, login, uwierzytelniony)
        if haslo is not None:
            check_password_policy(haslo)
        # Argon2 (64 MiB) poza transakcja i tylko po waznym tokenie: zgadywanie
        # tokenow nie kosztuje serwera pamieci.
        password_hash = _hash_hasla(haslo or generate_password()) if zaloz else None
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                wynik = self._przyjmij_conn(conn, z, login, sso=sso, password_hash=password_hash,
                                            teraz=teraz)
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        log.warning("zaproszenia: %r przyjal zaproszenie #%d do domu %d (rola %s%s)", login,
                    z.id, z.dom_id, z.rola, ", konto zalozone" if wynik.konto_zalozone else "")
        return wynik

    def _przyjmij_conn(self, conn: sqlite3.Connection, z: Zaproszenie, login: str, *,
                       sso: bool, password_hash: str | None, teraz: float) -> Przyjecie:
        row = conn.execute("SELECT id FROM users WHERE login = ?", (login,)).fetchone()
        zalozone = False
        if row is None:
            if password_hash is None:
                raise AuthError(404, "Nie ma takiego konta")
            # Jedyne miejsce, w ktorym konto powstaje z zaproszenia. Lustro
            # `users.rola` = bez domu; czlonkostwo (Dom 1: takze lustro) nizej.
            uid = int(conn.execute(
                "INSERT INTO users (login, password_hash, created_at, rola) VALUES (?, ?, ?, ?)",
                (login, password_hash, teraz, dm.BEZ_DOMU)).lastrowid)
            zalozone = True
        else:
            uid = row["id"]
            if not sso and password_hash is not None:
                # Ekran „ustaw haslo”: login zajety. Zaloguj sie i otworz link.
                raise AuthError(409, "Konto o tym loginie już istnieje — zaloguj się nim "
                                     "i otwórz link ponownie.")
            if dm.admin_instancji(conn, uid):
                raise AuthError(409, "Konto administracyjne nie należy do domów (§2.3) — "
                                     "przyjmij zaproszenie innym kontem.")
            if dm.czlonkostwo_conn(conn, uid, z.dom_id) is not None:
                # Zaproszenie nie podnosi (ani nie zmienia) roli czlonka; nie
                # jest tez zuzywane — moze trafic do wlasciwej osoby.
                raise AuthError(409, "Należysz już do tego domu. Zmianę roli robi osoba "
                                     "zarządzająca kontami.")
        # Prawo zapraszajacego jeszcze raz, w transakcji: odebrane miedzy
        # sprawdzeniem tokenu a zapisem tez zamyka link.
        if not zapraszajacy_moze(conn, z):
            raise AuthError(410, NIEWAZNE_BEZ_PRAWA)
        # Warunkowo: z dwoch rownoleglych przyjec przechodzi jedno.
        if conn.execute(
            "UPDATE zaproszenia SET przyjete_przez = ?, przyjete_przez_login = ?, "
            "przyjete_at = ? WHERE id = ? AND przyjete_at IS NULL AND odwolane_at IS NULL "
            "AND wygasa_at > ? AND proby < ?",
            (uid, login, teraz, z.id, teraz, MAX_PROB),
        ).rowcount != 1:
            raise AuthError(410, "To zaproszenie zostało już wykorzystane.")
        dm.ustaw_czlonkostwo_conn(conn, z.dom_id, uid, z.rola, teraz=teraz)
        conn.execute("UPDATE czlonkostwa SET zaproszenie_id = ? WHERE dom_id = ? AND user_id = ?",
                     (z.id, z.dom_id, uid))
        dm.zapisz_audyt(
            conn, z.dom_id, login, "zaproszenie.przyjete",
            f"zaproszenie #{z.id}: rola {z.rola}"
            + (", konto założone" if zalozone else "")
            + (" (SSO)" if sso else " (hasło)")
            + "; informacja o prywatności potwierdzona", teraz)
        return Przyjecie(z.id, z.dom_id, z.rola, uid, login, zalozone,
                         z.utworzone_przez_login if z.utworzone_przez is not None else None)


# ====================================================================== panel
def _str(data: dict, key: str, limit: int) -> str:
    value = data.get(key, "")
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > limit:
        raise AuthError(400, f"Niepoprawne pole {key!r}")
    return value


#: (login zapraszajacego, nazwa domu, login zaproszonego, rola) -> None.
Powiadom = Callable[[str, str, str, str], None]


def _nic(*_args) -> None:
    return None


class PanelZaproszenia:
    """Trasy zaproszen panelu (panel.py dopina je do tablic tras):

      GET  /api/domy/<id>/zaproszenia           lista (dom.zaproszenia)
      POST /api/domy/<id>/zaproszenia/utworz    nowe (dom.zaproszenia + haslo/2FA)
      POST /api/domy/<id>/zaproszenia/odwolaj   odwolanie (dom.zaproszenia)
      POST /api/zaproszenia/sprawdz             podglad tokenu (publiczna)
      POST /api/zaproszenia/przyjmij            przyjecie (publiczna: SSO,
                                                sesja panelu albo nowe haslo)
    """

    def __init__(self, auth: PanelAuth, zaproszenia: Zaproszenia, *,
                 sso_wlaczone: bool, powiadom: Powiadom = _nic) -> None:
        self.auth = auth
        self.z = zaproszenia
        self.rejestr = dm.RejestrDomow(auth.path)
        self.sso_wlaczone = sso_wlaczone
        self.powiadom = powiadom

    # ------------------------------------------------------- w domu
    def _sufit(self, session: Session, dom_id: int, uprawnienia: frozenset[str],
               admin: bool) -> list[str]:
        c = self.rejestr.czlonkostwo(session.user_id, dom_id)
        return dozwolone_role(c.rola if c else None, uprawnienia, admin=admin or c is None)

    def lista(self, session: Session, dom_id: int, uprawnienia: frozenset[str],
              admin: bool) -> dict:
        self.z.sprzataj()
        teraz = self.z.clock()
        return {
            "zaproszenia": [z.publiczne(teraz) for z in self.z.lista(dom_id)],
            "role": self._sufit(session, dom_id, uprawnienia, admin),
            "waznosc_domyslna_h": WAZNOSC_DOMYSLNA_H,
            "waznosc_max_h": WAZNOSC_MAX_H,
            "sso": self.sso_wlaczone,
        }

    def utworz(self, session: Session, data: dict, dom_id: int, uprawnienia: frozenset[str],
               admin: bool) -> dict:
        rola = _str(data, "rola", 32) or u.ROLA_PODGLAD
        if rola not in u.ROLE_DOMU:
            raise AuthError(400, "Nieznana rola")
        waznosc = data.get("waznosc_h", WAZNOSC_DOMYSLNA_H)
        if not isinstance(waznosc, int) or isinstance(waznosc, bool) or not (
                WAZNOSC_MIN_H <= waznosc <= WAZNOSC_MAX_H):
            raise AuthError(400, f"Ważność: od {WAZNOSC_MIN_H} do {WAZNOSC_MAX_H} godzin")
        dla = _str(data, "dla", 64).strip() or None
        if dla is not None and not login_ok(dla):
            raise AuthError(400, "Oczekiwany login: małe litery a-z, cyfry, '.', '_', '-' "
                                 "(jak w SSO)")
        # Sufit roli PRZED potwierdzeniem: zla rola nie zjada proby hasla.
        if rola not in self._sufit(session, dom_id, uprawnienia, admin):
            log.warning("zaproszenia: %r probowal zaprosic z rola %s ponad swoja (dom %d)",
                        session.login, rola, dom_id)
            raise AuthError(403, "Nie możesz zaprosić z rolą wyższą niż własna.")
        self.auth.reauth(session, _str(data, "confirm", 512))
        self.z.sprzataj()
        try:
            token, z = self.z.utworz(dom_id, kto_id=session.user_id, kto_login=session.login,
                                     rola=rola, waznosc_h=waznosc, dla=dla)
        except LookupError as exc:
            raise AuthError(404, "Nie ma takiego domu") from exc
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        konto = None
        if dla is not None:
            try:
                self.auth.user_id(dla)
                konto = True
            except LookupError:
                konto = False
        return {
            "ok": True,
            # Token RAZ, tylko w tej odpowiedzi — front sklada z niego link
            # `<adres panelu>/zaproszenie#<token>`.
            "token": token,
            "zaproszenie": z.publiczne(self.z.clock()),
            "konto_istnieje": konto,
            "instrukcja_sso": INSTRUKCJA_SSO if self.sso_wlaczone and not konto else None,
        }

    def odwolaj(self, session: Session, data: dict, dom_id: int) -> dict:
        zid = data.get("id")
        if not isinstance(zid, int) or isinstance(zid, bool) or zid < 1:
            raise AuthError(400, "Niepoprawne pole 'id'")
        try:
            z = self.z.odwolaj(dom_id, zid, kto_login=session.login)
        except LookupError as exc:
            raise AuthError(404, "Nie ma takiego zaproszenia") from exc
        except ValueError as exc:
            raise AuthError(409, str(exc)) from exc
        return {"ok": True, "zaproszenie": z.publiczne(self.z.clock())}

    # ------------------------------------------------------- publiczne
    def _opis(self, z: Zaproszenie) -> dict:
        dom = self.rejestr.dom(z.dom_id)
        return {
            "dom": dom.nazwa if dom else "?",
            "dom_id": z.dom_id,
            "rola": z.rola,
            "wygasa_at": _iso(z.wygasa_at),
            "informacja": INFORMACJA_O_PRYWATNOSCI,
        }

    def sprawdz(self, token: str, *, ip: str, tryb: str, login: str | None) -> dict:
        """Podglad dla ekranu przyjecia. `tryb`: `sso` (login z Authelii),
        `sesja` (zalogowane konto panelu) albo `haslo` (nowe konto bez SSO)."""
        z = self.z.sprawdz(token, ip=ip, login=login, uwierzytelniony=tryb != "haslo")
        konto = None
        if login is not None:
            try:
                self.auth.user_id(login)
                konto = True
            except LookupError:
                konto = False
        return {
            **self._opis(z),
            "tryb": tryb,
            "login": login,
            # Ekran „ustaw haslo”: login z zaproszenia, jesli je zawezono.
            "dla": z.dla if tryb == "haslo" else None,
            "konto_istnieje": konto,
            "min_haslo": MIN_PASSWORD_LEN,
        }

    def przyjmij(self, token: str, *, ip: str, login: str, sso: bool,
                 haslo: str | None = None, zaloz: bool = False,
                 uwierzytelniony: bool = True) -> Przyjecie:
        try:
            p = self.z.przyjmij(token, ip=ip, login=login, sso=sso, haslo=haslo, zaloz=zaloz,
                                uwierzytelniony=uwierzytelniony)
        except ValueError as exc:  # polityka hasla
            raise AuthError(400, str(exc)) from exc
        except dm.OstatniZarzadzajacy as exc:  # pragma: no cover — dopisanie nie odbiera
            raise AuthError(409, str(exc)) from exc
        if p.zapraszajacy:
            dom = self.rejestr.dom(p.dom_id)
            try:
                self.powiadom(p.zapraszajacy, dom.nazwa if dom else "?", p.login, p.rola)
            except Exception:  # noqa: BLE001 — powiadomienie to dodatek do przyjecia
                log.exception("zaproszenia: nie powiadomiono zapraszajacego")
        return p


# ============================================================== powiadomienie
def powiadamiacz(bramka_cfg, klucz: str | None, profile) -> Powiadom:
    """Powiadomienie zapraszajacego o przyjeciu (§7 E4 p. 3), w tle.

    TYLKO z jawnym odbiorca (bramka z funkcja `odbiorca`, kanal konta
    zapraszajacego): bez niego bramka rozeslalaby wiadomosc wedlug tras Domu 1,
    wiec — jak outbox domu ≠ 1 (§4.2) — nic nie wysylamy, zostaje wpis
    w dzienniku domu i log. `profile`: odbiorcy.ProfilePowiadomien."""
    if bramka_cfg is None or not getattr(bramka_cfg, "enabled", False) or not klucz:
        return _nic

    def wyslij(login: str, dom: str, kto: str, rola: str) -> None:
        def w_tle() -> None:
            try:
                asyncio.run(_wyslij(bramka_cfg, klucz, profile, login, dom, kto, rola))
            except Exception:  # noqa: BLE001
                log.exception("zaproszenia: powiadomienie zapraszajacego nie wyszlo")

        threading.Thread(target=w_tle, name="zaproszenie-powiadom", daemon=True).start()

    return wyslij


async def _wyslij(bramka_cfg, klucz: str, profile, login: str, dom: str, kto: str,
                  rola: str) -> bool:
    from .models import Notification, NotifyKind  # noqa: PLC0415
    from .notifiers.bramka import BramkaNotifier  # noqa: PLC0415

    p = profile.kanaly_osoby(login)
    if p is None or not p.ma_kanal:
        log.info("zaproszenia: zapraszajacy %r bez kanalu — tylko dziennik domu", login)
        return False
    kanal = BramkaNotifier(bramka_cfg, key=klucz)
    try:
        if not await kanal.obsluguje_odbiorcow():
            log.info("zaproszenia: bramka bez pola odbiorca — powiadomienie tylko w dzienniku")
            return False
        teraz = datetime.now(UTC)
        note = Notification(
            kind=NotifyKind.WATCHDOG, title="Zaproszenie przyjęte",
            text=f"{kto} dołączył(a) do domu „{dom}” z rolą {rola}.",
            dedup_key=f"zaproszenie:{kto}:{teraz.isoformat()}", ts=teraz, priority=3)
        return await kanal.send(note, p.adres())
    finally:
        await kanal.aclose()
