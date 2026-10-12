"""Zmiana loginu konta panelu w miejscu (`kidwatch user-login STARY NOWY`).

Po co: SSO (Authelia) dopasowuje konto po `Remote-User == users.login`.
Zanim wlaczy sie SSO, login prywatnego konta panelu musi byc loginem
z Authelii — bez zakladania nowego konta, bo to zgubiloby haslo, 2FA,
czlonkostwa, role, flage administratora, kanaly i historie.

`users.id` sie NIE zmienia, wiec wszystko, co trzyma `user_id`, zostaje
samo: haslo i TOTP (users), kody zapasowe (backup_codes), odstepstwa
(user_uprawnienia), czlonkostwa i ich odstepstwa (czlonkostwa,
czlonkostwa_uprawnienia), kanaly i preferencje (user_powiadomienia,
czlonkostwa_powiadomienia), flaga `admin_instancji` i rola (users).

Login jako TEKST (stad lista w MIEJSCA) — kazde takie miejsce zmieniamy
w tej samej transakcji. Bazy zdarzen domow sa podpiete (ATTACH) do tego
samego polaczenia: przy dzienniku DELETE/TRUNCATE zapis jest atomowy dla
wszystkich plikow; przy WAL (produkcja) SQLite gwarantuje atomowosc per
plik — kolejnosc zapisu jest wtedy jedyna roznica, a ponowne uruchomienie
polecenia dokonczy reszte (kazdy krok jest idempotentny: szuka STAREGO
loginu, ktorego juz nie ma).

Poza baza loginu nie ma: bramka dostaje od Kidwatcha same kanaly osoby
(`odbiorcy.Profil.adres`), serwer MDM i config.yaml nie znaja kont panelu,
a SSO porownuje naglowek z `users.login` przy kazdym zadaniu. Konto
w Authelii (docs/sso-tozsamosc.md w renacode-infra) zmienia sie tam.

Sesje i bilety 2FA konta sa kasowane (wylogowanie wszedzie). Wpis
`konto.login` w audycie: instancji i kazdego domu konta — sam stary i nowy
login. Tresci `opis` starszych wpisow audytu nie przepisujemy: to wolny
tekst z chwili zdarzenia (np. „konto X dodane”), a kolumna `login` —
kto to zrobil — idzie za kontem.

Domyslnie na sucho: te same zmiany w transakcji wycofanej na koncu, wiec
liczby w podgladzie sa prawdziwe, nie szacowane.

DOKONCZENIE. Gdy STAREGO konta juz nie ma, a NOWE jest i POWSTALO z tej
zmiany (dowod: wpis `konto.login` „STARY -> NOWY” w audycie, nowszy niz
zalozenie konta NOWY — _przemianowane) (przerwany albo
czesciowy przebieg: przy WAL panel-auth.db moze byc po zmianie, a baza domu
jeszcze nie; wpis kolejki rozdzielony przez zywy proces tuz po zmianie),
ponowne uruchomienie tego samego polecenia przepisuje same slady tekstowe —
bez `users.login`, bez sprawdzania zajetosci, bez wylogowania i bez
drugiego wpisu w audycie. `--dokoncz` wymusza ten tryb jawnie.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import domy as dm
from .panel_sso import login_ok

#: Miejsca, w ktorych login lezy jako tekst: (baza, tabela.kolumna, co to jest).
MIEJSCA = (
    ("panel-auth.db", "users.login", "login konta (to samo id)"),
    ("panel-auth.db", "login_failures.login", "licznik nieudanych hasel per (login, adres)"),
    ("panel-auth.db", "audyt.login", "kto wykonal zmiane w domu / instancji"),
    ("panel-auth.db", "game_requests.login", "kto zlecil czas gry z panelu"),
    ("panel-auth.db", "tv_pause_requests.login", "kto zlecil pauze TV z panelu"),
    ("panel-auth.db", "integracje.zmienione_przez", "kto ostatnio zmienil integracje"),
    ("panel-auth.db", "game_requests.login", "czas gry z WhatsAppa: 'whatsapp:<login>'"),
    ("panel-auth.db", "whatsapp_komendy_dziennik.login", "kto wydal komende z WhatsAppa"),
    ("baza domu", "outbox.odbiorca", "kolejka powiadomien konta"),
    ("baza domu", "sent.dedup_key", "dedup per konto: klucz '<zdarzenie>@<login>'"),
    ("baza domu", "notifications.channels", "historia: kanaly '<kanal>:<login>' (JSON)"),
    ("baza domu", "tv_pause.started_by/ended_by", "kto wlaczyl / zakonczyl pauze TV"),
)


class BladZmiany(ValueError):
    """Zmiana odrzucona (brak konta, zly albo zajety login)."""


@dataclass
class PlanZmiany:
    stary: str
    nowy: str
    user_id: int
    #: (miejsce, liczba zmienionych wierszy) — tylko niezerowe.
    zmiany: list[tuple[str, int]] = field(default_factory=list)
    #: Domy, w ktorych konto jest czlonkiem (wpis w ich dzienniku).
    domy: list[int] = field(default_factory=list)
    zapisano: bool = False
    #: Tryb dokonczenia: konto juz ma nowy login, przepisane same slady.
    dokonczenie: bool = False


def _tabela(conn: sqlite3.Connection, schemat: str, nazwa: str) -> bool:
    return conn.execute(
        f"SELECT 1 FROM {schemat}.sqlite_master WHERE type = 'table' AND name = ?",  # noqa: S608
        (nazwa,)).fetchone() is not None


def _kolumna(conn: sqlite3.Connection, schemat: str, tabela: str, kolumna: str) -> bool:
    return _tabela(conn, schemat, tabela) and kolumna in {
        r[1] for r in conn.execute(f"PRAGMA {schemat}.table_info({tabela})")}


def opis_zmiany(stary: str, nowy: str) -> str:
    return f"login konta zmieniony: {stary} -> {nowy}"


def _przemianowane(conn: sqlite3.Connection, stary: str, nowy: str,
                   utworzone: float | None) -> bool:
    """Dowod, ze konto NOWY to przemianowane STARE: wpis `konto.login`
    (instancji, zapisany w tej samej transakcji co `users.login` przy
    pierwszym etapie) z dokladnie ta para loginow, NOWSZY niz zalozenie
    obecnego konta NOWY. Konto zalozone pod tym loginem po zmianie (stare
    usuniete, login uzyty ponownie) dowodu nie ma."""
    if not _tabela(conn, "main", "audyt"):
        return False
    row = conn.execute(
        "SELECT MAX(ts) FROM audyt WHERE akcja = 'konto.login' AND dom_id IS NULL "
        "AND login = ? AND opis = ?", (nowy, opis_zmiany(stary, nowy))).fetchone()
    return bool(row and row[0] is not None and row[0] >= (utworzone or 0))


def _waliduj(conn: sqlite3.Connection, stary: str, nowy: str,
             dokoncz: bool = False) -> tuple[int, bool]:
    """(id konta, czy tryb dokonczenia)."""
    nowy_czysty = nowy.strip()
    if nowy_czysty != nowy or not login_ok(nowy):
        raise BladZmiany(f"login {nowy!r} niedozwolony — tylko a-z, 0-9, '.', '_', '-' "
                         f"(1-64 znaki, male litery: tak przychodzi Remote-User z Authelii)")
    if stary == nowy:
        raise BladZmiany("nowy login jest taki sam jak obecny")
    row = conn.execute("SELECT id FROM users WHERE login = ?", (stary,)).fetchone()
    if row is None:
        juz = conn.execute("SELECT id, created_at FROM users WHERE login = ?",
                           (nowy,)).fetchone()
        if juz is None:
            raise BladZmiany(f"nie ma konta {stary!r} (ani {nowy!r} — nie ma czego dokonczyc)")
        if not _przemianowane(conn, stary, nowy, juz[1]):
            # Konto NOWY istnieje, ale nie z tej zmiany (np. STARY usunieto,
            # a NOWY to inna osoba): dokonczenie przepisaloby jej slady
            # cudzego, usunietego konta — audyt, kolejke, dedup, historie.
            raise BladZmiany(f"konto {nowy!r} istnieje, ale nie powstalo przez zmiane "
                             f"z {stary!r} — brak wpisu konto.login w audycie")
        return int(juz[0]), True
    if dokoncz:
        raise BladZmiany(f"konto {stary!r} nadal istnieje — to zwykla zmiana, bez --dokoncz")
    zajety = conn.execute("SELECT login FROM users WHERE lower(login) = lower(?) AND id != ?",
                          (nowy, row[0])).fetchone()
    if zajety is not None:
        raise BladZmiany(f"login {nowy!r} jest zajety (konto {zajety[0]!r}, wielkosc liter "
                         f"nie ma znaczenia)")
    return int(row[0]), False


def _panel(conn: sqlite3.Connection, stary: str, nowy: str, uid: int,
           plan: PlanZmiany, teraz: float) -> None:
    def ile(miejsce: str, cur: sqlite3.Cursor) -> None:
        if cur.rowcount > 0:
            plan.zmiany.append((miejsce, cur.rowcount))

    if not plan.dokonczenie:
        ile("users.login", conn.execute("UPDATE users SET login = ? WHERE id = ?", (nowy, uid)))
    if _tabela(conn, "main", "login_failures"):
        # Blokada po nieudanych haslach idzie za kontem: zmiana loginu nie
        # moze jej zdjac. Wiersz nowego loginu (proby na nieistniejace konto)
        # laczymy z wierszem starego — wygrywa surowszy.
        stare = conn.execute("SELECT ip, failures, locked_until, updated_at FROM login_failures "
                             "WHERE login = ?", (stary,)).fetchall()
        for ip, failures, locked_until, updated_at in stare:
            conn.execute(
                "INSERT INTO login_failures (login, ip, failures, locked_until, updated_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT (login, ip) DO UPDATE SET "
                "failures = max(failures, excluded.failures), "
                "locked_until = max(coalesce(locked_until, 0), "
                "coalesce(excluded.locked_until, 0)), "
                "updated_at = max(updated_at, excluded.updated_at)",
                (nowy, ip, failures, locked_until, updated_at))
        ile("login_failures.login",
            conn.execute("DELETE FROM login_failures WHERE login = ?", (stary,)))
    for tabela, kolumna in (("audyt", "login"), ("game_requests", "login"),
                            ("tv_pause_requests", "login"), ("integracje", "zmienione_przez")):
        if _kolumna(conn, "main", tabela, kolumna):
            ile(f"{tabela}.{kolumna}", conn.execute(
                f"UPDATE {tabela} SET {kolumna} = ? WHERE {kolumna} = ?",  # noqa: S608
                (nowy, stary)))
    _whatsapp(conn, stary, nowy, ile)
    if plan.dokonczenie:
        # Konto juz dziala pod nowym loginem: bez wylogowania i drugiego wpisu.
        return
    for tabela in ("sessions", "tickets"):
        if _tabela(conn, "main", tabela):
            ile(f"{tabela} (wylogowanie)", conn.execute(
                f"DELETE FROM {tabela} WHERE user_id = ?", (uid,)))  # noqa: S608
    if _tabela(conn, "main", "czlonkostwa"):
        plan.domy = [r[0] for r in conn.execute(
            "SELECT dom_id FROM czlonkostwa WHERE user_id = ? ORDER BY dom_id", (uid,))]
    if _tabela(conn, "main", "audyt"):
        opis = opis_zmiany(stary, nowy)
        for dom_id in [None, *plan.domy]:
            dm.zapisz_audyt(conn, dom_id, nowy, "konto.login", opis, teraz)


def _whatsapp(conn: sqlite3.Connection, stary: str, nowy: str, ile) -> None:
    """Slady komend z WhatsAppa (komendy_bot.py). Kody, limity i cisza
    trzymaja numer albo `user_id`, nie login — zostaja same."""
    if _kolumna(conn, "main", "game_requests", "login"):
        from .gametime import WHATSAPP_PREFIKS  # noqa: PLC0415

        ile("game_requests.login (WhatsApp)", conn.execute(
            "UPDATE game_requests SET login = ? WHERE login = ?",
            (WHATSAPP_PREFIKS + nowy, WHATSAPP_PREFIKS + stary)))
    if _kolumna(conn, "main", "whatsapp_komendy_dziennik", "login"):
        ile("whatsapp_komendy_dziennik.login", conn.execute(
            "UPDATE whatsapp_komendy_dziennik SET login = ? WHERE login = ?", (nowy, stary)))


def _baza_domu(conn: sqlite3.Connection, s: str, dom_id: int, stary: str, nowy: str,
               plan: PlanZmiany) -> None:
    def ile(miejsce: str, n: int) -> None:
        if n > 0:
            plan.zmiany.append((f"dom {dom_id}: {miejsce}", n))

    if _kolumna(conn, s, "outbox", "odbiorca"):
        ile("outbox.odbiorca", conn.execute(
            f"UPDATE {s}.outbox SET odbiorca = ? WHERE odbiorca = ?", (nowy, stary)).rowcount)
    if _tabela(conn, s, "sent"):
        # Sufiks porownany dokladnie (nie LIKE: '_' w loginie to wzorzec LIKE).
        ile("sent.dedup_key", conn.execute(
            f"UPDATE OR REPLACE {s}.sent SET dedup_key = "
            f"substr(dedup_key, 1, length(dedup_key) - length(:stary)) || :nowy "
            f"WHERE length(dedup_key) > length(:stary) + 1 "
            f"AND substr(dedup_key, -length(:stary) - 1) = '@' || :stary",
            {"stary": stary, "nowy": nowy}).rowcount)
    if _tabela(conn, s, "notifications"):
        n = 0
        for nid, channels in conn.execute(
                f"SELECT id, channels FROM {s}.notifications WHERE instr(channels, ?) > 0",
                (f":{stary}\"",)).fetchall():
            try:
                kanaly = json.loads(channels)
            except ValueError:
                continue
            if not isinstance(kanaly, dict):
                continue
            nowe = {}
            for k, v in kanaly.items():
                kanal, _, kto = k.partition(":")
                nowe[f"{kanal}:{nowy}" if kto == stary else k] = v
            if nowe != kanaly:
                conn.execute(f"UPDATE {s}.notifications SET channels = ? WHERE id = ?",
                             (json.dumps(nowe, ensure_ascii=False), nid))
                n += 1
        ile("notifications.channels", n)
    for kolumna in ("started_by", "ended_by"):
        if _kolumna(conn, s, "tv_pause", kolumna):
            ile(f"tv_pause.{kolumna}", conn.execute(
                f"UPDATE {s}.tv_pause SET {kolumna} = ? WHERE {kolumna} = ?",
                (nowy, stary)).rowcount)


def bazy_domow(auth_path: str | Path, baza_domu_1: str | Path) -> dict[int, Path]:
    """dom -> istniejacy plik bazy zdarzen domu (domy.sciezka_bazy_domu)."""
    out = {}
    for dom in dm.RejestrDomow(auth_path).domy():
        p = dm.sciezka_bazy_domu(dom.id, baza_domu_1)
        if p.exists():
            out[dom.id] = p
    return out


def zmien_login(auth_path: str | Path, stary: str, nowy: str, *,
                bazy: dict[int, Path] | None = None, zapisz: bool = False,
                dokoncz: bool = False, teraz: float | None = None) -> PlanZmiany:
    """Zmiana loginu w panel-auth.db i bazach zdarzen domow (`bazy`).
    `zapisz=False`: te same zmiany, policzone i wycofane. BladZmiany przy
    odmowie — nic nie zapisano."""
    teraz = time.time() if teraz is None else teraz
    conn = sqlite3.connect(str(auth_path), timeout=10, isolation_level=None)
    try:
        conn.execute("PRAGMA foreign_keys = ON")
        aliasy = {}
        for dom_id, sciezka in sorted((bazy or {}).items()):
            alias = f"dom{int(dom_id)}"
            conn.execute(f"ATTACH DATABASE ? AS {alias}", (str(sciezka),))
            aliasy[dom_id] = alias
        conn.execute("BEGIN IMMEDIATE")
        try:
            uid, dokonczenie = _waliduj(conn, stary, nowy, dokoncz)
            plan = PlanZmiany(stary, nowy, uid, dokonczenie=dokonczenie)
            _panel(conn, stary, nowy, uid, plan, teraz)
            for dom_id, alias in aliasy.items():
                _baza_domu(conn, alias, dom_id, stary, nowy, plan)
            if zapisz:
                conn.execute("COMMIT")
                plan.zapisano = True
            else:
                conn.execute("ROLLBACK")
        except BaseException:
            if conn.in_transaction:
                conn.execute("ROLLBACK")
            raise
        return plan
    finally:
        conn.close()
