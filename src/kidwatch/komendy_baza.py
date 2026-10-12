"""Stan komend z WhatsAppa w panel-auth.db: dziennik, kody potwierdzen,
limity, wyslane powiadomienia (do rozpoznania cytatu), cisza kont,
licznik wywolan LLM i wylacznik administratora.

panel-auth.db, bo to ten sam plik co konta, kanaly i kolejki zadan panelu
(game_requests): jeden plik 0600 na wolumenie, w jednej kopii zapasowej.
Kazda operacja na wlasnym polaczeniu — pisze petla bota, czyta panel
z watkow serwera, a wylacznik zapisuje panel.

Pelne numery leza tylko tam, gdzie bez nich nie da sie dzialac (kod jest
przypisany do numeru, limit liczony per numer, cytat sprawdzany wobec
adresata) — i tylko numery KONT, ktore i tak sa w `user_powiadomienia`.
Nieznany numer trafia wylacznie do dziennika, zamaskowany.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .bramka_admin import mask
from .komendy import Komenda

SCHEMAT = """
-- Kazda wiadomosc do bota i co z nia zrobil (panel: dziennik komend).
CREATE TABLE IF NOT EXISTS whatsapp_komendy_dziennik (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            REAL NOT NULL,
    wiadomosc_id  TEXT,
    numer         TEXT NOT NULL,      -- zamaskowany: ...123
    login         TEXT,
    dom_id        INTEGER,
    akcja         TEXT,
    cel           TEXT,
    minuty        INTEGER,
    wynik         TEXT NOT NULL,
    szczegol      TEXT,
    llm           INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS ix_wa_dziennik_ts ON whatsapp_komendy_dziennik (ts);
CREATE INDEX IF NOT EXISTS ix_wa_dziennik_dom ON whatsapp_komendy_dziennik (dom_id, ts);

-- Id wiadomosci juz obsluzonych: bramka oddaje je ponownie, gdy
-- potwierdzenie (`/skrzynka/potwierdz`) sie nie udalo.
CREATE TABLE IF NOT EXISTS whatsapp_komendy_przetworzone (
    id  TEXT PRIMARY KEY,
    ts  REAL NOT NULL
);

-- Jeden oczekujacy kod na numer: nowa komenda zastepuje poprzednia.
CREATE TABLE IF NOT EXISTS whatsapp_komendy_kody (
    numer         TEXT PRIMARY KEY,
    kod           TEXT NOT NULL,
    user_id       INTEGER NOT NULL,
    dom_id        INTEGER,
    komenda       TEXT NOT NULL,      -- JSON Komenda
    llm           INTEGER NOT NULL DEFAULT 0,
    wiadomosc_id  TEXT,
    utworzony     REAL NOT NULL,
    wazny_do      REAL NOT NULL
);

-- Limity per numer konta: okno godzinowe, zle kody, blokada.
CREATE TABLE IF NOT EXISTS whatsapp_komendy_limity (
    numer            TEXT PRIMARY KEY,
    okno_od          REAL NOT NULL,
    wiadomosci       INTEGER NOT NULL DEFAULT 0,
    limit_zgloszony  INTEGER NOT NULL DEFAULT 0,
    zle_kody         INTEGER NOT NULL DEFAULT 0,
    zle_od           REAL,
    blokada_do       REAL
);

-- Powiadomienia wyslane przez bramke (id WhatsAppa) -> dom/urzadzenie:
-- odpowiedz-cytat wyznacza cel komendy bez dopytywania.
CREATE TABLE IF NOT EXISTS whatsapp_wyslane (
    id          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    dom_id      INTEGER NOT NULL,
    urzadzenie  TEXT,
    dziecko     TEXT,
    numer       TEXT                  -- adresat; NULL = tryb tras bramki
);

-- "cisza 2h": wyciszenie powiadomien WLASNEGO konta (odbiorcy.py).
CREATE TABLE IF NOT EXISTS whatsapp_cisza (
    user_id  INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    do_ts    REAL NOT NULL
);

-- Wywolania LLM na dobe UTC (limit kosztu).
CREATE TABLE IF NOT EXISTS whatsapp_llm_licznik (
    dzien       TEXT PRIMARY KEY,
    wywolania   INTEGER NOT NULL
);

-- Awaryjny wylacznik administratora: 'wylaczone' = '1'.
CREATE TABLE IF NOT EXISTS whatsapp_komendy_ustawienia (
    klucz    TEXT PRIMARY KEY,
    wartosc  TEXT NOT NULL
);
"""

# Wyniki w dzienniku (panel tlumaczy je na polski).
NIEZNANY_NUMER = "nieznany-numer"
BEZ_UPRAWNIEN = "bez-uprawnien"
WYLACZONE = "wylaczone"
LIMIT = "limit"
ZABLOKOWANY = "zablokowany"
PRZETERMINOWANA = "przeterminowana"
NIE_ROZUMIEM = "nie-rozumiem"
BEZ_LLM = "bez-llm"
DOPYTANIE = "dopytanie"
POTWIERDZENIE = "czeka-na-kod"
ZLY_KOD = "zly-kod"
KOD_WYGASL = "kod-wygasl"
ODMOWA = "odmowa"
WYKONANE = "wykonane"
BLAD = "blad"
ODPOWIEDZ = "odpowiedz"

#: Retencja dziennika i pomocniczych tabel.
DZIENNIK_DNI = 90
WYSLANE_DNI = 7
PRZETWORZONE_DNI = 3
#: Okno limitu wiadomosci (s).
OKNO = 3600.0


def dzien_utc(ts: float) -> str:
    return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d")


@dataclass(frozen=True)
class Konto:
    user_id: int
    login: str


@dataclass(frozen=True)
class Oczekujacy:
    kod: str
    user_id: int
    dom_id: int | None
    komenda: Komenda
    llm: bool
    wiadomosc_id: str | None
    wazny_do: float


@dataclass(frozen=True)
class Wyslane:
    dom_id: int
    urzadzenie: str | None
    dziecko: str | None
    numer: str | None


@dataclass(frozen=True)
class StanLimitu:
    """Wynik `licz_wiadomosc`: czy przetwarzac, i czy powiedziec o limicie
    (tylko raz na okno — dalej cisza, zeby nie gadac z kims, kto spamuje)."""

    ok: bool
    zglos: bool = False
    #: Blokada po zlych kodach (do kiedy), gdy to ona zatrzymala.
    blokada_do: float | None = None


class BazaKomend:
    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.path = str(path)
        self.clock = clock
        new = not Path(self.path).exists()
        with self._conn() as conn:
            conn.executescript(SCHEMAT)
        if new:
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------ dziennik
    def zapisz(self, *, numer: str, wynik: str, wiadomosc_id: str | None = None,
               login: str | None = None, dom_id: int | None = None,
               akcja: str | None = None, cel: str | None = None, minuty: int | None = None,
               szczegol: str | None = None, llm: bool = False) -> None:
        """`numer` pelny albo juz zamaskowany — do bazy idzie tylko maska."""
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO whatsapp_komendy_dziennik (ts, wiadomosc_id, numer, login, dom_id, "
                "akcja, cel, minuty, wynik, szczegol, llm) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (self.clock(), wiadomosc_id, numer if numer.startswith("...") else mask(numer),
                 login, dom_id, akcja, cel, minuty, wynik, (szczegol or "")[:300] or None,
                 int(llm)),
            )

    def dziennik(self, *, dom_id: int | None = None, limit: int = 100) -> list[dict]:
        """Najnowsze pierwsze. `dom_id=None` — wszystko (administrator),
        takze wiadomosci bez domu (nieznane numery)."""
        sql = "SELECT * FROM whatsapp_komendy_dziennik"
        args: tuple = ()
        if dom_id is not None:
            sql += " WHERE dom_id = ?"
            args = (dom_id,)
        with self._conn() as conn:
            rows = conn.execute(sql + " ORDER BY ts DESC, id DESC LIMIT ?", (*args, limit))
            return [{**dict(r), "llm": bool(r["llm"])} for r in rows]

    def luzowanie_dzis(self, dom_id: int, dziecko: str, akcja: str, tz: ZoneInfo) -> int:
        """Suma minut (`dodaj`) albo liczba (`odblokuj`) WYKONANYCH dzis
        (doba lokalna domu) z WhatsAppa dla dziecka."""
        teraz = datetime.fromtimestamp(self.clock(), tz)
        poczatek = teraz.replace(hour=0, minute=0, second=0, microsecond=0).timestamp()
        with self._conn() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n, COALESCE(SUM(minuty), 0) AS m "
                "FROM whatsapp_komendy_dziennik WHERE dom_id = ? AND cel = ? AND akcja = ? "
                "AND wynik = ? AND ts >= ?",
                (dom_id, dziecko, akcja, WYKONANE, poczatek),
            ).fetchone()
        return int(row["m"]) if akcja == "dodaj" else int(row["n"])

    # ------------------------------------------------------- przetworzone
    def oznacz_przetworzona(self, wiadomosc_id: str) -> bool:
        """False = juz obsluzona (bramka oddala ja ponownie)."""
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT OR IGNORE INTO whatsapp_komendy_przetworzone (id, ts) VALUES (?, ?)",
                (wiadomosc_id, self.clock()),
            )
            return cur.rowcount == 1

    # ------------------------------------------------------------- konta
    def konto_po_numerze(self, numer: str) -> Konto | None | bool:
        """Konto z tym numerem WhatsApp (kanal osoby). None = nieznany;
        False = numer przy kilku kontach (niejednoznaczny: odmowa)."""
        with self._conn() as conn:
            try:
                rows = conn.execute(
                    "SELECT u.id, u.login FROM user_powiadomienia p "
                    "JOIN users u ON u.id = p.user_id WHERE p.whatsapp = ?", (numer,)
                ).fetchall()
            except sqlite3.OperationalError:
                return None
        if not rows:
            return None
        if len(rows) > 1:
            return False
        return Konto(int(rows[0]["id"]), rows[0]["login"])

    # --------------------------------------------------------------- kody
    def nowy_kod(self, numer: str, konto: Konto, dom_id: int | None, komenda: Komenda, *,
                 llm: bool, wiadomosc_id: str | None, waznosc: float) -> str:
        """4 cyfry z `secrets`. Zastepuje poprzedni kod numeru: potwierdza
        sie zawsze OSTATNIA komenda, o ktora bot zapytal."""
        kod = f"{secrets.randbelow(10000):04d}"
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO whatsapp_komendy_kody (numer, kod, user_id, dom_id, komenda, llm, "
                "wiadomosc_id, utworzony, wazny_do) VALUES (?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT (numer) DO UPDATE SET kod=excluded.kod, user_id=excluded.user_id, "
                "dom_id=excluded.dom_id, komenda=excluded.komenda, llm=excluded.llm, "
                "wiadomosc_id=excluded.wiadomosc_id, utworzony=excluded.utworzony, "
                "wazny_do=excluded.wazny_do",
                (numer, kod, konto.user_id, dom_id,
                 json.dumps(komenda.__dict__, ensure_ascii=False), int(llm), wiadomosc_id,
                 teraz, teraz + waznosc),
            )
        return kod

    def uzyj_kodu(self, numer: str, kod: str) -> Oczekujacy | str:
        """Kod numeru -> komenda (kod znika: jednorazowy). Inaczej powod:
        ZLY_KOD (brak, cudzy, zly, juz uzyty) albo KOD_WYGASL. Porownanie
        w stalym czasie; caly odczyt i skasowanie w jednej transakcji."""
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM whatsapp_komendy_kody WHERE numer = ?",
                                   (numer,)).fetchone()
                if row is None or not hmac.compare_digest(row["kod"], kod):
                    conn.execute("COMMIT")
                    return ZLY_KOD
                conn.execute("DELETE FROM whatsapp_komendy_kody WHERE numer = ?", (numer,))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        if row["wazny_do"] < self.clock():
            return KOD_WYGASL
        dane = json.loads(row["komenda"])
        return Oczekujacy(row["kod"], int(row["user_id"]), row["dom_id"], Komenda(**dane),
                          bool(row["llm"]), row["wiadomosc_id"], float(row["wazny_do"]))

    # ------------------------------------------------------------- limity
    def licz_wiadomosc(self, numer: str, na_godzine: int, *, licz: bool = True) -> StanLimitu:
        """`licz=False` (potwierdzenie kodem) — tylko blokada po zlych kodach:
        limit dotyczy komend, a kazda komenda to dwie wiadomosci."""
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT * FROM whatsapp_komendy_limity WHERE numer = ?",
                                   (numer,)).fetchone()
                if row is None:
                    conn.execute("INSERT INTO whatsapp_komendy_limity (numer, okno_od, wiadomosci) "
                                 "VALUES (?, ?, ?)", (numer, teraz, int(licz)))
                    conn.execute("COMMIT")
                    return StanLimitu(True)
                if row["blokada_do"] is not None and row["blokada_do"] > teraz:
                    conn.execute("COMMIT")
                    return StanLimitu(False, blokada_do=row["blokada_do"])
                if not licz:
                    conn.execute("COMMIT")
                    return StanLimitu(True)
                if teraz - row["okno_od"] >= OKNO:
                    conn.execute("UPDATE whatsapp_komendy_limity SET okno_od = ?, wiadomosci = 1, "
                                 "limit_zgloszony = 0 WHERE numer = ?", (teraz, numer))
                    conn.execute("COMMIT")
                    return StanLimitu(True)
                n = row["wiadomosci"] + 1
                zglos = n > na_godzine and not row["limit_zgloszony"]
                conn.execute("UPDATE whatsapp_komendy_limity SET wiadomosci = ?, "
                             "limit_zgloszony = limit_zgloszony OR ? WHERE numer = ?",
                             (n, int(zglos), numer))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return StanLimitu(n <= na_godzine, zglos=zglos)

    def zly_kod(self, numer: str, *, prog: int, blokada: float) -> float | None:
        """Licznik zlych kodow; po `prog` w oknie blokady — blokada numeru.
        Zwraca koniec blokady, gdy ta wlasnie sie zaczela."""
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT zle_kody, zle_od FROM whatsapp_komendy_limity "
                                   "WHERE numer = ?", (numer,)).fetchone()
                if row is None:
                    conn.execute("INSERT INTO whatsapp_komendy_limity (numer, okno_od) "
                                 "VALUES (?, ?)", (numer, teraz))
                    zle, od = 0, teraz
                else:
                    zle, od = row["zle_kody"], row["zle_od"] or teraz
                    if teraz - od >= blokada:
                        zle, od = 0, teraz
                zle += 1
                do = teraz + blokada if zle >= prog else None
                conn.execute("UPDATE whatsapp_komendy_limity SET zle_kody = ?, zle_od = ?, "
                             "blokada_do = COALESCE(?, blokada_do) WHERE numer = ?",
                             (0 if do else zle, None if do else od, do, numer))
                if do:
                    # Oczekujacy kod przepada razem z blokada.
                    conn.execute("DELETE FROM whatsapp_komendy_kody WHERE numer = ?", (numer,))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return do

    def dobry_kod(self, numer: str) -> None:
        with self._conn() as conn:
            conn.execute("UPDATE whatsapp_komendy_limity SET zle_kody = 0, zle_od = NULL "
                         "WHERE numer = ?", (numer,))

    # ------------------------------------------------------------ wyslane
    def zapisz_wyslane(self, wiadomosc_id: str, dom_id: int, urzadzenie: str | None,
                       dziecko: str | None, numer: str | None) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO whatsapp_wyslane (id, ts, dom_id, urzadzenie, dziecko, "
                "numer) VALUES (?, ?, ?, ?, ?, ?)",
                (wiadomosc_id, self.clock(), dom_id, urzadzenie, dziecko, numer),
            )

    def wyslane(self, wiadomosc_id: str) -> Wyslane | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM whatsapp_wyslane WHERE id = ?",
                               (wiadomosc_id,)).fetchone()
        if row is None:
            return None
        return Wyslane(int(row["dom_id"]), row["urzadzenie"], row["dziecko"], row["numer"])

    # -------------------------------------------------------------- cisza
    def ustaw_cisze(self, user_id: int, do_ts: float) -> None:
        with self._conn() as conn:
            conn.execute("INSERT INTO whatsapp_cisza (user_id, do_ts) VALUES (?, ?) "
                         "ON CONFLICT (user_id) DO UPDATE SET do_ts = excluded.do_ts",
                         (user_id, do_ts))

    # ---------------------------------------------------------------- LLM
    def wywolanie_llm(self, limit: int) -> bool:
        """Rezerwuje jedno wywolanie z dobowego limitu. False = limit."""
        dzien = dzien_utc(self.clock())
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT wywolania FROM whatsapp_llm_licznik WHERE dzien = ?",
                                   (dzien,)).fetchone()
                n = row["wywolania"] if row else 0
                if n >= limit:
                    conn.execute("COMMIT")
                    return False
                conn.execute("INSERT INTO whatsapp_llm_licznik (dzien, wywolania) VALUES (?, 1) "
                             "ON CONFLICT (dzien) DO UPDATE SET wywolania = wywolania + 1",
                             (dzien,))
                conn.execute("COMMIT")
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return True

    def wywolania_llm(self, dni_temu: int = 0) -> int:
        """Wywolania LLM w dobie UTC sprzed `dni_temu` dni (0 = dzis)."""
        with self._conn() as conn:
            row = conn.execute("SELECT wywolania FROM whatsapp_llm_licznik WHERE dzien = ?",
                               (dzien_utc(self.clock() - dni_temu * 86400),)).fetchone()
        return int(row["wywolania"]) if row else 0

    # ----------------------------------------------------------- wylacznik
    def wylaczone(self) -> dict | None:
        """None = komendy dzialaja; inaczej {kto, ts}."""
        with self._conn() as conn:
            rows = dict(conn.execute("SELECT klucz, wartosc FROM whatsapp_komendy_ustawienia"))
        if rows.get("wylaczone") != "1":
            return None
        return {"kto": rows.get("wylaczone_przez"), "ts": float(rows.get("wylaczone_ts") or 0)}

    def ustaw_wylaczone(self, wylaczone: bool, kto: str) -> None:
        with self._conn() as conn:
            conn.executemany(
                "INSERT INTO whatsapp_komendy_ustawienia (klucz, wartosc) VALUES (?, ?) "
                "ON CONFLICT (klucz) DO UPDATE SET wartosc = excluded.wartosc",
                [("wylaczone", "1" if wylaczone else "0"), ("wylaczone_przez", kto),
                 ("wylaczone_ts", str(self.clock()))],
            )

    # ---------------------------------------------------------- sprzatanie
    def sprzataj(self) -> None:
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute("DELETE FROM whatsapp_komendy_dziennik WHERE ts < ?",
                         (teraz - DZIENNIK_DNI * 86400,))
            conn.execute("DELETE FROM whatsapp_wyslane WHERE ts < ?",
                         (teraz - WYSLANE_DNI * 86400,))
            conn.execute("DELETE FROM whatsapp_komendy_przetworzone WHERE ts < ?",
                         (teraz - PRZETWORZONE_DNI * 86400,))
            conn.execute("DELETE FROM whatsapp_komendy_kody WHERE wazny_do < ?", (teraz,))
            conn.execute("DELETE FROM whatsapp_cisza WHERE do_ts < ?", (teraz,))
            conn.execute("DELETE FROM whatsapp_llm_licznik WHERE dzien < ?",
                         (dzien_utc(teraz - 7 * 86400),))
