"""Trwaly stan w SQLite.

Trzy rzeczy musza przezyc restart, inaczej serwis klamie:
  1. otwarte sesje — inaczej po restarcie kazde zapytanie wyglada jak nowa sesja;
  2. klucze wyslanych powiadomien — inaczej restart w zlym momencie dubluje push;
  3. kursor strumienia — inaczej albo gubimy zdarzenia, albo czytamy je dwa razy.
"""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .models import Notification

ISO = "%Y-%m-%dT%H:%M:%S.%f%z"

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    device           TEXT NOT NULL,
    -- NULL = urzadzenie wspolne (telewizor). Sesje iPadow zawsze maja dziecko.
    child            TEXT,
    started_at       TEXT NOT NULL,
    last_activity_at TEXT NOT NULL,
    -- Osobno czas ostatniego ROZPOZNANEGO zdarzenia (aplikacja albo nieznana
    -- domena niesystemowa). Ruch wspoldzielony (CDN, SDK reklamowe) moze
    -- przedluzyc sesje tylko wtedy, gdy to bylo niedawno — inaczej odswiezanie
    -- aplikacji w tle trzymaloby sesje otwarta bez konca.
    last_identified_at TEXT,
    ended_at         TEXT,
    start_notified   INTEGER NOT NULL DEFAULT 0,
    -- 0 = sesja niepotwierdzona: pojedyncze zapytanie iPada lezacego na
    -- biurku (odswiezenie w tle, OCSP, powiadomienie). Zostaje w bazie dla
    -- diagnostyki, ale nie ma pushy i nie liczy sie do podsumowan, raportow,
    -- wykresow ani agregatow (engine.Engine._confirmed_start).
    confirmed        INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS ix_sessions_open ON sessions (device, ended_at);
CREATE INDEX IF NOT EXISTS ix_sessions_started ON sessions (started_at);

-- Odrebne minuty z ruchem do danej aplikacji. Klucz glowny sam zapewnia
-- unikalnosc, wiec "liczba roznych minut" to zwykly COUNT.
CREATE TABLE IF NOT EXISTS session_apps (
    session_id INTEGER NOT NULL,
    app        TEXT NOT NULL,
    minute     TEXT NOT NULL,
    PRIMARY KEY (session_id, app, minute)
);

CREATE TABLE IF NOT EXISTS app_cooldown (
    device      TEXT NOT NULL,
    app         TEXT NOT NULL,
    notified_at TEXT NOT NULL,
    PRIMARY KEY (device, app)
);

CREATE TABLE IF NOT EXISTS notify_log (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    device  TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    kind    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_notify_log ON notify_log (device, sent_at);

CREATE TABLE IF NOT EXISTS sent (
    dedup_key TEXT PRIMARY KEY,
    sent_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    device    TEXT,
    source_id TEXT NOT NULL,
    domain    TEXT NOT NULL,
    kind      TEXT NOT NULL,
    app       TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS ix_events_device_ts ON events (device, ts);

-- Odciski zapytan widzianych z AdGuarda; jego querylog zwraca zawsze najnowsza
-- strone, wiec bez tego kazde odpytanie powtarzalo by te same wpisy.
CREATE TABLE IF NOT EXISTS seen_queries (
    fingerprint TEXT PRIMARY KEY,
    seen_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_seen_queries ON seen_queries (seen_at);

-- Powiadomienia zdlawione limitem godzinowym, czekajace na zbiorcza wysylke.
CREATE TABLE IF NOT EXISTS throttled (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    device TEXT NOT NULL,
    label  TEXT NOT NULL,
    ts     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_throttled_device ON throttled (device);

-- Historia powiadomien dla panelu. Pelna tresc, nie tylko rodzaj jak w
-- notify_log: ntfy nie trzyma historii, a temat na ntfy.sh i tak trzeba
-- uznac za ulotny. `channels` to JSON {kanal: czy_dotarlo} — zapis powstaje
-- takze wtedy, gdy zaden kanal nie przyjal pusha, bo wlasnie wtedy panel
-- jest jedynym miejscem, w ktorym to widac.
CREATE TABLE IF NOT EXISTS notifications (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    sent_at   TEXT NOT NULL,
    kind      TEXT NOT NULL,
    device    TEXT,
    app       TEXT,
    title     TEXT NOT NULL,
    text      TEXT NOT NULL,
    priority  INTEGER NOT NULL,
    channels  TEXT NOT NULL,
    delivered INTEGER NOT NULL,
    -- JSON z formatting.payload (sekcje, aplikacje, tytuly) — panel rysuje z
    -- niego liste zamiast surowego tekstu. NULL dla prostych pushy i starych wpisow.
    data      TEXT
);
CREATE INDEX IF NOT EXISTS ix_notifications_ts ON notifications (ts);

-- Co lecialo na telewizorze: odcinki w obrebie sesji ogladania (tabela
-- sessions, device = nazwa TV). Zmiana tytulu zamyka odcinek i otwiera nowy —
-- push idzie tylko na start i koniec sesji, tytuly sa dla panelu i podsumowania.
CREATE TABLE IF NOT EXISTS tv_watch (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL,
    device     TEXT NOT NULL,
    started_at TEXT NOT NULL,
    ended_at   TEXT,
    package    TEXT NOT NULL,
    app        TEXT NOT NULL,
    title      TEXT,
    channel    TEXT
);
CREATE INDEX IF NOT EXISTS ix_tv_watch_session ON tv_watch (session_id);
CREATE INDEX IF NOT EXISTS ix_tv_watch_started ON tv_watch (device, started_at);
CREATE INDEX IF NOT EXISTS ix_notifications_device_ts ON notifications (device, ts);

-- Dokladny czas aplikacji na telewizorze z `dumpsys usagestats` (Android sam
-- liczy czas na pierwszym planie). Przyrosty miedzy odczytami, sumowane
-- w obrebie lokalnego dnia. Uzupelnia szacunek z sesji (odczyt co 30 s).
CREATE TABLE IF NOT EXISTS tv_usage (
    device    TEXT NOT NULL,
    day       TEXT NOT NULL,
    package   TEXT NOT NULL,
    app       TEXT NOT NULL,
    ms        INTEGER NOT NULL DEFAULT 0,
    last_used TEXT,
    PRIMARY KEY (device, day, package)
);

-- Agregat dnia per urzadzenie. Przezywa retencje surowych danych — z niego
-- sa trendy i eksport CSV. Dzien = dzien lokalny STARTU sesji (jak w /api/day
-- i /api/usage). top_apps i tv_apps to JSON [[aplikacja, minuty], ...].
CREATE TABLE IF NOT EXISTS daily_rollup (
    day           TEXT NOT NULL,
    device        TEXT NOT NULL,
    child         TEXT,
    kind          TEXT NOT NULL,
    minutes       INTEGER NOT NULL,
    sessions      INTEGER NOT NULL,
    night_minutes INTEGER NOT NULL,
    tv_minutes    INTEGER,
    top_apps      TEXT NOT NULL,
    tv_apps       TEXT,
    computed_at   TEXT NOT NULL,
    PRIMARY KEY (day, device)
);

-- Kolejka wyjsciowa: powiadomienie trafia tu w chwili zajecia klucza dedupu,
-- a wysyla je osobne zadanie (notifiers/base.py: Outbox). Bez niej klucz byl
-- zajety przed wysylka, wiec restart w trakcie wysylki gubil push na zawsze,
-- a wiszaca bramka trzymala tik i strumien DNS po ~60 s na notke.
-- Wpis znika dopiero po przyjeciu przez kanal; nieudany czeka do next_at
-- (backoff w Outbox), a last_error mowi, czemu ostatnia proba nie wyszla.
-- Obie kolumny dokladane w starej bazie przez Store._migrate (ADD COLUMN).
CREATE TABLE IF NOT EXISTS outbox (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    attempts   INTEGER NOT NULL DEFAULT 0,
    note       TEXT NOT NULL,
    next_at    TEXT,
    last_error TEXT
);

-- Pauzy monitoringu telewizora (tvpause.py). Wiersz = jedna pauza; otwarta
-- to ended_at IS NULL. Ten sam wiersz jest audytem (kto wlaczyl, kto albo co
-- zakonczylo) i zrodlem dopisku w raportach — bez niego zero minut TV
-- w tygodniu wyjazdu wygladaloby jak tydzien bez ogladania. Nowa tabela,
-- nie kolumny: produkcja ma SQLite 3.40 i migracje tylko przez IF NOT EXISTS.
CREATE TABLE IF NOT EXISTS tv_pause (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    -- NULL = do odwolania. Po terminie pauza przestaje dzialac od razu,
    -- a tik domyka wiersz (ended_at = until, ended_by = "auto").
    until      TEXT,
    ended_at   TEXT,
    started_by TEXT,
    ended_by   TEXT
);
"""


def to_iso(dt: datetime) -> str:
    if dt.tzinfo is None:
        raise ValueError(f"oczekuje aware datetime, dostalem {dt!r}")
    return dt.astimezone(UTC).strftime(ISO)


def episode_id(state: dict, now: datetime) -> str:
    """Identyfikator epizodu awarii do kluczy dedupu czujek.

    Licznik zgloszen zeruje sie po powrocie, a `sent` trzyma klucze 7 dni —
    sam licznik w kluczu sprawial, ze druga awaria w tygodniu nie dawala ani
    alarmu, ani "wrocilo". Czas pierwszego zgloszenia (`since` w stanie
    czujki) rozroznia epizody; stan bez `since` (sprzed tej poprawki) dostaje
    biezacy czas, czyli tez nowy klucz.
    """
    since = state.get("since")
    if since:
        return str(since)
    return now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def from_iso(text: str) -> datetime:
    return datetime.strptime(text, ISO)


def note_to_json(note: Notification) -> str:
    return json.dumps({
        "kind": str(note.kind), "title": note.title, "text": note.text,
        "dedup_key": note.dedup_key, "ts": to_iso(note.ts), "device": note.device,
        "app": note.app, "priority": note.priority, "tags": list(note.tags),
        "data": note.data,
    }, ensure_ascii=False)


def note_from_json(text: str) -> Notification:
    from .models import Notification, NotifyKind  # noqa: PLC0415

    d = json.loads(text)
    return Notification(
        kind=NotifyKind(d["kind"]), title=d["title"], text=d["text"],
        dedup_key=d["dedup_key"], ts=from_iso(d["ts"]), device=d.get("device"),
        app=d.get("app"), priority=int(d.get("priority", 3)), tags=tuple(d.get("tags") or ()),
        data=d.get("data"),
    )


@dataclass(frozen=True)
class OutboxItem:
    id: int
    attempts: int
    note: Notification
    created_at: datetime
    next_at: datetime | None = None
    last_error: str | None = None


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        if tmpdir := os.environ.get("SQLITE_TMPDIR"):
            # SQLite po cichu wraca do /tmp, gdy katalogu nie ma — a /tmp
            # w podzie to maly emptyDir (chart: SQLITE_TMPDIR).
            with contextlib.suppress(OSError):
                Path(tmpdir).mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.path, isolation_level=None)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        self._migrate()

    def _migrate(self) -> None:
        """Dokłada kolumny, ktorych CREATE TABLE IF NOT EXISTS nie doda do
        istniejacej tabeli. Bez tego stara baza wywala sie na SELECT."""
        columns = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(sessions)").fetchall()
        }
        if "last_identified_at" not in columns:
            self.conn.execute("ALTER TABLE sessions ADD COLUMN last_identified_at TEXT")
        if "confirmed" not in columns:
            self.conn.execute(
                "ALTER TABLE sessions ADD COLUMN confirmed INTEGER NOT NULL DEFAULT 1"
            )
            # Stare sesje iPadow: potwierdzona = taka, o ktorej poszedl push.
            # Telewizor (child NULL) zawsze byl potwierdzony.
            self.conn.execute(
                "UPDATE sessions SET confirmed = start_notified WHERE child IS NOT NULL"
            )
        note_cols = {
            row["name"]
            for row in self.conn.execute("PRAGMA table_info(notifications)").fetchall()
        }
        if "data" not in note_cols:
            self.conn.execute("ALTER TABLE notifications ADD COLUMN data TEXT")
        outbox_cols = {
            row["name"] for row in self.conn.execute("PRAGMA table_info(outbox)").fetchall()
        }
        if "next_at" not in outbox_cols:
            self.conn.execute("ALTER TABLE outbox ADD COLUMN next_at TEXT")
        if "last_error" not in outbox_cols:
            self.conn.execute("ALTER TABLE outbox ADD COLUMN last_error TEXT")
        self._migrate_child_nullable()

    def _migrate_child_nullable(self) -> None:
        """sessions.child bylo NOT NULL; telewizor nie ma dziecka.

        SQLite nie zdejmie ograniczenia ALTER-em, wiec przebudowa tabeli w jednej
        transakcji: nowa tabela z tym samym ukladem, kopia wierszy z ID (od nich
        zaleza session_apps i tv_watch), podmiana. Robi sie raz — przy kolejnym
        starcie kolumna juz dopuszcza NULL.
        """
        info = {
            row["name"]: row for row in self.conn.execute("PRAGMA table_info(sessions)")
        }
        if not info["child"]["notnull"]:
            return
        cols = ", ".join(info)
        self.conn.execute("BEGIN IMMEDIATE")
        try:
            self.conn.execute("ALTER TABLE sessions RENAME TO sessions_old")
            self.conn.execute("DROP INDEX IF EXISTS ix_sessions_open")
            self.conn.execute("DROP INDEX IF EXISTS ix_sessions_started")
            # execute, nie executescript — ten drugi zatwierdza transakcje.
            for stmt in SCHEMA.split(";"):
                if "EXISTS sessions (" in stmt or " ON sessions (" in stmt:
                    self.conn.execute(stmt)
            self.conn.execute(f"INSERT INTO sessions ({cols}) SELECT {cols} FROM sessions_old")
            self.conn.execute("DROP TABLE sessions_old")
            self.conn.execute("COMMIT")
        except BaseException:
            self.conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ---------------------------------------------------------------- meta
    def get_meta(self, key: str, default: str | None = None) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def delete_meta(self, key: str) -> None:
        self.conn.execute("DELETE FROM meta WHERE key=?", (key,))

    def get_json(self, key: str, default: object = None) -> object:
        raw = self.get_meta(key)
        return default if raw is None else json.loads(raw)

    def set_json(self, key: str, value: object) -> None:
        self.set_meta(key, json.dumps(value, ensure_ascii=False))

    # --------------------------------------------------------------- kursor
    def get_cursor(self, source: str) -> str | None:
        return self.get_meta(f"cursor:{source}")

    def set_cursor(self, source: str, cursor: str) -> None:
        self.set_meta(f"cursor:{source}", cursor)

    # -------------------------------------------------------------- sesje
    def open_session(
        self, device: str, child: str | None, at: datetime, confirmed: bool = True
    ) -> int:
        """`confirmed=False` dla iPadow: sesja czeka na potwierdzenie aktywnoscia."""
        cur = self.conn.execute(
            "INSERT INTO sessions (device, child, started_at, last_activity_at, "
            "last_identified_at, confirmed) VALUES (?, ?, ?, ?, ?, ?)",
            (device, child, to_iso(at), to_iso(at), to_iso(at), int(confirmed)),
        )
        return int(cur.lastrowid)

    def confirm_session(self, session_id: int, started_at: datetime | None = None) -> None:
        """Potwierdza sesje; `started_at` przesuwa jej poczatek na pierwsza
        aktywnosc, ktora ja potwierdzila (wczesniejszy samotny ping w tle nie
        wydluza sesji o kilka minut)."""
        if started_at is None:
            self.conn.execute("UPDATE sessions SET confirmed=1 WHERE id=?", (session_id,))
        else:
            self.conn.execute(
                "UPDATE sessions SET confirmed=1, started_at=MAX(started_at, ?) WHERE id=?",
                (to_iso(started_at), session_id),
            )
            # Minuty sprzed nowego poczatku (ten samotny ping) tez wypadaja —
            # inaczej aplikacja i "minuty nocne" liczylyby czas spoza sesji.
            self.conn.execute(
                "DELETE FROM session_apps WHERE session_id=? AND minute < ?",
                (session_id, started_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M")),
            )

    def get_open_session(self, device: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM sessions WHERE device=? AND ended_at IS NULL "
            "ORDER BY id DESC LIMIT 1",
            (device,),
        ).fetchone()

    def all_open_sessions(self, *, child_only: bool = False) -> list[sqlite3.Row]:
        """`child_only=True` pomija urzadzenia wspolne (telewizor) — ich sesje
        domyka wlasny obserwator, nie zegar bezczynnosci DNS."""
        sql = "SELECT * FROM sessions WHERE ended_at IS NULL"
        if child_only:
            sql += " AND child IS NOT NULL"
        return list(self.conn.execute(sql + " ORDER BY device").fetchall())

    def touch_session(self, session_id: int, at: datetime, identified: bool = True) -> None:
        """Odswieza czas aktywnosci. `identified=False` dla ruchu wspoldzielonego,
        ktory przedluza sesje, ale nie jest dowodem na konkretna aplikacje."""
        if identified:
            self.conn.execute(
                "UPDATE sessions SET last_activity_at=?, last_identified_at=? WHERE id=?",
                (to_iso(at), to_iso(at), session_id),
            )
        else:
            self.conn.execute(
                "UPDATE sessions SET last_activity_at=? WHERE id=?", (to_iso(at), session_id)
            )

    def mark_start_notified(self, session_id: int) -> None:
        self.conn.execute("UPDATE sessions SET start_notified=1 WHERE id=?", (session_id,))

    def close_session(self, session_id: int, at: datetime) -> None:
        self.conn.execute(
            "UPDATE sessions SET ended_at=? WHERE id=? AND ended_at IS NULL",
            (to_iso(at), session_id),
        )

    def record_app_minute(self, session_id: int, app: str, at: datetime) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO session_apps (session_id, app, minute) VALUES (?, ?, ?)",
            (session_id, app, at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M")),
        )

    def reassign_app_minutes(
        self, session_id: int, from_app: str, to_app: str, since: datetime
    ) -> None:
        """Przenosi minuty `from_app` od `since` na `to_app` (reklama YouTube
        rozpoznana po fakcie). OR IGNORE + DELETE, bo minuta gry moze juz byc."""
        cut = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M")
        self.conn.execute(
            "UPDATE OR IGNORE session_apps SET app=? WHERE session_id=? AND app=? AND minute>=?",
            (to_app, session_id, from_app, cut),
        )
        self.conn.execute(
            "DELETE FROM session_apps WHERE session_id=? AND app=? AND minute>=?",
            (session_id, from_app, cut),
        )

    def session_app_minutes(self, session_id: int) -> list[tuple[str, int]]:
        rows = self.conn.execute(
            "SELECT app, COUNT(*) AS n FROM session_apps WHERE session_id=? "
            "GROUP BY app ORDER BY n DESC, app ASC",
            (session_id,),
        ).fetchall()
        return [(r["app"], int(r["n"])) for r in rows]

    def last_app(self, session_id: int, exclude: str | None = None) -> str | None:
        """Aplikacja z najpozniejszej minuty sesji (do pusha "co teraz")."""
        row = self.conn.execute(
            "SELECT app FROM session_apps WHERE session_id=? AND app IS NOT ? "
            "ORDER BY minute DESC, app ASC LIMIT 1",
            (session_id, exclude),
        ).fetchone()
        return row["app"] if row else None

    def session_minutes(self, session_id: int) -> list[datetime]:
        """Rozne minuty z ruchem aplikacji w sesji, jako aware UTC."""
        rows = self.conn.execute(
            "SELECT DISTINCT minute FROM session_apps WHERE session_id=? ORDER BY minute",
            (session_id,),
        ).fetchall()
        return [
            datetime.strptime(r["minute"], "%Y-%m-%dT%H:%M").replace(tzinfo=UTC) for r in rows
        ]

    def sessions_between(
        self, start: datetime, end: datetime, confirmed_only: bool = True
    ) -> list[sqlite3.Row]:
        """Sesje rozpoczete w [start, end). Domyslnie tylko potwierdzone — tak
        licza podsumowania, raporty i agregaty."""
        sql = "SELECT * FROM sessions WHERE started_at >= ? AND started_at < ?"
        if confirmed_only:
            sql += " AND confirmed=1"
        return list(
            self.conn.execute(sql + " ORDER BY device, started_at", (to_iso(start), to_iso(end)))
        )

    # -------------------------------------------------------------- telewizor
    def open_tv_segment(
        self,
        session_id: int,
        device: str,
        at: datetime,
        package: str,
        app: str,
        title: str | None,
        channel: str | None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO tv_watch (session_id, device, started_at, package, app, title, "
            "channel) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (session_id, device, to_iso(at), package, app, title, channel),
        )
        return int(cur.lastrowid)

    def current_tv_segment(self, device: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM tv_watch WHERE device=? AND ended_at IS NULL ORDER BY id DESC LIMIT 1",
            (device,),
        ).fetchone()

    def close_tv_segments(self, device: str, at: datetime) -> None:
        self.conn.execute(
            "UPDATE tv_watch SET ended_at=? WHERE device=? AND ended_at IS NULL",
            (to_iso(at), device),
        )

    def tv_segments(self, session_id: int) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM tv_watch WHERE session_id=? ORDER BY started_at", (session_id,)
            ).fetchall()
        )

    def tv_segments_between(
        self, device: str, start: datetime, end: datetime
    ) -> list[sqlite3.Row]:
        return list(
            self.conn.execute(
                "SELECT * FROM tv_watch WHERE device=? AND started_at >= ? AND started_at < ? "
                "ORDER BY started_at",
                (device, to_iso(start), to_iso(end)),
            ).fetchall()
        )

    def add_tv_usage(
        self, device: str, day: str, package: str, app: str, ms: int, last_used: datetime | None
    ) -> None:
        self.conn.execute(
            "INSERT INTO tv_usage (device, day, package, app, ms, last_used) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(device, day, package) DO UPDATE SET "
            "ms = ms + excluded.ms, app = excluded.app, "
            "last_used = COALESCE(excluded.last_used, last_used)",
            (device, day, package, app, ms, to_iso(last_used) if last_used else None),
        )

    def tv_usage_between(self, device: str, first: str, last: str) -> list[tuple[str, int]]:
        """[(aplikacja, ms)] z dni first..last (YYYY-MM-DD, wlacznie), malejaco."""
        rows = self.conn.execute(
            "SELECT app, SUM(ms) AS ms FROM tv_usage WHERE device=? AND day >= ? AND day <= ? "
            "GROUP BY app HAVING SUM(ms) > 0 ORDER BY ms DESC, app ASC",
            (device, first, last),
        ).fetchall()
        return [(r["app"], int(r["ms"])) for r in rows]

    # ------------------------------------------------------ pauza telewizora
    def tv_pause_open(self) -> sqlite3.Row | None:
        """Pauza jeszcze niedomknieta — takze ta po terminie, ktorej tik
        jeszcze nie domknal. O tym, czy pauza DZIALA, mowi tv_paused_at."""
        return self.conn.execute(
            "SELECT * FROM tv_pause WHERE ended_at IS NULL ORDER BY id DESC LIMIT 1"
        ).fetchone()

    def tv_paused_at(self, at: datetime) -> sqlite3.Row | None:
        """Pauza obowiazujaca w chwili `at` albo None. Termin liczy sie od
        razu, bez czekania na tik — czujnik TV rusza w pierwszym odczycie."""
        stamp = to_iso(at)
        return self.conn.execute(
            "SELECT * FROM tv_pause WHERE ended_at IS NULL AND started_at <= ? "
            "AND (until IS NULL OR until > ?) ORDER BY id DESC LIMIT 1",
            (stamp, stamp),
        ).fetchone()

    def start_tv_pause(self, at: datetime, until: datetime | None, by: str | None) -> int:
        cur = self.conn.execute(
            "INSERT INTO tv_pause (started_at, until, started_by) VALUES (?, ?, ?)",
            (to_iso(at), to_iso(until) if until else None, by),
        )
        return int(cur.lastrowid)

    def set_tv_pause_until(self, pause_id: int, until: datetime | None) -> None:
        self.conn.execute(
            "UPDATE tv_pause SET until=? WHERE id=?",
            (to_iso(until) if until else None, pause_id),
        )

    def end_tv_pause(self, pause_id: int, at: datetime, by: str | None) -> None:
        self.conn.execute(
            "UPDATE tv_pause SET ended_at=?, ended_by=? WHERE id=? AND ended_at IS NULL",
            (to_iso(at), by, pause_id),
        )

    def tv_pauses_between(
        self, start: datetime, end: datetime
    ) -> list[tuple[datetime, datetime | None]]:
        """[(od, do)] pauz zachodzacych na [start, end). `do` None = do odwolania;
        dla pauzy po terminie, ktorej tik jeszcze nie domknal, to jej termin."""
        rows = self.conn.execute(
            "SELECT started_at, COALESCE(ended_at, until) AS till FROM tv_pause "
            "WHERE started_at < ? AND (COALESCE(ended_at, until) IS NULL "
            "OR COALESCE(ended_at, until) > ?) ORDER BY started_at",
            (to_iso(end), to_iso(start)),
        ).fetchall()
        return [
            (from_iso(r["started_at"]), from_iso(r["till"]) if r["till"] else None) for r in rows
        ]

    def last_tv_pause_end(self) -> datetime | None:
        """Koniec ostatniej pauzy (domknietej albo po terminie). Od niego czujka
        "TV nie odpowiada" liczy cisze — tydzien pauzy to nie tydzien awarii."""
        row = self.conn.execute(
            "SELECT MAX(COALESCE(ended_at, until)) AS till FROM tv_pause"
        ).fetchone()
        return from_iso(row["till"]) if row and row["till"] else None

    # -------------------------------------------------------------- agregaty
    def upsert_rollup(self, row: dict) -> None:
        self.conn.execute(
            "INSERT INTO daily_rollup (day, device, child, kind, minutes, sessions, "
            "night_minutes, tv_minutes, top_apps, tv_apps, computed_at) VALUES "
            "(:day, :device, :child, :kind, :minutes, :sessions, :night_minutes, "
            ":tv_minutes, :top_apps, :tv_apps, :computed_at) "
            "ON CONFLICT(day, device) DO UPDATE SET child=excluded.child, kind=excluded.kind, "
            "minutes=excluded.minutes, sessions=excluded.sessions, "
            "night_minutes=excluded.night_minutes, tv_minutes=excluded.tv_minutes, "
            "top_apps=excluded.top_apps, tv_apps=excluded.tv_apps, "
            "computed_at=excluded.computed_at",
            row,
        )

    def rollup_days(self) -> set[str]:
        return {r[0] for r in self.conn.execute("SELECT DISTINCT day FROM daily_rollup")}

    def session_start_range(self) -> tuple[str, str] | None:
        row = self.conn.execute("SELECT MIN(started_at), MAX(started_at) FROM sessions").fetchone()
        return None if row[0] is None else (row[0], row[1])

    # ------------------------------------------------------------ cooldown
    def app_last_notified(self, device: str, app: str) -> datetime | None:
        row = self.conn.execute(
            "SELECT notified_at FROM app_cooldown WHERE device=? AND app=?", (device, app)
        ).fetchone()
        return from_iso(row["notified_at"]) if row else None

    def set_app_notified(self, device: str, app: str, at: datetime) -> None:
        self.conn.execute(
            "INSERT INTO app_cooldown (device, app, notified_at) VALUES (?, ?, ?) "
            "ON CONFLICT(device, app) DO UPDATE SET notified_at=excluded.notified_at",
            (device, app, to_iso(at)),
        )

    # ------------------------------------------------------- limit / dedup
    def count_notifications_since(
        self,
        device: str,
        since: datetime,
        kinds: tuple[str, ...] | None = None,
        exclude_kinds: tuple[str, ...] | None = None,
    ) -> int:
        """Licznik powiadomien w oknie czasu, opcjonalnie zawezony do rodzajow.

        Warstwa DNS i warstwa odczytu z urzadzen maja OSOBNE budzety godzinowe.
        Bez tego rozdzielenia godzina grania (pushe o uruchomieniach) wypelniala
        licznik i silnik zaczynal dlawic wlasne powiadomienia o sesjach.
        """
        sql = "SELECT COUNT(*) AS n FROM notify_log WHERE device=? AND sent_at >= ?"
        params: list[object] = [device, to_iso(since)]
        if kinds:
            sql += " AND kind IN (" + ",".join("?" * len(kinds)) + ")"
            params += list(kinds)
        if exclude_kinds:
            sql += " AND kind NOT IN (" + ",".join("?" * len(exclude_kinds)) + ")"
            params += list(exclude_kinds)
        return int(self.conn.execute(sql, params).fetchone()["n"])

    def log_notification(self, device: str | None, at: datetime, kind: str) -> None:
        self.conn.execute(
            "INSERT INTO notify_log (device, sent_at, kind) VALUES (?, ?, ?)",
            (device or "", to_iso(at), kind),
        )

    def record_notification(
        self, note: Notification, results: dict[str, bool], at: datetime
    ) -> int:
        """Zapisuje wyslane powiadomienie z wynikiem per kanal (historia panelu)."""
        cur = self.conn.execute(
            "INSERT INTO notifications (ts, sent_at, kind, device, app, title, text, "
            "priority, channels, delivered, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                to_iso(note.ts),
                to_iso(at),
                str(note.kind),
                note.device,
                note.app,
                note.title,
                note.text,
                note.priority,
                json.dumps(results, ensure_ascii=False),
                int(any(results.values())),
                None if note.data is None else json.dumps(note.data, ensure_ascii=False),
            ),
        )
        return int(cur.lastrowid)

    def already_sent(self, dedup_key: str) -> bool:
        return (
            self.conn.execute("SELECT 1 FROM sent WHERE dedup_key=?", (dedup_key,)).fetchone()
            is not None
        )

    def mark_sent(self, dedup_key: str, at: datetime) -> bool:
        """Zwraca True, jesli to my zajelismy klucz (czyli push nalezy wyslac)."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO sent (dedup_key, sent_at) VALUES (?, ?)",
            (dedup_key, to_iso(at)),
        )
        return cur.rowcount == 1

    # ------------------------------------------------------ kolejka wyjsciowa
    def outbox_put(self, notes: Iterable[Notification], at: datetime) -> None:
        self.conn.executemany(
            "INSERT INTO outbox (created_at, note) VALUES (?, ?)",
            [(to_iso(at), note_to_json(n)) for n in notes],
        )

    def outbox_pending(self, limit: int = 50) -> list[OutboxItem]:
        """Wpisy w kolejnosci wstawienia (tej samej, w jakiej maja wyjsc)."""
        rows = self.conn.execute(
            "SELECT id, created_at, attempts, note, next_at, last_error FROM outbox "
            "ORDER BY id LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            OutboxItem(
                id=int(r["id"]),
                attempts=int(r["attempts"]),
                note=note_from_json(r["note"]),
                created_at=from_iso(r["created_at"]),
                next_at=from_iso(r["next_at"]) if r["next_at"] else None,
                last_error=r["last_error"],
            )
            for r in rows
        ]

    def outbox_head(self) -> OutboxItem | None:
        pending = self.outbox_pending(limit=1)
        return pending[0] if pending else None

    def outbox_attempt(self, item_id: int, next_at: datetime | None = None) -> None:
        """Liczy probe i od razu wyznacza nastepna — PRZED wysylka, zeby
        proces padajacy w samej wysylce nie ponawial jej bez przerwy."""
        self.conn.execute(
            "UPDATE outbox SET attempts = attempts + 1, next_at = ? WHERE id = ?",
            (None if next_at is None else to_iso(next_at), item_id),
        )

    def outbox_failed(self, item_id: int, error: str) -> None:
        self.conn.execute("UPDATE outbox SET last_error = ? WHERE id = ?", (error, item_id))

    def outbox_done(self, item_id: int) -> None:
        self.conn.execute("DELETE FROM outbox WHERE id = ?", (item_id,))

    # ---------------------------------------------------------- dlawienie
    def push_throttled(self, device: str, label: str, at: datetime) -> None:
        self.conn.execute(
            "INSERT INTO throttled (device, label, ts) VALUES (?, ?, ?)",
            (device, label, to_iso(at)),
        )

    def drain_throttled(self, device: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT label FROM throttled WHERE device=? ORDER BY id", (device,)
        ).fetchall()
        self.conn.execute("DELETE FROM throttled WHERE device=?", (device,))
        return [r["label"] for r in rows]

    def count_throttled(self, device: str) -> int:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM throttled WHERE device=?", (device,)
        ).fetchone()
        return int(row["n"])

    # ------------------------------------------------------------ zdarzenia
    def record_event(
        self,
        ts: datetime,
        device: str | None,
        source_id: str,
        domain: str,
        kind: str,
        app: str | None,
    ) -> None:
        self.conn.execute(
            "INSERT INTO events (ts, device, source_id, domain, kind, app) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (to_iso(ts), device, source_id, domain, kind, app),
        )

    def seen_before(self, fingerprints: Iterable[str], at: datetime) -> set[str]:
        """Zwraca odciski widziane wczesniej; nowe od razu zapisuje.

        Jedna transakcja, wiec nie ma okna, w ktorym rownolegly przebieg uznalby
        ten sam wpis za nowy.
        """
        fps = list(dict.fromkeys(fingerprints))
        if not fps:
            return set()
        placeholders = ",".join("?" * len(fps))
        rows = self.conn.execute(
            f"SELECT fingerprint FROM seen_queries WHERE fingerprint IN ({placeholders})",
            fps,
        ).fetchall()
        known = {r["fingerprint"] for r in rows}
        fresh = [(fp, to_iso(at)) for fp in fps if fp not in known]
        if fresh:
            self.conn.executemany(
                "INSERT OR IGNORE INTO seen_queries (fingerprint, seen_at) VALUES (?, ?)", fresh
            )
        return known

    # --------------------------------------------------------------- przeglad
    def top_domains(
        self,
        since: datetime,
        kinds: tuple[str, ...] | None = None,
        limit: int = 40,
    ) -> list[sqlite3.Row]:
        """Najczestsze domeny od `since`, z ich klasyfikacja.

        Sluzy do uzupelniania app_map.yaml z REALNYCH danych. Kazda lista domen
        gier napisana z gory jest niepelna — gry jezdza po wspoldzielonych CDN-ach
        i zmieniaja zaplecze. To zapytanie pokazuje, czego brakuje.
        """
        sql = [
            "SELECT domain, kind, app, COUNT(*) AS n,",
            "       COUNT(DISTINCT device) AS devices,",
            "       MIN(ts) AS pierwsze, MAX(ts) AS ostatnie",
            "FROM events WHERE ts >= ?",
        ]
        params: list[object] = [to_iso(since)]
        if kinds:
            sql.append("AND kind IN (" + ",".join("?" * len(kinds)) + ")")
            params += list(kinds)
        sql.append("GROUP BY domain, kind, app ORDER BY n DESC, domain ASC LIMIT ?")
        params.append(limit)
        return list(self.conn.execute(" ".join(sql), params).fetchall())

    def browsed_since(
        self, device: str, since: datetime, until: datetime | None = None, limit: int = 200
    ) -> list[tuple[str, int]]:
        """Nierozpoznane domeny odwiedzone przez urzadzenie w danym okresie.

        To jest najblizsze temu, co DNS wie o przegladaniu stron: widzi domene,
        nigdy adresu strony ani tresci.
        """
        sql = "SELECT domain, COUNT(*) AS n FROM events WHERE device=? AND kind='unknown' AND ts>=?"
        params: list[object] = [device, to_iso(since)]
        if until is not None:
            sql += " AND ts<=?"
            params.append(to_iso(until))
        sql += " GROUP BY domain ORDER BY n DESC, domain ASC LIMIT ?"
        params.append(limit)
        rows = self.conn.execute(sql, params).fetchall()
        return [(r["domain"], int(r["n"])) for r in rows]

    # ------------------------------------------------------------- sprzatanie
    def purge(
        self,
        now: datetime,
        retention_days: int,
        notifications_days: int = 0,
        rollup_days: int = 0,
    ) -> dict[str, int]:
        """Kasuje stare dane. retention_days=0 wylacza czyszczenie zdarzen,
        notifications_days=0 — czyszczenie historii powiadomien, rollup_days=0
        — agregatow dziennych (domyslnie trzymane bez limitu)."""
        deleted: dict[str, int] = {}
        if rollup_days > 0:
            cut_day = (now - timedelta(days=rollup_days)).strftime("%Y-%m-%d")
            deleted["daily_rollup"] = self.conn.execute(
                "DELETE FROM daily_rollup WHERE day < ?", (cut_day,)
            ).rowcount
        if notifications_days > 0:
            deleted["notifications"] = self.conn.execute(
                "DELETE FROM notifications WHERE ts < ?",
                (to_iso(now - timedelta(days=notifications_days)),),
            ).rowcount
        # Odciski i klucze dedupu sa potrzebne tylko krotko.
        short_cut = to_iso(now - timedelta(days=2))
        deleted["seen_queries"] = self.conn.execute(
            "DELETE FROM seen_queries WHERE seen_at < ?", (short_cut,)
        ).rowcount
        deleted["notify_log"] = self.conn.execute(
            "DELETE FROM notify_log WHERE sent_at < ?", (to_iso(now - timedelta(days=7)),)
        ).rowcount
        deleted["sent"] = self.conn.execute(
            "DELETE FROM sent WHERE sent_at < ?", (to_iso(now - timedelta(days=7)),)
        ).rowcount
        if retention_days > 0:
            cut = to_iso(now - timedelta(days=retention_days))
            deleted["events"] = self.conn.execute(
                "DELETE FROM events WHERE ts < ?", (cut,)
            ).rowcount
            # Szczegol per aplikacja zostaje w daily_rollup.tv_apps.
            deleted["tv_usage"] = self.conn.execute(
                "DELETE FROM tv_usage WHERE day < ?", (cut[:10],)
            ).rowcount
            # Sesje kasujemy razem z ich minutami, zeby nie zostawic sierot.
            for table in ("session_apps", "tv_watch"):
                self.conn.execute(
                    f"DELETE FROM {table} WHERE session_id IN "
                    "(SELECT id FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?)",
                    (cut,),
                )
            deleted["sessions"] = self.conn.execute(
                "DELETE FROM sessions WHERE ended_at IS NOT NULL AND ended_at < ?", (cut,)
            ).rowcount
        return deleted
