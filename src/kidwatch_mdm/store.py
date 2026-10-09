"""Stan serwera MDM w SQLite.

Osobna baza od kidwatch.db, na osobnym PVC: to osobny kontener i osobny
pisarz. Jedno polaczenie chronione blokada — przy kilku iPadach rownoleglosc
zadan jest znikoma, a jedno polaczenie wyklucza `database is locked` miedzy
watkami serwera HTTP i watkiem uzgadniania.
"""

from __future__ import annotations

import json
import plistlib
import secrets
import sqlite3
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS enrollments (
    token      TEXT PRIMARY KEY,
    label      TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    -- Ustawiane przy pierwszym Authenticate. Potem token nie wyda juz nowej
    -- tozsamosci, a urzadzenie z innym UDID nie moze sie nim zapisac.
    udid       TEXT,
    bound_at   TEXT
);

-- Kazde pobranie profilu wystawia nowy certyfikat. Do czasu zwiazania
-- wszystkie sa wazne; po Authenticate liczy sie tylko ten, ktory przyszedl.
CREATE TABLE IF NOT EXISTS identities (
    fingerprint TEXT PRIMARY KEY,
    token       TEXT NOT NULL REFERENCES enrollments(token),
    issued_at   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    udid             TEXT PRIMARY KEY,
    label            TEXT NOT NULL,
    enrollment_token TEXT NOT NULL,
    cert_fp          TEXT NOT NULL,
    serial           TEXT,
    product          TEXT,
    device_name      TEXT,
    os_version       TEXT,
    build_version    TEXT,
    topic            TEXT,
    push_token       BLOB,
    push_magic       TEXT,
    unlock_token     BLOB,
    supervised       INTEGER,
    enrolled_at      TEXT NOT NULL,
    last_seen_at     TEXT NOT NULL,
    checked_out_at   TEXT,
    info_json        TEXT,
    info_at          TEXT,
    security_json    TEXT,
    profiles_json    TEXT,
    apps_json        TEXT,
    apps_at          TEXT,
    ddm_status_json  TEXT,
    ddm_status_at    TEXT,
    -- DeclarationsToken, ktory iPad ostatnio pobral. Inny niz biezacy =
    -- polityka sie zmienila i trzeba wyslac komende DeclarativeManagement.
    ddm_token        TEXT,
    push_error       TEXT,
    push_error_at    TEXT,
    last_push_at     TEXT
);

CREATE TABLE IF NOT EXISTS commands (
    uuid         TEXT PRIMARY KEY,
    udid         TEXT NOT NULL,
    request_type TEXT NOT NULL,
    command      BLOB NOT NULL,
    -- queued -> sent -> acknowledged | error | format_error
    -- not_now: iPad zajety (np. zablokowany); wraca do kolejki przy Idle.
    status       TEXT NOT NULL,
    origin       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    sent_at      TEXT,
    done_at      TEXT,
    result       BLOB,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS ix_commands_queue ON commands (udid, status, created_at);

-- Co i w jakiej wersji zainstalowalismy. Uzgadnianie porownuje to z polityka
-- i z ProfileList, zeby wykryc profil zdjety lub nieaktualny.
CREATE TABLE IF NOT EXISTS profile_state (
    udid         TEXT NOT NULL,
    identifier   TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    command_uuid TEXT NOT NULL,
    installed_at TEXT,
    -- Nieudane instalacje: ponowienie po rosnacej przerwie, nie co obieg —
    -- inaczej jeden zly profil to alarm co kwadrans przez cala noc.
    failures     INTEGER NOT NULL DEFAULT 0,
    retry_after  TEXT,
    PRIMARY KEY (udid, identifier)
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Dziennik zdarzen dla Kidwatch: zapis, wypisanie, odrzucone wiadomosci,
-- bledy komend. Kidwatch czyta go przez API i zamienia w alarmy.
CREATE TABLE IF NOT EXISTS events (
    id     INTEGER PRIMARY KEY AUTOINCREMENT,
    at     TEXT NOT NULL,
    udid   TEXT,
    kind   TEXT NOT NULL,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS ix_events_at ON events (at);
"""

FINAL = ("acknowledged", "error", "format_error", "cancelled")


def now_utc() -> datetime:
    return datetime.now(UTC)


def iso(dt: datetime) -> str:
    return dt.astimezone(UTC).isoformat(timespec="seconds")


def from_iso(text: str | None) -> datetime | None:
    return datetime.fromisoformat(text) if text else None


@dataclass
class Command:
    uuid: str
    udid: str
    request_type: str
    command: dict
    status: str


class Store:
    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.executescript(SCHEMA)
        # Identyfikator TEJ bazy: nowa baza (nowy PVC, ponowny init) = nowy
        # identyfikator. Kidwatch po nim poznaje, ze numeracja zdarzen ruszyla
        # od 1 i jego kursor nic tu nie znaczy. Kopia odtworzona z backupu
        # zachowuje identyfikator — ja zdradza cofniety max(id).
        self.conn.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES ('instance', ?)",
            (json.dumps(str(uuid.uuid4())),),
        )

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self.conn.execute("BEGIN IMMEDIATE")
            try:
                yield self.conn
            except BaseException:
                self.conn.execute("ROLLBACK")
                raise
            self.conn.execute("COMMIT")

    def query(self, sql: str, params: tuple | dict = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self.conn.execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple | dict = ()) -> sqlite3.Row | None:
        with self._lock:
            return self.conn.execute(sql, params).fetchone()

    # ------------------------------------------------------------- zapisy
    def create_enrollment(self, label: str, ttl: timedelta, now: datetime | None = None) -> str:
        now = now or now_utc()
        token = secrets.token_urlsafe(24)
        with self.tx() as c:
            c.execute(
                "INSERT INTO enrollments (token, label, created_at, expires_at) VALUES (?,?,?,?)",
                (token, label, iso(now), iso(now + ttl)),
            )
        return token

    def enrollment(self, token: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM enrollments WHERE token = ?", (token,))

    def record_identity(self, token: str, fp: str, now: datetime | None = None) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO identities (fingerprint, token, issued_at) VALUES (?,?,?)",
                (fp, token, iso(now or now_utc())),
            )

    def identity(self, fp: str) -> sqlite3.Row | None:
        return self.one(
            "SELECT i.fingerprint, i.token, e.label, e.udid AS bound_udid, e.expires_at "
            "FROM identities i JOIN enrollments e ON e.token = i.token WHERE i.fingerprint = ?",
            (fp,),
        )

    # ----------------------------------------------------------- urzadzenia
    def device(self, udid: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM devices WHERE udid = ?", (udid,))

    def devices(self) -> list[sqlite3.Row]:
        return self.query("SELECT * FROM devices ORDER BY label")

    def device_by_cert(self, fp: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM devices WHERE cert_fp = ?", (fp,))

    def update_device(self, udid: str, **fields: Any) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k} = :{k}" for k in fields)
        with self.tx() as c:
            c.execute(f"UPDATE devices SET {cols} WHERE udid = :udid", {**fields, "udid": udid})  # noqa: S608

    def event(self, kind: str, udid: str | None = None, detail: Any = None) -> None:
        text = detail if isinstance(detail, str) or detail is None else json.dumps(detail)
        with self.tx() as c:
            c.execute(
                "INSERT INTO events (at, udid, kind, detail) VALUES (?,?,?,?)",
                (iso(now_utc()), udid, kind, text),
            )

    def last_events(self, count: int) -> list[sqlite3.Row]:
        rows = self.query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (count,))
        return list(reversed(rows))

    def events(self, since_id: int = 0, limit: int = 200) -> list[sqlite3.Row]:
        return self.query(
            "SELECT * FROM events WHERE id > ? ORDER BY id LIMIT ?", (since_id, limit)
        )

    def last_event_id(self) -> int:
        row = self.one("SELECT MAX(id) AS id FROM events")
        return int(row["id"] or 0)

    # -------------------------------------------------------------- komendy
    def enqueue(self, udid: str, request_type: str, body: dict, *, origin: str = "api") -> str:
        cmd_uuid = str(uuid.uuid4()).upper()
        command = {"CommandUUID": cmd_uuid, "Command": {"RequestType": request_type, **body}}
        with self.tx() as c:
            c.execute(
                "INSERT INTO commands (uuid, udid, request_type, command, status, origin, "
                "created_at) VALUES (?,?,?,?, 'queued', ?, ?)",
                (cmd_uuid, udid, request_type, plistlib.dumps(command), origin, iso(now_utc())),
            )
        return cmd_uuid

    def pending(self, udid: str, request_type: str) -> bool:
        """Czy taka komenda juz czeka — uzgadnianie nie dubluje zapytan."""
        row = self.one(
            "SELECT 1 FROM commands WHERE udid = ? AND request_type = ? "
            "AND status IN ('queued', 'sent', 'not_now') LIMIT 1",
            (udid, request_type),
        )
        return row is not None

    def last_progress_at(self, udid: str) -> datetime | None:
        """Ostatni postep kolejki: odpowiedz na komende albo nowa komenda.

        NotNow i Idle bez odpowiedzi to nie postep — iPad tylko sie odezwal.
        """
        row = self.one(
            "SELECT MAX(t) AS t FROM ("
            " SELECT MAX(done_at) AS t FROM commands WHERE udid = :u"
            " AND status IN ('acknowledged', 'error', 'format_error')"
            " UNION ALL SELECT MAX(created_at) FROM commands WHERE udid = :u"
            " AND status IN ('queued', 'sent', 'not_now'))",
            {"u": udid},
        )
        return from_iso(row["t"]) if row else None

    def requeue_not_now(self, udid: str) -> None:
        """Idle otwiera nowa sesje: odlozone NotNow wracaja do kolejki."""
        with self.tx() as c:
            c.execute(
                "UPDATE commands SET status = 'queued' WHERE udid = ? AND status = 'not_now'",
                (udid,),
            )

    def next_command(self, udid: str) -> Command | None:
        """Najstarsza niezakonczona komenda. 'sent' bez odpowiedzi tez wraca —
        iPad mogl zerwac polaczenie, zanim odpowiedzial."""
        with self.tx() as c:
            row = c.execute(
                "SELECT * FROM commands WHERE udid = ? AND status IN ('queued', 'sent') "
                "ORDER BY created_at, rowid LIMIT 1",
                (udid,),
            ).fetchone()
            if row is None:
                return None
            c.execute(
                "UPDATE commands SET status = 'sent', sent_at = ? WHERE uuid = ?",
                (iso(now_utc()), row["uuid"]),
            )
        return Command(
            row["uuid"], row["udid"], row["request_type"], plistlib.loads(row["command"]), "sent"
        )

    def command(self, cmd_uuid: str) -> sqlite3.Row | None:
        return self.one("SELECT * FROM commands WHERE uuid = ?", (cmd_uuid,))

    def finish_command(
        self, cmd_uuid: str, status: str, result: dict, error: str | None = None
    ) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE commands SET status = ?, done_at = ?, result = ?, error = ? WHERE uuid = ?",
                (
                    status,
                    iso(now_utc()) if status in FINAL else None,
                    plistlib.dumps(result, fmt=plistlib.FMT_BINARY),
                    error,
                    cmd_uuid,
                ),
            )

    def commands_for(self, udid: str, limit: int = 50) -> list[sqlite3.Row]:
        return self.query(
            "SELECT uuid, request_type, status, origin, created_at, sent_at, done_at, error "
            "FROM commands WHERE udid = ? ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (udid, limit),
        )

    def cancel_pending(self, udid: str) -> int:
        with self.tx() as c:
            cur = c.execute(
                "UPDATE commands SET status = 'cancelled', done_at = ? "
                "WHERE udid = ? AND status IN ('queued', 'sent', 'not_now')",
                (iso(now_utc()), udid),
            )
            return cur.rowcount

    # ------------------------------------------------------------ profile
    def profile_states(self, udid: str) -> dict[str, sqlite3.Row]:
        rows = self.query("SELECT * FROM profile_state WHERE udid = ?", (udid,))
        return {r["identifier"]: r for r in rows}

    def set_profile_state(
        self, udid: str, identifier: str, content_hash: str, command_uuid: str
    ) -> None:
        with self.tx() as c:
            c.execute(
                "INSERT INTO profile_state (udid, identifier, content_hash, command_uuid) "
                "VALUES (?,?,?,?) ON CONFLICT(udid, identifier) DO UPDATE SET "
                "content_hash = excluded.content_hash, command_uuid = excluded.command_uuid, "
                "installed_at = NULL, retry_after = NULL, "
                # Ponowienie TEJ SAMEJ tresci zachowuje licznik porazek (rosnaca
                # przerwa); nowa tresc zaczyna od zera.
                "failures = CASE WHEN profile_state.content_hash = excluded.content_hash "
                "THEN profile_state.failures ELSE 0 END",
                (udid, identifier, content_hash, command_uuid),
            )

    def mark_profile_installed(self, command_uuid: str) -> None:
        with self.tx() as c:
            c.execute(
                "UPDATE profile_state SET installed_at = ?, failures = 0, retry_after = NULL "
                "WHERE command_uuid = ?",
                (iso(now_utc()), command_uuid),
            )

    def mark_profile_failed(self, command_uuid: str, now: datetime | None = None) -> int:
        """Odlicza przerwe do ponowienia: 15 min, 30, 60 ... maks. dobe."""
        now = now or now_utc()
        with self.tx() as c:
            row = c.execute(
                "SELECT failures FROM profile_state WHERE command_uuid = ?", (command_uuid,)
            ).fetchone()
            if row is None:
                return 0
            failures = row["failures"] + 1
            wait = min(timedelta(minutes=15) * 2 ** (failures - 1), timedelta(hours=24))
            c.execute(
                "UPDATE profile_state SET failures = ?, retry_after = ? WHERE command_uuid = ?",
                (failures, iso(now + wait), command_uuid),
            )
            return failures

    def forget_profile(self, udid: str, identifier: str) -> None:
        with self.tx() as c:
            c.execute(
                "DELETE FROM profile_state WHERE udid = ? AND identifier = ?", (udid, identifier)
            )

    # ------------------------------------------------------------ ustawienia
    def setting(self, key: str, default: Any = None) -> Any:
        row = self.one("SELECT value FROM settings WHERE key = ?", (key,))
        return json.loads(row["value"]) if row else default

    def set_setting(self, key: str, value: Any) -> None:
        with self.tx() as c:
            if value is None:
                c.execute("DELETE FROM settings WHERE key = ?", (key,))
            else:
                c.execute(
                    "INSERT INTO settings (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (key, json.dumps(value)),
                )
