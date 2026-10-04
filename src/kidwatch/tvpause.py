"""Wstrzymanie monitoringu telewizora.

PO CO: rodzic wyjezdza z dziecmi, a w domu zostaja inni domownicy i ogladaja
telewizje. Ich ogladanie nie jest czasem ekranowym dzieci — bez pauzy szlyby
pushe "TV salon: start", a minuty trafialyby do podsumowan i raportow. iPady
jada z dziecmi (NextDNS dziala poza domem), wiec pauza dotyczy TYLKO
telewizora.

STAN: tabela tv_pause w kidwatch.db (store.py). Pauza ma termin albo trwa do
odwolania. Po terminie przestaje dzialac od razu (store.tv_paused_at), a tik
silnika domyka wiersz i wysyla push "Monitoring TV wznowiony".

ZMIANA z panelu albo z CLI idzie kolejka tv_pause_requests w panel-auth.db —
z tego samego powodu co czas gry (gametime.py): panel czyta kidwatch.db tylko
do odczytu, a jedynym pisarzem jest petla glowna. Zadanie pamieta login,
ktory je zlecil; wiersz tv_pause — kto pauze wlaczyl i kto (albo termin) ja
zakonczyl.

CZUJNIK w pauzie w ogole NIE odpytuje telewizora (sources/tv.py,
scheduler.device_loop) — zamiast odpytywac i wyrzucac wynik:
  * o ogladaniu domownikow nie powstaje nic: ani sesja, ani tytul w logu, ani
    odczyt w pamieci. Nie ma kodu, ktory moglby to przez pomylke zapisac;
  * telewizor wyjety z pradu albo zerwany tunel w czasie wyjazdu nic nie
    znacza. Czujka "TV nie odpowiada" w pauzie milczy, a po pauzie liczy
    cisze od jej konca (store.last_tv_pause_end), nie od ostatniego odczytu.
Koszt: liczniki usagestats po pauzie obejmuja tez czas z pauzy. Pierwszy
odczyt usagestats, ktorego okres zahacza o pauze, tylko ustawia punkt
odniesienia (TvWatcher._maybe_usage). Kilkanascie minut sprzed pauzy
przepada — wolimy niedoszacowac niz doliczyc dzieciom wieczor dziadkow.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .config import Config
from .models import Notification, NotifyKind
from .store import Store, from_iso, to_iso

log = logging.getLogger(__name__)

ACTIONS = frozenset({"pause", "resume"})
#: Dluzsza pauza to raczej pomylka w dacie niz wyjazd.
MAX_PAUSE_DAYS = 366
#: Wiecej oczekujacych zadan to klikanie w kolko, nie intencja.
MAX_PENDING = 5

REQUESTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS tv_pause_requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    action     TEXT NOT NULL,
    -- Termin pauzy (ISO, UTC); NULL = do odwolania. Przy "resume" zawsze NULL.
    until      TEXT,
    login      TEXT,
    created_at REAL NOT NULL,
    done_at    REAL,
    ok         INTEGER,
    error      TEXT
);
"""


class TooManyRequests(RuntimeError):
    pass


class TvPauseRequests:
    """Zadania pauzy z panelu i CLI w panel-auth.db (jak GameRequests).
    Kazda operacja na wlasnym polaczeniu — panel wola z watkow serwera,
    petla z watku glownego, CLI z osobnego procesu."""

    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.path = str(path)
        self.clock = clock
        new = not Path(self.path).exists()
        with self._conn() as conn:
            conn.executescript(REQUESTS_SCHEMA)
        if new:
            # Ten sam plik co konta panelu (hashe hasel) — jak w PanelAuth.
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

    def submit(self, action: str, until: datetime | None, login: str | None) -> int:
        if action not in ACTIONS:
            raise ValueError(f"nieznana akcja {action!r}")
        with self._conn() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM tv_pause_requests WHERE done_at IS NULL"
            ).fetchone()[0]
            if pending >= MAX_PENDING:
                raise TooManyRequests(action)
            cur = conn.execute(
                "INSERT INTO tv_pause_requests (action, until, login, created_at) "
                "VALUES (?, ?, ?, ?)",
                (action, to_iso(until) if until else None, login, self.clock()),
            )
            return int(cur.lastrowid)

    def pending(self) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(conn.execute(
                "SELECT * FROM tv_pause_requests WHERE done_at IS NULL ORDER BY id"
            ))

    def finish(self, request_id: int, ok: bool, error: str | None = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE tv_pause_requests SET done_at=?, ok=?, error=? WHERE id=?",
                (self.clock(), int(ok), error, request_id),
            )

    def latest(self) -> dict | None:
        """Ostatnie zadanie — panel pokazuje "wysylanie..." albo blad."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM tv_pause_requests ORDER BY id DESC LIMIT 1"
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "action": row["action"],
            "pending": row["done_at"] is None,
            "ok": None if row["ok"] is None else bool(row["ok"]),
            "error": row["error"],
            "created_at": datetime.fromtimestamp(row["created_at"], UTC).isoformat(),
        }


# ==================================================================== terminy
def parse_until(raw: str, tz, now: datetime) -> datetime:
    """Termin z panelu albo CLI -> aware UTC. "2026-10-10T18:00" bez strefy to
    czas lokalny z konfiguracji (tak podaje go <input type=datetime-local>).
    ValueError z opisem dla czlowieka."""
    try:
        dt = datetime.fromisoformat(raw.strip())
    except (ValueError, AttributeError) as exc:
        raise ValueError(f"zły termin {raw!r}, oczekuję RRRR-MM-DDTGG:MM") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    dt = dt.astimezone(UTC)
    if dt <= now:
        raise ValueError("termin już minął")
    if dt - now > timedelta(days=MAX_PAUSE_DAYS):
        raise ValueError(f"pauza dłuższa niż {MAX_PAUSE_DAYS} dni")
    return dt


def fmt_when(at: datetime, tz) -> str:
    return f"{at.astimezone(tz):%d.%m %H:%M}"


def fmt_until(until: datetime | None, tz) -> str:
    return "do odwołania" if until is None else f"do {fmt_when(until, tz)}"


def pause_facts(
    store: Store, tz, start: datetime, end: datetime
) -> tuple[list[str], bool]:
    """(dopiski do sekcji TV w raporcie, czy pauza objela caly okres).

    Bez dopisku zero minut TV w dniu wyjazdu wygladaloby jak dzien bez
    ogladania — a to dzien, w ktorym telewizora nie liczylismy.
    """
    facts: list[str] = []
    whole = False
    for since, till in store.tv_pauses_between(start, end):
        facts.append(f"monitoring wstrzymany od {fmt_when(since, tz)} {fmt_until(till, tz)}")
        if since <= start and (till is None or till >= end):
            whole = True
    return facts, whole


# ================================================================== sterownik
class TvPause:
    """Wykonuje zadania z kolejki i domyka pauzy po terminie. Wolany z tiku
    silnika (Engine._tv_pause_step), ktory przepuszcza powiadomienia przez
    wlasna bramke dedupu. Pushe niskim priorytetem: to informacja, nie alarm."""

    def __init__(self, cfg: Config, store: Store, requests: TvPauseRequests | None = None) -> None:
        self.cfg = cfg
        self.store = store
        self.requests = requests

    @property
    def name(self) -> str:
        return self.cfg.tv.name

    def step(self, now: datetime) -> list[Notification]:
        if not self.cfg.tv.enabled:
            return []
        # Najpierw termin: "wstrzymaj" klikniete po terminie poprzedniej
        # pauzy ma otworzyc NOWA pauze, a nie przedluzyc zakonczona.
        out = self.expire(now)
        if self.requests is None:
            return out
        for req in self.requests.pending():
            try:
                out.extend(self._apply(req, now))
            except Exception:
                # Zle zadanie nie moze zatkac kolejki na zawsze.
                log.exception("TV pauza: blad przy zadaniu %s", req["id"])
                self.requests.finish(int(req["id"]), False, "błąd serwera")
        return out

    def _apply(self, req, now: datetime) -> list[Notification]:
        assert self.requests is not None
        req_id, login = int(req["id"]), req["login"]
        if req["action"] == "pause":
            until = from_iso(req["until"]) if req["until"] else None
            if until is not None and until <= now:
                # Petla lezala dluzej niz do terminu — nie ma czego wstrzymywac.
                self.requests.finish(req_id, False, "Termin już minął")
                return []
            out = self.pause(now, until, login)
        elif req["action"] == "resume":
            out = self.resume(now, login)
        else:
            self.requests.finish(req_id, False, "Nieznana akcja")
            return []
        self.requests.finish(req_id, True)
        return out

    def pause(self, now: datetime, until: datetime | None, by: str | None) -> list[Notification]:
        tz = self.cfg.tz
        current = self.store.tv_paused_at(now)
        if current is not None:
            pause_id = int(current["id"])
            self.store.set_tv_pause_until(pause_id, until)
            lead = "Zmieniono termin pauzy."
        else:
            self._close_session()
            pause_id = self.store.start_tv_pause(now, until, by)
            lead = (f"{self.name}: bez powiadomień i bez liczenia czasu TV do raportów. "
                    "iPady monitorowane normalnie.")
        log.info("TV pauza: %s wstrzymuje monitoring %s", by or "?", fmt_until(until, tz))
        return [Notification(
            kind=NotifyKind.TV_PAUSE,
            title=f"Monitoring TV wstrzymany {fmt_until(until, tz)}",
            text=f"{lead}\nWłączone przez: {by or 'nieznany'}",
            dedup_key=f"tv-pause:{pause_id}:{now.astimezone(UTC):%Y%m%dT%H%M%S}",
            ts=now,
            device=self.name,
            priority=2,
            tags=("pause_button", "tv"),
        )]

    def resume(self, now: datetime, by: str | None) -> list[Notification]:
        row = self.store.tv_pause_open()
        if row is None:
            return []
        if row["until"] and from_iso(row["until"]) <= now:
            return self.expire(now)
        pause_id = int(row["id"])
        self.store.end_tv_pause(pause_id, now, by)
        log.info("TV pauza: %s wznawia monitoring", by or "?")
        since = fmt_when(from_iso(row["started_at"]), self.cfg.tz)
        return [self._resumed(pause_id, now,
                              f"Pauza od {since} wyłączona ręcznie przez: {by or 'nieznany'}.")]

    def expire(self, now: datetime) -> list[Notification]:
        row = self.store.tv_pause_open()
        if row is None or not row["until"]:
            return []
        until = from_iso(row["until"])
        if until > now:
            return []
        pause_id = int(row["id"])
        self.store.end_tv_pause(pause_id, until, "auto")
        log.info("TV pauza: termin %s minal — monitoring wznowiony", to_iso(until))
        tz = self.cfg.tz
        return [self._resumed(
            pause_id, now,
            f"Pauza od {fmt_when(from_iso(row['started_at']), tz)} skończyła się "
            f"{fmt_when(until, tz)}. Powiadomienia i liczenie czasu TV działają znowu.",
        )]

    def _resumed(self, pause_id: int, now: datetime, text: str) -> Notification:
        return Notification(
            kind=NotifyKind.TV_PAUSE,
            title="Monitoring TV wznowiony",
            text=f"{self.name}: {text}",
            dedup_key=f"tv-resume:{pause_id}",
            ts=now,
            device=self.name,
            priority=2,
            tags=("arrow_forward", "tv"),
        )

    def _close_session(self) -> None:
        """Ogladanie trwajace w chwili wlaczenia pauzy konczy sie po cichu na
        ostatnim odczycie: to, co bylo przed pauza, zostaje w raportach, ale
        push "koniec" w chwili wyjazdu bylby szumem."""
        session = self.store.get_open_session(self.name)
        if session is None:
            return
        last = from_iso(session["last_activity_at"])
        self.store.close_session(int(session["id"]), last)
        self.store.close_tv_segments(self.name, last)
