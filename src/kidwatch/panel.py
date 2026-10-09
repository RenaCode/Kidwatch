"""Panel WWW: historia powiadomien, sesje i stan iPadow.

Celowo bez frameworka — kilka endpointow GET tylko do odczytu i trzy
endpointy logowania nie uzasadniaja FastAPI w obrazie. Serwer chodzi
w osobnym watku procesu `run`, a kazde zapytanie otwiera WLASNE polaczenie
SQLite w trybie tylko do odczytu (`mode=ro`). Petla glowna pozostaje jedynym
pisarzem bazy.

Logowanie jest wlasne: haslo + opcjonalny TOTP (panel_auth.py). Kazde
/api/* poza /api/health, /api/auth/login i /api/auth/mfa wymaga sesji, a bez
niej dostaje 401. Konto z wlaczonym TOTP dostaje sesje dopiero po kodzie.
POST-y zmieniajace stan konta wymagaja tez tokenu CSRF — tak samo
POST /api/game (czas gry) i POST /api/tv/pause|resume (pauza monitoringu TV),
ktore NIE pisza do kidwatch.db, tylko dopisuja zadanie do kolejki
w panel-auth.db (gametime.py, tvpause.py). Konta i sesje leza
w osobnej bazie — panel_auth.py tlumaczy, dlaczego nie w kidwatch.db.
Statyczny front jest dostepny bez sesji: to sam kod ekranu logowania, zadnych
danych.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import mimetypes
import re
import sqlite3
import threading
from datetime import UTC, date, datetime, time, timedelta
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .bramka_admin import (
    BramkaAdmin,
    BramkaError,
    mask,
    normalize_number,
    normalize_recipients,
)
from .config import Config, MissingSecretError, WatchedDevice
from .gametime import ACTIONS, GameRequests, TooManyRequests
from .mdm import MdmApi, MdmError, build_api
from .panel_auth import (
    CSRF_COOKIE,
    CSRF_HEADER,
    SESSION_COOKIE,
    AuthError,
    PanelAuth,
    Session,
    box_from_env,
    csrf_ok,
)
from .store import from_iso, to_iso
from .tvpause import MAX_PAUSE_DAYS, TvPauseRequests, parse_until
from .tvpause import TooManyRequests as TooManyPauseRequests

log = logging.getLogger(__name__)

MAX_LIMIT = 500
#: Zakres wykresu uzycia. Gorny limit z retencji zdarzen nie wynika — sesje
#: trzymamy dluzej niz zdarzenia DNS — ale 90 slupkow to i tak granica
#: czytelnosci na telefonie.
USAGE_DEFAULT_DAYS = 14
USAGE_MAX_DAYS = 90
#: Ile aplikacji na dzien i urzadzenie w /api/usage. Wiecej nie zmiesci sie
#: w dymku nad slupkiem.
USAGE_TOP_APPS = 3
#: Trendy: tyle tygodni na wykresie liniowym.
TREND_WEEKS = 12
#: Eksport CSV: domyslny zakres i gorny limit (10 lat agregatow to ~10 tys.
#: wierszy na urzadzenie — nadal maly plik, ale dalej nie ma sensu).
EXPORT_DEFAULT_DAYS = 30
EXPORT_MAX_DAYS = 3660
#: Cialo POST to login i haslo w JSON-ie. Wiecej nie ma po co czytac.
MAX_BODY = 4096

#: Te same naglowki co w nginx pozostalych aplikacji RenaCode.
SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    # Panel stoi za Traefikiem z TLS. Przegladarka ignoruje HSTS po zwyklym
    # HTTP, wiec port-forward na localhost dalej dziala.
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
        "connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'"
    ),
}


class BadRequest(ValueError):
    pass


# ====================================================================== zapytania
class PanelQueries:
    """Zapytania panelu. Oddzielone od HTTP, zeby testowac je bez serwera."""

    def __init__(
        self,
        cfg: Config,
        db_path: str,
        requests: GameRequests | None = None,
        tv_requests: TvPauseRequests | None = None,
    ) -> None:
        self.cfg = cfg
        self.db_path = db_path
        #: Kolejka zadan czasu gry (panel-auth.db) — None, gdy game_time wylaczone.
        self.requests = requests
        #: Kolejka zadan pauzy TV (panel-auth.db) — None, gdy czujnik TV wylaczony.
        self.tv_requests = tv_requests

    def connect(self) -> sqlite3.Connection:
        if self.db_path == ":memory:":
            raise RuntimeError("panel wymaga bazy na dysku")
        conn = sqlite3.connect(f"file:{self.db_path}?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        # Jedna migawka na cale zadanie. Bez jawnej transakcji kazdy SELECT
        # widzial inny stan bazy: sesja otwarta przez petle glowna MIEDZY
        # zapytaniami /api/usage miala minuty aplikacji, ale nie miala dnia,
        # i konczylo sie KeyError -> 500. W WAL odczyt nie blokuje pisarza.
        conn.execute("BEGIN")
        return conn

    # ------------------------------------------------------------- pomocnicze
    def _day_bounds(self, day: date) -> tuple[str, str]:
        tz = self.cfg.tz
        start = datetime.combine(day, time.min, tzinfo=tz)
        return to_iso(start), to_iso(start + timedelta(days=1))

    def _parse_day(self, raw: str | None) -> date:
        if not raw:
            return datetime.now(self.cfg.tz).date()
        try:
            return date.fromisoformat(raw)
        except ValueError as exc:
            raise BadRequest(f"zla data: {raw!r}, oczekuje YYYY-MM-DD") from exc

    def _local(self, iso: str | None) -> str | None:
        return None if iso is None else from_iso(iso).astimezone(self.cfg.tz).isoformat()

    def _child_of(self, device: str | None) -> str | None:
        for dev in self.cfg.watched:
            if dev.name == device:
                return dev.child
        return None

    def _devices_for(self, params: dict[str, str]):
        """Urzadzenia po filtrze `child`. Bez filtra — wszystkie, takze te
        bez przypisanego dziecka (`child: null`, np. przyszly telewizor):
        one naleza do "Wszyscy", a do zadnego dziecka z osobna.

        Nieznane imie to 400, a nie pusta lista — pusta lista wygladalaby jak
        "dziecko nic dzis nie robilo", a to jest literowka w adresie albo
        dziecko usuniete z konfiguracji po zapamietaniu wyboru w przegladarce.
        """
        child = (params.get("child") or "").strip()
        if not child:
            return list(self.cfg.watched)
        if child not in self.children():
            raise BadRequest(f"nie znam dziecka {child!r}")
        return [d for d in self.cfg.watched if d.child == child]

    def children(self) -> list[str]:
        """Imiona w kolejnosci z konfiguracji, bez powtorzen (dziecko moze
        miec kilka urzadzen)."""
        return list(dict.fromkeys(d.child for d in self.cfg.watched if d.child))

    #: Obecnosc z UniFi starsza niz to jest "nie wiadomo", a nie "w domu" —
    #: kontroler w restarcie nie moze w panelu trzymac dziecka w domu.
    PRESENCE_STALE = timedelta(minutes=10)

    def _presence(self, conn: sqlite3.Connection, name: str) -> dict | None:
        row = conn.execute("SELECT value FROM meta WHERE key=?", (f"presence:{name}",)).fetchone()
        if row is None:
            return None
        data = json.loads(row["value"])
        if datetime.now(UTC) - from_iso(data["checked"]) > self.PRESENCE_STALE:
            return None
        return {"home": bool(data["home"]), "since": self._local(data["since"]),
                "essid": data.get("essid")}

    def _game(self, conn: sqlite3.Connection, child: str | None) -> dict | None:
        """Stan czasu gry dziecka: z meta `game:<profil>` (pisze petla glowna)
        i ostatnie zadanie z kolejki. ID profilu nie wychodzi do przegladarki."""
        if child is None or self.requests is None or not self.cfg.game_time.enabled:
            return None
        profiles = self.cfg.child_profiles()
        profile = profiles.get(child)
        if profile is None:
            return None
        row = conn.execute("SELECT value FROM meta WHERE key=?", (f"game:{profile}",)).fetchone()
        state = json.loads(row["value"]) if row else {}
        return {
            "mode": state.get("mode"),
            "observed": state.get("observed"),
            "bonus_until": self._local(state.get("bonus_until")),
            "source": state.get("source"),
            "confirmed_at": self._local(state.get("confirmed_at")),
            "error": state.get("error"),
            "retrying": bool(state.get("dirty")),
            "shared_with": [c for c, p in profiles.items() if p == profile and c != child],
            "default_bonus_minutes": self.cfg.game_time.default_bonus_minutes,
            "request": self.requests.latest(child),
        }

    def _today(self, conn: sqlite3.Connection, name: str) -> dict:
        """Dzis w skrocie dla karty: minuty, sesje, najczestsza aplikacja
        (z potwierdzonych sesji, jak w widoku Dzien)."""
        lo, hi = self._day_bounds(datetime.now(self.cfg.tz).date())
        rows = conn.execute(
            "SELECT started_at, last_activity_at, ended_at FROM sessions "
            "WHERE device=? AND started_at >= ? AND started_at < ? AND confirmed=1",
            (name, lo, hi),
        ).fetchall()
        top = conn.execute(
            "SELECT sa.app, COUNT(*) AS n FROM session_apps sa "
            "JOIN sessions s ON s.id = sa.session_id "
            "WHERE s.device=? AND s.started_at >= ? AND s.started_at < ? AND s.confirmed=1 "
            "GROUP BY sa.app ORDER BY n DESC, sa.app ASC LIMIT 1",
            (name, lo, hi),
        ).fetchone()
        return {
            "minutes": sum(self._session_minutes(r) for r in rows),
            "sessions": len(rows),
            "top_app": None if top is None else {"app": top["app"], "minutes": top["n"]},
        }

    def _now_playing(self, conn: sqlite3.Connection, name: str) -> dict | None:
        seg = conn.execute(
            "SELECT * FROM tv_watch WHERE device=? AND ended_at IS NULL ORDER BY id DESC LIMIT 1",
            (name,),
        ).fetchone()
        if seg is None:
            return None
        return {"app": seg["app"], "title": seg["title"], "channel": seg["channel"],
                "since": self._local(seg["started_at"])}

    def _tv_titles(self, conn: sqlite3.Connection, name: str, lo: str, hi: str) -> list[dict]:
        """Odcinki z telewizora w dobie — co lecialo i ile, dla widoku Dzien."""
        out = []
        for seg in conn.execute(
            "SELECT * FROM tv_watch WHERE device=? AND started_at >= ? AND started_at < ? "
            "ORDER BY started_at",
            (name, lo, hi),
        ):
            end = seg["ended_at"]
            minutes = (
                round((from_iso(end) - from_iso(seg["started_at"])).total_seconds() / 60)
                if end else None
            )
            out.append({"app": seg["app"], "title": seg["title"], "channel": seg["channel"],
                        "started_at": self._local(seg["started_at"]),
                        "ended_at": self._local(end), "minutes": minutes})
        return out

    @staticmethod
    def _session_minutes(row: sqlite3.Row) -> int:
        """Od pierwszego do ostatniego zapytania; otwarta sesja liczy sie do
        ostatniej aktywnosci, nie do "teraz" — inaczej roslaby sama."""
        end = row["ended_at"] or row["last_activity_at"]
        return max(0, round((from_iso(end) - from_iso(row["started_at"])).total_seconds() / 60))

    # ------------------------------------------------------------- endpointy
    def meta(self) -> dict:
        """Lista dzieci i urzadzen dla przelacznika i stalych kolorow serii.

        Zawsze PELNA, niezaleznie od wybranego dziecka: przelacznik musi
        pokazywac wszystkie opcje, a kolor urzadzenia na wykresie nie moze
        zalezec od tego, ile innych urzadzen akurat widac.
        """
        return {
            "children": self.children(),
            "devices": [
                {"name": d.name, "child": d.child, "kind": d.kind} for d in self.cfg.watched
            ],
        }

    def devices(self, conn: sqlite3.Connection, params: dict[str, str]) -> list[dict]:
        out = []
        for dev in self._devices_for(params):
            name = dev.name
            session = conn.execute(
                "SELECT started_at, last_activity_at FROM sessions "
                "WHERE device=? AND ended_at IS NULL AND confirmed=1 ORDER BY id DESC LIMIT 1",
                (name,),
            ).fetchone()
            last_note = conn.execute(
                "SELECT ts, title FROM notifications WHERE device=? ORDER BY ts DESC LIMIT 1",
                (name,),
            ).fetchone()
            dev_ok = conn.execute(
                "SELECT value FROM meta WHERE key=?", (f"dev-ok:{name}",)
            ).fetchone()
            out.append(
                {
                    "name": name,
                    "child": dev.child,
                    "kind": dev.kind,
                    "reads_device": dev.reads_device,
                    "presence": self._presence(conn, name),
                    "now_playing": self._now_playing(conn, name) if dev.kind == "tv" else None,
                    "session": None
                    if session is None
                    else {
                        "started_at": self._local(session["started_at"]),
                        "last_activity_at": self._local(session["last_activity_at"]),
                    },
                    "last_notification": None
                    if last_note is None
                    else {"ts": self._local(last_note["ts"]), "title": last_note["title"]},
                    "last_device_read": self._local(dev_ok["value"]) if dev_ok else None,
                    "game": self._game(conn, dev.child) if dev.kind == "ipad" else None,
                    "today": self._today(conn, name),
                }
            )
        return out

    def notifications(self, conn: sqlite3.Connection, params: dict[str, str]) -> dict:
        sql = "SELECT * FROM notifications WHERE 1=1"
        args: list = []
        if params.get("child"):
            # Po urzadzeniach dziecka, nie po kolumnie — tabela trzyma nazwe
            # urzadzenia, a przypisanie do dziecka zyje w konfiguracji.
            names = [d.name for d in self._devices_for(params)]
            sql += f" AND device IN ({','.join('?' * len(names))})"
            args += names
        if params.get("day"):
            lo, hi = self._day_bounds(self._parse_day(params["day"]))
            sql += " AND ts >= ? AND ts < ?"
            args += [lo, hi]
        if params.get("device"):
            sql += " AND device = ?"
            args.append(params["device"])
        if params.get("kind"):
            sql += " AND kind = ?"
            args.append(params["kind"])
        if params.get("before"):
            # Kursor "ts|id" ostatniego wiersza. Samo id nie wystarczy: lista
            # jest po czasie zdarzenia, a podsumowanie dnia albo zbiorcze
            # powiadomienie bywa zapisane pozniej niz zdarzenia, ktorych dotyczy.
            ts, _, raw_id = params["before"].rpartition("|")
            try:
                sql += " AND (ts < ? OR (ts = ? AND id < ?))"
                args += [ts, ts, int(raw_id)]
            except ValueError as exc:
                raise BadRequest("zly kursor 'before'") from exc
        try:
            # max(1, ...): SQLite traktuje ujemny LIMIT jak brak limitu.
            limit = max(1, min(int(params.get("limit") or 100), MAX_LIMIT))
        except ValueError as exc:
            raise BadRequest("limit musi byc liczba") from exc
        sql += " ORDER BY ts DESC, id DESC LIMIT ?"
        args.append(limit + 1)
        rows = conn.execute(sql, args).fetchall()
        items = [
            {
                "id": r["id"],
                "cursor": f"{r['ts']}|{r['id']}",
                "ts": self._local(r["ts"]),
                "kind": r["kind"],
                "device": r["device"],
                "child": self._child_of(r["device"]),
                "app": r["app"],
                "title": r["title"],
                "text": r["text"],
                "priority": r["priority"],
                "channels": json.loads(r["channels"]),
                "delivered": bool(r["delivered"]),
                "data": json.loads(r["data"]) if r["data"] else None,
            }
            for r in rows[:limit]
        ]
        return {"items": items, "has_more": len(rows) > limit}

    def day(self, conn: sqlite3.Connection, params: dict[str, str]) -> dict:
        """Podsumowanie doby per urzadzenie: sesje, minuty, top aplikacje, liczba pushy."""
        day = self._parse_day(params.get("day"))
        lo, hi = self._day_bounds(day)
        devices = []
        for dev in self._devices_for(params):
            name = dev.name
            sessions = conn.execute(
                "SELECT id, started_at, last_activity_at, ended_at FROM sessions "
                "WHERE device=? AND started_at >= ? AND started_at < ? AND confirmed=1 "
                "ORDER BY started_at",
                (name, lo, hi),
            ).fetchall()
            out_sessions = []
            total = 0
            for s in sessions:
                minutes = self._session_minutes(s)
                total += minutes
                apps = conn.execute(
                    "SELECT app, COUNT(*) AS n FROM session_apps WHERE session_id=? "
                    "GROUP BY app ORDER BY n DESC",
                    (s["id"],),
                ).fetchall()
                out_sessions.append(
                    {
                        "started_at": self._local(s["started_at"]),
                        "ended_at": self._local(s["ended_at"]),
                        "open": s["ended_at"] is None,
                        "minutes": minutes,
                        "apps": [{"app": a["app"], "minutes": a["n"]} for a in apps],
                    }
                )
            top = conn.execute(
                "SELECT sa.app, COUNT(*) AS n FROM session_apps sa "
                "JOIN sessions s ON s.id = sa.session_id "
                "WHERE s.device=? AND s.started_at >= ? AND s.started_at < ? AND s.confirmed=1 "
                "GROUP BY sa.app ORDER BY n DESC LIMIT 8",
                (name, lo, hi),
            ).fetchall()
            notes = conn.execute(
                "SELECT COUNT(*) AS n FROM notifications WHERE device=? AND ts >= ? AND ts < ?",
                (name, lo, hi),
            ).fetchone()["n"]
            devices.append(
                {
                    "name": name,
                    "child": dev.child,
                    "kind": dev.kind,
                    "sessions": out_sessions,
                    "titles": self._tv_titles(conn, name, lo, hi) if dev.kind == "tv" else [],
                    "session_minutes": total,
                    "top_apps": [{"app": t["app"], "minutes": t["n"]} for t in top],
                    "notifications": notes,
                }
            )
        return {"day": day.isoformat(), "devices": devices}


    def usage(self, conn: sqlite3.Connection, params: dict[str, str]) -> dict:
        """Uzycie dzien po dniu: per urzadzenie minuty sesji, liczba sesji
        i najczestsze aplikacje.

        Sesja nalezy do dnia, w ktorym SIE ZACZELA (lokalna strefa z
        konfiguracji) — tak samo jak w /api/day, zeby suma z wykresu zgadzala
        sie z widokiem dnia. Sesja przez polnoc nie jest dzielona.

        Urzadzenia bez dziecka (`child: null`) sa osobnymi seriami przy
        "Wszyscy" i znikaja przy wybranym dziecku — tak samo jak w kartach.

        `timeline=1` (tylko przy `days=1`, Pulpit) dokleja do kazdej komorki
        os dnia: odcinki sesji i ciagi minut per aplikacja. Liczone z tych
        samych wierszy co suma i `top_apps`, wiec minuty sesji sumuja sie do
        `minutes`, a minuty ciagow aplikacji — do jej minut dnia.
        """
        try:
            days = int(params.get("days") or USAGE_DEFAULT_DAYS)
        except ValueError as exc:
            raise BadRequest("days musi byc liczba") from exc
        if not 1 <= days <= USAGE_MAX_DAYS:
            raise BadRequest(f"days musi byc w zakresie 1..{USAGE_MAX_DAYS}")
        timeline = params.get("timeline") in ("1", "true")
        if timeline and days != 1:
            raise BadRequest("timeline tylko dla days=1")
        until = self._parse_day(params.get("until"))
        first = until - timedelta(days=days - 1)
        lo, _ = self._day_bounds(first)
        _, hi = self._day_bounds(until)
        devices = self._devices_for(params)
        day_keys = [(first + timedelta(days=i)).isoformat() for i in range(days)]
        tz = self.cfg.tz

        # cells[dzien][urzadzenie] = {minutes, sessions, apps{app: min}, spans}
        cells: dict[str, dict[str, dict]] = {
            k: {d.name: {"minutes": 0, "sessions": 0, "apps": {}, "spans": []} for d in devices}
            for k in day_keys
        }
        names = [d.name for d in devices]
        marks = ",".join("?" * len(names))
        session_day: dict[int, tuple[str, str]] = {}
        for s in conn.execute(
            f"SELECT id, device, started_at, last_activity_at, ended_at FROM sessions "
            f"WHERE device IN ({marks}) AND started_at >= ? AND started_at < ? AND confirmed=1",
            (*names, lo, hi),
        ):
            key = from_iso(s["started_at"]).astimezone(tz).date().isoformat()
            cell = cells[key][s["device"]]
            cell["minutes"] += self._session_minutes(s)
            cell["sessions"] += 1
            session_day[s["id"]] = (key, s["device"])
            if timeline:
                cell["spans"].append({
                    "started_at": self._local(s["started_at"]),
                    "ended_at": self._local(s["ended_at"] or s["last_activity_at"]),
                    "minutes": self._session_minutes(s),
                })

        # Jedno zapytanie na caly zakres zamiast jednego na sesje — przy 90
        # dniach i kilku urzadzeniach to setki zapytan na kazde odswiezenie.
        for a in conn.execute(
            f"SELECT sa.session_id, sa.app, COUNT(*) AS n FROM session_apps sa "
            f"JOIN sessions s ON s.id = sa.session_id "
            f"WHERE s.device IN ({marks}) AND s.started_at >= ? AND s.started_at < ? "
            f"AND s.confirmed=1 GROUP BY sa.session_id, sa.app",
            (*names, lo, hi),
        ):
            key, device = session_day[a["session_id"]]
            apps = cells[key][device]["apps"]
            apps[a["app"]] = apps.get(a["app"], 0) + a["n"]

        runs = self._app_runs(conn, names, marks, lo, hi, session_day) if timeline else {}
        rows = []
        for key in day_keys:
            per_device = []
            for name in names:
                cell = cells[key][name]
                top = sorted(cell["apps"].items(), key=lambda kv: (-kv[1], kv[0]))
                entry = {
                    "name": name,
                    "minutes": cell["minutes"],
                    "sessions": cell["sessions"],
                    "top_apps": [{"app": app, "minutes": n} for app, n in top[:USAGE_TOP_APPS]],
                }
                if timeline:
                    entry["timeline"] = {
                        "sessions": sorted(cell["spans"], key=lambda x: x["started_at"]),
                        "runs": runs.get(name, []),
                    }
                per_device.append(entry)
            rows.append({
                "day": key,
                "total_minutes": sum(d["minutes"] for d in per_device),
                "devices": per_device,
            })
        return {
            "from": first.isoformat(),
            "until": until.isoformat(),
            "devices": [{"name": d.name, "child": d.child, "kind": d.kind} for d in devices],
            "days": rows,
        }

    def _app_runs(self, conn, names, marks, lo, hi, session_day) -> dict[str, list[dict]]:
        """Ciagi kolejnych minut tej samej aplikacji w sesji, per urzadzenie.

        Minuta w `session_apps` to minuta z ruchem DNS (albo odtwarzania na
        TV) — ta sama, ktora liczy `COUNT(*)` w minutach aplikacji. Ciag
        konczy sie minute po ostatniej minucie, wiec jego dlugosc to dokladnie
        liczba jego minut. Kilka aplikacji w jednej minucie daje nachodzace
        na siebie ciagi — kazda dostaje swoja minute, jak w sumie."""
        out: dict[str, list[dict]] = {}
        cur: dict | None = None
        last: datetime | None = None
        for a in conn.execute(
            f"SELECT sa.session_id, sa.app, sa.minute FROM session_apps sa "
            f"JOIN sessions s ON s.id = sa.session_id "
            f"WHERE s.device IN ({marks}) AND s.started_at >= ? AND s.started_at < ? "
            f"AND s.confirmed=1 ORDER BY sa.session_id, sa.app, sa.minute",
            (*names, lo, hi),
        ):
            at = datetime.strptime(a["minute"], "%Y-%m-%dT%H:%M").replace(tzinfo=UTC)
            device = session_day[a["session_id"]][1]
            key = (a["session_id"], a["app"])
            if cur is not None and cur["key"] == key and at - last == timedelta(minutes=1):
                cur["minutes"] += 1
            else:
                cur = {"key": key, "app": a["app"], "start": at, "minutes": 1}
                out.setdefault(device, []).append(cur)
            last = at
        tz = self.cfg.tz
        return {
            device: sorted(
                (
                    {
                        "app": r["app"],
                        "started_at": r["start"].astimezone(tz).isoformat(),
                        "ended_at": (r["start"] + timedelta(minutes=r["minutes"]))
                        .astimezone(tz).isoformat(),
                        "minutes": r["minutes"],
                    }
                    for r in lst
                ),
                key=lambda r: (r["started_at"], r["app"]),
            )
            for device, lst in out.items()
        }

    # ------------------------------------------------------ pauza telewizora
    def tv_pause(self, conn: sqlite3.Connection) -> dict:
        """Stan pauzy monitoringu TV dla banera i karty telewizora. Zawsze
        caly, niezaleznie od wybranego dziecka — baner ma byc widoczny wszedzie."""
        if not self.cfg.tv.enabled:
            return {"available": False}
        now = to_iso(datetime.now(UTC))
        row = conn.execute(
            "SELECT * FROM tv_pause WHERE ended_at IS NULL AND started_at <= ? "
            "AND (until IS NULL OR until > ?) ORDER BY id DESC LIMIT 1",
            (now, now),
        ).fetchone()
        return {
            "available": True,
            "name": self.cfg.tv.name,
            "max_days": MAX_PAUSE_DAYS,
            "active": None if row is None else {
                "since": self._local(row["started_at"]),
                "until": self._local(row["until"]),
                "by": row["started_by"],
            },
            "request": self.tv_requests.latest() if self.tv_requests else None,
        }

    def _tv_pauses(self, conn: sqlite3.Connection, lo: str, hi: str) -> list[dict]:
        """Pauzy zachodzace na dobe — os dnia pokazuje je zamiast pustego pasa."""
        return [
            {"since": self._local(r["started_at"]), "until": self._local(r["till"])}
            for r in conn.execute(
                "SELECT started_at, COALESCE(ended_at, until) AS till FROM tv_pause "
                "WHERE started_at < ? AND (COALESCE(ended_at, until) IS NULL "
                "OR COALESCE(ended_at, until) > ?) ORDER BY started_at",
                (hi, lo),
            )
        ]

    # ------------------------------------------------------ wszystkie ekrany
    def _lanes_devices(self, params: dict[str, str]) -> list[tuple[WatchedDevice, bool]]:
        """(urzadzenie, wspolne). Przy wybranym dziecku telewizor wraca jako
        osobny, WSPOLNY pas — widoczny, ale nie doliczany do dziecka."""
        devs = self._devices_for(params)
        out = [(d, d.child is None) for d in devs]
        if params.get("child"):
            out += [(d, True) for d in self.cfg.watched if d.child is None]
        return out

    def _tv_exact(self, conn, name: str, first: date, last: date) -> list[tuple[str, int]]:
        rows = conn.execute(
            "SELECT app, SUM(ms) AS ms FROM tv_usage WHERE device=? AND day >= ? AND day <= ? "
            "GROUP BY app HAVING SUM(ms) > 0 ORDER BY ms DESC, app ASC",
            (name, first.isoformat(), last.isoformat()),
        ).fetchall()
        return [(r["app"], round(r["ms"] / 60000)) for r in rows]

    def screens(self, conn: sqlite3.Connection, params: dict[str, str]) -> dict:
        """Jedna os dnia dla iPadow (minuty z DNS) i telewizora (minuty sesji
        + tytuly), z sumami dnia i tygodnia ISO. "own" to urzadzenia dziecka
        (albo wszystkie iPady przy "Wszyscy"), "shared" — telewizor."""
        day = self._parse_day(params.get("day"))
        lo, hi = self._day_bounds(day)
        monday = day - timedelta(days=day.weekday())
        wlo, _ = self._day_bounds(monday)
        _, whi = self._day_bounds(monday + timedelta(days=6))
        lanes = []
        totals = {"day": {"own": 0, "shared": 0}, "week": {"own": 0, "shared": 0}}
        tv = None
        for dev, shared in self._lanes_devices(params):
            rows = conn.execute(
                "SELECT id, started_at, last_activity_at, ended_at FROM sessions "
                "WHERE device=? AND started_at >= ? AND started_at < ? AND confirmed=1 "
                "ORDER BY started_at",
                (dev.name, lo, hi),
            ).fetchall()
            week_minutes = sum(
                self._session_minutes(r) for r in conn.execute(
                    "SELECT started_at, last_activity_at, ended_at FROM sessions "
                    "WHERE device=? AND started_at >= ? AND started_at < ? AND confirmed=1",
                    (dev.name, wlo, whi),
                )
            )
            sessions = []
            for r in rows:
                apps = conn.execute(
                    "SELECT app, COUNT(*) AS n FROM session_apps WHERE session_id=? "
                    "GROUP BY app ORDER BY n DESC, app ASC", (r["id"],),
                ).fetchall()
                titles = []
                if dev.kind == "tv":
                    titles = [
                        {"title": t["title"], "app": t["app"], "channel": t["channel"],
                         "started_at": self._local(t["started_at"])}
                        for t in conn.execute(
                            "SELECT * FROM tv_watch WHERE session_id=? ORDER BY started_at",
                            (r["id"],),
                        )
                    ]
                sessions.append({
                    "started_at": self._local(r["started_at"]),
                    "ended_at": self._local(r["ended_at"]),
                    "open": r["ended_at"] is None,
                    "minutes": self._session_minutes(r),
                    "apps": [{"app": a["app"], "minutes": a["n"]} for a in apps],
                    "titles": titles,
                })
            day_minutes = sum(x["minutes"] for x in sessions)
            bucket = "shared" if shared else "own"
            totals["day"][bucket] += day_minutes
            totals["week"][bucket] += week_minutes
            lanes.append({
                "name": dev.name, "child": dev.child, "kind": dev.kind, "shared": shared,
                "day_minutes": day_minutes, "week_minutes": week_minutes, "sessions": sessions,
                "pauses": self._tv_pauses(conn, lo, hi) if dev.kind == "tv" else [],
            })
            if dev.kind == "tv" and tv is None:
                estimate: dict[str, int] = {}
                for x in sessions:
                    for a in x["apps"]:
                        estimate[a["app"]] = estimate.get(a["app"], 0) + a["minutes"]
                exact_day = self._tv_exact(conn, dev.name, day, day)
                exact_week = self._tv_exact(conn, dev.name, monday, monday + timedelta(days=6))
                known = {app for app, _ in exact_day}
                tv = {
                    "name": dev.name,
                    "exact_day": [
                        {"app": app, "minutes": m, "estimate_minutes": estimate.get(app)}
                        for app, m in exact_day
                    ] + [
                        # Aplikacja z sesji, ktorej usagestats jeszcze nie
                        # policzyl (wciaz na pierwszym planie).
                        {"app": app, "minutes": None, "estimate_minutes": m}
                        for app, m in sorted(estimate.items(), key=lambda kv: -kv[1])
                        if app not in known
                    ],
                    "exact_day_total": sum(m for _, m in exact_day),
                    "exact_week": [{"app": a, "minutes": m} for a, m in exact_week],
                    "exact_week_total": sum(m for _, m in exact_week),
                }
        return {
            "day": day.isoformat(),
            "week_from": monday.isoformat(),
            "week_to": (monday + timedelta(days=6)).isoformat(),
            "child": params.get("child") or None,
            "lanes": lanes,
            "totals": totals,
            "tv": tv,
        }

    # ------------------------------------------------------------- trendy
    def _rollups(self, conn, first: date, last: date) -> list[sqlite3.Row]:
        return list(conn.execute(
            "SELECT * FROM daily_rollup WHERE day >= ? AND day <= ? ORDER BY day, device",
            (first.isoformat(), last.isoformat()),
        ))

    def _series(self, params: dict[str, str]) -> list[dict]:
        """Serie trendu: dzieci (suma ich iPadow) i telewizor jako wspolny."""
        child = (params.get("child") or "").strip()
        if child and child not in self.children():
            raise BadRequest(f"nie znam dziecka {child!r}")
        kids = [child] if child else self.children()
        out = [{"key": c, "label": c, "shared": False,
                "devices": [d.name for d in self.cfg.watched if d.child == c]} for c in kids]
        out += [{"key": d.name, "label": f"{d.name} (wspólny)", "shared": True,
                 "devices": [d.name]} for d in self.cfg.watched if d.child is None]
        return out

    @staticmethod
    def _summarize(rows: list, devices: list[str], days: int) -> dict:
        mine = [r for r in rows if r["device"] in devices]
        minutes = sum(r["minutes"] for r in mine)
        apps: dict[str, int] = {}
        for r in mine:
            for app, n in json.loads(r["top_apps"]):
                apps[app] = apps.get(app, 0) + n
        exact = [r["tv_minutes"] for r in mine if r["tv_minutes"] is not None]
        active = {r["day"] for r in mine if r["minutes"] > 0}
        return {
            "minutes": minutes,
            "avg_daily": round(minutes / days) if days else 0,
            "days": days,
            "active_days": len(active),
            "sessions": sum(r["sessions"] for r in mine),
            "night_minutes": sum(r["night_minutes"] for r in mine),
            "tv_exact_minutes": sum(exact) if exact else None,
            "top_apps": [
                {"app": a, "minutes": n}
                for a, n in sorted(apps.items(), key=lambda kv: (-kv[1], kv[0]))[:5]
            ],
        }

    def trends(self, conn: sqlite3.Connection, params: dict[str, str]) -> dict:
        """Tydzien do tygodnia i miesiac do miesiaca z agregatow dziennych
        (daily_rollup, przezywaja retencje surowych danych) + 12 tygodni.

        Biezacy tydzien i miesiac sa NIEPELNE — dlatego obok sumy jest
        srednia dzienna liczona po dniach, ktore juz minely (z dzisiejszym).
        Dzisiejszy agregat jest odswiezany co 15 min.
        """
        today = self._parse_day(params.get("until"))
        series = self._series(params)
        monday = today - timedelta(days=today.weekday())
        month_first = today.replace(day=1)
        prev_month_last = month_first - timedelta(days=1)
        prev_month_first = prev_month_last.replace(day=1)
        first = min(monday - timedelta(weeks=TREND_WEEKS - 1), prev_month_first)
        rows = self._rollups(conn, first, today)

        def window(a: date, b: date) -> list:
            return [r for r in rows if a.isoformat() <= r["day"] <= b.isoformat()]

        periods = {
            "week": ((monday, today), (monday - timedelta(days=7), monday - timedelta(days=1))),
            "month": ((month_first, today), (prev_month_first, prev_month_last)),
        }
        compare = {}
        for key, ((ca, cb), (pa, pb)) in periods.items():
            cur, prev = window(ca, cb), window(pa, pb)
            compare[key] = {
                "current": {"from": ca.isoformat(), "to": cb.isoformat()},
                "previous": {"from": pa.isoformat(), "to": pb.isoformat()},
                "series": [
                    {"key": s["key"], "label": s["label"], "shared": s["shared"],
                     "current": self._summarize(cur, s["devices"], (cb - ca).days + 1),
                     "previous": self._summarize(prev, s["devices"], (pb - pa).days + 1)}
                    for s in series
                ],
            }

        weeks = []
        for i in range(TREND_WEEKS - 1, -1, -1):
            wa = monday - timedelta(weeks=i)
            wb = min(wa + timedelta(days=6), today)
            part = window(wa, wb)
            iso = wa.isocalendar()
            weeks.append({
                "week": f"{iso[0]}-W{iso[1]:02d}",
                "from": wa.isoformat(),
                "values": {
                    s["key"]: sum(r["minutes"] for r in part if r["device"] in s["devices"])
                    for s in series
                },
                "partial": wb < wa + timedelta(days=6),
            })
        has_data = bool(rows)
        return {
            "until": today.isoformat(),
            "series": [{k: s[k] for k in ("key", "label", "shared")} for s in series],
            "compare": compare,
            "weeks": weeks,
            "has_data": has_data,
        }

    # -------------------------------------------------------------- eksport
    CSV_COLUMNS = ("dzien", "urzadzenie", "dziecko", "rodzaj", "minuty", "sesje",
                   "minuty_nocne", "minuty_tv_dokladne", "top_aplikacje", "tv_aplikacje")

    def export_range(self, params: dict[str, str]) -> tuple[date, date]:
        last = self._parse_day(params.get("to"))
        first = (
            self._parse_day(params["from"]) if params.get("from")
            else last - timedelta(days=EXPORT_DEFAULT_DAYS - 1)
        )
        if first > last:
            raise BadRequest("'from' po 'to'")
        if (last - first).days >= EXPORT_MAX_DAYS:
            raise BadRequest(f"zakres dluzszy niz {EXPORT_MAX_DAYS} dni")
        return first, last

    @staticmethod
    def _cell(value) -> str:
        """Komorka CSV bez wstrzykiwania formul: nazwa aplikacji zaczynajaca
        sie od =, +, - albo @ bylaby w Excelu wykonana jako formula."""
        text = "" if value is None else str(value)
        # lstrip: arkusz pomija wiodace spacje, wiec " =1+1" tez jest formula.
        head = text.lstrip(" ")[:1]
        return "'" + text if head in ("=", "+", "-", "@", "\t", "\r") else text

    @staticmethod
    def _apps(raw: str | None) -> str:
        return "; ".join(f"{app} {n}" for app, n in json.loads(raw or "[]"))

    def export_csv(self, conn: sqlite3.Connection, params: dict[str, str]) -> str:
        """Agregaty dzienne do CSV. Przy wybranym dziecku tylko jego urzadzenia —
        wspolny telewizor nie jest dzieckiem i do niego nie trafia."""
        first, last = self.export_range(params)
        names = {d.name for d in self._devices_for(params)}
        buf = io.StringIO()
        # BOM: Excel bez niego czyta UTF-8 jako Windows-1250 i psuje polskie litery.
        buf.write("\ufeff")
        out = csv.writer(buf, lineterminator="\r\n")
        out.writerow(self.CSV_COLUMNS)
        for r in self._rollups(conn, first, last):
            if r["device"] not in names:
                continue
            out.writerow([self._cell(v) for v in (
                r["day"], r["device"], r["child"], r["kind"], r["minutes"], r["sessions"],
                r["night_minutes"], r["tv_minutes"], self._apps(r["top_apps"]),
                self._apps(r["tv_apps"]),
            )])
        return buf.getvalue()


# ========================================================================= HTTP
def _bramka_status(status: int) -> int:
    """Kod HTTP dla przegladarki z bledu bramki. 401/403 bramki to odrzucony
    klucz (BRAMKA_KLUCZ_ADMIN), czyli awaria po stronie serwera — przekazane dalej jako 401
    wygladaly dla frontu jak wygasla sesja panelu (api.js) i wylogowywaly
    rodzica zamiast pokazac blad."""
    return 502 if status >= 500 or status in (401, 403) else status


def _mdm_status(status: int) -> int:
    """Kody serwera MDM przekazane dalej, poza 401/403: te dotycza tokenu
    panelu u serwera MDM, a nie sesji przegladarki — front wylogowalby rodzica."""
    return 502 if status in (401, 403) else status


def _cookie(name: str, value: str, max_age: int, *, http_only: bool, secure: bool) -> str:
    parts = [f"{name}={value}", "Path=/", f"Max-Age={max_age}", "SameSite=Strict"]
    if http_only:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def make_handler(
    queries: PanelQueries,
    static_dir: Path,
    auth: PanelAuth,
    *,
    cookie_secure: bool = True,
    bramka: BramkaAdmin | None = None,
    mdm: MdmApi | None = None,
):
    static_root = static_dir.resolve()

    def session_cookies(token: str, session: Session, max_age: int) -> list[str]:
        return [
            # Sesja HttpOnly: JS jej nie widzi, wiec nie wycieknie przez XSS.
            _cookie(SESSION_COOKIE, token, max_age, http_only=True, secure=cookie_secure),
            # CSRF celowo BEZ HttpOnly — front czyta go i odsyla w naglowku.
            # Sam w sobie nic nie otwiera.
            _cookie(CSRF_COOKIE, session.csrf, max_age, http_only=False, secure=cookie_secure),
        ]

    def cleared_cookies() -> list[str]:
        return [
            _cookie(SESSION_COOKIE, "", 0, http_only=True, secure=cookie_secure),
            _cookie(CSRF_COOKIE, "", 0, http_only=False, secure=cookie_secure),
        ]

    class Handler(BaseHTTPRequestHandler):
        server_version = "kidwatch"
        sys_version = ""
        #: Timeout gniazda: bez niego wolny klient (slowloris) trzymal watek
        #: do timeoutu Traefika.
        timeout = 30

        def log_message(self, fmt: str, *args) -> None:  # noqa: D102
            log.debug("panel: " + fmt, *args)

        def _send(
            self,
            status: int,
            body: bytes,
            ctype: str,
            extra: dict | None = None,
            cookies: list[str] | None = None,
        ):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in {**SECURITY_HEADERS, **(extra or {})}.items():
                self.send_header(k, v)
            # Set-Cookie osobnym naglowkiem na kazde ciasteczko — w slowniku
            # `extra` drugie nadpisaloby pierwsze.
            for c in cookies or ():
                self.send_header("Set-Cookie", c)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status: int, payload, cookies: list[str] | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self._send(status, body, "application/json; charset=utf-8",
                       {"Cache-Control": "no-store"}, cookies)

        # --------------------------------------------------------- sesja
        def _cookies(self) -> dict[str, str]:
            try:
                jar = SimpleCookie(self.headers.get("Cookie", ""))
            except CookieError:
                return {}
            return {k: m.value for k, m in jar.items()}

        def _session(self) -> Session | None:
            return auth.session(self._cookies().get(SESSION_COOKIE))

        def _client_ip(self) -> str:
            # Za Traefikiem prawdziwy adres jest w X-Forwarded-For. Od niego
            # zalezy limit nieudanych logowan, wiec bierzemy OSTATNI wpis —
            # dopisany przez Traefika (zaufany hop). Pierwszy podaje klient
            # i podmieniajac go, zgadywalby hasla bez limitu.
            fwd = self.headers.get("X-Forwarded-For")
            last = fwd.split(",")[-1].strip() if fwd else ""
            return last or self.client_address[0]

        def _unauthorized(self) -> None:
            self._json(401, {"error": "Wymagane zalogowanie"}, cleared_cookies())

        def _read_json(self) -> dict:
            # Tylko application/json. Formularz albo text/plain z obcej strony
            # przechodzi bez preflightu CORS; JSON wymusza preflight, ktorego
            # ten serwer nie obsluguje, wiec przegladarka zadania nie wysle.
            ctype = self.headers.get("Content-Type", "").split(";")[0].strip().lower()
            if ctype != "application/json":
                raise AuthError(415, "Oczekuję application/json")
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError as exc:
                raise AuthError(400, "Zły Content-Length") from exc
            # Ujemna dlugosc to rfile.read(-1), czyli czytanie do zamkniecia
            # polaczenia — klient trzymalby watek panelu, ile chce.
            if length < 0:
                raise AuthError(400, "Zły Content-Length")
            if length > MAX_BODY:
                raise AuthError(413, "Za duże zapytanie")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AuthError(400, "Niepoprawny JSON") from exc
            if not isinstance(data, dict):
                raise AuthError(400, "Niepoprawny JSON")
            return data

        def do_POST(self) -> None:  # noqa: N802
            path = urlparse(self.path).path
            try:
                if path == "/api/auth/login":
                    self._login()
                elif path == "/api/auth/mfa":
                    self._mfa()
                elif path == "/api/auth/totp/setup":
                    self._json(200, auth.totp_setup(self._authed()))
                elif path == "/api/auth/totp/confirm":
                    self._totp_confirm()
                elif path == "/api/auth/totp/disable":
                    self._totp_disable()
                elif path == "/api/auth/logout":
                    self._logout()
                elif path == "/api/game":
                    self._game_request()
                elif path == "/api/tv/pause":
                    self._tv_pause_request("pause")
                elif path == "/api/tv/resume":
                    self._tv_pause_request("resume")
                elif path in ("/api/tv/aplikacja/instaluj", "/api/tv/aplikacja/paruj"):
                    self._tv_aplikacja(path)
                elif path == "/api/auth/password":
                    self._change_password()
                elif path.startswith("/api/profile/"):
                    self._profile_post(path)
                elif path.startswith("/api/mdm/"):
                    self._mdm_post(path)
                else:
                    self._json(404, {"error": "nie ma takiego endpointu"})
            except AuthError as exc:
                self._json(exc.status, {"error": exc.message})
            except Exception:
                log.exception("panel: blad przy POST %s", path)
                self._json(500, {"error": "blad serwera"})

        def _authed(self) -> Session:
            """Sesja + CSRF dla POST-ow zmieniajacych stan konta."""
            session = self._session()
            if session is None:
                raise AuthError(401, "Wymagane zalogowanie")
            if not csrf_ok(session, self.headers.get(CSRF_HEADER)):
                raise AuthError(403, "Nieprawidłowy token CSRF")
            return session

        @staticmethod
        def _str(data: dict, key: str, limit: int) -> str:
            value = data.get(key, "")
            if not isinstance(value, str) or len(value) > limit:
                raise AuthError(400, f"Niepoprawne pole {key!r}")
            return value

        def _login(self) -> None:
            data = self._read_json()
            login, password = data.get("login"), data.get("password")
            if not isinstance(login, str) or not isinstance(password, str):
                raise AuthError(400, "Podaj login i hasło")
            if not login.strip() or not password or len(login) > 128 or len(password) > 512:
                raise AuthError(400, "Podaj login i hasło")
            result = auth.login(
                login, password, ip=self._client_ip(), user_agent=self.headers.get("User-Agent")
            )
            if result.mfa_required:
                # Konto z 2FA: bilet, NIE sesja — ciasteczek tu nie ma.
                # CSRF przy /mfa nie dotyczy: uprawnieniem jest bilet w CIELE
                # zadania, a nie ciasteczko doklejane przez przegladarke.
                self._json(200, {"mfa_required": True, "challenge": result.challenge})
                return
            self._start_session(result.token, result.session, {"mfa_required": False})

        def _start_session(self, token: str, session: Session, payload: dict) -> None:
            max_age = int(auth.session_seconds)
            self._json(200, {"login": session.login, **payload},
                       session_cookies(token, session, max_age))

        def _mfa(self) -> None:
            data = self._read_json()
            token, session = auth.mfa(
                self._str(data, "challenge", 256), self._str(data, "code", 32),
                ip=self._client_ip(), user_agent=self.headers.get("User-Agent"),
            )
            self._start_session(token, session, {})

        def _totp_confirm(self) -> None:
            session = self._authed()
            codes = auth.totp_confirm(session, self._str(self._read_json(), "code", 32))
            self._json(200, {"ok": True, "backup_codes": codes})

        def _totp_disable(self) -> None:
            session = self._authed()
            data = self._read_json()
            auth.totp_disable(
                session, self._str(data, "password", 512), self._str(data, "code", 32)
            )
            self._json(200, {"ok": True})

        def _game_request(self) -> None:
            """Zadanie czasu gry. NIE wykonuje go — dopisuje do kolejki,
            ktora odbiera petla glowna (jedyny pisarz kidwatch.db)."""
            session = self._authed()
            if queries.requests is None:
                raise AuthError(404, "Czas gry jest wyłączony w konfiguracji")
            data = self._read_json()
            child, action = data.get("child"), data.get("action")
            if not isinstance(child, str) or child not in queries.children():
                raise AuthError(400, "Nieznane dziecko")
            if action not in ACTIONS:
                raise AuthError(400, "Nieznana akcja")
            minutes = None
            if action == "bonus":
                minutes = data.get("minutes", queries.cfg.game_time.default_bonus_minutes)
                if (
                    not isinstance(minutes, int)
                    or isinstance(minutes, bool)
                    or not 1 <= minutes <= queries.cfg.game_time.max_bonus_minutes
                ):
                    raise AuthError(400, "Niepoprawna liczba minut")
            try:
                req_id = queries.requests.submit(child, action, minutes, session.login)
            except TooManyRequests as exc:
                raise AuthError(429, "Za dużo oczekujących zmian — poczekaj chwilę") from exc
            log.info("panel: %s zleca czas gry %s dla %s", session.login, action, child)
            self._json(202, {"ok": True, "id": req_id})

        def _tv_pause_request(self, action: str) -> None:
            """Pauza monitoringu TV. Jak czas gry: tylko zadanie w kolejce,
            wykonuje je tik petli glownej (tvpause.py) — po kilkunastu s."""
            session = self._authed()
            if queries.tv_requests is None:
                raise AuthError(404, "Czujnik TV jest wyłączony w konfiguracji")
            data = self._read_json()
            until = None
            if action == "pause":
                # Termin podany jawnie: null = do odwolania. Brak pola to
                # raczej blad frontu niz swiadome "na zawsze".
                if "until" not in data:
                    raise AuthError(400, "Podaj termin albo null (do odwołania)")
                raw = data["until"]
                if raw is not None:
                    if not isinstance(raw, str) or len(raw) > 64:
                        raise AuthError(400, "Niepoprawny termin")
                    try:
                        until = parse_until(raw, queries.cfg.tz, datetime.now(UTC))
                    except ValueError as exc:
                        raise AuthError(400, f"Niepoprawny termin: {exc}") from exc
            try:
                req_id = queries.tv_requests.submit(action, until, session.login)
            except TooManyPauseRequests as exc:
                raise AuthError(429, "Za dużo oczekujących zmian — poczekaj chwilę") from exc
            log.info("panel: %s zleca %s monitoringu TV%s", session.login,
                     "wstrzymanie" if action == "pause" else "wznowienie",
                     f" do {to_iso(until)}" if until else "")
            self._json(202, {"ok": True, "id": req_id})

        def _tv_aplikacja(self, path: str) -> None:
            """Aplikacja Kidwatch TV (sources/tv_app.py): instalacja przez ADB
            i parowanie kodem z jej ekranu. Wykonuje petla serwisu."""
            from .sources import tv_app  # noqa: PLC0415

            session = self._authed()
            app = tv_app.AKTYWNA
            if app is None:
                raise AuthError(404, "Aplikacja TV jest wyłączona w konfiguracji")
            data = self._read_json()
            komunikat = None
            try:
                if path.endswith("/instaluj"):
                    log.info("panel: %s instaluje aplikacje Kidwatch TV", session.login)
                    komunikat = app.instaluj()
                else:
                    app.paruj(self._str(data, "kod", 16))
                    log.info("panel: %s sparowal aplikacje Kidwatch TV", session.login)
            except tv_app.AppError as exc:
                raise AuthError(409, str(exc)) from exc
            self._json(200, {**stan_aplikacji(), "message": komunikat})

        def _change_password(self) -> None:
            session = self._authed()
            data = self._read_json()
            closed = auth.change_password(
                session, self._str(data, "old", 512), self._str(data, "new", 512)
            )
            self._json(200, {"ok": True, "closed_sessions": closed})

        # ------------------------------------------------- profil: powiadomienia
        def _bramka(self) -> BramkaAdmin:
            if bramka is None:
                raise AuthError(404, "Bramka powiadomień nie jest skonfigurowana")
            return bramka

        def _profile_post(self, path: str) -> None:
            """Akcje WhatsAppa. Sesja + CSRF jak kazda zmiana stanu; bramke
            wola serwer swoim kluczem — przegladarka go nie zna."""
            session = self._authed()
            data = self._read_json()
            b = self._bramka()
            try:
                if path in ("/api/profile/whatsapp/start", "/api/profile/whatsapp/logout"):
                    # Zmiana NADAWCY jest tak samo grozna jak zmiana odbiorcow:
                    # przejeta sesja moglaby wylogowac bota i zeskanowac QR
                    # wlasnym telefonem - wtedy powiadomienia wszystkich
                    # aplikacji RenaCode szlyby z jej konta. Haslo albo 2FA.
                    auth.reauth(session, self._str(data, "confirm", 512))
                    if path.endswith("/start"):
                        result = b.start()
                    else:
                        result = b.logout()
                        log.warning("panel: %s rozlaczyl numer bota WhatsApp", session.login)
                elif path == "/api/profile/whatsapp/recipient":
                    number = normalize_number(self._str(data, "number", 64))
                    if number is None:
                        raise AuthError(400, "Podaj numer z kierunkowym, np. 48600100200")
                    # Numer jest wspolny dla wszystkich aplikacji RenaCode —
                    # przejeta sesja nie moze po cichu przekierowac powiadomien.
                    auth.reauth(session, self._str(data, "confirm", 512))
                    result = b.set_recipient(number)
                    log.warning("panel: %s zmienil numer odbiorcy na %s",
                                session.login, mask(number))
                elif path == "/api/profile/whatsapp/recipients":
                    try:
                        recipients = normalize_recipients(data.get("recipients"))
                    except ValueError as exc:
                        raise AuthError(400, str(exc)) from exc
                    # Cala lista jak pojedynczy numer wyzej: haslo albo kod 2FA.
                    auth.reauth(session, self._str(data, "confirm", 512))
                    result = b.set_recipients(recipients)
                    log.warning(
                        "panel: %s zapisal odbiorcow WhatsApp (%d, aktywni %d): %s",
                        session.login, len(recipients),
                        sum(r["aktywny"] for r in recipients),
                        ", ".join(mask(r["numer"])
                                  + (f" [{','.join(r['zrodla'])}]" if "zrodla" in r else "")
                                  + ("" if r["aktywny"] else " (wyl.)")
                                  for r in recipients) or "-",
                    )
                elif path == "/api/profile/test":
                    channel = data.get("channel", "auto")
                    if channel not in ("auto", "whatsapp", "email"):
                        raise AuthError(400, "Nieznany kanał")
                    result = b.test(channel)
                else:
                    self._json(404, {"error": "nie ma takiego endpointu"})
                    return
            except BramkaError as exc:
                self._json(_bramka_status(exc.status), {"error": exc.message})
                return
            log.info("panel: %s -> %s", session.login, path)
            self._json(200, result)

        def _profile_get(self, path: str, session: Session) -> None:
            if path == "/api/profile/notify":
                if bramka is None:
                    self._json(200, {"available": False})
                    return
                try:
                    self._json(200, {"available": True, **bramka.status()})
                except BramkaError as exc:
                    self._json(200, {"available": True, "error": exc.message})
            elif path == "/api/profile/whatsapp/qr":
                # QR podpina NADAWCE powiadomien, wiec jak /start i /logout
                # wymaga potwierdzenia tozsamosci - tu swiezego (K-1).
                auth.require_fresh_reauth(session)
                try:
                    self._json(200, self._bramka().qr())
                except BramkaError as exc:
                    self._json(_bramka_status(exc.status), {"error": exc.message})
            else:
                self._json(404, {"error": "nie ma takiego endpointu"})

        # ---------------------------------------------------------------- MDM
        # Panel jest posrednikiem: token API serwera MDM zostaje w backendzie,
        # a przegladarka widzi tylko zalogowana sesje panelu (+ CSRF przy akcjach).
        def _mdm_api(self) -> MdmApi:
            if mdm is None:
                raise MdmError(404, "integracja MDM wylaczona (mdm.enabled albo MDM_ADMIN_TOKEN)")
            return mdm

        def _mdm_get(self, path: str) -> None:
            try:
                api = self._mdm_api()
                if path == "/api/mdm":
                    self._json(200, {
                        "available": True,
                        "health": api.health(),
                        "devices": api.devices(),
                        "os_update": api.request("GET", "/api/os-update"),
                        "events": api.request("GET", "/api/events?last=50"),
                    })
                elif m := re.fullmatch(r"/api/mdm/devices/([0-9A-Fa-f-]{8,64})", path):
                    self._json(200, api.request("GET", f"/api/devices/{m[1]}"))
                else:
                    self._json(404, {"error": "nie ma takiego endpointu"})
            except MdmError as exc:
                if mdm is None:
                    self._json(200, {"available": False, "error": str(exc)})
                else:
                    self._json(_mdm_status(exc.status), {"error": str(exc)})

        def _mdm_post(self, path: str) -> None:
            session = self._authed()
            data = self._read_json()
            udid = data.get("udid")
            if udid is not None and (
                not isinstance(udid, str) or not re.fullmatch(r"[0-9A-Fa-f-]{8,64}", udid)
            ):
                raise AuthError(400, "Niepoprawny UDID")
            try:
                api = self._mdm_api()
                if path == "/api/mdm/refresh" and udid:
                    result = api.request("POST", f"/api/devices/{udid}/refresh")
                elif path == "/api/mdm/command" and udid:
                    rtype = data.get("request_type")
                    if rtype not in ("DeviceLock", "RestartDevice"):
                        raise AuthError(400, "Dozwolone: DeviceLock, RestartDevice")
                    body = {"request_type": rtype}
                    if rtype == "DeviceLock" and data.get("Message"):
                        body["Message"] = self._str(data, "Message", 200)
                    result = api.request("POST", f"/api/devices/{udid}/commands", body)
                elif path == "/api/mdm/enroll":
                    label = self._str(data, "label", 32)
                    result = api.request("POST", "/api/enrollments", {"label": label})
                elif path == "/api/mdm/os-update":
                    if data.get("clear"):
                        body = {"clear": True}
                    elif data.get("disabled"):
                        body = {"disabled": True}
                    else:
                        body = {
                            "target_version": self._str(data, "target_version", 16),
                            "deadline": self._str(data, "deadline", 19),
                        }
                    result = api.request("PUT", "/api/os-update", body)
                else:
                    self._json(404, {"error": "nie ma takiego endpointu"})
                    return
            except MdmError as exc:
                self._json(_mdm_status(exc.status), {"error": str(exc)})
                return
            log.info("panel: %s -> %s %s", session.login, path, udid or "")
            self._json(200, result)

        def _logout(self) -> None:
            session = self._session()
            if session is None:
                self._unauthorized()
                return
            if not csrf_ok(session, self.headers.get(CSRF_HEADER)):
                raise AuthError(403, "Nieprawidłowy token CSRF")
            auth.logout(session)
            self._json(200, {"ok": True}, cleared_cookies())

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_GET(self) -> None:  # noqa: N802
            url = urlparse(self.path)
            if url.path.startswith("/api/"):
                self._api(url.path, {k: v[-1] for k, v in parse_qs(url.query).items()})
            else:
                self._static(url.path)

        def _api(self, path: str, params: dict[str, str]) -> None:
            if path == "/api/health":
                self._json(200, {"ok": True, "now": datetime.now(UTC).isoformat()})
                return
            try:
                session = self._session()
            except sqlite3.Error as exc:
                log.warning("panel: baza logowania niedostepna: %s", exc)
                self._json(503, {"error": "baza logowania niedostepna"})
                return
            if session is None:
                self._unauthorized()
                return
            if path == "/api/auth/me":
                self._json(200, {
                    "login": session.login,
                    "session_expires_at": datetime.fromtimestamp(
                        session.expires_at, UTC).isoformat(),
                    **auth.account(session),
                })
                return
            if path == "/api/meta":
                self._json(200, queries.meta())
                return
            if path.startswith("/api/profile/"):
                try:
                    self._profile_get(path, session)
                except AuthError as exc:
                    self._json(exc.status, {"error": exc.message})
                return
            if path == "/api/export.csv":
                self._export(params)
                return
            if path == "/api/tv/aplikacja":
                self._json(200, stan_aplikacji())
                return
            if path == "/api/mdm" or path.startswith("/api/mdm/"):
                self._mdm_get(path)
                return
            routes = {
                "/api/screens": lambda c: queries.screens(c, params),
                "/api/trends": lambda c: queries.trends(c, params),
                "/api/devices": lambda c: queries.devices(c, params),
                "/api/notifications": lambda c: queries.notifications(c, params),
                "/api/day": lambda c: queries.day(c, params),
                "/api/usage": lambda c: queries.usage(c, params),
                "/api/tv/pause": lambda c: queries.tv_pause(c),
            }
            route = routes.get(path)
            if route is None:
                self._json(404, {"error": "nie ma takiego endpointu"})
                return
            try:
                conn = queries.connect()
                try:
                    self._json(200, route(conn))
                finally:
                    conn.close()
            except BadRequest as exc:
                self._json(400, {"error": str(exc)})
            except sqlite3.OperationalError as exc:
                # Swiezy pod: baza jeszcze nie istnieje albo bez tabeli historii.
                log.warning("panel: baza niedostepna: %s", exc)
                self._json(503, {"error": f"baza niedostepna: {exc}"})
            except Exception:
                log.exception("panel: blad przy %s", path)
                self._json(500, {"error": "blad serwera"})

        def _export(self, params: dict[str, str]) -> None:
            """CSV z agregatow dziennych. Sesja sprawdzona wyzej w _api."""
            try:
                first, last = queries.export_range(params)
                conn = queries.connect()
                try:
                    body = queries.export_csv(conn, params).encode("utf-8")
                finally:
                    conn.close()
            except BadRequest as exc:
                self._json(400, {"error": str(exc)})
                return
            except sqlite3.OperationalError as exc:
                log.warning("panel: baza niedostepna: %s", exc)
                self._json(503, {"error": f"baza niedostepna: {exc}"})
                return
            name = f"kidwatch-{first.isoformat()}_{last.isoformat()}.csv"
            self._send(200, body, "text/csv; charset=utf-8", {
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="{name}"',
            })

        def _static(self, path: str) -> None:
            rel = path.lstrip("/") or "index.html"
            target = (static_root / rel).resolve()
            # Ochrona przed ../ — tylko pliki z katalogu frontu.
            if not target.is_relative_to(static_root) or not target.is_file():
                target = static_root / "index.html"
            if not target.is_file():
                self._send(503, b"Front nie jest zbudowany.", "text/plain; charset=utf-8")
                return
            ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            if ctype.startswith("text/") or ctype == "application/javascript":
                ctype += "; charset=utf-8"
            cache = (
                "public, max-age=31536000, immutable"
                if target.parent.name == "assets"
                else "no-cache"
            )
            self._send(200, target.read_bytes(), ctype, {"Cache-Control": cache})

    return Handler


def _bramka_admin(cfg: Config) -> BramkaAdmin | None:
    """Profil -> Powiadomienia. Bez wlaczonej bramki albo bez klucza sekcja
    pokazuje "niedostepne" zamiast padac."""
    bc = cfg.notifiers.bramka
    if bc is None or not bc.enabled:
        return None
    try:
        key, fallback = bc.admin_key()
    except MissingSecretError as exc:
        log.warning("panel: zarzadzanie WhatsAppem niedostepne — %s", exc)
        return None
    if fallback:
        log.warning(
            "panel: brak BRAMKA_KLUCZ_ADMIN — zarzadzanie WhatsAppem kluczem BRAMKA_KLUCZ "
            "(dziala tylko ze starym wspolnym kluczem bramki)"
        )
    return BramkaAdmin(bc, key)


def stan_aplikacji() -> dict:
    """Stan aplikacji Kidwatch TV dla panelu (`available: false` = wylaczona)."""
    from .sources import tv_app  # noqa: PLC0415

    app = tv_app.AKTYWNA
    if app is None:
        return {"available": False}
    st = app.stan()
    return {
        "available": True,
        "paired": st.sparowana,
        "version": st.wersja,
        "permission": st.uprawnienie,
        "last_read": to_iso(st.ostatni_odczyt) if st.ostatni_odczyt else None,
        "error": st.blad,
        "adb": app.adb is not None,
    }


def start_panel(cfg: Config) -> ThreadingHTTPServer:
    """Startuje serwer panelu w watku demona i zwraca go (do `shutdown()`)."""
    auth = PanelAuth(
        cfg.panel_auth_path, box=box_from_env(), session_seconds=cfg.panel.session_hours * 3600
    )
    requests = GameRequests(cfg.panel_auth_path) if cfg.game_time.enabled else None
    tv_requests = TvPauseRequests(cfg.panel_auth_path) if cfg.tv.enabled else None
    queries = PanelQueries(cfg, cfg.store.path, requests, tv_requests)
    if not auth.has_users():
        log.warning(
            "panel: brak kont — nikt sie nie zaloguje. Zaloz konto: "
            "python -m kidwatch user-add <login>"
        )
    server = ThreadingHTTPServer(
        (cfg.panel.host, cfg.panel.port),
        make_handler(
            queries, Path(cfg.panel.static_dir), auth, cookie_secure=cfg.panel.cookie_secure,
            bramka=_bramka_admin(cfg), mdm=build_api(cfg.mdm),
        ),
    )
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="panel", daemon=True)
    thread.start()
    log.info("panel WWW na %s:%d", cfg.panel.host, cfg.panel.port)
    return server
