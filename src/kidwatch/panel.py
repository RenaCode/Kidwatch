"""Panel WWW: historia powiadomien, sesje i stan iPadow.

Celowo bez frameworka — kilka endpointow GET tylko do odczytu i trzy
endpointy logowania nie uzasadniaja FastAPI w obrazie. Serwer chodzi
w osobnym watku procesu `run`, a kazde zapytanie otwiera WLASNE polaczenie
SQLite w trybie tylko do odczytu (`mode=ro`). Petla glowna pozostaje jedynym
pisarzem bazy.

Logowanie jest wlasne: haslo + opcjonalny TOTP (panel_auth.py), a przy
`SSO_NAGLOWKI=1` takze sesja z naglowka Authelii (panel_sso.py). Kazde
/api/* poza /api/health, /api/auth/login i /api/auth/mfa wymaga sesji, a bez
niej dostaje 401. Konto z wlaczonym TOTP dostaje sesje dopiero po kodzie.
POST-y zmieniajace stan konta wymagaja tez tokenu CSRF — tak samo
POST /api/game (czas gry) i POST /api/tv/pause|resume (pauza monitoringu TV),
ktore NIE pisza do kidwatch.db, tylko dopisuja zadanie do kolejki
w panel-auth.db (gametime.py, tvpause.py). Konta i sesje leza
w osobnej bazie — panel_auth.py tlumaczy, dlaczego nie w kidwatch.db.
Kazda trasa /api/* ma w POST_TRASY albo GET_TRASY jedno uprawnienie
(uprawnienia.py) i zakres (`konto`, `dom`, `instancja`), sprawdzane w jednym
miejscu — _wymaga(). Konto `podglad` tylko oglada: kazda zmiana stanu poza
wlasnym haslem i 2FA dostaje 403, takze pauza telewizora.

DOMY (docs/architektura-domy.md §4.1, panel_domy.py). Trasy danych domu
leza pod `/api/domy/<id>/...`: dom pochodzi ze sciezki, nigdy z ciasteczka
ani z ciala. Najpierw dostep do domu (czlonkostwo albo aktywny administrator
instalacji z wpisem w `audyt`) — bez niego 404, nie 403 — potem uprawnienie
w tym domu (403). Stare trasy bez domu (`/api/day`) to alias jedynego domu
konta; konto z wiecej niz jednym domem dostaje na nich 409.
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
from collections.abc import Callable
from datetime import UTC, date, datetime, time, timedelta
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import NamedTuple
from urllib.parse import parse_qs, urlparse

from . import domy as dm
from .bramka_admin import (
    BramkaAdmin,
    BramkaError,
    mask,
    normalize_number,
    normalize_recipients,
)
from .config import Config, HomeConfig, MissingSecretError, WatchedDevice
from .gametime import ACTIONS, GameRequests, TooManyRequests
from .mdm import (
    MdmApi,
    MdmError,
    build_api,
    config_domu,
    udid_w_domie,
    urzadzenie_domu,
    zakres_tokenu,
    zakres_z_whoami,
)
from .odbiorcy import ProfilePowiadomien
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
from .panel_domy import (
    PREFIKS_DOMU,
    BezKonfiguracji,
    DomyPanelu,
    KontekstDomu,
    admin_aktywny,
    pokaz_argo,
    uprawnienia_sesji,
)
from .panel_integracje import PanelIntegracje
from .panel_komendy import KomendyPanelu
from .panel_konta import PanelKonta, WDomu
from .panel_sso import SsoConfig
from .panel_sso import config_from_env as sso_from_env
from .store import from_iso, to_iso
from .tvpause import MAX_PAUSE_DAYS, TvPauseRequests, parse_until
from .tvpause import TooManyRequests as TooManyPauseRequests
from .uprawnienia import (
    CZAS_GRY,
    DOM_INTEGRACJE,
    KONTA,
    KONTO_WLASNE,
    MDM_KOMENDY,
    MDM_PODGLAD,
    OPISY,
    PODGLAD,
    TV_APLIKACJA,
    TV_PAUZA,
    WHATSAPP,
    ZAKRES_DOM,
    ZAKRES_INSTANCJA,
    ZAKRES_KONTO,
    nazwa_roli,
)

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
#: Zapis integracji niesie klucz ADB (PEM, 2-3 kB przed escapowaniem JSON).
MAX_BODY_INTEGRACJI = 32 * 1024

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
        cfg: HomeConfig | BezKonfiguracji,
        db_path: str,
        requests: GameRequests | None = None,
        tv_requests: TvPauseRequests | None = None,
    ) -> None:
        #: Konfiguracja JEDNEGO domu; zapytania czytaja tylko jego baze.
        self.cfg = cfg
        self.db_path = str(db_path)
        #: Kolejka zadan czasu gry (panel-auth.db) — None, gdy game_time wylaczone.
        self.requests = requests
        #: Kolejka zadan pauzy TV (panel-auth.db) — None, gdy czujnik TV wylaczony.
        self.tv_requests = tv_requests
        #: Dom z konfiguracja w bazie: posrednik MDM z tokenem z sejfu domu
        #: (`mdm` — None, gdy integracja wylaczona albo bez tokenu). Dla domu
        #: z config.yaml `mdm_z_bazy` jest False i panel bierze MDM instancji.
        self.mdm_z_bazy = False
        self.mdm: MdmApi | None = None

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
                    "game": self._game(conn, dev.child) if dev.kind != "tv" else None,
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


# ================================================================= uprawnienia
#: Trasa bez sesji panelu: logowanie i drugi skladnik. Wylogowanie tez —
#: samo sprawdza sesje i CSRF, a bez sesji odsyla jeszcze na portal SSO.
PUBLICZNA = "publiczna"

#: Zakresy tras (§4.1): `konto` — konto samo o sobie, `instancja` — wspolne
#: dla instalacji (bot WhatsApp), `dom` — dane i czynnosci domu; trasa domu
#: ma w kluczu PREFIKS_DOMU, a <id> pochodzi ze sciezki zadania.
KONTO, DOM, INSTANCJA = ZAKRES_KONTO, ZAKRES_DOM, ZAKRES_INSTANCJA
_D = PREFIKS_DOMU

#: Router POST: sciezka -> (uprawnienie, metoda handlera, zakres). Innych
#: sciezek do_POST nie zna (404). Metoda trasy PUBLICZNA nie dostaje
#: argumentow, pozostale — (klucz trasy, sesja, kontekst domu albo None) po
#: sprawdzeniu sesji, CSRF, domu i uprawnienia. Nowa trasa wymaga tu decyzji;
#: test_uprawnienia.py i test_domy_panel.py pilnuja, ze kazda ma uprawnienie
#: i zakres, ze trasa domu lezy pod prefiksem, a `podglad` i obcy dom
#: dostaja odmowe.
POST_TRASY: dict[str, tuple[str, str, str]] = {
    "/api/auth/login": (PUBLICZNA, "_login", KONTO),
    "/api/auth/mfa": (PUBLICZNA, "_mfa", KONTO),
    "/api/auth/logout": (PUBLICZNA, "_logout", KONTO),
    "/api/auth/totp/setup": (KONTO_WLASNE, "_totp_setup", KONTO),
    "/api/auth/totp/confirm": (KONTO_WLASNE, "_totp_confirm", KONTO),
    "/api/auth/totp/disable": (KONTO_WLASNE, "_totp_disable", KONTO),
    "/api/auth/password": (KONTO_WLASNE, "_change_password", KONTO),
    # Kanaly (numer, e-mail) sa osoby, wspolne dla jej domow.
    "/api/konto/kanaly": (KONTO_WLASNE, "_konta_post", KONTO),
    # Bot WhatsApp bramki jest jeden na instalacje.
    "/api/profile/whatsapp/start": (WHATSAPP, "_profile_post", INSTANCJA),
    "/api/profile/whatsapp/logout": (WHATSAPP, "_profile_post", INSTANCJA),
    "/api/profile/whatsapp/recipient": (WHATSAPP, "_profile_post", INSTANCJA),
    "/api/profile/whatsapp/recipients": (WHATSAPP, "_profile_post", INSTANCJA),
    "/api/profile/test": (WHATSAPP, "_profile_post", INSTANCJA),
    # Awaryjny wylacznik komend z WhatsAppa (bot jest jeden na instalacje).
    "/api/whatsapp/komendy/wylacznik": (WHATSAPP, "_komendy_post", INSTANCJA),
    f"{_D}/game": (CZAS_GRY, "_game_request", DOM),
    f"{_D}/tv/pause": (TV_PAUZA, "_tv_pause_request", DOM),
    f"{_D}/tv/resume": (TV_PAUZA, "_tv_pause_request", DOM),
    f"{_D}/tv/aplikacja/instaluj": (TV_APLIKACJA, "_tv_aplikacja", DOM),
    f"{_D}/tv/aplikacja/paruj": (TV_APLIKACJA, "_tv_aplikacja", DOM),
    f"{_D}/mdm/refresh": (MDM_KOMENDY, "_mdm_post", DOM),
    f"{_D}/mdm/command": (MDM_KOMENDY, "_mdm_post", DOM),
    f"{_D}/mdm/enroll": (MDM_KOMENDY, "_mdm_post", DOM),
    f"{_D}/mdm/os-update": (MDM_KOMENDY, "_mdm_post", DOM),
    # Powiadomienia (panel_konta.py): wlasne preferencje w domu — kazdy
    # czlonek; czlonkowie domu — zarzadzanie kontami w tym domu.
    f"{_D}/konto/powiadomienia": (KONTO_WLASNE, "_konta_post", DOM),
    f"{_D}/konta/dodaj": (KONTA, "_konta_post", DOM),
    f"{_D}/konta/usun": (KONTA, "_konta_post", DOM),
    f"{_D}/konta/rola": (KONTA, "_konta_post", DOM),
    f"{_D}/konta/uprawnienia": (KONTA, "_konta_post", DOM),
    f"{_D}/konta/powiadomienia": (KONTA, "_konta_post", DOM),
    f"{_D}/konta/kanaly": (KONTA, "_konta_post", DOM),
    f"{_D}/konta/tryb": (KONTA, "_konta_post", DOM),
    # Integracje domu (panel_integracje.py): uprawnienie `dom.integracje`
    # w domu ORAZ aktywny administrator instalacji (decyzja 2026-10-12).
    f"{_D}/integracje/zapisz": (DOM_INTEGRACJE, "_integracje_post", DOM),
    f"{_D}/integracje/usun-sekret": (DOM_INTEGRACJE, "_integracje_post", DOM),
}

#: GET /api/*: sciezka -> (uprawnienie, zakres); klucz z "/" na koncu to
#: prefiks (UDID w sciezce). Numery WhatsAppa, UDID-y i stan aplikacji TV to
#: ekrany zarzadzania — maja uprawnienia czynnosci, nie podgladu.
GET_TRASY: dict[str, tuple[str, str]] = {
    "/api/health": (PUBLICZNA, KONTO),
    "/api/auth/me": (KONTO_WLASNE, KONTO),
    "/api/profile/notify": (WHATSAPP, INSTANCJA),
    "/api/profile/whatsapp/qr": (WHATSAPP, INSTANCJA),
    # Dziennik komend z WhatsAppa: wszystkie (administrator) i domu.
    "/api/whatsapp/komendy": (WHATSAPP, INSTANCJA),
    f"{_D}/komendy": (KONTA, DOM),
    f"{_D}/meta": (PODGLAD, DOM),
    f"{_D}/screens": (PODGLAD, DOM),
    f"{_D}/trends": (PODGLAD, DOM),
    f"{_D}/devices": (PODGLAD, DOM),
    f"{_D}/notifications": (PODGLAD, DOM),
    f"{_D}/day": (PODGLAD, DOM),
    f"{_D}/usage": (PODGLAD, DOM),
    f"{_D}/export.csv": (PODGLAD, DOM),
    f"{_D}/tv/pause": (PODGLAD, DOM),
    f"{_D}/tv/aplikacja": (TV_APLIKACJA, DOM),
    f"{_D}/mdm": (MDM_PODGLAD, DOM),
    f"{_D}/mdm/devices/": (MDM_PODGLAD, DOM),
    f"{_D}/konto/powiadomienia": (KONTO_WLASNE, DOM),
    f"{_D}/konta": (KONTA, DOM),
    # Dom -> Dziennik: zmiany w domu i wejscia administratora (§2.3).
    f"{_D}/dziennik": (KONTA, DOM),
    # Integracje domu: ustawienia i maski sekretow — tylko administrator.
    f"{_D}/integracje": (DOM_INTEGRACJE, DOM),
    # Odswiezanie ekranu po zapisie: tylko wersja i stan przeladowania.
    f"{_D}/integracje/stan": (DOM_INTEGRACJE, DOM),
}

_SCIEZKA_DOMU = re.compile(r"/api/domy/([1-9][0-9]{0,8})(/.+)")


class Trasa(NamedTuple):
    #: Klucz w POST_TRASY / GET_TRASY (dla domu — z PREFIKS_DOMU).
    klucz: str
    uprawnienie: str
    zakres: str
    #: Metoda handlera (POST); None dla GET.
    metoda: str | None
    #: Dom ze sciezki; None = trasa bez domu albo alias (dom wybiera konto).
    dom_id: int | None
    alias: bool = False


def _klucz_get(path: str) -> str | None:
    if path in GET_TRASY and not path.endswith("/"):
        return path
    for klucz in GET_TRASY:
        if klucz.endswith("/") and path.startswith(klucz) and len(path) > len(klucz):
            return klucz
    return None


def trasa(metoda: str, path: str) -> Trasa | None:
    """Trasa zadania albo None (404). `/api/domy/<id>/x` -> trasa domu
    z <id>; stara sciezka `/api/x` trasy domu -> alias (dom z konta)."""
    tabela = POST_TRASY if metoda == "POST" else GET_TRASY
    dom_id, alias = None, False
    if m := _SCIEZKA_DOMU.fullmatch(path):
        dom_id, klucz_sciezki = int(m[1]), _D + m[2]
    elif path.startswith("/api/domy/"):
        return None
    else:
        klucz_sciezki = path
    klucz = klucz_sciezki if metoda == "POST" else _klucz_get(klucz_sciezki)
    if klucz is None or klucz not in tabela:
        if dom_id is not None or not path.startswith("/api/"):
            return None
        # Alias trasy domu sprzed domow: /api/day -> /api/domy/<id>/day.
        klucz_sciezki = _D + path.removeprefix("/api")
        klucz = klucz_sciezki if metoda == "POST" else _klucz_get(klucz_sciezki)
        if klucz is None or klucz not in tabela:
            return None
        alias = True
    wpis = tabela[klucz]
    upr, zakres = (wpis[0], wpis[2]) if metoda == "POST" else wpis
    if (zakres == DOM) != (dom_id is not None or alias):
        return None
    return Trasa(klucz, upr, zakres, wpis[1] if metoda == "POST" else None, dom_id, alias)


def get_uprawnienie(path: str) -> str | None:
    """Uprawnienie trasy GET albo None, gdy takiej trasy nie ma."""
    t = trasa("GET", path)
    return None if t is None else t.uprawnienie


def _cookie(name: str, value: str, max_age: int, *, http_only: bool, secure: bool) -> str:
    parts = [f"{name}={value}", "Path=/", f"Max-Age={max_age}", "SameSite=Strict"]
    if http_only:
        parts.append("HttpOnly")
    if secure:
        parts.append("Secure")
    return "; ".join(parts)


def make_handler(
    domy: DomyPanelu,
    static_dir: Path,
    auth: PanelAuth,
    *,
    cookie_secure: bool = True,
    bramka: BramkaAdmin | None = None,
    mdm: MdmApi | None = None,
    sso: SsoConfig | None = None,
    konta: PanelKonta | None = None,
    integracje: PanelIntegracje | None = None,
    komendy: KomendyPanelu | None = None,
):
    """`sso` = None: naglowki `Remote-*` ignorowane w calosci (panel_sso.py).
    `domy`: domy panelu z `PanelQueries` kazdego domu (panel_domy.py).
    `integracje`: ekran integracji domu (panel_integracje.py); None = 503."""
    static_root = static_dir.resolve()

    def session_cookies(token: str, session: Session, max_age: int) -> list[str]:
        return [
            # Sesja HttpOnly: JS jej nie widzi, wiec nie wycieknie przez XSS.
            _cookie(SESSION_COOKIE, token, max_age, http_only=True, secure=cookie_secure),
            # CSRF celowo BEZ HttpOnly — front czyta go i odsyla w naglowku.
            # Sam w sobie nic nie otwiera.
            _cookie(CSRF_COOKIE, session.csrf, max_age, http_only=False, secure=cookie_secure),
        ]

    def _bez_sso(session: Session | None) -> Session | None:
        """Sesja `sso` zyje tylko z naglowkiem Authelii. Bez niego (port-forward,
        flaga wylaczona po wycofaniu SSO) to zwykly token na okaziciela, ktory
        nie przeszedl hasla ani TOTP panelu: skopiowane ciasteczko nie moze
        ominac drogi awaryjnej, ktora zada hasla i TOTP."""
        return None if session is not None and session.kind == "sso" else session

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
        #: Ciasteczka nowej sesji SSO, doklejane do odpowiedzi na to zadanie.
        _sso_cookies: tuple[str, ...] | list[str] = ()
        #: Zadanie przyszlo z `Remote-User` przy wlaczonym SSO, czyli przez
        #: Authelie — wylogowanie musi skonczyc tez jej sesje.
        _via_sso = False
        #: `Remote-Groups` zadania przez Authelie; None = bez naglowka SSO.
        #: Tylko bezpiecznik roli administratora (panel_domy.admin_aktywny).
        _grupy: tuple[str, ...] | None = None

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
            for c in [*self._sso_cookies, *(cookies or ())]:
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
            """Sesja z ciasteczka, a przy SSO — uzytkownika z `Remote-User`.

            Bez naglowka (port-forward, gdy Authelia lezy) dziala zwykla sesja
            z hasla. Z naglowkiem: sesja tego samego uzytkownika zostaje,
            brak sesji albo sesja KOGOS INNEGO (zmiana konta w Authelii w tej
            samej przegladarce) — nowa sesja `sso`. SsoError/AuthError (400
            podwojny naglowek, 403 brak grupy albo konta) leca wyzej."""
            session = auth.session(self._cookies().get(SESSION_COOKIE))
            if sso is None:
                return _bez_sso(session)
            self._via_sso = bool(self.headers.get_all("Remote-User"))
            ident = sso.identity(self.headers)
            if ident is None:
                return _bez_sso(session)
            self._grupy = ident.groups
            if session is not None and session.login == ident.login:
                return session
            if session is not None:
                auth.logout(session)
            token, session = auth.sso_login(
                ident.login, ip=self._client_ip(), user_agent=self.headers.get("User-Agent")
            )
            self._sso_cookies = session_cookies(token, session, int(auth.session_seconds))
            return session

        def _admin(self, session: Session) -> bool:
            return admin_aktywny(session, self._grupy)

        def _wymaga(self, session: Session, t: Trasa) -> KontekstDomu | None:
            """Jedyne miejsce sprawdzania dostepu. Trasa domu: najpierw dom
            (czlonkostwo albo aktywny administrator; inaczej 404, 409 przy
            aliasie z wieloma domami), potem uprawnienie W TYM domu (403),
            na koniec wpis w `audyt` dla administratora bez czlonkostwa.
            Uprawnienia z bazy panelu, nigdy z `Remote-Groups`."""
            ctx = None
            admin = self._admin(session)
            if t.zakres == DOM:
                dom_id = t.dom_id if t.dom_id is not None else domy.alias(session, admin)
                ctx = domy.dostep(session, dom_id, admin)
                uprawnienia = ctx.uprawnienia
            else:
                uprawnienia = uprawnienia_sesji(session, admin)
            if t.uprawnienie not in uprawnienia:
                log.warning("panel: %r (rola %s) bez uprawnienia %s do %s %s",
                            session.login, session.rola, t.uprawnienie, self.command,
                            urlparse(self.path).path)
                raise AuthError(
                    403, f"To konto nie ma uprawnienia „{t.uprawnienie}” "
                    f"({OPISY.get(t.uprawnienie, '?')}) — poproś właściciela panelu.",
                )
            if ctx is not None:
                domy.audytuj(session, ctx, self.command if self.command != "HEAD" else "GET",
                             t.klucz)
            elif t.zakres == INSTANCJA and self.command == "POST":
                domy.audytuj_instancje(session, t.klucz)
            return ctx

        def _deny(self, exc: AuthError) -> None:
            payload = {"error": exc.message}
            if self._via_sso:
                payload["logout_url"] = sso.logout_url
            self._json(exc.status, payload)

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

        def _read_json(self, limit: int = MAX_BODY) -> dict:
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
            if length > limit:
                raise AuthError(413, "Za duże zapytanie")
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                raise AuthError(400, "Niepoprawny JSON") from exc
            if not isinstance(data, dict):
                raise AuthError(400, "Niepoprawny JSON")
            return data

        def do_POST(self) -> None:  # noqa: N802
            self._sso_cookies, self._via_sso, self._grupy = [], False, None
            path = urlparse(self.path).path
            try:
                t = trasa("POST", path)
                if t is None:
                    self._json(404, {"error": "nie ma takiego endpointu"})
                    return
                if t.uprawnienie == PUBLICZNA:
                    getattr(self, t.metoda)()
                else:
                    session = self._authed()
                    getattr(self, t.metoda)(t.klucz, session, self._wymaga(session, t))
            except AuthError as exc:
                self._deny(exc)
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

        def _totp_setup(self, _path: str, session: Session, _ctx=None) -> None:
            self._json(200, auth.totp_setup(session))

        def _totp_confirm(self, _path: str, session: Session, _ctx=None) -> None:
            codes = auth.totp_confirm(session, self._str(self._read_json(), "code", 32))
            self._json(200, {"ok": True, "backup_codes": codes})

        def _totp_disable(self, _path: str, session: Session, _ctx=None) -> None:
            data = self._read_json()
            auth.totp_disable(
                session, self._str(data, "password", 512), self._str(data, "code", 32)
            )
            self._json(200, {"ok": True})

        def _game_request(self, _path: str, session: Session, ctx: KontekstDomu) -> None:
            """Zadanie czasu gry. NIE wykonuje go — dopisuje do kolejki domu
            (`dom_id`), ktora odbiera petla tego domu (jedyny pisarz jego bazy).
            Dziecko musi nalezec do TEGO domu."""
            queries = ctx.queries
            if queries.requests is None:
                raise AuthError(404, "Czas gry jest wyłączony w konfiguracji")
            data = self._read_json()
            child, action = data.get("child"), data.get("action")
            if not isinstance(child, str) or child not in queries.children():
                raise AuthError(400, "Nieznane dziecko")
            # "shorten" zleca tylko bot komend (-15 z WhatsAppa), nie panel.
            if action not in ACTIONS or action == "shorten":
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

        def _tv_pause_request(self, path: str, session: Session, ctx: KontekstDomu) -> None:
            """Pauza monitoringu TV. Jak czas gry: tylko zadanie w kolejce
            domu, wykonuje je tik petli domu (tvpause.py) — po kilkunastu s."""
            queries = ctx.queries
            action = "pause" if path.endswith("/pause") else "resume"
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

        def _tv_aplikacja(self, path: str, session: Session, ctx: KontekstDomu) -> None:
            """Aplikacja Kidwatch TV (sources/tv_app.py): instalacja przez ADB
            i parowanie kodem z jej ekranu. Wykonuje petla serwisu."""
            from .sources import tv_app  # noqa: PLC0415

            app = aplikacja_tv(ctx.dom_id)
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
            self._json(200, {**stan_aplikacji(ctx.dom_id), "message": komunikat})

        def _change_password(self, _path: str, session: Session, _ctx=None) -> None:
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

        def _profile_post(self, path: str, session: Session, _ctx=None) -> None:
            """Akcje WhatsAppa. Sesja + CSRF jak kazda zmiana stanu; bramke
            wola serwer swoim kluczem — przegladarka go nie zna."""
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

        # ------------------------------------------- konta i ich powiadomienia
        def _konta(self) -> PanelKonta:
            if konta is None:
                raise AuthError(503, "Zarządzanie kontami jest niedostępne")
            return konta

        def _w_domu(self, ctx: KontekstDomu) -> WDomu:
            return WDomu(ctx.dom_id, ctx.uprawnienia, ctx.queries.children(),
                         admin=ctx.admin, administracja=ctx.administracja)

        def _konta_post(self, path: str, session: Session, ctx: KontekstDomu | None) -> None:
            k = self._konta()
            data = self._read_json()
            if ctx is None:  # /api/konto/kanaly — kanaly osoby, bez domu
                self._json(200, k.moje_kanaly(session, data))
                return
            akcje = {
                "/konto/powiadomienia": k.moje_preferencje,
                "/konta/dodaj": k.dodaj,
                "/konta/usun": k.usun,
                "/konta/rola": k.rola,
                "/konta/uprawnienia": k.uprawnienia,
                "/konta/powiadomienia": k.preferencje,
                "/konta/kanaly": k.kanaly,
                "/konta/tryb": k.tryb,
            }
            self._json(200, akcje[path.removeprefix(PREFIKS_DOMU)](
                session, data, self._w_domu(ctx)))

        # ----------------------------------------------------- integracje domu
        def _integracje(self) -> PanelIntegracje:
            if integracje is None:
                raise AuthError(503, "Ekran integracji jest niedostępny")
            return integracje

        def _integracje_post(self, path: str, session: Session, ctx: KontekstDomu) -> None:
            p = self._integracje()
            data = self._read_json(MAX_BODY_INTEGRACJI)
            akcja = {"/integracje/zapisz": p.zapisz, "/integracje/usun-sekret": p.usun_sekret}
            try:
                wynik = akcja[path.removeprefix(PREFIKS_DOMU)](session, data, ctx)
            except AuthError:
                raise
            except Exception as exc:
                # Bez log.exception: cialo zadania niesie sekrety, a tresc
                # nieprzewidzianego wyjatku moglaby je powtorzyc. Sam typ.
                log.error("panel: blad zapisu integracji domu %d: %s", ctx.dom_id,
                          type(exc).__name__)
                raise AuthError(500, "blad serwera") from None
            self._json(200, wynik)

        # ---------------------------------------------------------------- MDM
        # Panel jest posrednikiem: token API serwera MDM zostaje w backendzie,
        # a przegladarka widzi tylko zalogowana sesje panelu (+ CSRF przy akcjach).
        def _mdm_domu(self, ctx: KontekstDomu) -> MdmApi | None:
            # Dom z konfiguracja w bazie: token z sejfu domu (ekran integracji;
            # inny dom tylko z WLASNYM tokenem — queries_domow, E3b). Dom 1
            # z config.yaml: MDM_ADMIN_TOKEN jak dotad. Inny dom bez bazy — nic.
            q = ctx.queries
            if getattr(q, "mdm_z_bazy", False):
                return q.mdm
            return mdm if ctx.dom_id == dm.DOM_1 else None

        def _udid_domu(self, ctx: KontekstDomu, udid: str, api: MdmApi | None = None) -> None:
            """Druga bariera (§4.3, E3b): UDID spoza domu = 404, zanim panel
            zawola serwer MDM — niezaleznie od filtra po stronie serwera.

            Z `api`: dodatkowo dom urzadzenia wg serwera musi byc tym domem.
            Token instancji Domu 1 serwer nie filtruje, a iPad innego domu,
            ktorego ten dom nie wpisal jeszcze do `urzadzenia`, przeszedlby
            wyjatek Domu 1 w `udid_w_domie`."""
            try:
                nasz = udid_w_domie(udid, ctx.dom_id, getattr(ctx.queries, "cfg", None),
                                    domy.rejestr.dom_udidu)
            except sqlite3.Error as exc:
                raise AuthError(503, "Baza panelu niedostępna") from exc
            if nasz and api is not None:
                nasz = urzadzenie_domu(api.request("GET", f"/api/devices/{udid}"), ctx.dom_id)
            if not nasz:
                log.warning("panel: UDID spoza domu %d odrzucony", ctx.dom_id)
                raise MdmError(404, "nieznane urzadzenie")

        def _mdm_domowe(self, ctx: KontekstDomu, rows: list) -> list:
            """Lista z serwera bez urzadzen i zdarzen innych domow (token
            instancji Domu 1 widzi wszystko)."""
            nasze: dict[str, bool] = {}
            out = []
            for r in rows if isinstance(rows, list) else []:
                if not isinstance(r, dict):
                    continue
                if r.get("dom_id") is not None and r["dom_id"] != ctx.dom_id:
                    continue
                udid = r.get("udid")
                if isinstance(udid, str) and udid:
                    if udid not in nasze:
                        try:
                            self._udid_domu(ctx, udid)
                            nasze[udid] = True
                        except MdmError:
                            nasze[udid] = False
                    if not nasze[udid]:
                        continue
                out.append(r)
            return out

        def _mdm_api(self, ctx: KontekstDomu) -> MdmApi:
            api = self._mdm_domu(ctx)
            if api is None:
                raise MdmError(404, "integracja MDM wylaczona (mdm.enabled albo token MDM)")
            return api

        def _mdm_get(self, path: str, ctx: KontekstDomu) -> None:
            try:
                api = self._mdm_api(ctx)
                if path == "/mdm":
                    devices = self._mdm_domowe(ctx, api.devices())
                    health = api.health()
                    if isinstance(health, dict):
                        # Licznik z /api/health obejmuje urzadzenia wszystkich domow.
                        health["devices"] = len(devices)
                    self._json(200, {
                        "available": True,
                        "health": health,
                        "devices": devices,
                        "os_update": api.request("GET", "/api/os-update"),
                        "events": self._mdm_domowe(
                            ctx, api.request("GET", "/api/events?last=50")),
                    })
                elif m := re.fullmatch(r"/mdm/devices/([0-9A-Fa-f-]{8,64})", path):
                    self._udid_domu(ctx, m[1])
                    detail = api.request("GET", f"/api/devices/{m[1]}")
                    if not urzadzenie_domu(detail, ctx.dom_id):
                        raise MdmError(404, "nieznane urzadzenie")
                    self._json(200, detail)
                else:
                    self._json(404, {"error": "nie ma takiego endpointu"})
            except MdmError as exc:
                if self._mdm_domu(ctx) is None:
                    self._json(200, {"available": False, "error": str(exc)})
                else:
                    self._json(_mdm_status(exc.status), {"error": str(exc)})

        def _mdm_post(self, path: str, session: Session, ctx: KontekstDomu) -> None:
            path = path.removeprefix(PREFIKS_DOMU)
            data = self._read_json()
            udid = data.get("udid")
            if udid is not None and (
                not isinstance(udid, str) or not re.fullmatch(r"[0-9A-Fa-f-]{8,64}", udid)
            ):
                raise AuthError(400, "Niepoprawny UDID")
            try:
                api = self._mdm_api(ctx)
                if udid:
                    self._udid_domu(ctx, udid, api)
                if path == "/mdm/refresh" and udid:
                    result = api.request("POST", f"/api/devices/{udid}/refresh")
                elif path == "/mdm/command" and udid:
                    rtype = data.get("request_type")
                    if rtype not in ("DeviceLock", "RestartDevice"):
                        raise AuthError(400, "Dozwolone: DeviceLock, RestartDevice")
                    body = {"request_type": rtype}
                    if rtype == "DeviceLock" and data.get("Message"):
                        body["Message"] = self._str(data, "Message", 200)
                    result = api.request("POST", f"/api/devices/{udid}/commands", body)
                elif path == "/mdm/enroll":
                    label = self._str(data, "label", 32)
                    result = api.request("POST", "/api/enrollments", {"label": label})
                elif path == "/mdm/os-update":
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

        def _komendy_post(self, _path: str, session: Session, _ctx=None) -> None:
            wylaczone = self._read_json().get("wylaczone")
            if not isinstance(wylaczone, bool):
                raise AuthError(400, "Pole „wylaczone”: true albo false")
            if komendy is None:
                raise AuthError(409, "Komendy z WhatsAppa są wyłączone w konfiguracji")
            try:
                wynik = komendy.ustaw_wylacznik(wylaczone, session.login)
            except LookupError as exc:
                raise AuthError(409, str(exc)) from None
            log.warning("panel: %s %s komendy z WhatsAppa dla wszystkich", session.login,
                        "WYLACZA" if wylaczone else "wlacza")
            self._json(200, wynik)

        def _logout(self) -> None:
            # Sama sesja z ciasteczka: wylogowanie nie zaklada sesji SSO tylko
            # po to, zeby ja zaraz skasowac.
            session = auth.session(self._cookies().get(SESSION_COOKIE))
            self._via_sso = sso is not None and bool(self.headers.get_all("Remote-User"))
            portal = {"logout_url": sso.logout_url} if self._via_sso else {}
            if session is None:
                if portal:
                    # Sesji panelu juz nie ma, ale Authelia wpuscilaby dalej —
                    # front i tak ma przejsc przez portal.
                    self._json(200, {"ok": True, **portal}, cleared_cookies())
                else:
                    self._unauthorized()
                return
            if not csrf_ok(session, self.headers.get(CSRF_HEADER)):
                raise AuthError(403, "Nieprawidłowy token CSRF")
            auth.logout(session)
            if portal:
                log.info("panel: wylogowanie SSO %r", session.login)
            self._json(200, {"ok": True, **portal}, cleared_cookies())

        def do_HEAD(self) -> None:  # noqa: N802
            self.do_GET()

        def do_GET(self) -> None:  # noqa: N802
            self._sso_cookies, self._via_sso, self._grupy = [], False, None
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
            except AuthError as exc:
                # Tylko SSO: podwojny naglowek, brak grupy albo konta w panelu.
                log.warning("panel: odmowa SSO z %s: %s", self._client_ip(), exc.message)
                self._deny(exc)
                return
            if session is None:
                self._unauthorized()
                return
            t = trasa("GET", path)
            if t is None:
                self._json(404, {"error": "nie ma takiego endpointu"})
                return
            try:
                ctx = self._wymaga(session, t)
            except AuthError as exc:
                self._json(exc.status, {"error": exc.message})
                return
            if ctx is None:
                self._api_konta(t.klucz, session)
                return
            self._api_domu(t.klucz.removeprefix(PREFIKS_DOMU), path, session, ctx, params)

        def _api_konta(self, klucz: str, session: Session) -> None:
            """GET poza domem: /api/auth/me i ekran bota WhatsApp."""
            if klucz == "/api/auth/me":
                self._json(200, self._me(session))
                return
            if klucz == "/api/whatsapp/komendy":
                self._json(200, komendy.stan() if komendy is not None
                           else {"wlaczone": False, "wpisy": []})
                return
            try:
                self._profile_get(klucz, session)
            except AuthError as exc:
                self._json(exc.status, {"error": exc.message})

        def _me(self, session: Session) -> dict:
            """Konto, jego domy z uprawnieniami per dom (przelacznik domow)
            i — dla zgodnosci z frontem sprzed domow — `rola`/`uprawnienia`
            jedynego domu (przy wielu: tylko konto i instancja)."""
            admin = self._admin(session)
            poza = uprawnienia_sesji(session, admin)
            widoczne = domy.widoczne(session, admin)
            lista = [{
                "id": w.dom.id,
                "nazwa": w.dom.nazwa,
                "rola": w.rola,
                "administracja": w.administracja,
                "uprawnienia": sorted(w.uprawnienia | poza),
            } for w in widoczne]
            jedyny = widoczne[0] if len(widoczne) == 1 else None
            return {
                "login": session.login,
                "session_expires_at": datetime.fromtimestamp(
                    session.expires_at, UTC).isoformat(),
                # sso: sesja z Authelii; logout_url: "Wyloguj" ma przejsc
                # przez portal, inaczej nastepne zadanie zalogowaloby od nowa.
                "sso": session.kind == "sso",
                # Front chowa przyciski wedlug `uprawnienia` (nie nazwy
                # roli); serwer i tak odmawia (403) niezaleznie od frontu.
                "rola": nazwa_roli(jedyny.rola) if jedyny and jedyny.rola else None,
                "uprawnienia": sorted(poza | (jedyny.uprawnienia if jedyny else frozenset())),
                "domy": lista,
                "admin_instancji": admin,
                # Argo CD w przelaczniku aplikacji: tylko wlasciciel (rola
                # konta `wlasciciel`, lustro Domu 1) albo aktywny administrator
                # instalacji. Decyzja tutaj, front tylko ja czyta; samo Argo
                # i tak stoi za Authelia z wlasna polityka dostepu.
                "pokaz_argo": pokaz_argo(session, admin),
                "logout_url": sso.logout_url if self._via_sso else None,
                **auth.account(session),
            }

        def _api_domu(self, rest: str, path: str, session: Session, ctx: KontekstDomu,
                      params: dict[str, str]) -> None:
            """GET trasy domu; `rest` = klucz bez PREFIKS_DOMU (`/day`)."""
            queries = ctx.queries
            if rest == "/meta":
                self._json(200, queries.meta())
                return
            if rest in ("/konto/powiadomienia", "/konta", "/dziennik"):
                try:
                    k, wd = self._konta(), self._w_domu(ctx)
                    self._json(200, {"/konto/powiadomienia": k.moje, "/konta": k.lista,
                                     "/dziennik": k.dziennik}[rest](session, wd))
                except AuthError as exc:
                    self._json(exc.status, {"error": exc.message})
                return
            if rest == "/export.csv":
                self._export(queries, params)
                return
            if rest in ("/integracje", "/integracje/stan"):
                try:
                    p = self._integracje()
                    akcja = p.lista if rest == "/integracje" else p.stan
                    self._json(200, akcja(session, ctx))
                except AuthError as exc:
                    self._json(exc.status, {"error": exc.message})
                return
            if rest == "/tv/aplikacja":
                self._json(200, stan_aplikacji(ctx.dom_id))
                return
            if rest == "/komendy":
                self._json(200, komendy.dziennik_domu(ctx.dom_id) if komendy is not None
                           else {"wlaczone": False, "wpisy": []})
                return
            if rest == "/mdm" or rest.startswith("/mdm/"):
                # Prefiks (UDID w sciezce): reszta sciezki zadania, nie klucz.
                m = _SCIEZKA_DOMU.fullmatch(path)
                self._mdm_get(m[2] if m else path.removeprefix("/api"), ctx)
                return
            routes = {
                "/screens": lambda c: queries.screens(c, params),
                "/trends": lambda c: queries.trends(c, params),
                "/devices": lambda c: queries.devices(c, params),
                "/notifications": lambda c: queries.notifications(c, params),
                "/day": lambda c: queries.day(c, params),
                "/usage": lambda c: queries.usage(c, params),
                "/tv/pause": lambda c: queries.tv_pause(c),
            }
            route = routes.get(rest)
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

        def _export(self, queries: PanelQueries, params: dict[str, str]) -> None:
            """CSV z agregatow dziennych. Sesja i dom sprawdzone wyzej w _api."""
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


def aplikacja_tv(dom_id: int):
    """Aplikacja Kidwatch TV domu. Rejestr jest jeszcze jeden na proces
    (`tv_app.AKTYWNA`, petla Domu 1; per dom — etap E3b/E6), wiec inny dom
    jej nie ma, zamiast dostac telewizor Domu 1."""
    from .sources import tv_app  # noqa: PLC0415

    return tv_app.AKTYWNA if dom_id == dm.DOM_1 else None


def stan_aplikacji(dom_id: int = dm.DOM_1) -> dict:
    """Stan aplikacji Kidwatch TV dla panelu (`available: false` = wylaczona)."""
    app = aplikacja_tv(dom_id)
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


#: Konfiguracja domu spoza config.yaml (E2: z bazy); None = dom bez konfiguracji.
KonfiguracjaDomu = Callable[[dm.Dom], HomeConfig | None]


def queries_domow(cfg: Config, konfiguracja_domu: KonfiguracjaDomu | None = None,
                  ) -> Callable[[dm.Dom], PanelQueries]:
    """Fabryka `PanelQueries` domu: baza domu (`sciezka_bazy_domu`)
    i konfiguracja z `konfiguracja_domu` — `run` podaje te sama, na ktorej
    chodzi srodowisko domu (dla Domu 1 w trybie `baza`: z bazy, E2). Bez niej
    Dom 1 w trybie `yaml` bierze config.yaml, jak przed domami; dom bez
    konfiguracji — panel bez urzadzen."""

    def zbuduj(dom: dm.Dom) -> PanelQueries:
        home: HomeConfig | BezKonfiguracji | None = None
        if konfiguracja_domu is not None:
            home = konfiguracja_domu(dom)
        if home is None and dom.id == dm.DOM_1 and dom.zrodlo_konfiguracji == dm.ZRODLO_YAML:
            home = cfg
        if home is None:
            home = BezKonfiguracji(timezone=dom.strefa)
        requests = (GameRequests(cfg.panel_auth_path, dom_id=dom.id)
                    if home.game_time.enabled else None)
        tv_requests = (TvPauseRequests(cfg.panel_auth_path, dom_id=dom.id)
                       if home.tv.enabled else None)
        q = PanelQueries(home, str(dm.sciezka_bazy_domu(dom.id, cfg.store.path)),
                         requests, tv_requests)
        if getattr(home, "sekrety", None) is not None and hasattr(home, "mdm"):
            q.mdm_z_bazy = True
            mdm_cfg = config_domu(home.mdm, cfg.mdm.url)
            q.mdm = build_api(mdm_cfg)
            # Token instancji w domu innym niz Dom 1 widzialby iPady Domu 1 (E3b):
            # porownanie z MDM_ADMIN_TOKEN, a dla domu != 1 takze serwer
            # (/api/whoami) — brak odpowiedzi to tez odmowa (fail-closed).
            if q.mdm is not None and zakres_tokenu(dom.id, mdm_cfg.token()) is None:
                q.mdm.close()
                q.mdm = None
            if q.mdm is not None and dom.id != dm.DOM_1:
                try:
                    zakres = zakres_z_whoami(dom.id, q.mdm.request("GET", "/api/whoami"))
                except MdmError as exc:
                    log.error("panel: dom %d: zakres tokenu MDM nieznany (%s) — MDM wylaczone",
                              dom.id, exc)
                    zakres = None
                if zakres is None:
                    q.mdm.close()
                    q.mdm = None
        return q

    return zbuduj


def _sejf_procesu():
    """KEK procesu dla ekranu integracji — czytany przy kazdym zadaniu: brak
    klucza (BrakKek) to 503 na tym ekranie, nie blad startu panelu."""
    from .sejf import Sejf  # noqa: PLC0415

    return Sejf.z_srodowiska()


def start_panel(cfg: Config, *, konfiguracja_domu: KonfiguracjaDomu | None = None,
                stany: dm.StanyDomow | None = None) -> ThreadingHTTPServer:
    """Startuje serwer panelu w watku demona i zwraca go (do `shutdown()`).
    `stany`: stan przeladowan domow od nadzorcy (domy.Nadzorca); None = ekran
    integracji mowi, ze zmiana zadziala po restarcie. Zwrocony serwer ma
    `domy_panelu` — `run` uniewaznia nim PanelQueries domu po przeladowaniu."""
    auth = PanelAuth(
        cfg.panel_auth_path, box=box_from_env(), session_seconds=cfg.panel.session_hours * 3600
    )
    domy_panelu = DomyPanelu(cfg.panel_auth_path, queries_domow(cfg, konfiguracja_domu))
    if not auth.has_users():
        log.warning(
            "panel: brak kont — nikt sie nie zaloguje. Zaloz konto: "
            "python -m kidwatch user-add <login>"
        )
    sso = sso_from_env()
    if sso is not None:
        log.info("panel: SSO wlaczone — sesja z naglowka Remote-User (grupy: %s)",
                 ", ".join(sso.groups))
    server = ThreadingHTTPServer(
        (cfg.panel.host, cfg.panel.port),
        make_handler(
            domy_panelu, Path(cfg.panel.static_dir), auth, cookie_secure=cfg.panel.cookie_secure,
            bramka=_bramka_admin(cfg), mdm=build_api(cfg.mdm), sso=sso,
            konta=PanelKonta(auth, ProfilePowiadomien(cfg.panel_auth_path)),
            integracje=PanelIntegracje(auth, _sejf_procesu, stany=stany),
            komendy=KomendyPanelu(cfg.panel_auth_path, cfg.whatsapp_komendy),
        ),
    )
    server.domy_panelu = domy_panelu
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="panel", daemon=True)
    thread.start()
    log.info("panel WWW na %s:%d", cfg.panel.host, cfg.panel.port)
    return server
