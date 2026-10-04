"""Agregaty dzienne (tabela daily_rollup) — historia dluzsza niz retencja.

Surowe zdarzenia DNS i sesje znikaja po `store.retention_days` (30 dni), a
trendy "12 tygodni" i "miesiac do miesiaca" potrzebuja wiecej. Raz policzony
dzien zostaje jako jeden wiersz na urzadzenie: minuty, sesje, top aplikacje,
minuty nocne i — dla telewizora — dokladne minuty z usagestats.

Liczymy TAK SAMO jak /api/usage i /api/day w panelu: sesja nalezy do dnia,
w ktorym sie zaczela, minuty to czas od pierwszego do ostatniego zdarzenia.
Inaczej wykres trendu i wykres dzienny pokazywalyby rozne liczby za ten sam
dzien.

Kiedy: dzis i wczoraj co ROLLUP_EVERY (sesja przez polnoc domyka sie juz po
polnocy), plus kazdy dzien z sesjami, ktory jeszcze nie ma agregatu —
pierwszy start po aktualizacji zbiera cala istniejaca historie, a przerwa
w dzialaniu serwisu nie zostawia dziury. Starsze dni sa juz ostateczne.
"""

from __future__ import annotations

import json
import logging
from datetime import date, datetime, time, timedelta

from .config import Config
from .store import Store, from_iso, to_iso

log = logging.getLogger(__name__)

ROLLUP_EVERY = timedelta(minutes=15)
#: Wersja sposobu liczenia. Zmiana przelicza raz wszystkie dni, ktore maja
#: jeszcze surowe sesje — "starsze dni sa ostateczne" dotyczy danych, nie
#: regul. 2: tylko sesje potwierdzone (bez samotnych zapytan w tle, ktore
#: wersja 1 liczyla jako sesje i minuty nocne).
ROLLUP_VERSION = 2
#: Ile aplikacji trzymac w agregacie. Wiecej nie pokaze zaden widok.
TOP_APPS = 10


def _session_minutes(row) -> int:
    end = row["ended_at"] or row["last_activity_at"]
    return max(0, round((from_iso(end) - from_iso(row["started_at"])).total_seconds() / 60))


def compute_day(cfg: Config, store: Store, day: date, now: datetime) -> list[dict]:
    """Wiersze daily_rollup dla wszystkich obserwowanych urzadzen w dniu `day`.
    Urzadzenie bez aktywnosci dostaje wiersz z zerami — dzien bez uzycia to
    tez informacja, a ponowne przeliczenie musi umiec "wyzerowac" dzien."""
    tz = cfg.tz
    start = datetime.combine(day, time.min, tzinfo=tz)
    rows = store.sessions_between(start, start + timedelta(days=1))
    window = cfg.engine.night_window()
    out = []
    for dev in cfg.watched:
        sessions = [r for r in rows if r["device"] == dev.name]
        apps: dict[str, int] = {}
        night = set()
        for row in sessions:
            sid = int(row["id"])
            for app, n in store.session_app_minutes(sid):
                apps[app] = apps.get(app, 0) + n
            if window is not None:
                night.update(
                    m for m in store.session_minutes(sid)
                    if window.contains(m.astimezone(tz).time())
                )
        top = sorted(apps.items(), key=lambda kv: (-kv[1], kv[0]))[:TOP_APPS]
        tv_minutes = tv_apps = None
        if dev.kind == "tv":
            usage = store.tv_usage_between(dev.name, day.isoformat(), day.isoformat())
            tv_minutes = round(sum(ms for _, ms in usage) / 60000)
            tv_apps = json.dumps(
                [[app, round(ms / 60000)] for app, ms in usage[:TOP_APPS]], ensure_ascii=False
            )
        out.append({
            "day": day.isoformat(),
            "device": dev.name,
            "child": dev.child,
            "kind": dev.kind,
            "minutes": sum(_session_minutes(r) for r in sessions),
            "sessions": len(sessions),
            "night_minutes": len(night),
            "tv_minutes": tv_minutes,
            "top_apps": json.dumps([list(t) for t in top], ensure_ascii=False),
            "tv_apps": tv_apps,
            "computed_at": to_iso(now),
        })
    return out


def days_to_refresh(cfg: Config, store: Store, now: datetime) -> list[date]:
    today = now.astimezone(cfg.tz).date()
    days = {today, today - timedelta(days=1)}
    span = store.session_start_range()
    if span is not None:
        done = store.rollup_days()
        first = from_iso(span[0]).astimezone(cfg.tz).date()
        recount = store.get_meta("rollup_version") != str(ROLLUP_VERSION)
        # Przy przeliczaniu nie ruszamy dnia, ktory retencja mogla juz
        # nadgryzc (sesje kasowane po ended_at) — wyzerowalibysmy historie.
        retention = cfg.store.retention_days
        safe = (now - timedelta(days=retention)).astimezone(cfg.tz).date() + timedelta(days=1)
        d = first
        while d < today:
            if d.isoformat() not in done or (recount and (not retention or d >= safe)):
                days.add(d)
            d += timedelta(days=1)
    return sorted(days)


def refresh_rollups(cfg: Config, store: Store, now: datetime, force: bool = False) -> int:
    """Przelicza agregaty, nie czesciej niz co ROLLUP_EVERY. Zwraca liczbe dni."""
    last = store.get_meta("rollup_at")
    if not force and last is not None and now - from_iso(last) < ROLLUP_EVERY:
        return 0
    store.set_meta("rollup_at", to_iso(now))
    days = days_to_refresh(cfg, store, now)
    for day in days:
        for row in compute_day(cfg, store, day, now):
            store.upsert_rollup(row)
    store.set_meta("rollup_version", str(ROLLUP_VERSION))
    if len(days) > 2:
        log.info("agregaty dzienne: przeliczono %d dni (uzupelnienie historii)", len(days))
    return len(days)
