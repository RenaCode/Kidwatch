"""Wszystkie ekrany (iPady + TV), dokladny czas z usagestats, agregaty
dzienne, trendy i eksport CSV."""

from __future__ import annotations

import http.client
import json
from datetime import UTC, date, datetime, timedelta

import pytest

from conftest import local, make_config, panel_login
from kidwatch.classifier import Classifier
from kidwatch.config import PanelConfig, StoreConfig, TvConfig
from kidwatch.engine import Engine
from kidwatch.panel import BadRequest, PanelQueries, start_panel
from kidwatch.panel_auth import PanelAuth
from kidwatch.rollup import compute_day, refresh_rollups
from kidwatch.sources.tv import (
    TvProbe,
    TvWatcher,
    UsageSnapshot,
    parse_usagestats,
    usage_deltas,
)
from kidwatch.store import Store

TZ = local(2026, 10, 2, 0, 0).tzinfo
YT = "com.google.android.youtube.tv"


def ms(dt: datetime) -> int:
    return int(dt.timestamp() * 1000)


# ================================================================== usagestats
#: Ksztalt z UserUsageStatsService.printIntervalStats (android12-release) po
#: grepie z USAGE_COMMAND, z -c: liczby w milisekundach.
DUMP = """user=0
  In-memory daily stats
    beginTime=1790892000000 endTime=1790935200000
      package=com.google.android.youtube.tv totalTimeUsed=4805000 lastTimeUsed=1790935000000 totalTimeVisible=4900000 lastTimeVisible=1790935000000 lastTimeComponentUsed=0 totalTimeFS=0 lastTimeFS=0 appLaunchCount=3
      package=com.google.android.tvlauncher totalTimeUsed=600000 lastTimeUsed=1790935100000 totalTimeVisible=600000 lastTimeVisible=0 lastTimeComponentUsed=0 totalTimeFS=0 lastTimeFS=0 appLaunchCount=9
  In-memory weekly stats
    beginTime=1790460000000 endTime=1790935200000
      package=com.google.android.youtube.tv totalTimeUsed=99999999 lastTimeUsed=1790935000000 totalTimeVisible=0 lastTimeVisible=0 lastTimeComponentUsed=0 totalTimeFS=0 lastTimeFS=0 appLaunchCount=30
"""  # noqa: E501


def test_parser_bierze_tylko_blok_dzienny():
    snap = parse_usagestats(DUMP)
    assert snap.begin == 1790892000000
    assert snap.packages[YT] == (4805000, 1790935000000)
    assert set(snap.packages) == {YT, "com.google.android.tvlauncher"}


def test_parser_przyjmuje_format_bez_c():
    text = (
        "  In-memory daily stats\n"
        '    timeRange="2 paź 2026, 00:00 – 12:00"\n'
        '      package=com.netflix.ninja totalTimeUsed="1:20:05" '
        'lastTimeUsed="2026-10-02 11:00:00" totalTimeVisible="1:21:00"\n'
    )
    assert parse_usagestats(text).packages["com.netflix.ninja"][0] == 4805000


def test_parser_bez_bloku_dziennego():
    assert parse_usagestats("Last 24 hour events (beginTime=1 endTime=2)\n") is None


def test_przyrosty_w_interwale_i_po_jego_zmianie():
    first, state = usage_deltas(None, UsageSnapshot(100, {YT: (60_000, 5)}))
    assert first == [(YT, 60_000, 5)]
    same, state = usage_deltas(state, UsageSnapshot(100, {YT: (90_000, 6)}))
    assert same == [(YT, 30_000, 6)]
    nothing, state = usage_deltas(state, UsageSnapshot(100, {YT: (90_000, 6)}))
    assert nothing == []
    # Nowy interwal dzienny: licznik od zera, liczymy caly.
    rolled, _ = usage_deltas(state, UsageSnapshot(200, {YT: (10_000, 7)}))
    assert rolled == [(YT, 10_000, 7)]


def test_cofniety_licznik_w_tym_samym_interwale_nie_dubluje_czasu():
    # Audyt runda 4, pkt 7: TV wyjety z pradu wczytuje starszy zapis
    # usagestats (ten sam beginTime, mniejsze sumy). 2 h -> 3 h -> 2,6 h ->
    # 2,8 h to 3 h ogladania, nie 5,8 h.
    hour = 3_600_000
    total = 0
    state = None
    for value in (2 * hour, 3 * hour, int(2.6 * hour), int(2.8 * hour), int(3.2 * hour)):
        deltas, state = usage_deltas(state, UsageSnapshot(100, {YT: (value, 1)}))
        total += sum(ms for _, ms, _ in deltas)
    assert total == int(3.2 * hour)


def test_odczyt_bez_beginTime_jest_pomijany():
    state = None
    for value in (60_000, 90_000):
        deltas, state = usage_deltas(state, UsageSnapshot(0, {YT: (value, 1)}))
        assert deltas == []


def test_zapis_przyrostow_po_dniu_konca_uzycia_bez_ekranu_glownego():
    store = Store(":memory:")
    w = TvWatcher(TvProbe(None), "TV salon", store, tz=TZ, usage_minutes=15)
    now = local(2026, 10, 3, 0, 5).astimezone(UTC)
    ended = local(2026, 10, 2, 23, 50)
    snap = UsageSnapshot(1, {YT: (20 * 60_000, ms(ended)),
                             "com.google.android.tvlauncher": (60_000, ms(ended))})
    assert w.record_usage(snap, now) == 20 * 60_000
    assert store.tv_usage_between("TV salon", "2026-10-02", "2026-10-02") == [
        ("YouTube", 20 * 60_000)
    ]
    # Ponowny odczyt bez zmian nic nie dopisuje.
    assert w.record_usage(snap, now) == 0


async def test_odczyt_usagestats_co_15_minut():
    class Shell:
        def __init__(self):
            self.calls = []

        async def shell(self, cmd):
            self.calls.append(cmd)
            if "usagestats" in cmd:
                return DUMP
            if "power" in cmd:
                return "mWakefulness=Asleep"
            return ""

        async def aclose(self):
            pass

    shell = Shell()
    store = Store(":memory:")
    w = TvWatcher(TvProbe(shell), "TV salon", store, tz=TZ, usage_minutes=15)
    t = local(2026, 10, 2, 12, 0).astimezone(UTC)
    for minute in (0, 5, 14, 15):
        await w.poll(t + timedelta(minutes=minute))
    assert sum("usagestats" in c for c in shell.calls) == 2


# ================================================================== agregaty
@pytest.fixture
def disk(tmp_path):
    cfg = make_config(
        panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path / "web"),
                          cookie_secure=False),
        tv=TvConfig(enabled=True, host="192.0.2.10"),
    )
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    store = Store(cfg.store.path)
    yield cfg, store
    store.close()


def fill(store):
    """2.10: Kuba 15:00-15:47 (Roblox, YouTube) i 23:00-23:20 w nocy; Zosia
    16:00-16:30; TV 19:00-20:00 Bluey + 40 min YouTube wg usagestats.
    Tydzien wczesniej (25.09) Kuba 30 min."""
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 15, 0))
    for m in range(3):
        store.record_app_minute(sid, "Roblox", local(2026, 10, 2, 15, m))
    store.record_app_minute(sid, "YouTube", local(2026, 10, 2, 15, 5))
    store.close_session(sid, local(2026, 10, 2, 15, 47))
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 23, 0))
    for m in range(4):
        store.record_app_minute(sid, "YouTube", local(2026, 10, 2, 23, m))
    store.close_session(sid, local(2026, 10, 2, 23, 20))
    sid = store.open_session("iPad Zosi", "Zosia", local(2026, 10, 2, 16, 0))
    store.record_app_minute(sid, "Minecraft", local(2026, 10, 2, 16, 0))
    store.close_session(sid, local(2026, 10, 2, 16, 30))
    sid = store.open_session("TV salon", None, local(2026, 10, 2, 19, 0))
    store.mark_start_notified(sid)
    store.open_tv_segment(sid, "TV salon", local(2026, 10, 2, 19, 0),
                          "com.disney.disneyplus", "Disney+", "Bluey", None)
    for m in range(0, 60, 10):
        store.record_app_minute(sid, "Disney+", local(2026, 10, 2, 19, m))
    store.close_tv_segments("TV salon", local(2026, 10, 2, 20, 0))
    store.close_session(sid, local(2026, 10, 2, 20, 0))
    store.add_tv_usage("TV salon", "2026-10-02", YT, "YouTube", 40 * 60_000, None)
    store.add_tv_usage("TV salon", "2026-10-02", "com.disney.disneyplus", "Disney+",
                       58 * 60_000, None)
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 9, 25, 10, 0))
    store.record_app_minute(sid, "YouTube", local(2026, 9, 25, 10, 0))
    store.close_session(sid, local(2026, 9, 25, 10, 30))


def test_agregat_dnia(disk):
    cfg, store = disk
    fill(store)
    rows = {r["device"]: r for r in compute_day(cfg, store, date(2026, 10, 2),
                                                 datetime.now(UTC))}
    kuba = rows["iPad Kuby"]
    assert (kuba["minutes"], kuba["sessions"], kuba["night_minutes"]) == (67, 2, 4)
    assert json.loads(kuba["top_apps"])[0] == ["YouTube", 5]
    assert kuba["tv_minutes"] is None and kuba["child"] == "Kuba"
    tv = rows["TV salon"]
    assert (tv["kind"], tv["child"], tv["minutes"], tv["tv_minutes"]) == ("tv", None, 60, 98)
    assert json.loads(tv["tv_apps"]) == [["Disney+", 58], ["YouTube", 40]]


def test_agregaty_uzupelniaja_historie_i_przezywaja_retencje(disk):
    cfg, store = disk
    fill(store)
    now = local(2026, 10, 3, 12, 0).astimezone(UTC)
    assert refresh_rollups(cfg, store, now) == 9  # 25.09 .. 03.10
    # Za wczesnie na kolejne przeliczenie.
    assert refresh_rollups(cfg, store, now + timedelta(minutes=5)) == 0
    # Retencja surowych danych kasuje sesje — agregat zostaje.
    store.purge(local(2026, 11, 30, 0, 0).astimezone(UTC), retention_days=30)
    assert store.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
    left = store.conn.execute(
        "SELECT minutes FROM daily_rollup WHERE day='2026-10-02' AND device='iPad Kuby'"
    ).fetchone()
    assert left[0] == 67
    assert store.conn.execute("SELECT COUNT(*) FROM tv_usage").fetchone()[0] == 0
    # Osobna, jawna retencja agregatow.
    store.purge(local(2026, 11, 30, 0, 0).astimezone(UTC), 30, rollup_days=60)
    assert store.conn.execute("SELECT MIN(day) FROM daily_rollup").fetchone()[0] == "2026-09-30"


def test_tik_silnika_liczy_agregaty(disk, app_map):
    cfg, store = disk
    fill(store)
    Engine(cfg, store, Classifier(app_map)).tick(local(2026, 10, 3, 12, 0).astimezone(UTC))
    assert "2026-10-02" in store.rollup_days()


def test_raport_tygodnia_z_dokladnym_czasem_tv(disk, app_map):
    cfg, store = disk
    fill(store)
    note = Engine(cfg, store, Classifier(app_map)).build_weekly(
        date(2026, 9, 28), local(2026, 10, 4, 19, 0).astimezone(UTC)
    )
    assert "Dokladnie z TV (1 h 38 min):\n\u2022 Disney+ 58 min\n\u2022 YouTube 40 min" in note.text


# ============================================================ wszystkie ekrany
def test_ekrany_dziecka_z_TV_jako_wspolnym_pasem(disk):
    cfg, store = disk
    fill(store)
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        kuba = q.screens(conn, {"day": "2026-10-02", "child": "Kuba"})
        wszyscy = q.screens(conn, {"day": "2026-10-02"})
    assert [(x["name"], x["shared"]) for x in kuba["lanes"]] == [
        ("iPad Kuby", False), ("TV salon", True)
    ]
    # TV jest widoczny, ale NIE doliczony do dziecka.
    assert kuba["totals"]["day"] == {"own": 67, "shared": 60}
    assert kuba["totals"]["week"] == {"own": 67, "shared": 60}
    assert wszyscy["totals"]["day"] == {"own": 97, "shared": 60}
    assert kuba["week_from"] == "2026-09-28"
    tv_lane = kuba["lanes"][1]
    assert tv_lane["sessions"][0]["titles"][0]["title"] == "Bluey"
    tv = kuba["tv"]
    assert tv["exact_day_total"] == 98
    assert tv["exact_day"][0] == {"app": "Disney+", "minutes": 58, "estimate_minutes": 6}
    assert tv["exact_week"][1] == {"app": "YouTube", "minutes": 40}


def test_ekrany_bez_telewizora(disk):
    cfg, store = disk
    cfg.tv = TvConfig()
    fill(store)
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        res = q.screens(conn, {"day": "2026-10-02", "child": "Zosia"})
    assert res["tv"] is None
    assert [x["name"] for x in res["lanes"]] == ["iPad Zosi"]


# ===================================================================== trendy
def test_trendy_tydzien_do_tygodnia_i_12_tygodni(disk):
    cfg, store = disk
    fill(store)
    refresh_rollups(cfg, store, local(2026, 10, 3, 12, 0).astimezone(UTC))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        res = q.trends(conn, {"until": "2026-10-03", "child": "Kuba"})
    assert [s["key"] for s in res["series"]] == ["Kuba", "TV salon"]
    week = {s["key"]: s for s in res["compare"]["week"]["series"]}
    cur, prev = week["Kuba"]["current"], week["Kuba"]["previous"]
    assert (cur["minutes"], cur["days"], cur["avg_daily"]) == (67, 6, 11)
    assert (prev["minutes"], prev["days"], prev["avg_daily"]) == (30, 7, 4)
    assert cur["night_minutes"] == 4
    assert cur["top_apps"][0] == {"app": "YouTube", "minutes": 5}
    assert week["TV salon"]["shared"] is True
    assert week["TV salon"]["current"]["tv_exact_minutes"] == 98
    month = {s["key"]: s for s in res["compare"]["month"]["series"]}
    assert month["Kuba"]["current"]["minutes"] == 67
    assert month["Kuba"]["previous"]["minutes"] == 30
    assert len(res["weeks"]) == 12
    assert res["weeks"][-1] == {"week": "2026-W40", "from": "2026-09-28",
                                "values": {"Kuba": 67, "TV salon": 60}, "partial": True}
    assert res["weeks"][-2]["values"]["Kuba"] == 30


def test_trendy_nieznane_dziecko(disk):
    cfg, _ = disk
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn, pytest.raises(BadRequest):
        q.trends(conn, {"child": "Ola"})


# ====================================================================== CSV
def get(port, path, cookie=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Cookie": cookie} if cookie else {})
    r = conn.getresponse()
    body = r.read()
    conn.close()
    return r, body


def test_eksport_csv_tylko_zalogowany_z_naglowkami(disk):
    cfg, store = disk
    fill(store)
    store.add_tv_usage("TV salon", "2026-10-01", "x.y", "=HYPERLINK(1)", 60_000, None)
    refresh_rollups(cfg, store, local(2026, 10, 3, 12, 0).astimezone(UTC))
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    port = server.server_address[1]
    try:
        r, _ = get(port, "/api/export.csv?from=2026-10-01&to=2026-10-02")
        assert r.status == 401
        cookie = panel_login(port, "rodzic", "dlugie-haslo-testowe")
        r, body = get(port, "/api/export.csv?from=2026-10-01&to=2026-10-02", cookie)
        assert r.status == 200
        assert r.headers["Content-Type"] == "text/csv; charset=utf-8"
        assert r.headers["Content-Disposition"] == (
            'attachment; filename="kidwatch-2026-10-01_2026-10-02.csv"'
        )
        text = body.decode("utf-8")
        assert text.startswith("﻿dzien,urzadzenie,dziecko,rodzaj,minuty")
        lines = text.strip().split("\r\n")
        assert len(lines) == 1 + 2 * 3  # dwa dni x trzy urzadzenia
        assert "2026-10-02,iPad Kuby,Kuba,ipad,67,2,4,,YouTube 5; Roblox 3," in lines
        # Nazwa aplikacji wygladajaca jak formula nie wykona sie w Excelu.
        assert any(",'=HYPERLINK(1) 1" in line for line in lines)

        r, body = get(port, "/api/export.csv?from=2026-10-01&to=2026-10-02&child=Zosia",
                      cookie)
        lines = body.decode("utf-8").strip().split("\r\n")
        assert {line.split(",")[1] for line in lines[1:]} == {"iPad Zosi"}

        r, _ = get(port, "/api/export.csv?from=2026-10-05&to=2026-10-02", cookie)
        assert r.status == 400
        r, _ = get(port, "/api/export.csv?from=2000-01-01&to=2026-10-02", cookie)
        assert r.status == 400
        r, body = get(port, "/api/screens?day=2026-10-02&child=Kuba", cookie)
        assert r.status == 200 and json.loads(body)["totals"]["day"]["shared"] == 60
        r, body = get(port, "/api/trends", cookie)
        assert r.status == 200 and len(json.loads(body)["weeks"]) == 12
    finally:
        server.shutdown()
