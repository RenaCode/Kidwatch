"""Potwierdzanie sesji: iPad lezacy na biurku nie moze dawac sesji "0 min"
z pushami start+koniec. Progi produkcyjne (confirm_minutes=5,
confirm_moments=3) — conftest dla innych testow luzuje je do 1."""

from __future__ import annotations

from datetime import UTC, date, timedelta
from pathlib import Path

import pytest

from conftest import ev, local, make_config
from kidwatch.classifier import Classifier
from kidwatch.engine import Engine
from kidwatch.models import NotifyKind
from kidwatch.rollup import compute_day
from kidwatch.store import Store

OCSP = "eip-terr-eu.cdp1.digicert.com.akahost.net"


@pytest.fixture
def eng(classifier):
    cfg = make_config(engine={"confirm_moments": 3, "confirm_minutes": 5},
                      watchdog={"enabled": False})
    return Engine(cfg, Store(":memory:"), classifier)


@pytest.fixture
def prod_eng():
    """Jak `eng`, ale z prawdziwym app_map.yaml: w odswiezeniu w tle liczy
    sie, ktore domeny pakietu sa aplikacja, a ktore szumem."""
    cfg = make_config(engine={"confirm_moments": 3, "confirm_minutes": 5},
                      watchdog={"enabled": False})
    app_map = Path(__file__).resolve().parents[1] / "app_map.yaml"
    return Engine(cfg, Store(":memory:"), Classifier(app_map))


SESSION_KINDS = {NotifyKind.SESSION_START, NotifyKind.SESSION_END, NotifyKind.APP,
                 NotifyKind.NIGHT}


def run(eng, events, until):
    """Zdarzenia [(czas, domena)] + tik co 30 s do `until`. Tylko pushe sesji —
    podsumowanie dnia o 20:30 nie jest tematem tych testow."""
    out = []
    events = sorted(events)
    t = events[0][0]
    while t <= until:
        while events and events[0][0] <= t:
            out += eng.handle(ev(*events.pop(0)))
        out += eng.tick(t)
        t += timedelta(seconds=30)
    return [n for n in out if n.kind in SESSION_KINDS]


@pytest.mark.parametrize("domain", [
    "www.youtube.com",   # odswiezenie YouTube w tle
    OCSP,                # sprawdzenie certyfikatu
    "ecsv3.roblox.com",  # powiadomienie aplikacji (jak Happy Color)
])
def test_pojedyncze_zapytanie_nie_daje_sesji_ani_pushy(eng, domain):
    t = local(2026, 10, 2, 14, 0)
    out = run(eng, [(t, domain)], t + timedelta(minutes=20))
    assert out == []
    row = eng.store.conn.execute("SELECT * FROM sessions").fetchone()
    # Zostaje w bazie (diagnostyka), zamknieta i oznaczona.
    assert row["confirmed"] == 0 and row["ended_at"] is not None
    # ...ale nie liczy sie nigdzie.
    summary = eng.build_summary(date(2026, 10, 2), t + timedelta(hours=8))
    assert "*Kuba* — brak aktywnosci" in summary.text
    rollup = {r["device"]: r for r in compute_day(eng.cfg, eng.store, date(2026, 10, 2), t)}
    assert rollup["iPad Kuby"]["sessions"] == 0 and rollup["iPad Kuby"]["minutes"] == 0


def test_kilka_zapytan_w_jednej_chwili_to_dalej_tlo(eng):
    t = local(2026, 10, 2, 14, 0)
    events = [(t + timedelta(seconds=s), d) for s, d in
              ((0, "www.youtube.com"), (2, "i.ytimg.com"), (3, OCSP), (59, "www.youtube.com"))]
    assert run(eng, events, t + timedelta(minutes=20)) == []


def test_prawdziwa_sesja_nie_traci_startu(eng):
    """Ogladanie z zapytaniami co 20 s: start po minucie, z godzina poczatku."""
    t = local(2026, 10, 2, 15, 0)
    events = [(t + timedelta(seconds=20 * i), "r1.googlevideo.com") for i in range(30)]
    out = run(eng, events, t + timedelta(minutes=25))
    starts = [n for n in out if n.kind is NotifyKind.SESSION_START]
    ends = [n for n in out if n.kind is NotifyKind.SESSION_END]
    assert len(starts) == 1 and len(ends) == 1
    assert starts[0].text == "15:00 — YouTube"
    assert starts[0].ts == (t + timedelta(minutes=1)).astimezone(UTC)
    assert "15:00–15:09" in ends[0].text


# Odswiezenie YouTube w tle na lezacym iPadzie (wzor z produkcji, 2026-10):
# pakiet zapytan w JEDNEJ sekundzie, razem z szumem analityki i Apple.
BACKGROUND_BURST = (
    "youtubei.googleapis.com",
    "redirector.googlevideo.com",
    "rr5---sn-abcd1234.googlevideo.com",
    "rr2---sn-abcd1234.googlevideo.com",
    "s.youtube.com",
    "app-measurement.com",
    "oauth2.googleapis.com",
    "gateway.icloud.com",
)


def assert_nothing_counted(eng, day):
    rows = eng.store.conn.execute("SELECT * FROM sessions").fetchall()
    assert rows and all(r["confirmed"] == 0 and r["start_notified"] == 0 for r in rows)
    end = local(2026, 10, 3, 23, 0)
    rollup = {r["device"]: r for r in compute_day(eng.cfg, eng.store, day, end)}
    assert rollup["iPad Kuby"]["sessions"] == 0 and rollup["iPad Kuby"]["minutes"] == 0


def test_pakiet_zapytan_w_jednej_sekundzie_to_odswiezenie_w_tle(prod_eng):
    """Piec i wiecej zapytan aplikacji w tej samej sekundzie to JEDNA chwila
    aktywnosci — dawniej "seria 5 zapytan" potwierdzala sesje z pushem."""
    t = local(2026, 10, 3, 13, 41, 47)
    out = run(prod_eng, [(t, d) for d in BACKGROUND_BURST], t + timedelta(minutes=20))
    assert out == []
    assert_nothing_counted(prod_eng, date(2026, 10, 3))


def test_pakiet_i_pojedyncze_zapytanie_cdn_po_minucie_to_dalej_tlo(prod_eng):
    """Dokladnie wzor z produkcji: pakiet, jedno rr* po 65 s i cisza. Sama
    rozpietosc >= 1 min dawniej tez potwierdzala."""
    t = local(2026, 10, 3, 13, 41, 47)
    events = [(t, d) for d in BACKGROUND_BURST]
    events.append((t + timedelta(seconds=65), "rr5---sn-abcd1234.googlevideo.com"))
    out = run(prod_eng, events, t + timedelta(minutes=20))
    assert out == []
    assert_nothing_counted(prod_eng, date(2026, 10, 3))


def test_ogladanie_potwierdza_sie_w_ciagu_dwoch_minut(prod_eng):
    """Prawdziwe ogladanie: otwarcie aplikacji pakietem, potem segmenty
    googlevideo co 10-20 s przez 3 minuty."""
    t = local(2026, 10, 3, 15, 0)
    events = [(t, d) for d in BACKGROUND_BURST]
    s = 0
    for gap in [10, 20, 15, 10, 20, 15] * 3:
        s += gap
        events.append((t + timedelta(seconds=s), "rr5---sn-abcd1234.googlevideo.com"))
    out = run(prod_eng, events, t + timedelta(minutes=20))
    starts = [n for n in out if n.kind is NotifyKind.SESSION_START]
    assert len(starts) == 1
    assert starts[0].text == "15:00 — YouTube"
    assert starts[0].ts <= (t + timedelta(minutes=2)).astimezone(UTC)


@pytest.mark.parametrize("gaps", [[30, 45, 60] * 3, [60] * 8])
def test_gra_z_ruchem_co_30_60_s_jest_sesja(prod_eng, gaps):
    t = local(2026, 10, 3, 16, 0)
    events = [(t, "ecsv3.roblox.com")]
    s = 0
    for gap in gaps:
        s += gap
        events.append((t + timedelta(seconds=s), "assetgame.roblox.com"))
    out = run(prod_eng, events, t + timedelta(minutes=30))
    starts = [n for n in out if n.kind is NotifyKind.SESSION_START]
    assert len(starts) == 1 and starts[0].text == "16:00 — Roblox"
    assert starts[0].ts <= (t + timedelta(minutes=2)).astimezone(UTC)


def test_gra_odzywajaca_sie_co_3_minuty_jest_sesja(eng):
    """Wzor z nagrania Asphalta: zapytanie gry co ~3 min."""
    t = local(2026, 10, 2, 17, 10)
    events = [(t + timedelta(seconds=190 * i), "ecsv3.roblox.com") for i in range(8)]
    out = run(eng, events, t + timedelta(minutes=40))
    starts = [n for n in out if n.kind is NotifyKind.SESSION_START]
    assert len(starts) == 1 and starts[0].text.startswith("17:10")


def test_samotny_ping_nie_przesuwa_poczatku_prawdziwej_sesji(eng):
    t = local(2026, 10, 2, 14, 0)
    events = [(t, OCSP)] + [
        (t + timedelta(minutes=8, seconds=20 * i), "r1.googlevideo.com") for i in range(10)
    ]
    out = run(eng, events, t + timedelta(minutes=12))
    [start] = [n for n in out if n.kind is NotifyKind.SESSION_START]
    assert start.text == "14:08 — YouTube"
    row = eng.store.conn.execute("SELECT * FROM sessions").fetchone()
    assert row["confirmed"] == 1
    assert row["started_at"].startswith("2026-10-02T12:08")  # UTC


def test_alarm_nocny_dopiero_po_potwierdzeniu(eng):
    t = local(2026, 10, 2, 23, 30)
    assert run(eng, [(t, "www.youtube.com")], t + timedelta(minutes=20)) == []
    t2 = local(2026, 10, 3, 1, 0)
    events = [(t2 + timedelta(seconds=20 * i), "r1.googlevideo.com") for i in range(10)]
    out = run(eng, events, t2 + timedelta(minutes=3))
    [start] = [n for n in out if n.dedup_key.startswith("start:")]
    assert start.kind is NotifyKind.NIGHT
    assert start.title == "\U0001F319 Kuba uzywa iPada w nocy"
    assert start.text.startswith("01:00")
