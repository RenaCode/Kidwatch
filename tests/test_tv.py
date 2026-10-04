"""Czujnik telewizora: parsowanie dumpsys, sesje ogladania, pushe, podsumowanie.

Probki w tests/fixtures/tv/ maja uklad dumpsys z Androida 12 i wartosci
z prawdziwego telewizora (YouTube "Myjka okien | Fiksiki ...", Disney+
"Bluey" z state=2, Netflix z metadata null). Po aktualizacji systemu TV
nagraj nowe:  python -m kidwatch tv --raw
"""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest

from conftest import local, make_config
from kidwatch.config import TvConfig
from kidwatch.engine import Engine
from kidwatch.models import NotifyKind
from kidwatch.scheduler import device_loop
from kidwatch.sources.tv import (
    TvProbe,
    TvUnavailable,
    TvWatcher,
    parse_description,
    parse_media_sessions,
    parse_snapshot,
)
from kidwatch.store import Store

FIX = Path(__file__).parent / "fixtures" / "tv"


def fx(name: str) -> str:
    return (FIX / f"{name}.txt").read_text(encoding="utf-8")


def snap(media: str, activity: str = "youtube", power: str = "awake"):
    return parse_snapshot(fx(f"media_{media}"), fx(f"activity_{activity}"), fx(f"power_{power}"))


# ================================================================= parsowanie
def test_youtube_tytul_i_kanal_z_opisu_z_przecinkami():
    sessions = parse_media_sessions(fx("media_youtube_playing"))
    yt = sessions[0]
    assert yt.package == "com.google.android.youtube.tv"
    assert yt.active is True
    assert yt.state == 3
    assert yt.title == "Myjka okien | Fiksiki | Zabawa Nauka dla dzieci"
    assert yt.channel == "Fiksiki"
    disney = sessions[1]
    assert (disney.package, disney.active, disney.state, disney.title, disney.channel) == (
        "com.disney.disneyplus", False, 2, "Bluey", None,
    )


def test_opis_dzielony_od_prawej():
    assert parse_description("A, B, tytul z przecinkiem, Kanal, null") == (
        "A, B, tytul z przecinkiem", "Kanal",
    )
    assert parse_description("null") == (None, None)
    assert parse_description(None) == (None, None)


def test_netflix_bez_metadanych_to_sama_nazwa_aplikacji():
    playing = snap("netflix", "launcher").playing({})
    assert playing is not None
    assert playing.app == "Netflix"
    assert playing.title is None
    assert playing.label == "Netflix"


def test_youtube_gra_z_etykieta_kanal_tytul_aplikacja():
    playing = snap("youtube_playing").playing({})
    assert playing.label == "Fiksiki: Myjka okien | Fiksiki | Zabawa Nauka dla dzieci (YouTube)"


def test_pauza_liczy_sie_tylko_na_pierwszym_planie():
    """Disney+ state=2 active=true: dziecko zatrzymalo bajke — dalej oglada.
    Ta sama sesja, gdy na ekranie jest ekran glowny, to juz nie ogladanie."""
    assert snap("disney_paused", "disney").playing({}).label == "Bluey (Disney+)"
    assert snap("disney_paused", "launcher").playing({}) is None


def test_uspiony_ekran_i_wygaszacz_to_nie_ogladanie():
    assert snap("youtube_playing", power="asleep").playing({}) is None
    assert snap("youtube_playing", power="dreaming").playing({}) is None


def test_brak_sesji_to_nic_nie_gra():
    assert snap("empty").playing({}) is None


def test_nazwa_aplikacji_z_konfiguracji_nadpisuje_wbudowana():
    assert snap("netflix").playing({"com.netflix.ninja": "Netfliks"}).app == "Netfliks"


# ===================================================================== sesje
@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def watcher(store, **kw):
    return TvWatcher(TvProbe(None), "TV salon", store, tz=local(2026, 10, 2, 0, 0).tzinfo,
                     idle_minutes=10, **kw)


def test_start_push_zmiana_tytulu_tylko_w_panelu_koniec_push(store):
    w = watcher(store)
    t0 = local(2026, 10, 2, 9, 0)
    start = w.observe(snap("youtube_playing"), t0)
    assert [n.kind for n in start] == [NotifyKind.TV_START]
    assert start[0].title == (
        "TV salon: start — Fiksiki: Myjka okien | Fiksiki | Zabawa Nauka dla dzieci (YouTube)"
    )

    # Ten sam tytul i kolejny — bez pushy.
    assert w.observe(snap("youtube_playing"), t0 + timedelta(seconds=30)) == []
    assert w.observe(snap("disney_paused", "disney"), t0 + timedelta(minutes=20)) == []
    assert w.observe(snap("netflix"), t0 + timedelta(minutes=40)) == []
    t_last = t0 + timedelta(minutes=55)
    assert w.observe(snap("netflix"), t_last) == []

    # Przerwa krotsza niz idle — dalej ta sama sesja.
    assert w.observe(snap("empty", "launcher"), t_last + timedelta(minutes=5)) == []
    end = w.observe(snap("empty", "launcher"), t_last + timedelta(minutes=10))
    assert [n.kind for n in end] == [NotifyKind.TV_END]
    assert end[0].title == "TV salon: koniec — 3 tytuły, 55 min"
    assert "Fiksiki: Myjka okien" in end[0].text and "Bluey" in end[0].text

    row = store.conn.execute("SELECT * FROM sessions").fetchone()
    assert row["child"] is None
    assert row["ended_at"] is not None
    segs = store.conn.execute("SELECT app, title, ended_at FROM tv_watch ORDER BY id").fetchall()
    assert [(s["app"], s["title"]) for s in segs] == [
        ("YouTube", "Myjka okien | Fiksiki | Zabawa Nauka dla dzieci"),
        ("Disney+", "Bluey"),
        ("Netflix", None),
    ]
    assert all(s["ended_at"] for s in segs)


def test_uspienie_konczy_od_razu(store):
    w = watcher(store)
    t0 = local(2026, 10, 2, 18, 0)
    w.observe(snap("youtube_playing"), t0)
    w.observe(snap("youtube_playing"), t0 + timedelta(minutes=30))
    end = w.observe(snap("youtube_playing", power="asleep"), t0 + timedelta(minutes=31))
    assert end[0].title == "TV salon: koniec — 1 tytuł, 30 min"


def test_nieosiagalny_telewizor_domyka_sesje_po_idle(store):
    w = watcher(store)
    t0 = local(2026, 10, 2, 18, 0)
    w.observe(snap("youtube_playing"), t0)
    assert w.on_unreachable(t0 + timedelta(minutes=5)) == []
    assert [n.kind for n in w.on_unreachable(t0 + timedelta(minutes=11))] == [NotifyKind.TV_END]
    assert w.on_unreachable(t0 + timedelta(minutes=12)) == []


def test_start_w_cichych_godzinach_ma_wyzszy_priorytet(store):
    from datetime import time  # noqa: PLC0415

    from kidwatch.config import QuietHours  # noqa: PLC0415

    w = watcher(store, quiet_hours=QuietHours(start=time(21, 30), end=time(7, 0)))
    note = w.observe(snap("youtube_playing"), local(2026, 10, 2, 23, 0))[0]
    assert "W CICHYCH GODZINACH" in note.title
    assert note.priority >= 4


def test_silnik_DNS_nie_zamyka_sesji_telewizora(store, classifier):
    """Sesja TV nie dostaje zdarzen DNS; zegar bezczynnosci iPadow zamknalby ja
    po idle_minutes i wyslal push w formacie iPada."""
    cfg = make_config()
    cfg.tv = TvConfig(enabled=True, host="192.0.2.10")
    engine = Engine(cfg, store, classifier)
    t0 = local(2026, 10, 2, 15, 0)
    watcher(store).observe(snap("youtube_playing"), t0)
    notes = engine.tick(t0 + timedelta(hours=2))
    assert NotifyKind.SESSION_END not in [n.kind for n in notes]
    assert store.get_open_session("TV salon") is not None


def test_podsumowanie_dnia_obejmuje_telewizor(store, classifier):
    cfg = make_config()
    cfg.tv = TvConfig(enabled=True, host="192.0.2.10")
    engine = Engine(cfg, store, classifier)
    w = watcher(store)
    t0 = local(2026, 10, 2, 9, 0)
    w.observe(snap("youtube_playing"), t0)
    w.observe(snap("disney_paused", "disney"), t0 + timedelta(minutes=45))
    w.observe(snap("empty"), t0 + timedelta(minutes=60))
    note = engine.summary_for(t0.date(), local(2026, 10, 2, 20, 30))[0]
    assert "*TV salon* — 1 sesja, 45 min" in note.text
    assert "Fiksiki: Myjka okien" in note.text and "Bluey" in note.text


def test_podsumowanie_bez_ogladania(store, classifier):
    cfg = make_config()
    cfg.tv = TvConfig(enabled=True, host="192.0.2.10")
    note = Engine(cfg, store, classifier).summary_for(
        local(2026, 10, 2, 0, 0).date(), local(2026, 10, 2, 20, 30))[0]
    assert "*TV salon* — nic nie gralo" in note.text


# =============================================================== petla i czujka
class FlakyShell:
    """Odpowiada z probek albo udaje wyjety z pradu telewizor."""

    def __init__(self, down: bool = False) -> None:
        self.down = down

    async def shell(self, command: str) -> str:
        if self.down:
            raise TvUnavailable("ConnectionRefusedError")
        if "media_session" in command:
            return fx("media_youtube_playing")
        if "activity" in command:
            return fx("activity_youtube")
        return fx("power_awake")

    async def aclose(self) -> None:
        pass


class Sink:
    def __init__(self) -> None:
        self.notes = []

    async def send_all(self, notes) -> None:
        self.notes.extend(notes)


async def _no_sleep(_):
    return None


async def test_petla_odczytuje_telewizor_i_zapisuje_udany_odczyt(store):
    w = TvWatcher(TvProbe(FlakyShell()), "TV salon", store)
    sink = Sink()
    await device_loop([w], sink, 30, sleep=_no_sleep, max_iterations=1, store=store)
    assert [n.kind for n in sink.notes] == [NotifyKind.TV_START]
    assert store.get_meta("dev-ok:TV salon") is not None


async def test_czujka_po_dobie_bez_odczytu_z_podpowiedzia_dla_TV(store):
    from datetime import UTC, datetime  # noqa: PLC0415

    from kidwatch.store import to_iso  # noqa: PLC0415

    store.set_meta("dev-ok:TV salon", to_iso(datetime.now(UTC) - timedelta(hours=25)))
    w = TvWatcher(TvProbe(FlakyShell(down=True)), "TV salon", store)
    sink = Sink()
    await device_loop([w], sink, 30, sleep=_no_sleep, max_iterations=1, store=store,
                      unreachable_alert_hours=24)
    assert len(sink.notes) == 1
    assert sink.notes[0].kind is NotifyKind.WATCHDOG
    assert "WireGuard" in sink.notes[0].text


async def test_klucz_ADB_jest_wymagany(tmp_path):
    from kidwatch.sources.tv import AdbTcpShell  # noqa: PLC0415

    with pytest.raises(FileNotFoundError, match="kidwatch-adb"):
        AdbTcpShell("192.0.2.10", 5555, tmp_path, 5)
