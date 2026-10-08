"""Pilot Google TV (sources/tv_pilot.py) i jego miejsce w odczycie zapasowym."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime, timedelta

import pytest

from kidwatch.models import NotifyKind
from kidwatch.sources.tv import TvProbe, TvWatcher
from kidwatch.sources.tv_pilot import PilotError, PilotTv
from kidwatch.sources.tv_siec import HybridProbe, LicznikRuchu
from kidwatch.store import Store
from test_tv_siec import TV_IP, Kontroler, MartweAdb

T0 = datetime(2026, 10, 8, 18, 0, tzinfo=UTC)


class AtrapaRemote:
    """Udaje androidtvremote2.AndroidTVRemote."""

    def __init__(self, pilot) -> None:
        self.pilot = pilot
        self.is_on = True
        self.current_app = "com.google.android.youtube.tv"
        self.parowanie = None
        self.cb = {}

    async def async_generate_cert_if_missing(self):
        return True

    async def async_start_pairing(self):
        self.parowanie = "start"

    async def async_finish_pairing(self, code):
        if code != "A1B2C3":
            raise RuntimeError("InvalidAuth")
        self.parowanie = "ok"

    async def async_connect(self):
        return None

    def keep_reconnecting(self, cb=None):
        self.cb["invalid"] = cb

    def add_is_on_updated_callback(self, cb):
        self.cb["on"] = cb

    def add_current_app_updated_callback(self, cb):
        self.cb["app"] = cb

    def add_is_available_updated_callback(self, cb):
        self.cb["av"] = cb


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


async def _start(tmp_path, sparowany=False):
    if sparowany:
        tmp_path.joinpath("sparowany").write_text("x")
    pilot = PilotTv("tv", tmp_path, remote_factory=AtrapaRemote)
    task = asyncio.create_task(pilot.uruchom())
    for _ in range(20):
        await asyncio.sleep(0)
    return pilot, task


async def test_niesparowany_nie_laczy_sie(tmp_path):
    pilot, task = await _start(tmp_path)
    assert not pilot.stan().sparowany and not pilot.stan().polaczony
    task.cancel()


async def test_parowanie_z_watku_panelu(tmp_path):
    pilot, task = await _start(tmp_path)
    blad = {}

    def panel():
        try:
            pilot.paruj_start()
            with pytest.raises(PilotError):
                pilot.paruj_kod("XYZ")          # zly format, bez telewizora
            pilot.paruj_kod("a1b2c3")
        except Exception as exc:  # noqa: BLE001
            blad["e"] = exc

    t = threading.Thread(target=panel)
    t.start()
    await asyncio.to_thread(t.join)
    assert not blad, blad
    for _ in range(20):
        await asyncio.sleep(0)
    st = pilot.stan()
    assert st.sparowany and st.polaczony and st.wlaczony
    assert st.aplikacja == "com.google.android.youtube.tv"
    task.cancel()


async def test_utrata_parowania_kasuje_znacznik(tmp_path):
    pilot, task = await _start(tmp_path, sparowany=True)
    assert pilot.stan().polaczony
    pilot.remote.cb["invalid"]()
    assert not pilot.stan().sparowany
    task.cancel()


def uklad(store, pilot, kontroler=None):
    licznik = (LicznikRuchu(kontroler, TV_IP, None, okno_min=3, odswiez_s=0)
               if kontroler else None)
    probe = HybridProbe(TvProbe(MartweAdb()), licznik, store, prog_mb=10,
                        device_name="TV salon", pilot=pilot)
    return TvWatcher(probe, "TV salon", store, idle_minutes=10)


async def test_aplikacja_z_pilota_nazywa_sesje(store, tmp_path):
    pilot, task = await _start(tmp_path, sparowany=True)
    k = Kontroler()
    w = uklad(store, pilot, k)
    notes = []
    for i in range(6):
        k.bajty += 30_000_000
        notes += await w.poll(T0 + timedelta(minutes=i))
    starty = [n for n in notes if n.kind is NotifyKind.TV_START]
    assert starty[0].title == "TV salon: start — YouTube"
    assert "pilota Google TV" in starty[0].text
    # Wylaczenie pilotem konczy od razu.
    pilot.remote.cb["on"](False)
    notes = await w.poll(T0 + timedelta(minutes=7))
    assert [n.kind for n in notes] == [NotifyKind.TV_END]
    task.cancel()


async def test_ekran_glowny_to_nie_ogladanie(store, tmp_path):
    pilot, task = await _start(tmp_path, sparowany=True)
    pilot.remote.cb["app"]("com.google.android.apps.tv.launcherx")
    w = uklad(store, pilot)
    assert await w.poll(T0) == []
    task.cancel()


async def test_otwarta_aplikacja_bez_ruchu_to_nie_ogladanie(store, tmp_path):
    pilot, task = await _start(tmp_path, sparowany=True)
    k = Kontroler()
    w = uklad(store, pilot, k)
    notes = []
    for i in range(6):
        notes += await w.poll(T0 + timedelta(minutes=i))
    assert not [n for n in notes if n.kind is NotifyKind.TV_START]
    task.cancel()
