"""Testy petli cyklicznej."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from conftest import ev, local
from kidwatch.models import NotifyKind
from kidwatch.notifiers.base import Dispatcher
from kidwatch.scheduler import _maybe_purge, source_loop, tick_loop
from kidwatch.store import to_iso

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


class Collector:
    name = "zbieracz"

    def __init__(self):
        self.sent = []

    async def send(self, note):
        self.sent.append(note)
        return True

    async def aclose(self):
        pass


async def _no_sleep(_s):
    return None


# ================================================================= tick_loop
async def test_tick_loop_przekazuje_powiadomienia_do_wysylki(engine, store):
    collector = Collector()
    engine.handle(ev(local(2026, 9, 27, 10, 0), "www.youtube.com"))
    # Przesun "teraz" tak, zeby sesja wygasla.
    engine.clock = type("C", (), {"now": staticmethod(lambda: local(2026, 9, 27, 10, 30))})()

    await tick_loop(
        engine, Dispatcher([collector]), store, sleep=_no_sleep, max_iterations=1
    )
    assert any(n.kind is NotifyKind.SESSION_END for n in collector.sent)


async def test_tick_loop_przezywa_wyjatek_w_tiku(engine, store):
    """Wyjatek w tiku nie moze zabic petli — razem z nia umarlaby czujka."""
    calls = {"n": 0}

    def exploding_tick(now=None):
        calls["n"] += 1
        raise RuntimeError("cos peklo")

    engine.tick = exploding_tick
    await tick_loop(engine, Dispatcher([]), store, sleep=_no_sleep, max_iterations=3)
    assert calls["n"] == 3  # petla przezyla wszystkie trzy


# ================================================================ sprzatanie
def test_sprzatanie_dzieje_sie_raz_na_dobe(store):
    _maybe_purge(store, retention_days=30, now=NOW)
    first = store.get_meta("last_purge")
    assert first is not None

    _maybe_purge(store, retention_days=30, now=NOW + timedelta(hours=5))
    assert store.get_meta("last_purge") == first  # jeszcze nie czas

    _maybe_purge(store, retention_days=30, now=NOW + timedelta(days=1, minutes=1))
    assert store.get_meta("last_purge") != first


def test_pierwsze_sprzatanie_dzieje_sie_od_razu(store):
    assert store.get_meta("last_purge") is None
    _maybe_purge(store, retention_days=30, now=NOW)
    assert store.get_meta("last_purge") == to_iso(NOW)


# =============================================================== source_loop
class FakeSource:
    name = "atrapa"

    def __init__(self, events):
        self._events = events

    async def events(self):
        for event in self._events:
            yield event

    async def aclose(self):
        pass


async def test_source_loop_zapisuje_kursor(engine, store):
    from kidwatch.models import DnsEvent  # noqa: PLC0415

    events = [
        DnsEvent(
            ts=local(2026, 9, 27, 10, 0),
            device_id="ipad-kuby",
            domain="www.youtube.com",
            cursor="kursor-1",
        )
    ]
    collector = Collector()
    await source_loop(FakeSource(events), engine, Dispatcher([collector]), store)
    assert store.get_cursor("atrapa") == "kursor-1"
    assert len(collector.sent) == 1


async def test_source_loop_przezywa_zle_zdarzenie(engine, store):
    """Jedno zle zdarzenie nie moze zatrzymac strumienia."""
    calls = {"n": 0}
    original = engine.handle

    def flaky(event):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("zle zdarzenie")
        return original(event)

    engine.handle = flaky
    events = [
        ev(local(2026, 9, 27, 10, 0), "www.youtube.com"),
        ev(local(2026, 9, 27, 10, 1), "ecsv3.roblox.com"),
    ]
    collector = Collector()
    await source_loop(FakeSource(events), engine, Dispatcher([collector]), store)
    assert calls["n"] == 2  # drugie zdarzenie zostalo przetworzone


# ===================================================================== tetno
async def test_tetno_jest_dotykane_po_udanym_tiku(engine, store, tmp_path):
    beat = tmp_path / "beat"
    await tick_loop(
        engine, Dispatcher([]), store, sleep=_no_sleep, max_iterations=1, heartbeat_path=beat
    )
    assert beat.is_file()
    assert int(beat.read_text()) > 0


async def test_tetno_NIE_jest_dotykane_gdy_tik_wywala_wyjatek(engine, store, tmp_path):
    """Gdyby bylo, sonda liveness zglaszalaby zdrowie martwego serwisu — czyli
    dokladnie ta cicha awaria, przed ktora ma chronic."""
    beat = tmp_path / "beat"

    def exploding_tick(now=None):
        raise RuntimeError("cos peklo")

    engine.tick = exploding_tick
    await tick_loop(
        engine, Dispatcher([]), store, sleep=_no_sleep, max_iterations=2, heartbeat_path=beat
    )
    assert not beat.exists()


async def test_blad_zapisu_tetna_nie_zabija_petli(engine, store, tmp_path):
    # Sciezka wskazuje na plik jako katalog rodzica — zapis musi sie nie udac.
    blocker = tmp_path / "plik"
    blocker.write_text("x")
    await tick_loop(
        engine,
        Dispatcher([]),
        store,
        sleep=_no_sleep,
        max_iterations=2,
        heartbeat_path=blocker / "beat",
    )


async def test_source_loop_wznawia_zrodlo_po_nieprzewidzianym_wyjatku(engine, store):
    """Regresja: wyjatek, ktorego zrodlo nie przewidzialo, konczyl source_loop,
    a cmd_run konczy proces po pierwszym zakonczonym zadaniu — awaria jednego
    parsera zabijala TV, UniFi i panel razem z warstwa DNS."""
    from kidwatch.models import DnsEvent  # noqa: PLC0415

    class FlakySource(FakeSource):
        def __init__(self):
            super().__init__([])
            self.runs = 0

        async def events(self):
            self.runs += 1
            if self.runs == 1:
                raise ValueError("nieprzewidziany format odpowiedzi")
            yield DnsEvent(
                ts=local(2026, 9, 27, 10, 0), device_id="ipad-kuby",
                domain="www.youtube.com", cursor="k-2",
            )

    waits: list[float] = []

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    src = FlakySource()
    await source_loop(src, engine, Dispatcher([Collector()]), store, sleep=record_sleep)
    assert src.runs == 2
    assert waits and waits[0] > 0
    assert store.get_cursor("atrapa") == "k-2"
