"""Hybryda ADB + ruch sieci (sources/tv_siec.py).

Scenariusz z 2026-10-07: port ADB otwarty, uzgadnianie wisi (TcpTimeout) od
rana, wieczorem ogladanie - i ani jednego pusha. Z zapasem z UniFi start
i koniec maja przyjsc mimo martwego ADB.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from kidwatch.models import NotifyKind
from kidwatch.sources.tv import TvProbe, TvUnavailable, TvWatcher
from kidwatch.sources.tv_siec import STREAMING, HybridProbe, LicznikRuchu
from kidwatch.sources.unifi import UnifiError
from kidwatch.store import Store

TV_IP = "192.0.2.219"
T0 = datetime(2026, 10, 7, 17, 0, tzinfo=UTC)
MB = 1_000_000


class MartweAdb:
    async def shell(self, command: str) -> str:
        raise TvUnavailable("TcpTimeoutException: Reading from 192.0.2.219:5555 timed out")

    async def aclose(self) -> None:
        pass


class Kontroler:
    """Atrapa UniFi: licznik bajtow telewizora ustawiany z testu."""

    def __init__(self) -> None:
        self.bajty: int | None = 0
        self.pada = False
        self.wired = False

    async def stations(self) -> list[dict]:
        if self.pada:
            raise UnifiError("kontroler w restarcie")
        if self.bajty is None:
            return [{"ip": "192.0.2.50", "tx_bytes": 1, "rx_bytes": 1}]
        if self.wired:
            return [{"ip": TV_IP, "wired-tx_bytes": 0, "wired-rx_bytes": self.bajty}]
        return [{"ip": TV_IP, "tx_bytes": 0, "rx_bytes": self.bajty}]


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def uklad(store, kontroler, **kw):
    licznik = LicznikRuchu(kontroler, TV_IP, None, okno_min=3, odswiez_s=0)
    probe = HybridProbe(TvProbe(MartweAdb()), licznik, store, prog_mb=10,
                        device_name="TV salon", **kw)
    return TvWatcher(probe, "TV salon", store, idle_minutes=10, adb_alert_minutes=30)


async def _przebieg(w, kontroler, start, minut, mb_na_minute):
    """Odczyt co minute; zwraca wszystkie powiadomienia."""
    out = []
    for i in range(minut):
        kontroler.bajty += int(mb_na_minute * MB)
        out += await w.poll(start + timedelta(minutes=i))
    return out


async def test_ogladanie_przy_martwym_ADB_daje_start_i_koniec(store):
    k = Kontroler()
    w = uklad(store, k)
    t = T0
    notes = await _przebieg(w, k, t, 3, 0.1)          # ekran glowny: cisza
    assert notes == []
    notes = await _przebieg(w, k, t + timedelta(minutes=3), 20, 30)   # YouTube ~4 Mb/s
    starty = [n for n in notes if n.kind is NotifyKind.TV_START]
    assert len(starty) == 1
    assert starty[0].title == f"TV salon: start — {STREAMING}"
    assert "z ruchu sieci" in starty[0].text
    notes = await _przebieg(w, k, t + timedelta(minutes=23), 15, 0)    # wylaczone ogladanie
    konce = [n for n in notes if n.kind is NotifyKind.TV_END]
    assert len(konce) == 1


async def test_po_kablu_licza_sie_wired_bajty(store):
    k = Kontroler()
    k.wired = True
    w = uklad(store, k)
    notes = await _przebieg(w, k, T0, 6, 30)
    assert [n.kind for n in notes if n.kind is NotifyKind.TV_START] == [NotifyKind.TV_START]


async def test_bez_pelnego_okna_nie_ma_startu(store):
    """Swiezo po starcie nie ma punktu odniesienia - jedna probka to nie ruch."""
    k = Kontroler()
    k.bajty = 10_000 * MB
    w = uklad(store, k)
    assert await w.poll(T0) == []


async def test_telewizor_poza_siecia_to_dalej_nieosiagalny(store):
    k = Kontroler()
    k.bajty = None
    w = uklad(store, k)
    with pytest.raises(TvUnavailable):
        await w.poll(T0)


async def test_padniety_kontroler_nie_maskuje_bledu_ADB(store):
    k = Kontroler()
    k.pada = True
    w = uklad(store, k)
    with pytest.raises(TvUnavailable, match="TcpTimeout"):
        await w.poll(T0)


async def test_serwis_z_NextDNS(store):
    k = Kontroler()
    w = uklad(store, k, nextdns_ids=["tv-salon"])
    store.record_event(ts=T0 + timedelta(minutes=4), device=None, source_id="tv-salon",
                       domain="rr1.googlevideo.com", kind="app", app="YouTube")
    notes = await _przebieg(w, k, T0, 8, 30)
    starty = [n for n in notes if n.kind is NotifyKind.TV_START]
    assert starty and starty[0].title == "TV salon: start — YouTube"


async def test_alarm_ADB_raz_na_dobe_gdy_ruch_pokazuje_ogladanie(store):
    k = Kontroler()
    w = uklad(store, k)
    notes = await _przebieg(w, k, T0, 60, 30)
    alarmy = [n for n in notes if n.kind is NotifyKind.WATCHDOG]
    assert len(alarmy) == 1
    assert "ADB nie odpowiada" in alarmy[0].title
    assert "Zawsze zezwalaj" in alarmy[0].text


async def test_dzialajace_ADB_ma_pierwszenstwo(store):
    from test_tv import FlakyShell  # noqa: PLC0415

    k = Kontroler()
    licznik = LicznikRuchu(k, TV_IP, None, okno_min=3, odswiez_s=0)
    probe = HybridProbe(TvProbe(FlakyShell()), licznik, store, prog_mb=10)
    w = TvWatcher(probe, "TV salon", store)
    notes = await w.poll(T0)
    assert notes[0].kind is NotifyKind.TV_START
    assert "Fiksiki" in notes[0].title           # tytul z ADB, nie "Streaming"
    assert "z ruchu sieci" not in notes[0].text


# ================================================================ Sony REST
from kidwatch.sources.sony import SonyAuthError, SonyClient, Zrodlo, parse_zrodlo  # noqa: E402


def test_parse_tuner_hdmi_i_aplikacja():
    assert parse_zrodlo({"source": "tv:dvbt", "title": "TVP1 HD", "dispNum": "001",
                         "programTitle": "Teleexpress"}) == Zrodlo("tuner", "TVP1 HD",
                                                                  "Teleexpress")
    assert parse_zrodlo({"source": "extInput:hdmi", "uri": "extInput:hdmi?port=2",
                         "title": ""}) == Zrodlo("hdmi", "HDMI 2")
    assert parse_zrodlo({"source": "extInput:hdmi", "title": "PlayStation"}).nazwa == "PlayStation"
    assert parse_zrodlo(None) is None


class FakeSony:
    def __init__(self, wlaczony=True, zrodlo=None, psk="k", blad=None):
        self._w, self._z, self.psk, self._blad = wlaczony, zrodlo, psk, blad

    async def wlaczony(self):
        if self._blad:
            raise self._blad
        return self._w

    async def zrodlo(self):
        if isinstance(self._z, Exception):
            raise self._z
        return self._z

    async def aclose(self):
        pass


def uklad_sony(store, sony, kontroler=None):
    licznik = (LicznikRuchu(kontroler, TV_IP, None, okno_min=3, odswiez_s=0)
               if kontroler else None)
    probe = HybridProbe(TvProbe(MartweAdb()), licznik, store, prog_mb=10,
                        device_name="TV salon", sony=sony)
    return TvWatcher(probe, "TV salon", store, idle_minutes=10, adb_alert_minutes=30)


async def test_antena_z_kanalem_i_programem_przy_martwym_ADB(store):
    sony = FakeSony(zrodlo=Zrodlo("tuner", "TVP1 HD", "Teleexpress"))
    w = uklad_sony(store, sony)
    notes = await w.poll(T0)
    assert notes[0].kind is NotifyKind.TV_START
    assert notes[0].title == "TV salon: start — TVP1 HD: Teleexpress (Telewizja)"
    assert "API telewizora" in notes[0].text


async def test_czuwanie_wedlug_sony_konczy_od_razu(store):
    sony = FakeSony(zrodlo=Zrodlo("hdmi", "HDMI 1"))
    w = uklad_sony(store, sony)
    assert (await w.poll(T0))[0].kind is NotifyKind.TV_START
    sony._w = False
    notes = await w.poll(T0 + timedelta(minutes=1))
    assert [n.kind for n in notes] == [NotifyKind.TV_END]


async def test_aplikacja_wedlug_sony_decyduje_ruch(store):
    k = Kontroler()
    w = uklad_sony(store, FakeSony(zrodlo=None), k)
    notes = await _przebieg(w, k, T0, 6, 30)
    assert [n.title for n in notes if n.kind is NotifyKind.TV_START] == [
        f"TV salon: start — {STREAMING}"]


async def test_bez_PSK_tylko_zasilanie_a_ruch_decyduje(store):
    k = Kontroler()
    w = uklad_sony(store, FakeSony(zrodlo=Zrodlo("tuner", "X"), psk=None), k)
    notes = await _przebieg(w, k, T0, 6, 0)
    assert notes == []   # wlaczony, ale bez ruchu i bez klucza nic nie wiemy o antenie


async def test_zly_PSK_nie_wywraca_odczytu(store):
    k = Kontroler()
    w = uklad_sony(store, FakeSony(zrodlo=SonyAuthError("403")), k)
    notes = await _przebieg(w, k, T0, 6, 30)
    assert any(n.kind is NotifyKind.TV_START for n in notes)


async def test_sony_nieosiagalny_i_brak_w_sieci_to_nieosiagalny(store):
    from kidwatch.sources.sony import SonyError  # noqa: PLC0415

    k = Kontroler()
    k.bajty = None
    w = uklad_sony(store, FakeSony(blad=SonyError("timeout")), k)
    with pytest.raises(TvUnavailable):
        await w.poll(T0)


async def test_klient_sony_wysyla_psk_i_czyta_zasilanie():
    import httpx  # noqa: PLC0415

    widziane = []

    def handler(r: httpx.Request):
        widziane.append(r.headers.get("X-Auth-PSK"))
        if r.url.path.endswith("/system"):
            return httpx.Response(200, json={"result": [{"status": "active"}], "id": 1})
        return httpx.Response(200, json={"error": [403, "Forbidden"], "id": 1})

    c = SonyClient("tv", "tajne", http=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    assert await c.wlaczony() is True
    with pytest.raises(SonyAuthError):
        await c.zrodlo()
    assert widziane == ["tajne", "tajne"]
    await c.aclose()


def test_zapytania_sony_nie_trafiaja_do_logu_httpx(caplog):
    import logging  # noqa: PLC0415

    import kidwatch.sources.sony  # noqa: F401, PLC0415

    with caplog.at_level(logging.INFO, logger="httpx"):
        lg = logging.getLogger("httpx")
        lg.info('HTTP Request: POST http://192.0.2.219/sony/system "HTTP/1.1 200 OK"')
        lg.info('HTTP Request: POST http://bramka/v1/wyslij "HTTP/1.0 200 OK"')
    assert [r.getMessage() for r in caplog.records] == [
        'HTTP Request: POST http://bramka/v1/wyslij "HTTP/1.0 200 OK"']
