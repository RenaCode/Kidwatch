"""Aplikacja Kidwatch TV (tv-app/, sources/tv_app.py): odczyt, parowanie,
instalacja przez ADB i pierwszenstwo w odczycie telewizora."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime

import httpx
import pytest

from kidwatch.models import NotifyKind
from kidwatch.sources import tv_app
from kidwatch.sources.tv import TvProbe, TvWatcher
from kidwatch.sources.tv_app import AplikacjaTv, AppError, snapshot_z_json
from kidwatch.sources.tv_siec import HybridProbe
from kidwatch.store import Store
from test_tv_siec import MartweAdb

T0 = datetime(2026, 10, 9, 18, 0, tzinfo=UTC)
YT = "com.google.android.youtube.tv"


def stan(ekran=True, sesje=None):
    return {"wersja": "0.1.7", "ekran": ekran, "uprawnienie": True, "sesje": sesje if
            sesje is not None else [{"pakiet": YT, "stan": 3, "tytul": "Myjka okien",
                                     "podtytul": "Fiksiki", "opis": None}]}


class TvHttp:
    """Atrapa serwera aplikacji na TV (Serwer.kt)."""

    def __init__(self):
        self.kod = "123456"
        self.token = None
        self.odp = stan()
        self.pada = False

    def handler(self, r: httpx.Request):
        if self.pada:
            raise httpx.ConnectError("brak")
        if r.url.path == "/paruj":
            import json  # noqa: PLC0415
            if json.loads(r.content)["kod"] != self.kod:
                return httpx.Response(403, json={"blad": "zly kod"})
            self.token = "t" * 64
            return httpx.Response(200, json={"token": self.token})
        if r.url.path == "/stan":
            if r.headers.get("Authorization") != f"Bearer {self.token}":
                return httpx.Response(401, json={})
            return httpx.Response(200, json=self.odp)
        return httpx.Response(404, json={})


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


def aplikacja(tmp_path, tv):
    return AplikacjaTv("tv", tmp_path,
                       http=httpx.AsyncClient(transport=httpx.MockTransport(tv.handler)))


def test_json_na_snapshot_jak_z_dumpsys():
    s = snapshot_z_json(stan())
    p = s.playing({})
    assert s.zrodlo == "aplikacja"
    assert p.label == "Fiksiki: Myjka okien (YouTube)"
    assert snapshot_z_json(stan(ekran=False)).playing({}) is None


def test_pauza_liczy_sie_tylko_ze_znanym_pierwszym_planem():
    """Bez pierwszego planu (pilot Google TV usuniety) pauza nie jest ogladaniem."""
    s = stan(sesje=[{"pakiet": YT, "stan": 2, "tytul": "X"}])
    assert snapshot_z_json(s).playing({}) is None
    assert snapshot_z_json(s, foreground=YT).playing({}).title == "X"


async def _paruj(app, kod):
    app.loop = asyncio.get_running_loop()
    wynik = {}

    def panel():
        try:
            app.paruj(kod)
        except Exception as exc:  # noqa: BLE001
            wynik["e"] = exc

    t = threading.Thread(target=panel)
    t.start()
    await asyncio.to_thread(t.join)
    return wynik.get("e")


async def test_parowanie_zapisuje_token_a_zly_kod_nie(tmp_path):
    tv = TvHttp()
    app = aplikacja(tmp_path, tv)
    assert isinstance(await _paruj(app, "12"), AppError)
    assert isinstance(await _paruj(app, "654321"), AppError)
    assert not app.sparowana
    assert await _paruj(app, "123456") is None
    assert app.sparowana and (tmp_path / "token").read_text() == tv.token


def watcher(store, app):
    probe = HybridProbe(TvProbe(MartweAdb()), None, store, device_name="TV salon",
                        aplikacja=app)
    return TvWatcher(probe, "TV salon", store, idle_minutes=10)


async def test_aplikacja_ma_pierwszenstwo_i_daje_tytul(store, tmp_path):
    tv = TvHttp()
    app = aplikacja(tmp_path, tv)
    await _paruj(app, "123456")
    notes = await watcher(store, app).poll(T0)
    assert notes[0].kind is NotifyKind.TV_START
    assert notes[0].title == "TV salon: start — Fiksiki: Myjka okien (YouTube)"
    assert "ruchu" not in notes[0].text and "pilota" not in notes[0].text


async def test_aplikacja_nie_odpowiada_to_odczyt_zastepczy(store, tmp_path):
    from kidwatch.sources.tv import TvUnavailable  # noqa: PLC0415

    tv = TvHttp()
    app = aplikacja(tmp_path, tv)
    await _paruj(app, "123456")
    tv.pada = True
    with pytest.raises(TvUnavailable, match="TcpTimeout"):   # dalej: martwe ADB
        await watcher(store, app).poll(T0)
    assert app.stan().blad == "ConnectError"


class AdbNagrywa:
    def __init__(self):
        self.polecenia = []

    async def push(self, local, remote, limit_s=120.0):
        self.polecenia.append(f"push {remote}")

    async def shell(self, command, limit_s=None):
        self.polecenia.append(command)
        return "Success" if command.startswith("pm install") else ""


async def test_instalacja_przez_adb_daje_uprawnienie_i_otwiera_aplikacje(tmp_path):
    apk = tmp_path / "kidwatch-tv.apk"
    apk.write_bytes(b"apk")
    app = AplikacjaTv("tv", tmp_path, apk=str(apk))
    app.adb = AdbNagrywa()
    app.loop = asyncio.get_running_loop()
    opis = await asyncio.to_thread(app.instaluj)
    assert "kod parowania" in opis
    assert app.adb.polecenia == [
        f"push {tv_app.APK_NA_TV}",
        f"pm install -r {tv_app.APK_NA_TV}",
        f"rm -f {tv_app.APK_NA_TV}",
        f"cmd notification allow_listener {tv_app.NASLUCH}",
        f"am start -n {tv_app.AKTYWNOSC}",
    ]
    await app.aclose()


async def test_instalacja_bez_adb_mowi_dlaczego(tmp_path):
    app = AplikacjaTv("tv", tmp_path)
    app.loop = asyncio.get_running_loop()
    with pytest.raises(AppError, match="ADB"):
        await asyncio.to_thread(app.instaluj)
    await app.aclose()
