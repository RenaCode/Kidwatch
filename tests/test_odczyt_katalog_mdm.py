"""Odczyt iPadow, gdy lockdown nie poda listy aplikacji.

Produkcja (2026-10-23): po tunelu lista procesow dziala, a installation_proxy
i diagnostics padaja na ConnectionTerminatedError przy kazdym obiegu. Bez listy
aplikacji zaden proces nie dostawal nazwy — zero powiadomien „odpalil X”,
za to co minute WARNING „czesciowy odczyt” i ~150 nazw w INFO.

Tu: katalog aplikacji z serwera MDM jako zapasowe zrodlo (z izolacja domow),
dopasowanie po czlonie bundle ID, runner testow XCTest, logi bez powtorzen,
start uslugi bez wiszacych Future i proba z EscrowBag.

Dane neutralne: com.example.*, UDID-y testowe.
"""

from __future__ import annotations

import asyncio
import gc
import logging
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from kidwatch.mdm import AppCatalog, MdmApi, MdmError
from kidwatch.models import NotifyKind
from kidwatch.scheduler import UnmatchedLog
from kidwatch.sources.device import (
    DeviceProbe,
    DeviceTarget,
    DeviceUnavailable,
    DeviceWatcher,
    InstalledApp,
    TcpLockdownBackend,
    looks_like_app,
)
from test_device import BACKLIGHT_OFF, FakeBackend
from test_mdm_domy import DOM_2, UDID_A, UDID_B, uklad  # noqa: F401 - fixture

NOW = datetime(2026, 10, 23, 12, 0, tzinfo=UTC)
UDID = "UDID-C-000000000003"
TARGET = DeviceTarget(udid=UDID, host="10.0.0.2")

#: Lista z MDM: Identifier + Name (bez pliku wykonywalnego).
MDM_APPS = [
    {"id": "com.example.SimpleGame", "name": "Prosta Gra", "version": "1.0"},
    {"id": "com.example.reader", "name": "Czytnik Bajek", "version": "2.3"},
]
PIDS = {
    "1": {"ProcessName": "launchd"},
    "37": {"ProcessName": "SpringBoard"},
    "500": {"ProcessName": "SimpleGame"},  # juz dziala przed pierwszym odczytem
    "600": {"ProcessName": "CzytnikBajek"},
}


class FakeMdmApi:
    """Atrapa MdmApi.request: `/api/devices/<udid>` z serwera MDM."""

    def __init__(self, devices: dict[str, dict]) -> None:
        self.devices = devices
        self.calls: list[str] = []
        self.fail: Exception | None = None

    def request(self, method: str, path: str, body=None):
        self.calls.append(path)
        if self.fail is not None:
            raise self.fail
        udid = path.rsplit("/", 1)[-1]
        if udid not in self.devices:
            raise MdmError(404, "nieznane urzadzenie")
        return self.devices[udid]

    def close(self) -> None:
        pass


def mdm_device(apps_at: datetime, apps=MDM_APPS) -> dict:
    return {"udid": UDID, "apps": apps, "apps_at": apps_at.isoformat(timespec="seconds")}


def watcher(store, responses, catalog=None, fallback_apps=None) -> DeviceWatcher:
    return DeviceWatcher(
        DeviceProbe(TARGET, FakeBackend(responses)),
        "iPad (Dziecko 3)",
        "Dziecko 3",
        store,
        catalog=catalog,
        fallback_apps=fallback_apps,
    )


# ============================================= 1. katalog MDM jako zapas
async def test_padniety_get_apps_bierze_nazwe_z_katalogu_MDM(store, caplog):
    """Zywy get_apps pada; MDM zna aplikacje -> proces `SimpleGame` dostaje
    nazwe z MDM. Juz dzialajace aplikacje NIE sa „odpalone” po tym, jak
    pojawi sie lista (zmiana zrodla to nie uruchomienie)."""
    caplog.set_level(logging.INFO)
    api = FakeMdmApi({UDID: mdm_device(NOW - timedelta(minutes=7))})
    catalog = AppCatalog(api)
    responses = {"apps": None, "pids": dict(PIDS), "backlight": BACKLIGHT_OFF}
    w = watcher(store, responses, catalog)

    assert await w.poll(NOW) == []  # katalog jeszcze pusty, odswiezenie w tle
    await catalog.wait()
    assert await w.poll(NOW + timedelta(minutes=1)) == [], (
        "aplikacje dzialajace przed pojawieniem sie listy to nie uruchomienia"
    )

    responses["pids"] = dict(PIDS) | {"700": {"ProcessName": "SimpleGame"}}
    notes = await w.poll(NOW + timedelta(minutes=2))
    assert [n.kind for n in notes] == [NotifyKind.DEVICE_LAUNCH]
    assert notes[0].text == "odpalil: Prosta Gra"
    assert "katalog MDM (2 aplikacji, lista sprzed 8 min) — lockdown nie podal listy" in (
        caplog.text
    )
    assert "apki=mdm" in caplog.text, "zamiast USTALAM — zrodlo listy zastepczej"
    assert len(api.calls) == 1, "katalog pytany rzadko (cache), nie co obieg"


async def test_zywy_get_apps_wygrywa_i_nie_pyta_MDM(store):
    api = FakeMdmApi({UDID: mdm_device(NOW)})
    responses = {
        "apps": {"com.example.SimpleGame": {"ApplicationType": "User",
                                            "CFBundleDisplayName": "Gra z iPada"}},
        "pids": dict(PIDS),
        "backlight": BACKLIGHT_OFF,
    }
    w = watcher(store, responses, AppCatalog(api))
    await w.poll(NOW)
    responses["pids"] = dict(PIDS) | {"701": {"ProcessName": "SimpleGame"}}
    notes = await w.poll(NOW + timedelta(minutes=1))
    assert notes[0].text == "odpalil: Gra z iPada"
    assert api.calls == []


async def test_katalog_MDM_przed_known_apps(store):
    api = FakeMdmApi({UDID: mdm_device(NOW)})
    catalog = AppCatalog(api)
    responses = {"apps": None, "pids": dict(PIDS), "backlight": BACKLIGHT_OFF}
    w = watcher(store, responses, catalog,
                fallback_apps={"com.example.SimpleGame": "STARA NAZWA"})
    await w.poll(NOW)
    await catalog.wait()
    await w.poll(NOW + timedelta(minutes=1))
    responses["pids"] = dict(PIDS) | {"702": {"ProcessName": "SimpleGame"}}
    notes = await w.poll(NOW + timedelta(minutes=2))
    assert notes[0].text == "odpalil: Prosta Gra"


# ================================================ 2. swiezosc i wiek listy
async def test_za_stary_katalog_spada_do_known_apps(store, caplog):
    caplog.set_level(logging.INFO)
    api = FakeMdmApi({UDID: mdm_device(NOW - timedelta(hours=30))})
    catalog = AppCatalog(api)
    responses = {"apps": None, "pids": dict(PIDS), "backlight": BACKLIGHT_OFF}
    w = watcher(store, responses, catalog,
                fallback_apps={"com.example.SimpleGame": "Z konfiguracji"})
    await w.poll(NOW)
    await catalog.wait()
    assert catalog.apps(UDID, NOW) is None
    assert "lista sprzed 30 h — za stara" in caplog.text
    responses["pids"] = dict(PIDS) | {"703": {"ProcessName": "SimpleGame"}}
    notes = await w.poll(NOW + timedelta(minutes=1))
    assert notes[0].text == "odpalil: Z konfiguracji"


async def test_wiek_katalogu_i_odswiezanie_co_kilka_minut():
    api = FakeMdmApi({UDID: mdm_device(NOW - timedelta(minutes=5))})
    catalog = AppCatalog(api, refresh=timedelta(minutes=10))
    assert catalog.apps(UDID, NOW) is None
    await catalog.wait()
    apps, age = catalog.apps(UDID, NOW + timedelta(minutes=1))
    assert age == timedelta(minutes=6)
    assert apps["com.example.SimpleGame"] == InstalledApp("com.example.SimpleGame", "Prosta Gra")
    await catalog.wait()
    assert len(api.calls) == 1
    catalog.apps(UDID, NOW + timedelta(minutes=11))
    await catalog.wait()
    assert len(api.calls) == 2


async def test_UDID_spoza_MDM_i_awaria_serwera():
    """404 = iPada nie ma w MDM (albo jest w innym domu) -> brak listy.
    Awaria serwera nie kasuje poprzedniej listy."""
    api = FakeMdmApi({})
    catalog = AppCatalog(api, refresh=timedelta(0))
    catalog.apps(UDID, NOW)
    await catalog.wait()
    assert catalog.apps(UDID, NOW) is None

    await catalog.wait()
    api.devices[UDID] = mdm_device(NOW)
    catalog.apps(UDID, NOW)
    await catalog.wait()
    assert catalog.apps(UDID, NOW) is not None
    api.fail = MdmError(503, "serwer MDM nieosiagalny")
    catalog.apps(UDID, NOW)
    await catalog.wait()
    assert catalog.apps(UDID, NOW) is not None, "poprzednia lista zostaje"


# ===================================== 3. izolacja domow na serwerze MDM
def test_katalog_tokenem_domu_widzi_TYLKO_swoje_aplikacje(uklad):  # noqa: F811
    svc, klient, h = uklad
    for udid, app in ((UDID_A, "com.example.dom1"), (UDID_B, "com.example.dom2")):
        svc.store.update_device(
            udid, apps_json=f'[{{"id": "{app}", "name": "Apka", "version": "1"}}]',
            apps_at="2026-10-23T11:50:00+00:00",
        )
    http = httpx.Client(base_url=str(klient.base_url), headers=h[DOM_2])
    catalog = AppCatalog(MdmApi(None, "", client=http))
    try:
        apps, at = catalog.fetch(UDID_B)
        assert list(apps) == ["com.example.dom2"]
        assert at == datetime(2026, 10, 23, 11, 50, tzinfo=UTC)
        assert catalog.fetch(UDID_A) == ({}, None), "obcy UDID = 404 = brak listy"
        surowo = klient.get(f"/api/devices/{UDID_A}", headers=h[DOM_2])
        assert surowo.status_code == 404
        assert "com.example.dom1" not in surowo.text
    finally:
        http.close()


# =================================== 4. dopasowanie po katalogu i runner
CATALOG_APPS = {
    "com.example.SimpleGame": InstalledApp("com.example.SimpleGame", "Prosta Gra"),
    "com.example.reader": InstalledApp("com.example.reader", "Czytnik Bajek"),
    "com.example.Sim": InstalledApp("com.example.Sim", "Sim"),
}


@pytest.mark.parametrize(
    ("process", "expected"),
    [
        ("SimpleGame", "Prosta Gra"),       # ostatni czlon bundle ID, dokladnie
        ("CzytnikBajek", "Czytnik Bajek"),  # splaszczona nazwa wyswietlana
        ("Sim", "Sim"),                     # dokladne bije przedrostek „SimpleGame”
        ("SimpleGameUITests-Runner", None),
        ("SimpleGameTests-Runner", None),
    ],
)
def test_dopasowanie_procesu_do_katalogu_MDM(process, expected):
    assert looks_like_app(process, CATALOG_APPS) == expected


def test_plik_wykonywalny_bije_heurystyke():
    apps = {"com.example.a": InstalledApp("com.example.a", "Zupelnie Inna", "Silnik")}
    assert looks_like_app("Silnik", apps) == "Zupelnie Inna"


async def test_runner_testow_UI_to_nie_osobna_aplikacja(store):
    """`XUITests-Runner` obok `X` = jedno uruchomienie X; runner nie trafia ani
    do powiadomien, ani do „procesow bez dopasowania”."""
    responses = {"apps": None, "pids": dict(PIDS), "backlight": BACKLIGHT_OFF}
    w = watcher(store, responses, fallback_apps={"com.example.SimpleGame": "Prosta Gra"})
    await w.poll(NOW)
    responses["pids"] = dict(PIDS) | {
        "800": {"ProcessName": "SimpleGameUITests-Runner"},
        "801": {"ProcessName": "SimpleGame"},
    }
    notes = await w.poll(NOW + timedelta(minutes=1))
    assert [n.text for n in notes] == ["odpalil: Prosta Gra"]
    assert "SimpleGameUITests-Runner" not in w.unmatched


async def test_stary_zapis_pidow_to_nowy_punkt_odniesienia(store):
    """Zapis sprzed tej zmiany mial tylko dopasowane PID-y (tu: zadnego, bo nie
    bylo listy). Bez wersji formatu pierwszy obieg po wdrozeniu zglosilby
    kazda dzialajaca aplikacje jako odpalona."""
    store.set_json(f"dev:{UDID}:pids", {})
    responses = {"apps": None, "pids": dict(PIDS), "backlight": BACKLIGHT_OFF}
    w = watcher(store, responses, fallback_apps={"com.example.SimpleGame": "Prosta Gra"})
    assert await w.poll(NOW) == []


# ========================================================= 5. logi bez powtorzen
def test_niedopasowane_loguje_tylko_zmiany(caplog):
    caplog.set_level(logging.DEBUG, logger="kidwatch.scheduler")
    log = UnmatchedLog("iPad (Dziecko 3)")
    log.report({"Alfa", "Beta"}, NOW)
    log.report({"Alfa", "Beta"}, NOW + timedelta(minutes=1))
    log.report({"Alfa", "Beta"}, NOW + timedelta(minutes=2))
    log.report({"Alfa", "Gamma"}, NOW + timedelta(minutes=3))
    log.report({"Alfa", "Beta"}, NOW + timedelta(minutes=4))  # Beta juz zgloszona
    info = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    debug = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    assert info == [
        "iPad (Dziecko 3): nowe procesy bez dopasowania do aplikacji (2 z 2): Alfa, Beta",
        "iPad (Dziecko 3): nowe procesy bez dopasowania do aplikacji (1 z 2): Gamma",
    ]
    assert len(debug) == 3, "pelna lista tylko przy zmianie zbioru"

    caplog.clear()
    log.report({"Alfa", "Beta"}, NOW + timedelta(hours=1, minutes=1))
    assert [r.getMessage() for r in caplog.records if r.levelno == logging.INFO] == [
        "iPad (Dziecko 3): 2 procesow bez dopasowania do aplikacji (pelna lista na DEBUG)"
    ]


async def test_czesciowy_odczyt_WARNING_raz_na_serie(caplog):
    caplog.set_level(logging.DEBUG, logger="kidwatch.sources.device")
    backend = FakeBackend({"apps": None, "pids": dict(PIDS), "backlight": None})
    probe = DeviceProbe(TARGET, backend)
    for _ in range(5):
        await probe.snapshot()
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "czesciowy odczyt" in warnings[0].getMessage()

    backend.responses["apps"] = {}  # pusta lista: odczyt sie udal
    backend.responses["backlight"] = BACKLIGHT_OFF
    await probe.snapshot()
    assert "znow pelny (po 5 obiegach z brakiem: apps, ekran)" in caplog.text

    caplog.clear()
    backend.responses["apps"] = None
    await probe.snapshot()
    assert sum(r.levelno == logging.WARNING for r in caplog.records) == 1, "nowa seria"


# ========================== 6. start uslugi: bez wiszacych Future, etap bledu
class _Conn:
    """Polaczenie uslugi: odpowiada tylko, gdy start szedl z EscrowBag."""

    def __init__(self, ok: bool) -> None:
        self.ok = ok
        self.closed = False

    async def send_plist(self, data):
        self.sent = data

    async def recv_plist(self):
        from pymobiledevice3.exceptions import ConnectionTerminatedError  # noqa: PLC0415

        if not self.ok:
            raise ConnectionTerminatedError() from asyncio.IncompleteReadError(b"", 4)
        return {"LookupResult": {"com.example.SimpleGame": {
            "ApplicationType": "User", "CFBundleDisplayName": "Prosta Gra",
            "CFBundleExecutable": "SimpleGame"}}}

    async def close(self):
        self.closed = True


class _Lockdown:
    """Klient lockdown z publicznymi metodami, ktorych uzywa start uslugi."""

    def __init__(self, start_error: Exception | None = None, escrow_ok: bool = True) -> None:
        self.start_error = start_error
        self.escrow_ok = escrow_ok
        self.escrow_calls: list[bool] = []

    async def get_service_connection_attributes(self, name, include_escrow_bag=False):
        self.escrow_calls.append(include_escrow_bag)
        if self.start_error is not None:
            raise self.start_error
        return {"Port": 50001, "EnableServiceSSL": False}

    async def start_lockdown_service(self, name, include_escrow_bag=False):
        # Sciezka LockdownService.connect() z biblioteki (kanarek).
        await self.get_service_connection_attributes(name, include_escrow_bag)
        return await self.create_service_connection(50001)

    async def create_service_connection(self, port):
        return _Conn(self.escrow_ok and self.escrow_calls[-1])


def _backend(lockdown, escrow_bag: bool = True) -> TcpLockdownBackend:
    b = TcpLockdownBackend(TARGET, {"HostID": "x", **({"EscrowBag": b"e"} if escrow_bag else {})})

    async def connect():
        return lockdown

    b._connect = connect
    return b


async def test_nieudany_start_uslugi_NIE_zostawia_wiszacej_Future():
    """pymobiledevice3 LockdownService.connect() robi set_exception na Future,
    na ktora nikt nie czeka -> „Future exception was never retrieved”
    z NotPairedError/ConnectionRefusedError w logu przy kazdym obiegu."""
    from pymobiledevice3.exceptions import NotPairedError  # noqa: PLC0415

    loop = asyncio.get_running_loop()
    zgloszone: list[dict] = []
    poprzedni = loop.get_exception_handler()
    loop.set_exception_handler(lambda _loop, ctx: zgloszone.append(ctx))
    try:
        b = _backend(_Lockdown(start_error=NotPairedError()))
        komunikat = ""
        try:
            await b.apps()
        except DeviceUnavailable as exc:
            komunikat = str(exc)
        # Wyjatek trzyma ramke connect(), a ta — Future. asyncio zglasza
        # niepobrany wyjatek dopiero przy jej sprzataniu (jak na produkcji,
        # gdy obieg zapomni blad), wiec najpierw puszczamy wszystkie odwolania.
        del b
        gc.collect()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(poprzedni)
    assert [c.get("message") for c in zgloszone] == []
    assert "get_apps: StartService: NotPairedError" in komunikat


async def test_zerwana_usluga_podaje_etap_i_przyczyne_a_potem_probuje_z_EscrowBag(caplog):
    caplog.set_level(logging.INFO)
    lockdown = _Lockdown(escrow_ok=True)
    b = _backend(lockdown)
    raw = await b.apps()
    assert raw["com.example.SimpleGame"]["CFBundleExecutable"] == "SimpleGame"
    assert lockdown.escrow_calls == [False, True]
    assert "get_apps dziala dopiero z EscrowBag" in caplog.text
    await b.apps()
    assert lockdown.escrow_calls == [False, True, True], "udana proba zostaje na stale"


async def test_EscrowBag_bez_efektu_nie_jest_ponawiany_co_obieg():
    lockdown = _Lockdown(escrow_ok=False)
    b = _backend(lockdown)
    with pytest.raises(DeviceUnavailable) as exc:
        await b.apps()
    assert "get_apps: odczyt: ConnectionTerminatedError <- IncompleteReadError(0 z 4 B)" in str(
        exc.value
    )
    assert lockdown.escrow_calls == [False, True]
    with pytest.raises(DeviceUnavailable):
        await b.apps()
    assert lockdown.escrow_calls == [False, True, False], "druga proba z EscrowBag za godzine"


async def test_bez_EscrowBag_w_rekordzie_jedna_proba():
    lockdown = _Lockdown(escrow_ok=False)
    b = _backend(lockdown, escrow_bag=False)
    with pytest.raises(DeviceUnavailable):
        await b.apps()
    assert lockdown.escrow_calls == [False]
