"""Testy odczytu stanu iPada przez lockdown.

Wszystkie dane w tym pliku to REALNE wartosci zobaczone na iPad13,2 / iPadOS 27.0
(2026-09-27). Nazwy procesow jak `Dominguez` czy `academy` nie sa wymyslone —
tak faktycznie nazywaja sie pliki wykonywalne Disney+ i "Logiki i Matematyki".
"""

from __future__ import annotations

import pathlib
from datetime import UTC, datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo

import pytest

from kidwatch.models import NotifyKind
from kidwatch.sources.device import (
    DeviceProbe,
    DeviceTarget,
    DeviceUnavailable,
    DeviceWatcher,
    InstalledApp,
    load_pair_record,
    looks_like_app,
)
from kidwatch.store import Store

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)
UDID = "00008101-0000000000000001"

#: Realne aplikacje uzytkownika z iPada.
APPS_RAW = {
    "com.gameloft.asphalt9": {"ApplicationType": "User", "CFBundleDisplayName": "Asphalt"},
    "com.gameloft.asphalt8": {"ApplicationType": "User", "CFBundleDisplayName": "Asphalt 8"},
    "com.disney.disneyplus": {"ApplicationType": "User", "CFBundleDisplayName": "Disney+"},
    "com.fingersoft.legohillclimbadventures": {
        "ApplicationType": "User",
        "CFBundleDisplayName": "LEGO Hill Climb Adventures",
    },
    "net.speedymind.academy": {
        "ApplicationType": "User",
        "CFBundleDisplayName": "Logika i Matematyka",
    },
    "com.netflix.Netflix": {"ApplicationType": "User", "CFBundleDisplayName": "Netflix"},
    "com.google.ios.youtube": {"ApplicationType": "User", "CFBundleDisplayName": "YouTube"},
    # Systemowa — NIE moze trafic do wynikow, bo na iPadzie jest ich ponad 240.
    "com.apple.Preferences": {"ApplicationType": "System", "CFBundleDisplayName": "Ustawienia"},
}
PIDS_RAW = {
    "1": {"ProcessName": "launchd"},
    "37": {"ProcessName": "SpringBoard"},
    "3076": {"ProcessName": "YouTube"},
    "4234": {"ProcessName": "Asphalt9"},
    "4500": {"ProcessName": "Asphalt8"},
    "4503": {"ProcessName": "LEGOHillClimbAdventures"},
    "4678": {"ProcessName": "Dominguez"},
    "1229": {"ProcessName": "SafariViewService"},
}
BACKLIGHT_OFF = {"CurrentNits": 0, "IODisplayParameters": {"brightness": {"value": 33202}}}
BACKLIGHT_ON = {"CurrentNits": 315, "IODisplayParameters": {"brightness": {"value": 33202}}}
ALIASES = {"Dominguez": "com.disney.disneyplus"}


TARGET = DeviceTarget(udid=UDID, host="ipad-kuby")
TZ_WARSAW = ZoneInfo("Europe/Warsaw")


class FakeBackend:
    """Atrapa warstwy lockdown. Wartosc None dla danego odczytu = ten odczyt pada.

    Dzieki temu logika probe/watcher jest testowalna bez urzadzenia i bez
    pymobiledevice3 — cala zaleznosc siedzi w TcpLockdownBackend.
    """

    def __init__(self, responses: dict[str, Any]) -> None:
        self.responses = responses
        self.closed = False
        self.calls: list[str] = []

    async def _get(self, key: str) -> Any:
        self.calls.append(key)
        value = self.responses.get(key)
        if value is None:
            raise DeviceUnavailable(f"{key}: Device not found")
        if isinstance(value, BaseException):
            raise value
        return value

    async def apps(self):
        return await self._get("apps")

    async def pids(self):
        return await self._get("pids")

    async def backlight(self):
        return await self._get("backlight")

    async def aclose(self):
        self.closed = True


def make_probe(responses: dict[str, Any], **kw) -> DeviceProbe:
    return DeviceProbe(TARGET, FakeBackend(responses), **kw)


def apps_of(raw=APPS_RAW) -> dict[str, InstalledApp]:
    return {
        b: InstalledApp(b, m["CFBundleDisplayName"])
        for b, m in raw.items()
        if m.get("ApplicationType") == "User"
    }


# ======================================================= dopasowanie nazw
@pytest.mark.parametrize(
    ("process", "expected"),
    [
        ("Asphalt9", "Asphalt"),
        ("LEGOHillClimbAdventures", "LEGO Hill Climb Adventures"),
        ("YouTube", "YouTube"),
        ("Netflix", "Netflix"),
        # Proces nazywa sie zupelnie inaczej niz aplikacja — stad aliasy.
        ("academy", "Logika i Matematyka"),
    ],
)
def test_proces_dopasowuje_sie_do_aplikacji(process, expected):
    assert looks_like_app(process, apps_of()) == expected


def test_REGRESJA_asphalt8_nie_moze_udawac_asphalta_9():
    """Dopasowanie po przedrostku przypisywalo `Asphalt8` aplikacji o nazwie
    "Asphalt" (czyli Asphaltowi 9) i push mowilby o ZLEJ GRZE. Trafienie
    dokladne w ostatni czlon bundle ID musi bic przedrostek."""
    assert looks_like_app("Asphalt8", apps_of()) == "Asphalt 8"
    assert looks_like_app("Asphalt9", apps_of()) == "Asphalt"


def test_alias_ratuje_proces_o_nazwie_bez_zwiazku():
    """Disney+ chodzi jako `Dominguez`. Zadna heurystyka tego nie zlapie."""
    assert looks_like_app("Dominguez", apps_of()) is None
    assert looks_like_app("Dominguez", apps_of(), ALIASES) == "Disney+"


@pytest.mark.parametrize(
    "process",
    ["SpringBoard", "SafariViewService", "SafariBookmarksSyncAgent", "CalendarWidgetExtension"],
)
def test_uslugi_towarzyszace_nie_sa_aplikacjami(process):
    assert looks_like_app(process, apps_of(), ALIASES) is None


def test_pusta_nazwa_procesu_nie_wybucha():
    assert looks_like_app("", apps_of()) is None
    assert looks_like_app("   ", apps_of()) is None


# ============================================================== DeviceProbe
def test_udid_i_host_sa_obowiazkowe():
    """Przy dwoch iPadach brak wskazania urzadzenia to losowy wybor — wolimy
    jasny blad."""
    with pytest.raises(ValueError, match="UDID"):
        DeviceTarget(udid="", host="ipad")
    with pytest.raises(ValueError, match="host"):
        DeviceTarget(udid=UDID, host="")


def test_domyslny_port_lockdown():
    """Ten sam port po USB i po sieci."""
    assert DeviceTarget(udid=UDID, host="x").port == 62078


async def test_lista_aplikacji_pomija_systemowe():
    probe = make_probe({"apps": APPS_RAW})
    apps = await probe.installed_apps()
    assert len(apps) == 7
    assert "com.apple.Preferences" not in apps
    assert apps["com.gameloft.asphalt9"].label == "Asphalt"


async def test_procesy_sa_mapowane_na_pid():
    probe = make_probe({"pids": PIDS_RAW})
    running = await probe.running()
    assert running[4234] == "Asphalt9"
    assert running[37] == "SpringBoard"
    assert all(isinstance(k, int) for k in running)


async def test_procesy_bez_nazwy_sa_pomijane():
    probe = make_probe(
        {"pids": {"1": {"ProcessName": "a"}, "2": {}, "nie-liczba": {"ProcessName": "b"}}}
    )
    assert await probe.running() == {1: "a"}


@pytest.mark.parametrize(
    ("payload", "expected"), [(BACKLIGHT_OFF, False), (BACKLIGHT_ON, True)]
)
async def test_stan_ekranu_czyta_nits_a_nie_suwaka(payload, expected):
    """CurrentNits to emitowane swiatlo. Przy zgaszonym ekranie bylo 0, choc
    `brightness.value` wynosilo 33202 — dlatego NIE wolno czytac brightness."""
    probe = make_probe({"backlight": payload})
    assert await probe.screen_on() is expected


async def test_brak_nits_to_niedostepnosc():
    probe = make_probe({"backlight": {"IODisplayParameters": {}}})
    with pytest.raises(DeviceUnavailable, match="CurrentNits"):
        await probe.screen_on()


async def test_przekroczony_czas_to_niedostepnosc():
    import asyncio  # noqa: PLC0415

    class SlowBackend(FakeBackend):
        async def apps(self):
            await asyncio.sleep(5)
            return {}

    probe = DeviceProbe(TARGET, SlowBackend({}), timeout=0.05)
    with pytest.raises(DeviceUnavailable, match="czas"):
        await probe.installed_apps()


async def test_czesciowa_awaria_oddaje_to_co_sie_udalo():
    """SPRAWDZONE NA ZYWO: bywa, ze apps i ekran przechodza, a procesy nie.
    Czesciowa wiedza jest lepsza niz zadna."""
    probe = make_probe({"apps": APPS_RAW, "backlight": BACKLIGHT_OFF})
    snap = await probe.snapshot()
    assert len(snap.apps) == 7
    assert snap.running == {}
    assert snap.screen_on is False


async def test_gdy_wszystko_padnie_snapshot_podnosi_wyjatek():
    probe = make_probe({})
    with pytest.raises(DeviceUnavailable):
        await probe.snapshot()


async def test_nieodczytany_ekran_to_None_a_nie_False():
    """None znaczy "nie wiem", False znaczy "wygaszony". Zlanie tych dwoch
    dawaloby falszywe zdarzenia wygaszenia przy kazdej usterce sieci."""
    probe = make_probe({"apps": APPS_RAW, "pids": PIDS_RAW})
    assert (await probe.snapshot()).screen_on is None


async def test_zamykanie_przekazuje_sie_do_backendu():
    backend = FakeBackend({"apps": APPS_RAW})
    probe = DeviceProbe(TARGET, backend)
    await probe.aclose()
    assert backend.closed is True


# ======================================================== rekord parowania
def test_brak_rekordu_parowania_mowi_CO_ZROBIC(tmp_path):
    with pytest.raises(DeviceUnavailable, match="lockdown pair"):
        load_pair_record(UDID, tmp_path)


def test_nieczytelny_rekord_parowania(tmp_path):
    (tmp_path / f"{UDID}.plist").write_bytes(b"to nie jest plist")
    with pytest.raises(DeviceUnavailable, match="nieczytelny"):
        load_pair_record(UDID, tmp_path)


def test_poprawny_rekord_parowania_sie_wczytuje(tmp_path):
    import plistlib  # noqa: PLC0415

    # Klucze jak w prawdziwym rekordzie z ~/.pymobiledevice3/
    record = {"HostID": "abc", "SystemBUID": "def", "HostPrivateKey": b"x"}
    (tmp_path / f"{UDID}.plist").write_bytes(plistlib.dumps(record))
    assert load_pair_record(UDID, tmp_path)["HostID"] == "abc"


# ============================================================ DeviceWatcher
def make_watcher(store, responses, aliases=ALIASES):
    return DeviceWatcher(
        make_probe(responses), "iPad (Dziecko 1)", "Dziecko 1", store, aliases=aliases
    )


async def test_PIERWSZY_odczyt_jest_tylko_punktem_odniesienia(store):
    """Bez tego pierwsze uruchomienie zglosiloby kazda z 7 aplikacji jako NOWA."""
    w = make_watcher(store, {"apps": APPS_RAW, "pids": PIDS_RAW, "backlight": BACKLIGHT_OFF})
    assert w.has_baseline is False
    assert await w.poll(NOW) == []
    assert w.has_baseline is True


async def test_nowa_aplikacja_daje_push(store):
    responses = {"apps": dict(APPS_RAW), "pids": PIDS_RAW, "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    w.probe.backend.responses["apps"] = dict(APPS_RAW) | {
        "com.roblox.robloxmobile": {"ApplicationType": "User", "CFBundleDisplayName": "Roblox"}
    }
    notes = await w.poll(NOW)
    assert len(notes) == 1
    assert "NOWA APLIKACJA" in notes[0].title
    assert "Roblox" in notes[0].text
    assert notes[0].priority == 4


async def test_usuniecie_aplikacji_ma_nizszy_priorytet(store):
    responses = {"apps": dict(APPS_RAW), "pids": PIDS_RAW, "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    reduced = dict(APPS_RAW)
    del reduced["com.gameloft.asphalt8"]
    w.probe.backend.responses["apps"] = reduced
    notes = await w.poll(NOW)
    assert len(notes) == 1
    assert "usunieto" in notes[0].title
    assert "Asphalt 8" in notes[0].text


async def test_nowy_pid_znanej_aplikacji_to_URUCHOMIENIE(store):
    """Odpalic aplikacje mozna tylko z ODBLOKOWANEGO iPada, wiec to jednoczesnie
    dowod, ze urzadzenie bylo uzywane."""
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    w.probe.backend.responses["pids"] = dict(PIDS_RAW) | {"5001": {"ProcessName": "Netflix"}}
    notes = await w.poll(NOW)
    assert len(notes) == 1
    assert notes[0].title == "Dziecko 1"
    assert notes[0].text == "odpalil: Netflix"


async def test_restart_procesu_systemowego_nie_daje_pushu(store):
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    w.probe.backend.responses["pids"] = dict(PIDS_RAW) | {"5002": {"ProcessName": "cfprefsd"}}
    assert await w.poll(NOW) == []


async def test_zamkniecie_aplikacji_nie_zasmieca_pushami(store):
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    reduced = dict(PIDS_RAW)
    del reduced["4234"]
    w.probe.backend.responses["pids"] = reduced
    assert await w.poll(NOW) == []


async def test_wlaczenie_ekranu_jest_zglaszane(store):
    responses = {"apps": APPS_RAW, "pids": PIDS_RAW, "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    w.probe.backend.responses["backlight"] = BACKLIGHT_ON
    notes = await w.poll(NOW)
    assert len(notes) == 1
    assert notes[0].kind is NotifyKind.DEVICE_SCREEN
    assert "ekran wlaczony" in notes[0].title


async def test_niezmieniony_stan_nie_generuje_niczego(store):
    responses = {"apps": APPS_RAW, "pids": PIDS_RAW, "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    assert await w.poll(NOW) == []
    assert await w.poll(NOW) == []


async def test_nieodczytany_ekran_NIE_udaje_wygaszenia(store):
    """iPad spi wiekszosc doby i wtedy jest nieosiagalny. Gdyby usterka odczytu
    udawala wygaszenie, dostawalbys falszywe zdarzenia bez konca."""
    responses = {"apps": APPS_RAW, "pids": PIDS_RAW, "backlight": BACKLIGHT_ON}
    w = make_watcher(store, responses)
    await w.poll(NOW)
    w.probe.backend.responses["backlight"] = None
    assert await w.poll(NOW) == []


async def test_stan_przezywa_restart_procesu(tmp_path):
    """Nowy Store na tej samej bazie nie moze zglosic wszystkiego od nowa."""
    db = tmp_path / "dev.db"
    responses = {"apps": APPS_RAW, "pids": PIDS_RAW, "backlight": BACKLIGHT_OFF}

    s1 = Store(db)
    await make_watcher(s1, responses).poll(NOW)
    s1.close()

    s2 = Store(db)
    w2 = make_watcher(s2, responses)
    assert w2.has_baseline is True
    assert await w2.poll(NOW) == []
    s2.close()


async def test_nierozpoznane_procesy_sa_zbierane_do_domapowania(store):
    """Jak nieznane domeny w app_map.yaml — chcemy wiedziec, czego brakuje."""
    responses = {
        "apps": APPS_RAW,
        "pids": dict(PIDS_RAW) | {"6000": {"ProcessName": "JakasNowaGra"}},
        "backlight": BACKLIGHT_OFF,
    }
    w = make_watcher(store, responses, aliases={})
    await w.poll(NOW)
    assert "JakasNowaGra" in w.unmatched
    # Disney+ bez aliasu tez trafia na liste.
    assert "Dominguez" in w.unmatched


async def test_niedostepny_iPad_propaguje_wyjatek(store):
    """iPad spi = nieosiagalny. To NORMALNY stan; decyzje podejmuje petla wyzej,
    nie watcher — dlatego wyjatek leci dalej, a nie jest zjadany."""
    w = make_watcher(store, {})
    with pytest.raises(DeviceUnavailable):
        await w.poll(NOW)


# =================================== budzet godzinowy i ciche godziny (audyt #7)
from datetime import time as _time  # noqa: E402

from kidwatch.config import QuietHours  # noqa: E402
from kidwatch.models import DEVICE_KINDS  # noqa: E402


async def test_wlasny_limit_godzinowy_dlawi_lawine_uruchomien(store):
    """Bez limitu godzina przelaczania aplikacji dawala nieograniczona liczbe
    pushy."""
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = DeviceWatcher(
        make_probe(responses), "iPad (Dziecko 1)", "Dziecko 1", store,
        aliases=ALIASES, max_per_hour=2
    )
    await w.poll(NOW)

    sent = []
    for i in range(1, 7):
        responses["pids"] = dict(PIDS_RAW) | {
            str(p): {"ProcessName": "Netflix"} for p in range(7000, 7000 + i)
        }
        sent += await w.poll(NOW + timedelta(minutes=i))
    launches = [n for n in sent if n.kind is NotifyKind.DEVICE_LAUNCH]
    assert len(launches) == 2, f"limit 2/h przepuscil {len(launches)}"


async def test_powiadomienia_z_iPada_NIE_zjadaja_budzetu_warstwy_DNS(store):
    """NAJPODSTEPNIEJSZA z uwag audytu: wspolny licznik sprawial, ze godzina
    grania wypelniala notify_log i silnik zaczynal dlawic WLASNE pushe o sesjach."""
    for i in range(20):
        store.log_notification(
            "iPad (Dziecko 1)", NOW + timedelta(seconds=i), NotifyKind.DEVICE_LAUNCH.value
        )
    window = NOW - timedelta(hours=1)
    # Licznik warstwy DNS musi te wiersze POMIJAC.
    dns_used = store.count_notifications_since(
        "iPad (Dziecko 1)", window, exclude_kinds=tuple(k.value for k in DEVICE_KINDS)
    )
    device_used = store.count_notifications_since(
        "iPad (Dziecko 1)", window, kinds=tuple(k.value for k in DEVICE_KINDS)
    )
    assert dns_used == 0
    assert device_used == 20


async def test_w_cichych_godzinach_priorytet_ROSNIE_a_nie_wycisza(store):
    """Aktywnosc noca jest wlasnie tym, co chcesz wiedziec — wyciszenie byloby
    odwrotnoscia celu."""
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = DeviceWatcher(
        make_probe(responses),
        "iPad (Dziecko 1)",
        "Dziecko 1",
        store,
        tz=TZ_WARSAW,
        aliases=ALIASES,
        quiet_hours=QuietHours(start=_time(21, 30), end=_time(7, 0)),
    )
    noc = datetime(2026, 9, 27, 23, 15, tzinfo=UTC)
    await w.poll(noc)
    responses["pids"] = dict(PIDS_RAW) | {"8001": {"ProcessName": "Netflix"}}
    notes = await w.poll(noc + timedelta(minutes=1))
    assert len(notes) == 1
    assert notes[0].priority >= 4, "nocny push musi miec podniesiony priorytet"


async def test_inwentarz_NIE_jest_dlawiony_limitem(store):
    """Nowa aplikacja to zdarzenie rzadkie i wazne. Zgubienie go w limicie
    zniweczyloby caly sens."""
    responses = {"apps": dict(APPS_RAW), "pids": PIDS_RAW, "backlight": BACKLIGHT_OFF}
    w = DeviceWatcher(
        make_probe(responses), "iPad (Dziecko 1)", "Dziecko 1", store,
        aliases=ALIASES, max_per_hour=0
    )
    await w.poll(NOW)
    responses["apps"] = dict(APPS_RAW) | {
        "com.roblox.robloxmobile": {"ApplicationType": "User", "CFBundleDisplayName": "Roblox"}
    }
    notes = await w.poll(NOW + timedelta(minutes=1))
    assert [n.kind for n in notes] == [NotifyKind.DEVICE_INVENTORY]


# ================================= punkt odniesienia per sygnal (audyt #9)
async def test_trwale_padajacy_odczyt_apek_NIE_blokuje_wykrywania_uruchomien(store):
    """Jeden globalny znacznik oparty na liscie aplikacji sprawial, ze trwala
    awaria tego odczytu blokowala wykrywanie uruchomien NA ZAWSZE."""
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    assert await w.poll(NOW) == []  # punkt odniesienia dla wszystkich sygnalow

    # Od teraz lista aplikacji pada TRWALE — ale zapisana wczesniej wystarcza,
    # zeby nazwac proces, a wykrywanie uruchomien musi dzialac dalej.
    responses["apps"] = None
    responses["pids"] = dict(PIDS_RAW) | {"9001": {"ProcessName": "Netflix"}}
    notes = await w.poll(NOW + timedelta(minutes=1))
    assert [n.kind for n in notes] == [NotifyKind.DEVICE_LAUNCH]
    assert "Netflix" in notes[0].text

    # I kolejny obieg tez, nie tylko pierwszy.
    responses["pids"] = dict(PIDS_RAW) | {
        "9001": {"ProcessName": "Netflix"},
        "9002": {"ProcessName": "Asphalt9"},
    }
    notes = await w.poll(NOW + timedelta(minutes=2))
    assert [n.kind for n in notes] == [NotifyKind.DEVICE_LAUNCH]
    assert "Asphalt" in notes[0].text


# ==================================== klucz dedupu uruchomienia (audyt #10)
async def test_ten_sam_PID_w_INNYM_DNIU_nie_jest_gubiony(store):
    """iOS po restarcie numeruje PID-y od nowa, a klucze dedupu zyja 7 dni. Bez
    daty ta sama apka na tym samym PID-zie w ciagu tygodnia gubila sie bez sladu."""
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = make_watcher(store, responses)
    await w.poll(NOW)

    responses["pids"] = dict(PIDS_RAW) | {"4321": {"ProcessName": "Netflix"}}
    dzien1 = await w.poll(NOW + timedelta(minutes=1))
    assert [n.kind for n in dzien1] == [NotifyKind.DEVICE_LAUNCH]
    assert dzien1[0].dedup_key != f"dev-launch:{UDID}:4321:Netflix", "klucz musi zawierac date"

    # Nastepnego dnia ten sam PID i ta sama apka. Cofamy punkt odniesienia tak,
    # jakby proces w miedzyczasie zniknal (restart iPada), ale NIE ruszamy
    # pozostalych, zeby nie zglosic wszystkiego na nowo.
    baseline = dict(store.get_json(f"dev:{UDID}:pids"))
    baseline.pop("4321", None)
    store.set_json(f"dev:{UDID}:pids", baseline)

    dzien2 = await w.poll(NOW + timedelta(days=1))
    assert [n.kind for n in dzien2] == [NotifyKind.DEVICE_LAUNCH], (
        "push z innego dnia nie moze zniknac przez dedup opary na samym PID-zie"
    )


# ================================== katalog cache rekordow (audyt #1)
def test_backend_ma_JAWNY_zapisywalny_katalog_cache(tmp_path):
    """Bez jawnej sciezki pymobiledevice3 robi mkdir pod $HOME. W podzie
    z readOnlyRootFilesystem: true to OSError przy KAZDYM polaczeniu, zamieniany
    potem na DeviceUnavailable — czyli serwis nigdy by nie zadzialal, raportujac
    "iPad spi"."""
    from kidwatch.sources.device import TcpLockdownBackend  # noqa: PLC0415

    b = TcpLockdownBackend(TARGET, {"HostID": "x"})
    assert b._cache_dir is not None
    assert str(b._cache_dir).startswith(("/tmp", "/private/tmp", "/var/folders"))

    wlasny = tmp_path / "cache"
    assert TcpLockdownBackend(TARGET, {"HostID": "x"}, cache_dir=wlasny)._cache_dir == wlasny


# ==================================== zamykanie polaczen uslug (audyt #2)
async def test_polaczenia_uslug_sa_ZAMYKANE():
    """Kazda usluga otwiera wlasne gniazdo. Bez zamykania trzy odczyty na minute
    na urzadzenie zostawiaja ~1000 deskryptorow w ciagu doby."""
    zamkniete = []

    class FakeService:
        def __init__(self, client):
            self.client = client

        async def get_apps(self, **kw):
            return {}

        async def close(self):
            zamkniete.append(True)

    from kidwatch.sources.device import TcpLockdownBackend  # noqa: PLC0415

    b = TcpLockdownBackend(TARGET, {"HostID": "x"})
    b._client = object()  # udajemy polaczony klient
    await b._service(FakeService, "get_apps")
    assert zamkniete == [True], "usluga musi byc zamknieta po odczycie"


async def test_anulowanie_ZERWIE_klienta_zeby_nie_czytac_cudzej_odpowiedzi():
    """CancelledError NIE jest podklasa Exception. Bez osobnej galezi klient
    zostawal z niedoczytana odpowiedzia i kolejny odczyt dostawal cudzy payload."""
    import asyncio as _asyncio  # noqa: PLC0415

    class SlowService:
        def __init__(self, client):
            pass

        async def get_apps(self, **kw):
            await _asyncio.sleep(10)

        async def close(self):
            pass

    from kidwatch.sources.device import TcpLockdownBackend  # noqa: PLC0415

    b = TcpLockdownBackend(TARGET, {"HostID": "x"})
    b._client = object()
    task = _asyncio.create_task(b._service(SlowService, "get_apps"))
    await _asyncio.sleep(0.02)
    task.cancel()
    with pytest.raises(_asyncio.CancelledError):
        await task
    assert b._client is None, "anulowanie musi porzucic klienta"


# ============================== adres IPv6 nie nadaje sie (sprawdzone na sprzecie)
def test_konfiguracja_ODRZUCA_adres_IPv6():
    """Sprawdzone na dwoch iPadach: po IPv6 `os_trace` (procesy) dziala, ale
    `installation_proxy` (aplikacje) i `diagnostics` (ekran) padaja na
    ConnectionTerminatedError. Ten sam iPad po IPv4 oddaje wszystko.

    Bonjour zglasza iPady wlasnie po IPv6, wiec bez tej walidacji latwo wkleic
    taki adres i dostac warstwe okaleczona w sposob wygladajacy na awarie sieci.
    """
    from kidwatch.config import DeviceConfig  # noqa: PLC0415

    for zly in (
        "fd00:4664:5cc2:4ccc:14a8:7ce7:1023:df5f",
        "[fd00:4664::1]",
        "fe80::1",
    ):
        with pytest.raises(Exception, match="IPv6"):
            DeviceConfig(
                display_name="iPad", child="K", source_ids=["a"], udid="X", host=zly
            )

    # IPv4 przechodzi.
    ok = DeviceConfig(
        display_name="iPad", child="K", source_ids=["a"], udid="X", host="100.101.102.103"
    )
    assert ok.host == "100.101.102.103"


# ====================== awaryjna lista aplikacji z konfiguracji (iPad Dziecka 2)
async def test_awaryjna_lista_pozwala_NAZWAC_proces_bez_odczytu_inwentarza(store):
    """Na iPadzie Dziecka 2 `installation_proxy` po sieci pada, a lista procesow
    dziala. Bez awaryjnej listy uruchomienia przychodzilyby BEZ NAZW — `Asphalt9`
    to tylko napis, dopoki nie wiadomo, ze istnieje apka "Asphalt"."""
    responses = {"apps": None, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = DeviceWatcher(
        make_probe(responses),
        "iPad (Dziecko 2)",
        "Dziecko 2",
        store,
        aliases=ALIASES,
        fallback_apps={
            "com.gameloft.asphalt9": "Asphalt",
            "com.mojang.minecraftpe": "Minecraft",
            "com.disney.disneyplus": "Disney+",
        },
    )
    await w.poll(NOW)  # punkt odniesienia dla procesow

    responses["pids"] = dict(PIDS_RAW) | {"9100": {"ProcessName": "Minecraft"}}
    notes = await w.poll(NOW + timedelta(minutes=1))
    assert len(notes) == 1
    assert notes[0].text == "odpalil: Minecraft", notes[0].text


async def test_zywy_odczyt_MA_PIERWSZENSTWO_nad_awaryjna_lista(store):
    """Awaryjna lista jest statyczna i moze byc nieaktualna. Gdy zywy odczyt
    dziala, wygrywa on."""
    responses = {"apps": APPS_RAW, "pids": dict(PIDS_RAW), "backlight": BACKLIGHT_OFF}
    w = DeviceWatcher(
        make_probe(responses),
        "iPad (Dziecko 1)",
        "Dziecko 1",
        store,
        aliases=ALIASES,
        fallback_apps={"com.gameloft.asphalt9": "STARA NAZWA"},
    )
    await w.poll(NOW)
    responses["pids"] = dict(PIDS_RAW) | {"9200": {"ProcessName": "Asphalt9"}}
    notes = await w.poll(NOW + timedelta(minutes=1))
    assert notes[0].text == "odpalil: Asphalt", "zywy odczyt musi wygrac"


def test_konfiguracja_klastra_ma_awaryjne_listy_dla_OBU_iPadow():
    """iPad Dziecka 2 bez tej listy dawalby uruchomienia bez nazw."""
    import yaml  # noqa: PLC0415

    cfg_path = (
        pathlib.Path(__file__).resolve().parents[1] / "charts/kidwatch/files/config.yaml"
    )
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    for dev in cfg["devices"]:
        assert dev.get("known_apps"), f"{dev['display_name']} bez known_apps"
        assert len(dev["known_apps"]) >= 5


def test_awaryjne_listy_pozwalaja_nazwac_realne_procesy():
    """Nazwy procesow zobaczone na sprzecie: Disney+ chodzi jako `Dominguez`,
    "Logika i Matematyka" jako `academy`."""
    import yaml  # noqa: PLC0415

    cfg_path = (
        pathlib.Path(__file__).resolve().parents[1] / "charts/kidwatch/files/config.yaml"
    )
    cfg = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    aliases = cfg["device_read"]["process_aliases"]
    drugie = next(d for d in cfg["devices"] if "com.mojang.minecraftpe" in d["known_apps"])
    apps = {b: InstalledApp(b, n) for b, n in drugie["known_apps"].items()}

    oczekiwane = {
        "Asphalt9": "Asphalt",
        "Asphalt8": "Asphalt 8",
        "Minecraft": "Minecraft",
        "Dominguez": "Disney+",
        "academy": "Logika i Matematyka",
    }
    for proc, label in oczekiwane.items():
        assert looks_like_app(proc, apps, aliases) == label, proc

    # Powloka i uslugi systemowe NIE moga byc raportowane jako aplikacje.
    for proc in ("SpringBoard", "AskToUIHost", "FamilyControlsAgent"):
        assert looks_like_app(proc, apps, aliases) is None, proc
