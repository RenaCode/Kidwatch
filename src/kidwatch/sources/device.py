"""Odczyt stanu iPada przez uslugi lockdown, po SIECI.

Zweryfikowane na realnym sprzecie 2026-09-27 (iPad13,2 "iPad (Dziecko 1)",
iPadOS 27.0). Bez MDM, nadzoru, Developer Mode, jailbreaka i wymazywania.

## Dlaczego polaczenie WPROST PO IP, a nie przez usbmuxd

`pymobiledevice3 processes ps` przez transport usbmux po Wi-Fi pada 0/6 razy
("Connection was terminated abruptly"). Przez bezposrednie TCP do portu 62078
te same odczyty dzialaja bez zarzutu:

    apps list          0,18 s   7 aplikacji uzytkownika
    ioregistry         0,10 s   CurrentNits
    os_trace pid list  0,12 s   414 procesow, w tym Asphalt8, Asphalt9, YouTube

Ograniczenie bylo w TRANSPORCIE, nie w usludze. Poza tym bezposrednie TCP nie
potrzebuje Bonjour, wiec dziala przez overlay VPN (Tailscale) z DOWOLNEJ sieci —
szkola, komorka, dom kolegi — i na Linuksie, bo caly ten tor to czysty Python.

## Parowanie

`create_using_tcp` jest KORUTYNA. `autopair=True` konczy sie
`GetProhibitedError` — rekord parowania trzeba wczytac z pliku i przekazac jako
`pair_record=`. Rekord (`HostID`, `HostCertificate`, `HostPrivateKey`,
`RootCertificate`, `RootPrivateKey`, `SystemBUID`, `DeviceCertificate`,
`EscrowBag`) nie korzysta z keychaina, wiec jest PRZENOSNY: skopiowany na VPS
czyni go tym samym zaufanym hostem. Samo parowanie wymaga jednorazowo USB.

## Czego ta warstwa NIE da

iPad odpada od Wi-Fi, gdy zasnie — wtedy jest nieosiagalny i zaden VPN tego nie
naprawi. Przy zgaszonym ekranie odpowiadal tylko na kablu (ladowanie trzyma
lacze). Dlatego `DeviceUnavailable` to NORMALNY stan, nie awaria, a warstwa DNS
(reszta kidwatcha) zostaje jako niezalezne zrodlo: tam iPad dzwoni na zewnatrz,
wiec nic nie musi sie do niego dobijac.

## Identyfikacja

Wylacznie po UDID. Nazwy zwodza: dwa iPady zglaszaly sie przez usbmux jako
"Jan Kowalski's iPad" i "iPad (2)", a przez bonjour jako "iPad (Dziecko 1)" i
"iPad (Dziecko 2)" — przy czym apki dziecka byly na tym pierwszym.
"""

from __future__ import annotations

import asyncio
import contextlib
import inspect
import logging
import plistlib
import tempfile
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from ..models import DEVICE_KINDS, Notification, NotifyKind
from ..store import Store
from .base import Unreachable

log = logging.getLogger(__name__)

#: Limit na jeden odczyt. iPad po Wi-Fi bywa leniwy, ale nie wisi — a bez limitu
#: jedna zawieszona odpowiedz zatrzymalaby caly obieg.
DEFAULT_TIMEOUT = 20.0

#: Port lockdown. Ten sam po USB i po sieci.
LOCKDOWN_PORT = 62078


class DeviceUnavailable(Unreachable):
    """iPad nie odpowiada: spi, wyniesiony z sieci albo zerwane parowanie.

    To NORMALNY stan, nie blad — iPad spi wiekszosc doby.
    """


@dataclass(frozen=True, slots=True)
class DeviceTarget:
    """Gdzie szukac iPada. `host` to nazwa z Tailscale albo adres IP."""

    udid: str
    host: str
    port: int = LOCKDOWN_PORT

    def __post_init__(self) -> None:
        if not self.udid:
            raise ValueError("UDID jest obowiazkowy — bez niego nie wiadomo, ktory iPad")
        if not self.host:
            raise ValueError("host jest obowiazkowy (nazwa Tailscale albo IP)")


@dataclass(frozen=True, slots=True)
class InstalledApp:
    bundle_id: str
    name: str

    @property
    def label(self) -> str:
        return self.name or self.bundle_id


@dataclass(frozen=True, slots=True)
class DeviceSnapshot:
    """Stan iPada w jednej chwili."""

    apps: dict[str, InstalledApp] = field(default_factory=dict)
    running: dict[int, str] = field(default_factory=dict)
    #: None znaczy "nie wiem". NIE mylic z False ("wygaszony") — zlanie tych
    #: dwoch dawaloby falszywe zdarzenia wygaszenia przy kazdej usterce sieci.
    screen_on: bool | None = None


class LockdownBackend(Protocol):
    """Trzy odczyty, ktorych potrzebujemy. Cala zaleznosc od pymobiledevice3
    siedzi w implementacji — logika wyzej jest testowalna bez urzadzenia."""

    async def apps(self) -> dict[str, dict[str, Any]]: ...
    async def pids(self) -> dict[str, dict[str, Any]]: ...
    async def backlight(self) -> dict[str, Any]: ...
    async def aclose(self) -> None: ...


async def _maybe(value):
    """pymobiledevice3 miesza funkcje sync i async miedzy wersjami."""
    return await value if inspect.isawaitable(value) else value


def load_pair_record(udid: str, folder: str | Path) -> dict[str, Any]:
    """Wczytuje rekord parowania wygenerowany przy jednorazowym parowaniu po USB."""
    path = Path(folder) / f"{udid}.plist"
    if not path.is_file():
        raise DeviceUnavailable(
            f"brak rekordu parowania {path}. Sparuj raz po kablu:\n"
            f"  pymobiledevice3 lockdown pair --udid {udid}"
        )
    try:
        return plistlib.loads(path.read_bytes())
    except (OSError, plistlib.InvalidFileException) as exc:
        raise DeviceUnavailable(f"nieczytelny rekord parowania {path}: {exc}") from exc


class TcpLockdownBackend:
    """Prawdziwy odczyt przez pymobiledevice3, po bezposrednim TCP."""

    def __init__(
        self,
        target: DeviceTarget,
        pair_record: dict[str, Any],
        cache_dir: Path | None = None,
    ) -> None:
        self.target = target
        self._pair_record = pair_record
        # MUSI byc jawny i ZAPISYWALNY. Bez tego pymobiledevice3 wola
        # create_pairing_records_cache_folder(None) -> get_home_folder(), ktore
        # robi mkdir(parents=True) pod $HOME. W podzie z
        # readOnlyRootFilesystem: true to OSError przy KAZDYM polaczeniu, a
        # `except Exception` zamienialo go w DeviceUnavailable — czyli serwis
        # nigdy by nie zadzialal, raportujac "iPad spi".
        self._cache_dir = Path(cache_dir) if cache_dir else Path(tempfile.gettempdir()) / "pmd3"
        self._client = None

    @staticmethod
    def _why(exc: BaseException) -> str:
        """Czytelna przyczyna. Goly TimeoutError ma pusty tekst, a "TimeoutError: "
        nic nie mowi — a to NAJCZESTSZY przypadek, bo iPad spi wiekszosc doby."""
        text = str(exc).strip()
        name = type(exc).__name__
        if isinstance(exc, (TimeoutError, asyncio.TimeoutError, ConnectionError, OSError)):
            return text or "nie odpowiada (spi albo poza siecia)"
        return f"{name}: {text}" if text else name

    async def _connect(self):
        if self._client is not None:
            return self._client
        try:
            from pymobiledevice3.lockdown import create_using_tcp  # noqa: PLC0415
        except ImportError as exc:  # pragma: no cover
            raise DeviceUnavailable(f"brak pymobiledevice3: {exc}") from exc
        try:
            self._cache_dir.mkdir(parents=True, exist_ok=True)
            self._client = await create_using_tcp(
                hostname=self.target.host,
                port=self.target.port,
                identifier=self.target.udid,
                # autopair=True daje GetProhibitedError — rekord podajemy sami.
                autopair=False,
                pair_record=self._pair_record,
                pairing_records_cache_folder=self._cache_dir,
                keep_alive=True,
            )
        except Exception as exc:
            raise DeviceUnavailable(f"{self.target.host}: {self._why(exc)}") from exc
        return self._client

    async def _service(self, factory, method: str, *args, **kwargs):
        """Jedno wywolanie uslugi lockdown, z ZAMKNIECIEM polaczenia.

        Kazda usluga otwiera WLASNE gniazdo przez start_lockdown_service. Bez
        zamkniecia przy trzech odczytach na minute na urzadzenie zostaje ~1000
        deskryptorow w ciagu doby, a na iPadzie narastaja kanaly lockdownd.
        """
        client = await self._connect()
        service = factory(client)
        try:
            return await _maybe(getattr(service, method)(*args, **kwargs))
        except asyncio.CancelledError:
            # Anulowanie (zwykle limit czasu z _with_timeout) przerywa odczyt
            # W POLOWIE odpowiedzi. CancelledError NIE jest podklasa Exception,
            # wiec bez tej galezi klient zostawal z niedoczytana odpowiedzia w
            # strumieniu i kolejny odczyt dostawalby cudzy payload.
            self._client = None
            raise
        except Exception as exc:
            # Zerwane polaczenie trzeba porzucic, inaczej kolejny odczyt padnie
            # na tym samym martwym gniazdzie.
            self._client = None
            raise DeviceUnavailable(f"{method}: {self._why(exc)}") from exc
        finally:
            with contextlib.suppress(Exception):
                await _maybe(service.close())

    async def apps(self) -> dict[str, dict[str, Any]]:
        from pymobiledevice3.services.installation_proxy import (  # noqa: PLC0415
            InstallationProxyService,
        )

        raw = await self._service(InstallationProxyService, "get_apps", application_type="User")
        return raw if isinstance(raw, dict) else {}

    async def pids(self) -> dict[str, dict[str, Any]]:
        from pymobiledevice3.services.os_trace import OsTraceService  # noqa: PLC0415

        raw = await self._service(OsTraceService, "get_pid_list")
        if isinstance(raw, dict):
            inner = raw.get("Payload", raw)
            if isinstance(inner, dict):
                return inner
        return {}

    async def backlight(self) -> dict[str, Any]:
        from pymobiledevice3.services.diagnostics import DiagnosticsService  # noqa: PLC0415

        raw = await self._service(DiagnosticsService, "ioregistry", ioclass="AppleARMBacklight")
        return raw if isinstance(raw, dict) else {}

    async def aclose(self) -> None:
        client, self._client = self._client, None
        if client is None:
            return
        try:
            await _maybe(client.close())
        except Exception:  # pragma: no cover
            log.debug("blad przy zamykaniu polaczenia z %s", self.target.host, exc_info=True)


class DeviceProbe:
    """Jedno urzadzenie. Tlumaczy surowe odpowiedzi na model domenowy."""

    def __init__(
        self,
        target: DeviceTarget,
        backend: LockdownBackend,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self.target = target
        self.backend = backend
        self.timeout = timeout

    @property
    def udid(self) -> str:
        return self.target.udid

    @classmethod
    def over_tcp(
        cls,
        target: DeviceTarget,
        pair_record_dir: str | Path,
        timeout: float = DEFAULT_TIMEOUT,
        cache_dir: str | Path | None = None,
    ) -> DeviceProbe:
        record = load_pair_record(target.udid, pair_record_dir)
        return cls(
            target, TcpLockdownBackend(target, record, cache_dir=cache_dir), timeout=timeout
        )

    async def _with_timeout(self, coro):
        try:
            return await asyncio.wait_for(coro, timeout=self.timeout)
        except TimeoutError as exc:
            raise DeviceUnavailable(f"{self.target.host}: przekroczony czas") from exc

    async def installed_apps(self) -> dict[str, InstalledApp]:
        """Aplikacje UZYTKOWNIKA. Systemowych nie zwracamy — na iPadzie jest ich
        ponad 240 i tylko zaszumilyby kazde porownanie."""
        raw = await self._with_timeout(self.backend.apps())
        out: dict[str, InstalledApp] = {}
        for bundle_id, meta in raw.items():
            if not isinstance(meta, dict):
                continue
            if meta.get("ApplicationType") not in (None, "User"):
                continue
            name = meta.get("CFBundleDisplayName") or meta.get("CFBundleName") or bundle_id
            out[str(bundle_id)] = InstalledApp(str(bundle_id), str(name))
        return out

    async def running(self) -> dict[int, str]:
        """{pid: nazwa procesu}. PID-y rosna z czasem uruchomienia."""
        raw = await self._with_timeout(self.backend.pids())
        out: dict[int, str] = {}
        for pid, meta in raw.items():
            name = meta.get("ProcessName") if isinstance(meta, dict) else None
            if not name:
                continue
            try:
                out[int(pid)] = str(name)
            except (TypeError, ValueError):
                continue
        return out

    async def screen_on(self) -> bool:
        """Czy ekran FAKTYCZNIE swieci.

        `CurrentNits` to emitowane swiatlo, nie ustawienie suwaka: przy zgaszonym
        ekranie odczyt byl 0, choc `brightness.value` wynosilo 33202.
        """
        raw = await self._with_timeout(self.backend.backlight())
        nits = raw.get("CurrentNits")
        if not isinstance(nits, (int, float)) or isinstance(nits, bool):
            raise DeviceUnavailable("ioregistry: brak CurrentNits")
        return nits > 0

    async def snapshot(self) -> DeviceSnapshot:
        """Pelny stan. Nieudany pojedynczy odczyt nie przekresla pozostalych —
        tak zachowal sie realny przebieg, gdy apps i ekran przeszly, a procesy nie."""
        apps: dict[str, InstalledApp] = {}
        running: dict[int, str] = {}
        screen: bool | None = None
        errors: list[str] = []

        try:
            apps = await self.installed_apps()
        except DeviceUnavailable as exc:
            errors.append(f"apps: {exc}")
        try:
            running = await self.running()
        except DeviceUnavailable as exc:
            errors.append(f"procesy: {exc}")
        try:
            screen = await self.screen_on()
        except DeviceUnavailable as exc:
            errors.append(f"ekran: {exc}")

        if errors and not apps and not running and screen is None:
            raise DeviceUnavailable("; ".join(errors))
        if errors:
            log.warning("czesciowy odczyt z %s: %s", self.target.udid, "; ".join(errors))
        return DeviceSnapshot(apps=apps, running=running, screen_on=screen)

    async def aclose(self) -> None:
        await self.backend.aclose()


# =========================================================== sledzenie zmian
#: Procesy, ktore nalezy pominac przy wykrywaniu uruchomien: to uslugi
#: towarzyszace aplikacjom, nie same aplikacje.
IGNORED_PROCESS_SUFFIXES = (
    "Extension",
    "Service",
    "Agent",
    "Helper",
    "Widget",
    "SafeBrowsing",
)


def _flatten(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


def looks_like_app(
    process_name: str,
    apps: dict[str, InstalledApp],
    aliases: dict[str, str] | None = None,
) -> str | None:
    """Dopasowuje nazwe procesu do zainstalowanej aplikacji.

    iOS nazywa proces po pliku wykonywalnym, nie po bundle ID: "Asphalt 9" jest
    procesem `Asphalt9`, "Logika i Matematyka" procesem `academy`, a Disney+
    procesem `Dominguez` — bez zadnego zwiazku z nazwa.

    Dopasowanie jest PUNKTOWANE, a nie "pierwszy pasujacy". Trafienie dokladne
    bije przedrostek, bo inaczej `Asphalt8` dopasowywal sie do aplikacji o nazwie
    "Asphalt" (czyli Asphalta 9) i push mowilby o zlej grze. Sprawdzone na
    realnych danych z iPada.

    `aliases` mapuje nazwe procesu na bundle ID dla przypadkow, ktorych zadna
    heurystyka nie zlapie (Dominguez -> com.disney.disneyplus). Nieznane procesy
    zwracaja None i sa logowane, zebys mogl je domapowac.
    """
    if any(process_name.endswith(suffix) for suffix in IGNORED_PROCESS_SUFFIXES):
        return None
    needle = _flatten(process_name)
    if not needle:
        return None

    if aliases:
        target = aliases.get(process_name) or aliases.get(process_name.lower())
        if target:
            app = apps.get(target)
            return app.label if app else target

    best: tuple[int, int, str] | None = None
    for app in apps.values():
        flat_name = _flatten(app.name)
        tail = _flatten(app.bundle_id.rsplit(".", 1)[-1])

        score = 0
        if tail and tail == needle:
            score = 3                      # ostatni czlon bundle ID, dokladnie
        elif flat_name and flat_name == needle:
            score = 3                      # nazwa aplikacji, dokladnie
        elif flat_name and (flat_name.startswith(needle) or needle.startswith(flat_name)):
            score = 1                      # przedrostek — najslabszy dowod
        elif tail and (tail.startswith(needle) or needle.startswith(tail)):
            score = 1
        if not score:
            continue
        candidate = (score, len(flat_name), app.label)
        if best is None or candidate > best:
            best = candidate
    return best[2] if best else None


class DeviceWatcher:
    """Porownuje kolejne zdjecia stanu iPada i zglasza roznice.

    PIERWSZY odczyt jest wylacznie punktem odniesienia i NIE generuje ani jednego
    powiadomienia. Bez tego pierwsze uruchomienie zalaloby telefon zgloszeniem
    kazdej zainstalowanej aplikacji jako "nowej".
    """

    def __init__(
        self,
        probe: DeviceProbe,
        device_name: str,
        child: str,
        store: Store,
        tz=None,
        aliases: dict[str, str] | None = None,
        max_per_hour: int = 30,
        quiet_hours=None,
        fallback_apps: dict[str, str] | None = None,
    ) -> None:
        self.probe = probe
        self.device_name = device_name
        self.child = child
        self.store = store
        self.tz = tz
        #: Wlasny budzet godzinowy, ODDZIELONY od warstwy DNS. Bez tego godzina
        #: przelaczania aplikacji dawala nieograniczona liczbe pushy, a przy
        #: wspolnym liczniku dodatkowo zaglodzila by powiadomienia o sesjach DNS.
        self.max_per_hour = max_per_hour
        #: W cichych godzinach NIE wyciszamy — aktywnosc noca jest wlasnie tym,
        #: co chcesz wiedziec. Podnosimy priorytet.
        self.quiet_hours = quiet_hours
        #: proces -> bundle ID, dla nazw, ktorych heurystyka nie zlapie
        self.aliases = dict(aliases or {})
        #: nazwy procesow, ktorych nie udalo sie przypisac — do domapowania
        self.unmatched: set[str] = set()
        #: Awaryjna lista aplikacji, gdy zywy odczyt inwentarza nie dziala.
        #: Bez niej uruchomienia przychodzilyby BEZ NAZW aplikacji.
        self.fallback_apps = {
            b: InstalledApp(b, n) for b, n in (fallback_apps or {}).items()
        }

    # --------------------------------------------------------------- klucze
    def _key(self, what: str) -> str:
        return f"dev:{self.probe.udid}:{what}"

    @property
    def has_baseline(self) -> bool:
        return self.store.get_meta(self._key("apps")) is not None

    # ---------------------------------------------------------------- odczyt
    async def poll(self, now: datetime) -> list[Notification]:
        """Jeden obieg. DeviceUnavailable nie jest tu bledem — iPad moze byc
        poza siecia — wiec wyjatek propaguje do wolajacego, ktory decyduje."""
        snapshot = await self.probe.snapshot()
        out: list[Notification] = []

        prev_apps = self.store.get_json(self._key("apps"))
        prev_pids = self.store.get_json(self._key("pids"))
        prev_screen = self.store.get_meta(self._key("screen"))

        # Punkt odniesienia liczony PER SYGNAL. Jeden globalny znacznik oparty na
        # liscie aplikacji sprawial, ze trwale padajacy odczyt apek blokowal
        # wykrywanie uruchomien NA ZAWSZE: prev_apps nigdy sie nie zapisywal,
        # wiec kazdy obieg byl "pierwszy" i _launch_changes nie bylo wolane.
        apps_known = isinstance(prev_apps, dict)
        pids_known = isinstance(prev_pids, dict)
        screen_known = prev_screen is not None

        if snapshot.apps:
            if apps_known:
                out += self._app_inventory_changes(snapshot, dict(prev_apps), now)
            self.store.set_json(
                self._key("apps"), {b: a.name for b, a in snapshot.apps.items()}
            )

        if snapshot.running:
            # Kolejnosc: zywy odczyt -> zapisany w bazie -> awaryjny z konfiguracji.
            known_apps = (
                snapshot.apps
                or {b: InstalledApp(b, n) for b, n in (prev_apps or {}).items()}
                or self.fallback_apps
            )
            current = {}
            for pid, proc in snapshot.running.items():
                label = looks_like_app(proc, known_apps, self.aliases)
                if label:
                    current[str(pid)] = label
                elif proc[:1].isupper() and "." not in proc and len(proc) > 3:
                    # Wyglada na aplikacje, ale nie wiemy na ktora. Zbieramy,
                    # zebys mogl dopisac alias — jak z domenami w app_map.yaml.
                    self.unmatched.add(proc)
            if pids_known:
                out += self._launch_changes(current, dict(prev_pids), now)
            self.store.set_json(self._key("pids"), current)

        if snapshot.screen_on is not None:
            state = "on" if snapshot.screen_on else "off"
            if screen_known and prev_screen != state:
                out += self._screen_change(snapshot.screen_on, now)
            self.store.set_meta(self._key("screen"), state)

        if not (apps_known and pids_known and screen_known):
            log.info(
                "%s: punkt odniesienia (apki=%s procesy=%s ekran=%s) — bez powiadomien "
                "dla brakujacych sygnalow",
                self.device_name,
                "znany" if apps_known else "USTALAM",
                "znany" if pids_known else "USTALAM",
                "znany" if screen_known else "USTALAM",
            )
        return out

    # ------------------------------------------------------------- roznice
    def _app_inventory_changes(
        self, snapshot: DeviceSnapshot, previous: dict, now: datetime
    ) -> list[Notification]:
        out: list[Notification] = []
        added = [b for b in snapshot.apps if b not in previous]
        removed = [b for b in previous if b not in snapshot.apps]

        for bundle_id in sorted(added):
            app = snapshot.apps[bundle_id]
            out += self._emit(
                Notification(
                    kind=NotifyKind.DEVICE_INVENTORY,
                    title=f"{self.device_name} — NOWA APLIKACJA",
                    text=f"{app.label}\n{bundle_id}",
                    dedup_key=f"dev-install:{self.probe.udid}:{bundle_id}",
                    ts=now,
                    device=self.device_name,
                    app=app.label,
                    priority=4,
                    tags=("new", "package"),
                )
            )
        for bundle_id in sorted(removed):
            name = previous.get(bundle_id) or bundle_id
            out += self._emit(
                Notification(
                    kind=NotifyKind.DEVICE_INVENTORY,
                    title=f"{self.device_name} — usunieto aplikacje",
                    text=f"{name}\n{bundle_id}",
                    dedup_key=f"dev-remove:{self.probe.udid}:{bundle_id}:{now:%Y%m%d}",
                    ts=now,
                    device=self.device_name,
                    app=str(name),
                    priority=2,
                    tags=("wastebasket",),
                )
            )
        return out

    def _launch_changes(
        self, current: dict[str, str], previous: dict, now: datetime
    ) -> list[Notification]:
        """Nowy PID znanej aplikacji = ktos ja odpalil.

        Odpalic aplikacje mozna tylko z ODBLOKOWANEGO iPada, wiec to jednoczesnie
        dowod, ze urzadzenie bylo uzywane — pewniejszy niz semantyka powiadomien
        Darwin, ktore mowia "stan sie zmienil", ale nie mowia na jaki.
        """
        out: list[Notification] = []
        started = {pid: label for pid, label in current.items() if pid not in previous}
        for pid, label in sorted(started.items(), key=lambda kv: int(kv[0])):
            out += self._emit(
                Notification(
                    kind=NotifyKind.DEVICE_LAUNCH,
                    title=self.child,
                    text=f"odpalil: {label}",
                    # Data w kluczu: iOS po restarcie zaczyna numerowac PID-y od
                    # nowa, a klucze dedupu zyja 7 dni. Bez daty ta sama apka na
                    # tym samym PID-zie w ciagu tygodnia gubila sie bez sladu.
                    dedup_key=(
                        f"dev-launch:{self.probe.udid}:{now:%Y%m%d}:{pid}:{label}"
                    ),
                    ts=now,
                    device=self.device_name,
                    app=label,
                    priority=3,
                    tags=("play",),
                )
            )
        return out

    def _screen_change(self, screen_on: bool, now: datetime) -> list[Notification]:
        local = now.astimezone(self.tz) if self.tz else now
        if screen_on:
            return self._emit(
                Notification(
                    kind=NotifyKind.DEVICE_SCREEN,
                    title=f"{self.device_name} — ekran wlaczony",
                    text=f"{local:%H:%M}",
                    dedup_key=f"dev-screen-on:{self.probe.udid}:{now:%Y%m%dT%H%M%S}",
                    ts=now,
                    device=self.device_name,
                    priority=2,
                    tags=("bulb",),
                )
            )
        return self._emit(
            Notification(
                kind=NotifyKind.DEVICE_SCREEN,
                title=f"{self.device_name} — ekran wygaszony",
                text=f"{local:%H:%M}",
                dedup_key=f"dev-screen-off:{self.probe.udid}:{now:%Y%m%dT%H%M%S}",
                ts=now,
                device=self.device_name,
                priority=1,
                tags=("zzz",),
            )
        )

    def _in_quiet_hours(self, ts: datetime) -> bool:
        if self.quiet_hours is None:
            return False
        local = ts.astimezone(self.tz).time() if self.tz else ts.time()
        return self.quiet_hours.contains(local)

    def _emit(self, note: Notification) -> list[Notification]:
        """Dedup, limit godzinowy i priorytet nocny.

        Limit liczy TYLKO rodzaje z warstwy urzadzen — warstwa DNS ma wlasny
        budzet i nie wolno jej zaglodzic pushami o uruchomieniach.

        Inwentarz (nowa/usunieta aplikacja) NIE jest dlawiony: to zdarzenie
        rzadkie i wazne, a zgubienie go w limicie zniweczyloby caly sens.
        """
        if not self.store.mark_sent(note.dedup_key, note.ts):
            return []

        if note.kind is not NotifyKind.DEVICE_INVENTORY and note.device:
            used = self.store.count_notifications_since(
                note.device,
                note.ts - timedelta(hours=1),
                kinds=tuple(k.value for k in DEVICE_KINDS),
            )
            if used >= self.max_per_hour:
                log.info(
                    "%s: limit %d/h wyczerpany, pomijam %s",
                    note.device,
                    self.max_per_hour,
                    note.kind.value,
                )
                return []

        if self._in_quiet_hours(note.ts):
            # Nocy nie wyciszamy — to wlasnie wtedy chcesz wiedziec.
            note = replace(note, priority=max(note.priority, 4))

        self.store.log_notification(note.device, note.ts, note.kind.value)
        return [note]
