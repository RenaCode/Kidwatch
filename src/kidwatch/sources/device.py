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
import re
import ssl
import tempfile
import time
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

#: Przypomnienie o trwajacej serii czesciowych odczytow co tyle obiegow
#: (przy odczycie co minute — mniej wiecej raz na godzine).
PARTIAL_REMIND_EVERY = 60


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
    #: Plik wykonywalny (CFBundleExecutable) — tylko z zywego odczytu lockdown.
    #: To DOKLADNIE nazwa procesu; katalog MDM i known_apps go nie znaja.
    executable: str = ""

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
    # KAZDY blad odczytu i parsowania (uciety XML = ExpatError, smiec binarny,
    # zly typ) pomija tylko to urzadzenie — wyjatek spoza DeviceUnavailable
    # wylatywal z build_watchers i wywracal przeladowanie calego domu.
    # Komunikat bez tresci pliku (klucz prywatny hosta): tylko typ bledu.
    try:
        rekord = plistlib.loads(path.read_bytes())
    except Exception as exc:
        raise DeviceUnavailable(
            f"nieczytelny rekord parowania {path}: {type(exc).__name__}") from None
    if not isinstance(rekord, dict):
        raise DeviceUnavailable(
            f"nieczytelny rekord parowania {path}: {type(rekord).__name__} zamiast slownika")
    return rekord


#: Atrybuty, o ktore pytamy installation_proxy. Bez ReturnAttributes `Lookup`
#: oddaje CALY Info.plist kazdej aplikacji (uprawnienia, ikony, schematy URL)
#: w jednej ramce. Tu kilkaset bajtow na aplikacje.
APP_ATTRIBUTES = [
    "CFBundleIdentifier",
    "CFBundleDisplayName",
    "CFBundleName",
    "CFBundleExecutable",
    "ApplicationType",
]

#: Po nieudanej probie z EscrowBag nastepna nie wczesniej niz po tylu sekundach
#: (kazda proba to dodatkowe polaczenie z iPadem).
ESCROW_RETRY_SECONDS = 3600.0
#: Limit samej proby z EscrowBag — miesci sie w limicie calego odczytu
#: (DEFAULT_TIMEOUT), wiec zawieszona proba nie zjada calego budzetu.
ESCROW_ATTEMPT_SECONDS = 8.0
#: Limit zamkniecia porzuconego klienta lockdown.
CLOSE_TIMEOUT_SECONDS = 2.0


class _ConnectionDropped(DeviceUnavailable):
    """Usluga zerwala polaczenie (ConnectionTerminatedError i pokrewne) —
    jedyny przypadek, w ktorym probujemy jeszcze raz z EscrowBag."""


class _StageError(Exception):
    """Etap startu uslugi, na ktorym padlo; przyczyna w __cause__."""

    def __init__(self, stage: str) -> None:
        super().__init__(stage)
        self.stage = stage


def _dropped(exc: BaseException) -> bool:
    """ConnectionTerminatedError pymobiledevice3 albo to, co pod nim lezy."""
    cur: BaseException | None = exc
    for _ in range(5):
        if cur is None:
            break
        if type(cur).__name__ == "ConnectionTerminatedError" or isinstance(
            cur, (asyncio.IncompleteReadError, ConnectionResetError, ssl.SSLError)
        ):
            return True
        cur = cur.__cause__
    return False


def _describe_cause(exc: BaseException) -> str:
    if isinstance(exc, asyncio.IncompleteReadError):
        # 0 z 4 B = iPad zamknal zaraz po starcie uslugi; N z duzej liczby =
        # zerwanie W TRAKCIE odpowiedzi (rozmiar, MTU tunelu).
        expected = "?" if exc.expected is None else exc.expected
        return f"IncompleteReadError({len(exc.partial)} z {expected} B)"
    text = str(exc).strip()[:160]
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


class TcpLockdownBackend:
    """Prawdziwy odczyt przez pymobiledevice3, po bezposrednim TCP.

    ## installation_proxy i diagnostics po sieci (ConnectionTerminatedError)

    Na dwoch iPadach — po IPv6 w domowym LAN, a potem po tunelu z NAT — lista
    procesow (os_trace_relay) dziala, a lista aplikacji (installation_proxy)
    i ekran (diagnostics_relay) padaja przy kazdym obiegu na
    ConnectionTerminatedError. Nazwy uslug sa wlasciwe (`.shim.remote` to
    wariant RSD/tunelu iOS 17+, nie lockdown po TCP). Hipotezy:

      1. TLS uslugi: StartService obu padajacych uslug zwraca
         `EnableServiceSSL`, os_trace_relay (chodzi czystym tekstem) — nie.
         ssl.SSLError to OSError, ktory pymobiledevice3 zamienia na
         ConnectionTerminatedError, gubiac przyczyne w komunikacie;
      2. iPad zamyka usluge zaraz po starcie (zablokowany pek kluczy) —
         lockdownd oczekuje wtedy `EscrowBag` w StartService (tak synchronizuje
         sie zablokowane urzadzenie; rekord parowania go zawiera);
      3. rozmiar odpowiedzi: Lookup bez ReturnAttributes to caly Info.plist
         kazdej aplikacji w jednej ramce.

    Dlatego: usluge startujemy sami etapami (StartService, polaczenie, TLS),
    a komunikat bledu niesie ETAP i lancuch przyczyn (np. `TLS uslugi: ... <-
    SSLError: ...` albo `odczyt: ... <- IncompleteReadError(0 z 4 B)`) — to
    rozstrzyga miedzy hipotezami na produkcji. Po zerwaniu installation_proxy
    albo diagnostics probujemy RAZ z EscrowBag (hipoteza 2; udana proba
    zostaje na stale, nieudana wraca najwczesniej po ESCROW_RETRY_SECONDS).
    Lista aplikacji pyta tylko o potrzebne atrybuty (hipoteza 3).
    """

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
        #: usluga -> True (dziala TYLKO z EscrowBag) albo chwila ostatniej
        #: nieudanej proby z EscrowBag (time.monotonic).
        self._escrow: dict[str, bool | float] = {}
        #: Zadania zamykajace porzucone klienty (sciezka anulowania).
        self._closing: set[asyncio.Task] = set()

    @staticmethod
    def _why(exc: BaseException) -> str:
        """Czytelna przyczyna. Goly TimeoutError ma pusty tekst, a "TimeoutError: "
        nic nie mowi — a to NAJCZESTSZY przypadek, bo iPad spi wiekszosc doby.

        Z lancuchem przyczyn: pymobiledevice3 zamienia SSLError, zerwane
        gniazdo i krotki odczyt na jeden ConnectionTerminatedError bez tekstu,
        a dopiero przyczyna mowi, CO padlo."""
        text = str(exc).strip()
        name = type(exc).__name__
        if isinstance(exc, (TimeoutError, asyncio.TimeoutError, ConnectionError, OSError)):
            base = text or "nie odpowiada (spi albo poza siecia)"
        else:
            base = f"{name}: {text}" if text else name
        chain: list[str] = []
        cur = exc.__cause__ or (None if exc.__suppress_context__ else exc.__context__)
        while cur is not None and len(chain) < 3:
            chain.append(_describe_cause(cur))
            cur = cur.__cause__ or (None if cur.__suppress_context__ else cur.__context__)
        return base + "".join(f" <- {c}" for c in chain)

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

    @staticmethod
    async def _start(service, escrow: bool) -> str | None:
        """Start uslugi ETAPAMI, zamiast LockdownService.connect().

        Dwa powody:
          * connect() w pymobiledevice3 11.x robi `fut.set_exception(e)` na
            wspolnej Future, na ktora nikt nie czeka — kazdy nieudany start
            (NotPairedError, ConnectionRefusedError z portu uslugi) konczyl sie
            w logu "Future exception was never retrieved" z pelnym tracebackiem
            (asyncio zglasza to dopiero przy sprzataniu Future);
          * etap (StartService / polaczenie / TLS) w komunikacie rozstrzyga
            hipotezy z docstringu klasy.

        To ta sama sekwencja co LockdownClient.start_lockdown_service, na
        publicznych metodach klienta. Zwraca None, gdy usluga jest juz
        polaczona albo to obiekt bez API lockdown (atrapa w testach) — wtedy
        metoda uslugi polaczy sie sama."""
        lockdown = getattr(service, "lockdown", None)
        name = getattr(service, "service_name", None)
        if (
            getattr(service, "_service", True) is not None
            or getattr(service, "_is_developer_service", False)
            or not name
            or not hasattr(lockdown, "get_service_connection_attributes")
            or not hasattr(lockdown, "create_service_connection")
        ):
            return None
        try:
            attr = await lockdown.get_service_connection_attributes(
                name, include_escrow_bag=escrow
            )
        except Exception as exc:
            raise _StageError("StartService") from exc
        try:
            conn = await lockdown.create_service_connection(attr["Port"])
        except Exception as exc:
            raise _StageError(f"polaczenie z portem uslugi {attr.get('Port')}") from exc
        if attr.get("EnableServiceSSL", False):
            try:
                with lockdown.ssl_file() as f:
                    await conn.ssl_start(f)
            except BaseException as exc:
                with contextlib.suppress(Exception):
                    await conn.close()
                if isinstance(exc, Exception):
                    raise _StageError("TLS uslugi") from exc
                raise
        service._service = conn
        return "odczyt"

    def _escrow_allowed(self, label: str) -> bool:
        state = self._escrow.get(label)
        if state is True:
            return False  # pierwsza proba juz szla z EscrowBag
        if isinstance(state, float) and time.monotonic() - state < ESCROW_RETRY_SECONDS:
            return False
        return bool(self._pair_record.get("EscrowBag"))

    async def _service(
        self, factory, method: str, *args, label: str | None = None,
        escrow_retry: bool = False, **kwargs,
    ):
        """Jedno wywolanie uslugi lockdown, z ZAMKNIECIEM polaczenia.

        Kazda usluga otwiera WLASNE gniazdo przez start_lockdown_service. Bez
        zamkniecia przy trzech odczytach na minute na urzadzenie zostaje ~1000
        deskryptorow w ciagu doby, a na iPadzie narastaja kanaly lockdownd.

        `escrow_retry`: po zerwanym polaczeniu jedna proba z EscrowBag
        (docstring klasy, hipoteza 2). `label` — nazwa w komunikatach.
        """
        label = label or method
        with_escrow = self._escrow.get(label) is True
        try:
            return await self._call(factory, method, args, kwargs, label, with_escrow)
        except _ConnectionDropped as first:
            if not escrow_retry or not self._escrow_allowed(label):
                raise
            # Diagnoza pierwszej proby (etap + przyczyna) ZAWSZE w logu — druga
            # moze zawisnac i zostac anulowana razem z calym odczytem.
            log.info("%s: %s pada (%s) — proba z EscrowBag", self.target.host, label, first)
            # Znacznik PRZED proba: anulowanie w jej trakcie nie moze
            # oznaczac „sprobuj znowu w nastepnym obiegu”.
            self._escrow[label] = time.monotonic()
            try:
                result = await asyncio.wait_for(
                    self._call(factory, method, args, kwargs, label, True),
                    timeout=ESCROW_ATTEMPT_SECONDS,
                )
            except (DeviceUnavailable, TimeoutError) as second:
                log.info("%s: %s z EscrowBag tez pada: %s", self.target.host, label,
                         str(second) or f"przekroczony czas ({ESCROW_ATTEMPT_SECONDS:.0f} s)")
                raise first from None
            self._escrow[label] = True
            log.info(
                "%s: %s dziala dopiero z EscrowBag w StartService — kolejne odczyty z nim",
                self.target.host, label,
            )
            return result
        except DeviceUnavailable as exc:
            if not with_escrow or getattr(exc, "stage", None) != "StartService":
                raise
            # StartService z EscrowBag odrzucony (np. nowy rekord parowania bez
            # waznego EscrowBag) — wracamy do proby bez niego, nie trzymamy
            # „dziala tylko z EscrowBag” na stale.
            self._escrow.pop(label, None)
            log.info("%s: %s — StartService z EscrowBag odrzucony (%s), wracam do proby bez",
                     self.target.host, label, exc)
            return await self._call(factory, method, args, kwargs, label, False)

    async def _close_quietly(self, client) -> None:
        """Zamyka porzucony klient lockdown (samo gniazdo, bez StopSession —
        na zerwanym polaczeniu StopSession i tak by nie doszedl)."""
        if client is None:
            return
        with contextlib.suppress(Exception):
            await asyncio.wait_for(_maybe(client.close()), timeout=CLOSE_TIMEOUT_SECONDS)

    def _drop_client(self, client, *, background: bool = False):
        """Porzuca klienta po bledzie. Bez zamkniecia zostawalo otwarte
        polaczenie lockdown na kazdy nieudany odczyt (co obieg)."""
        if self._client is client:
            self._client = None
        if background:
            # W trakcie anulowania nie czekamy na zamkniecie — osobne zadanie,
            # trzymane do konca (bez odwolania GC moglby je zebrac).
            task = asyncio.get_running_loop().create_task(self._close_quietly(client))
            self._closing.add(task)
            task.add_done_callback(self._closing.discard)
            return None
        return self._close_quietly(client)

    async def _call(self, factory, method: str, args, kwargs, label: str, escrow: bool):
        client = await self._connect()
        service = factory(client)
        stage = "start uslugi"
        try:
            stage = await self._start(service, escrow) or "usluga"
            return await _maybe(getattr(service, method)(*args, **kwargs))
        except asyncio.CancelledError:
            # Anulowanie (zwykle limit czasu z _with_timeout) przerywa odczyt
            # W POLOWIE odpowiedzi. CancelledError NIE jest podklasa Exception,
            # wiec bez tej galezi klient zostawal z niedoczytana odpowiedzia w
            # strumieniu i kolejny odczyt dostawalby cudzy payload.
            self._drop_client(client, background=True)
            raise
        except Exception as exc:
            # Zerwane polaczenie trzeba porzucic, inaczej kolejny odczyt padnie
            # na tym samym martwym gniazdzie.
            await self._drop_client(client)
            cause: BaseException = exc
            if isinstance(exc, _StageError):
                stage, cause = exc.stage, exc.__cause__ or exc
            cls = _ConnectionDropped if _dropped(cause) else DeviceUnavailable
            note = " (z EscrowBag)" if escrow else ""
            error = cls(f"{label}: {stage}{note}: {self._why(cause)}")
            error.stage = stage
            raise error from cause
        finally:
            with contextlib.suppress(Exception):
                await _maybe(service.close())

    async def apps(self) -> dict[str, dict[str, Any]]:
        from pymobiledevice3.services.installation_proxy import (  # noqa: PLC0415
            InstallationProxyService,
        )

        # `lookup` zamiast `get_apps`: to samo polecenie Lookup, ale z
        # ReturnAttributes (mala odpowiedz, a CFBundleExecutable = nazwa procesu).
        raw = await self._service(
            InstallationProxyService,
            "lookup",
            {"ApplicationType": "User", "ReturnAttributes": APP_ATTRIBUTES},
            label="get_apps",
            escrow_retry=True,
        )
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

        raw = await self._service(
            DiagnosticsService, "ioregistry", ioclass="AppleARMBacklight", escrow_retry=True
        )
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
        #: Seria czesciowych odczytow: zestaw padajacych sygnalow i ich licznik.
        self._partial: tuple[str, ...] | None = None
        self._partial_count = 0

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
            out[str(bundle_id)] = InstalledApp(
                str(bundle_id), str(name), str(meta.get("CFBundleExecutable") or "")
            )
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
        errors: dict[str, str] = {}

        try:
            apps = await self.installed_apps()
        except DeviceUnavailable as exc:
            errors["apps"] = f"apps: {exc}"
        try:
            running = await self.running()
        except DeviceUnavailable as exc:
            errors["procesy"] = f"procesy: {exc}"
        try:
            screen = await self.screen_on()
        except DeviceUnavailable as exc:
            errors["ekran"] = f"ekran: {exc}"

        if errors and not apps and not running and screen is None:
            # iPad spi: seria czesciowych odczytow trwa dalej (nie zerujemy).
            raise DeviceUnavailable("; ".join(errors.values()))
        self._report_partial(tuple(errors), "; ".join(errors.values()))
        return DeviceSnapshot(apps=apps, running=running, screen_on=screen)

    def _report_partial(self, failing: tuple[str, ...], text: str) -> None:
        """WARNING raz na serie (ten sam zestaw padajacych odczytow), potem
        DEBUG z licznikiem i przypomnienie co PARTIAL_REMIND_EVERY obiegow.

        Trwale padajaca lista aplikacji dawala WARNING co minute — 1440
        identycznych linii na dobe zagluszalo wszystko inne w logu."""
        if not failing:
            if self._partial is not None:
                log.info(
                    "odczyt z %s znow pelny (po %d obiegach z brakiem: %s)",
                    self.target.udid, self._partial_count, ", ".join(self._partial),
                )
            self._partial, self._partial_count = None, 0
            return
        if failing != self._partial:
            self._partial, self._partial_count = failing, 1
            log.warning(
                "czesciowy odczyt z %s: %s (powtorzenia na DEBUG, przypomnienie co %d obiegow)",
                self.target.udid, text, PARTIAL_REMIND_EVERY,
            )
            return
        self._partial_count += 1
        if self._partial_count % PARTIAL_REMIND_EVERY == 0:
            log.warning(
                "czesciowy odczyt z %s trwa: %d obiegow z rzedu; ostatnio: %s",
                self.target.udid, self._partial_count, text,
            )
        else:
            log.debug("czesciowy odczyt z %s (%d. z rzedu): %s",
                      self.target.udid, self._partial_count, text)

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

#: Wersja zapisu `dev:<udid>:pids` (meta `dev:<udid>:pids_v`): "2" = wszystkie
#: PID-y, dopasowane z nazwa aplikacji, pozostale z pustym napisem.
PIDS_FORMAT = "2"

#: Bezpieczniki uruchomien przy liscie bez plikow wykonywalnych
#: (DeviceWatcher._launch_changes).
LAUNCH_COOLDOWN = timedelta(minutes=10)
LAUNCH_BURST_LIMIT = 3


#: Runner testow XCTest (`<Cel>UITests-Runner`, `<Cel>Tests-Runner`). Po
#: przedrostku dopasowalby sie do aplikacji `<Cel>` i kazdy przebieg testow UI
#: dawalby DRUGIE „odpalil <Cel>”. Testowana aplikacja i tak chodzi obok jako
#: zwykly proces `<Cel>` i to on jest uruchomieniem — runner pomijamy (nie jest
#: ani osobna aplikacja, ani „procesem bez dopasowania”).
TEST_RUNNER = re.compile(r"Tests?-Runner$")


def is_test_runner(process_name: str) -> bool:
    return bool(TEST_RUNNER.search(process_name))


def _flatten(text: str) -> str:
    return "".join(ch for ch in text.lower() if ch.isalnum())


#: Czlony bundle ID i nazwy, ktore nic nie mowia o aplikacji. Bez pliku
#: wykonywalnego (katalog MDM, known_apps) `com.google.photos` dopasowywal sie
#: do systemowego procesu `Photos`, ogon `.game` do `gamed` i `Games`, `.app`
#: do `appstored`, a `.mobile` do `mobileassetd` i `MobileSafari` — a launchd
#: odpala demony z nowym PID-em, wiec kazdy restart byl „odpalil X”.
GENERIC_MEMBERS = frozenset({
    "app", "apps", "ios", "ipados", "mobile", "ipad", "iphone", "client", "game", "games",
    "free", "lite", "hd", "pro", "plus", "premium", "music", "photos", "photo", "camera",
    "maps", "map", "home", "news", "cloud", "mail", "video", "videos", "tv", "player",
    "kids", "kid", "edu", "school", "store", "chat", "messenger", "browser", "web",
    "social", "main", "prod", "release", "global", "official", "full", "paid", "universal",
    "application", "ipadapp", "iphoneapp", "mobileapp", "x", "settings", "calendar",
    "notes", "clock", "weather", "files", "books", "podcasts", "health", "wallet",
})

#: Najkrotszy czlon, ktory moze dac dopasowanie po przedrostku.
PREFIX_MIN_LENGTH = 5
#: Najkrotszy czlon dla dopasowania dokladnego (bez pliku wykonywalnego).
EXACT_MIN_LENGTH = 3

_DAEMON_WORDS = (
    "daemon", "agent", "service", "helper", "extension", "widget", "poster",
    "intents", "provider", "subscriber", "proxy", "relay", "renderer",
)


def looks_like_daemon(process_name: str) -> bool:
    """Demon albo proces pomocniczy iOS: `appstored`, `gamed`, `cloudd`
    (male litery, konczy sie na `d`) albo slowo-klucz w nazwie
    (`PhotosPosterProvider`, `ClipsAppIntents`, `DTServiceHub`). Taki proces
    dopasowujemy wylacznie DOKLADNIE."""
    lower = process_name.lower()
    if process_name[:1].islower() and process_name.endswith("d"):
        return True
    return any(word in lower for word in _DAEMON_WORDS)


def _usable(member: str, minimum: int) -> bool:
    return len(member) >= minimum and member not in GENERIC_MEMBERS


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

    Ta sama punktacja dziala dla listy z katalogu MDM (Identifier + Name, bez
    pliku wykonywalnego): `com.example.SomeGame` <-> proces `SomeGame` to
    dokladne trafienie w ostatni czlon bundle ID. Gdy znamy plik wykonywalny
    (zywy odczyt lockdown), jego dokladna zgodnosc bije wszystko.
    """
    if any(process_name.endswith(suffix) for suffix in IGNORED_PROCESS_SUFFIXES):
        return None
    if is_test_runner(process_name):
        return None
    needle = _flatten(process_name)
    if not needle:
        return None

    if aliases:
        target = aliases.get(process_name) or aliases.get(process_name.lower())
        if target:
            app = apps.get(target)
            return app.label if app else target

    # Przedrostek tylko dla procesu, ktory nie wyglada na demona, i tylko gdy
    # obie strony maja co najmniej PREFIX_MIN_LENGTH znakow i nie sa generyczne.
    prefix_ok = not looks_like_daemon(process_name) and _usable(needle, PREFIX_MIN_LENGTH)
    best: tuple[int, int, str] | None = None
    for app in apps.values():
        flat_name = _flatten(app.name)
        tail = _flatten(app.bundle_id.rsplit(".", 1)[-1])
        name_ok = _usable(flat_name, EXACT_MIN_LENGTH)
        tail_ok = _usable(tail, EXACT_MIN_LENGTH)

        score = 0
        if app.executable and app.executable == process_name:
            score = 4                      # plik wykonywalny = nazwa procesu
        elif tail_ok and tail == needle:
            score = 3                      # ostatni czlon bundle ID, dokladnie
        elif name_ok and flat_name == needle:
            score = 3                      # nazwa aplikacji, dokladnie
        elif (
            prefix_ok
            and _usable(flat_name, PREFIX_MIN_LENGTH)
            and (flat_name.startswith(needle) or needle.startswith(flat_name))
        ):
            score = 1                      # przedrostek — najslabszy dowod
        elif (
            prefix_ok
            and _usable(tail, PREFIX_MIN_LENGTH)
            and (tail.startswith(needle) or needle.startswith(tail))
        ):
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
        catalog=None,
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
        #: Katalog aplikacji z serwera MDM (mdm.AppCatalog) — zapasowa lista,
        #: gdy lockdown nie poda inwentarza. Ustawiany po zbudowaniu czujki MDM.
        self.catalog = catalog
        #: Skad ostatnio wzielismy liste do nazywania procesow (do logu zmian).
        self._apps_source: str | None = None
        self._baseline_state: str | None = None
        #: aplikacja -> ostatnie „odpalil” przy liscie bez plikow wykonywalnych
        self._last_launch: dict[str, datetime] = {}

    # --------------------------------------------------------------- klucze
    def _key(self, what: str) -> str:
        return f"dev:{self.probe.udid}:{what}"

    @property
    def has_baseline(self) -> bool:
        return self.store.get_meta(self._key("apps")) is not None

    def _apps_for_matching(
        self, snapshot: DeviceSnapshot, prev_apps, now: datetime
    ) -> tuple[dict[str, InstalledApp], str | None, str]:
        """Lista do nazywania procesow: (aplikacje, rodzaj zrodla, opis).

        Kolejnosc: zywy odczyt -> katalog MDM (swiezy) -> ostatni zywy odczyt
        zapisany w bazie -> known_apps z konfiguracji -> brak (None).
        Katalog MDM przed zapisem z bazy: ten moze miec miesiace, katalog
        najwyzej `max_age` (domyslnie dobe)."""
        if snapshot.apps:
            return snapshot.apps, "zywy", "zywy odczyt lockdown"
        if self.catalog is not None:
            found = self.catalog.apps(self.probe.udid, now)
            if found is not None:
                apps, age = found
                minutes = int(age.total_seconds() // 60)
                return apps, "mdm", (
                    f"katalog MDM ({len(apps)} aplikacji, lista sprzed {minutes} min)"
                )
        if isinstance(prev_apps, dict) and prev_apps:
            return (
                {b: InstalledApp(b, n) for b, n in prev_apps.items()},
                "baza",
                "ostatni zywy odczyt zapisany w bazie",
            )
        if self.fallback_apps:
            return self.fallback_apps, "known_apps", "known_apps z konfiguracji"
        return {}, None, "brak"

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
        # Format 2: WSZYSTKIE PID-y (bez dopasowania z pustym opisem). Stary
        # zapis mial tylko dopasowane — po zmianie zrodla listy aplikacji
        # (np. katalog MDM zamiast niczego) kazda juz dzialajaca aplikacja
        # wygladalaby na swiezo odpalona. Stary format = nowy punkt odniesienia.
        pids_known = isinstance(prev_pids, dict) and (
            self.store.get_meta(self._key("pids_v")) == PIDS_FORMAT
        )
        screen_known = prev_screen is not None
        apps_source: str | None = None

        if snapshot.apps:
            if apps_known:
                out += self._app_inventory_changes(snapshot, dict(prev_apps), now)
            self.store.set_json(
                self._key("apps"), {b: a.name for b, a in snapshot.apps.items()}
            )

        if snapshot.running:
            known_apps, apps_source, described = self._apps_for_matching(
                snapshot, prev_apps, now
            )
            if apps_source != self._apps_source:
                log.info(
                    "%s: lista aplikacji do nazywania procesow: %s%s",
                    self.device_name,
                    described,
                    "" if snapshot.apps else " — lockdown nie podal listy",
                )
                self._apps_source = apps_source
            current: dict[str, str] = {}
            for pid, proc in snapshot.running.items():
                label = looks_like_app(proc, known_apps, self.aliases)
                current[str(pid)] = label or ""
                if (
                    not label
                    and proc[:1].isupper()
                    and "." not in proc
                    and len(proc) > 3
                    and not is_test_runner(proc)
                ):
                    # Wyglada na aplikacje, ale nie wiemy na ktora. Zbieramy,
                    # zebys mogl dopisac alias — jak z domenami w app_map.yaml.
                    self.unmatched.add(proc)
            if pids_known:
                out += self._launch_changes(
                    current, dict(prev_pids), now, guarded=apps_source != "zywy"
                )
            self.store.set_json(self._key("pids"), current)
            self.store.set_meta(self._key("pids_v"), PIDS_FORMAT)

        if snapshot.screen_on is not None:
            state = "on" if snapshot.screen_on else "off"
            if screen_known and prev_screen != state:
                out += self._screen_change(snapshot.screen_on, now)
            self.store.set_meta(self._key("screen"), state)

        if not (apps_known and pids_known and screen_known):
            # „apki” to inwentarz z lockdown (nowa/usunieta aplikacja). Bez
            # niego procesy nazywamy lista zastepcza — wtedy jej zrodlo zamiast
            # USTALAM, bo uruchomienia dzialaja.
            state = "apki=%s procesy=%s ekran=%s" % (  # noqa: UP031
                "znany" if apps_known else (apps_source or "USTALAM"),
                "znany" if pids_known else "USTALAM",
                "znany" if screen_known else "USTALAM",
            )
            # Tylko przy ZMIANIE stanu: trwale padajacy odczyt dawal te linie
            # co obieg.
            if state != self._baseline_state:
                log.info(
                    "%s: punkt odniesienia (%s) — bez powiadomien dla brakujacych sygnalow",
                    self.device_name,
                    state,
                )
            self._baseline_state = state
        else:
            self._baseline_state = None
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
        self, current: dict[str, str], previous: dict, now: datetime, guarded: bool = False
    ) -> list[Notification]:
        """Nowy PID znanej aplikacji = ktos ja odpalil.

        Odpalic aplikacje mozna tylko z ODBLOKOWANEGO iPada, wiec to jednoczesnie
        dowod, ze urzadzenie bylo uzywane — pewniejszy niz semantyka powiadomien
        Darwin, ktore mowia "stan sie zmienil", ale nie mowia na jaki.

        `guarded` — lista bez plikow wykonywalnych (katalog MDM, known_apps,
        zapis z bazy), wiec dopasowanie jest heurystyczne. Bezpieczniki:
          * ta sama aplikacja najwyzej raz na LAUNCH_COOLDOWN — proces
            pomocniczy restartowany przez launchd nie zasypie powiadomieniami;
          * wiecej niz LAUNCH_BURST_LIMIT roznych aplikacji „odpalonych” w jednym
            obiegu to raczej szum (np. fala restartow demonow po odblokowaniu,
            ktore heurystyka wziela za aplikacje) niz dziecko — WARNING w logu
            i zadnego powiadomienia z tego obiegu. Czlowiek nie otwiera czterech
            aplikacji w minute; jesli tak, zobaczy je DNS i nastepne obiegi.
        """
        out: list[Notification] = []
        started = {
            pid: label for pid, label in current.items() if label and pid not in previous
        }
        if guarded and started:
            labels = set(started.values())
            if len(labels) > LAUNCH_BURST_LIMIT:
                log.warning(
                    "%s: %d aplikacji „odpalonych” w jednym obiegu (%s) przy liscie bez "
                    "plikow wykonywalnych — to raczej szum dopasowania, bez powiadomien",
                    self.device_name, len(labels), ", ".join(sorted(labels)),
                )
                return []
            fresh: dict[str, str] = {}
            for pid, label in started.items():
                last = self._last_launch.get(label)
                if last is not None and now - last < LAUNCH_COOLDOWN:
                    log.debug("%s: %s ponownie po %s — w odstepie ochronnym, pomijam",
                              self.device_name, label, now - last)
                    continue
                if label not in fresh.values():
                    fresh[pid] = label
            started = fresh
            for label in started.values():
                self._last_launch[label] = now
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
