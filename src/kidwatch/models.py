"""Modele danych wspolne dla calego serwisu.

Kazdy `datetime` przechodzacy przez system jest swiadomy strefy (aware) i trzymany
w UTC. Konwersja na strefe lokalna nastepuje wylacznie przy formatowaniu tekstu
powiadomienia, bo tylko tam jest widoczna dla czlowieka.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum


class Kind(StrEnum):
    """Wynik klasyfikacji domeny.

    AMBIGUOUS to trzecia droga, potrzebna z powodu gier. Wspoldzielone CDN-y
    (CloudFront, Akamai, Fastly) i SDK reklamowe (Unity Ads, AppLovin) obsluguja
    jednoczesnie uslugi Apple w tle ORAZ ruch grany przez dziecko. Zaliczenie ich
    do szumu gubi cala sesje grania; zaliczenie do aktywnosci otwiera widmowe
    sesje przy spiacym iPadzie.

    Dlatego taki ruch PRZEDLUZA otwarta sesje, ale nigdy jej nie otwiera i nigdy
    nie nadaje nazwy aplikacji.
    """

    NOISE = "noise"
    APP = "app"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class DnsEvent:
    """Jedno zapytanie DNS zaobserwowane przez zrodlo.

    Zrodla identyfikuja urzadzenie roznie i niekonsekwentnie: NextDNS podaje
    `device.name` ORAZ `device.id`, AdGuard `client_id` ORAZ adres IP. Dlatego
    niesiemy oba tropy — `device_id` jest tym preferowanym, `device_alt`
    zapasowym. Konfiguracja moze wymieniac dowolny z nich.

    `cursor` to identyfikator pozwalajacy wznowic strumien od tego miejsca
    (NextDNS: id zdarzenia SSE). AdGuard go nie ma.
    """

    ts: datetime
    device_id: str
    domain: str
    cursor: str | None = None
    device_alt: str | None = None
    #: Pod jakim kluczem zapisac `cursor` (meta cursor:<klucz>). Przy kilku
    #: profilach NextDNS kazdy strumien ma wlasny kursor; None = nazwa zrodla.
    cursor_key: str | None = None

    def __post_init__(self) -> None:
        if self.ts.tzinfo is None:
            raise ValueError(f"DnsEvent.ts musi byc aware, dostalem naive: {self.ts!r}")


@dataclass(frozen=True, slots=True)
class Classification:
    kind: Kind
    app: str | None = None


class NotifyKind(StrEnum):
    SESSION_START = "session_start"
    APP = "app"
    SESSION_END = "session_end"
    DAILY = "daily"
    THROTTLED = "throttled"
    WATCHDOG = "watchdog"
    # --- warstwa odczytu wprost z iPada. Osobne rodzaje, bo inaczej jej
    #     powiadomienia zjadaly budzet godzinowy warstwy DNS: godzina grania
    #     wypelnialaby notify_log i silnik zaczynalby dlawic WLASNE pushe.
    DEVICE_LAUNCH = "device_launch"
    DEVICE_SCREEN = "device_screen"
    DEVICE_INVENTORY = "device_inventory"
    # --- telewizor (sources/tv.py) i czujka UniFi (sources/unifi.py)
    TV_START = "tv_start"
    TV_END = "tv_end"
    #: Wstrzymanie i wznowienie monitoringu telewizora (tvpause.py).
    TV_PAUSE = "tv_pause"
    DNS_PROFILE = "dns_profile"
    # --- noc, raport tygodniowy, czas gry (gametime.py)
    NIGHT = "night"
    WEEKLY = "weekly"
    GAME = "game"


#: Rodzaje pochodzace z odczytu urzadzen. Maja wlasny budzet godzinowy.
DEVICE_KINDS = frozenset(
    {NotifyKind.DEVICE_LAUNCH, NotifyKind.DEVICE_SCREEN, NotifyKind.DEVICE_INVENTORY}
)


@dataclass(frozen=True, slots=True)
class Notification:
    """Gotowe powiadomienie. Silnik zwraca liste takich obiektow i nic nie wysyla.

    `dedup_key` czyni wysylke idempotentna: store pamieta juz wyslane klucze, wiec
    restart w zlym momencie nie zdubluje pusha.
    """

    kind: NotifyKind
    title: str
    text: str
    dedup_key: str
    ts: datetime
    device: str | None = None
    app: str | None = None
    priority: int = 3
    tags: tuple[str, ...] = ()
    #: Tresc w postaci strukturalnej dla panelu (formatting.py: sekcje,
    #: aplikacje z minutami, tytuly). None = panel pokazuje sam `text`.
    data: dict | None = None


@dataclass
class AppUsage:
    """Przyblizone zuzycie czasu na aplikacje, liczone w odrebnych minutach.

    NIE jest to pomiar czasu uzytkowania. iPad cachuje odpowiedzi DNS, wiec
    dziecko moze grac godzine generujac zapytania w kilku minutach. Ta liczba
    jest dolnym oszacowaniem i tak jest opisywana w powiadomieniach.
    """

    app: str
    minutes: set[str] = field(default_factory=set)

    @property
    def approx_minutes(self) -> int:
        return len(self.minutes)
