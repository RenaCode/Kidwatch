"""Konfiguracja: YAML dla ustawien, zmienne srodowiskowe dla sekretow.

Sekrety nigdy nie sa czytane z pliku. Ich brak jest zglaszany dopiero wtedy, gdy
dany komponent ma faktycznie ruszyc, dzieki czemu `replay` i testy dzialaja na
pustym srodowisku.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import time
from datetime import time as dt_time
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class MissingSecretError(RuntimeError):
    """Podnoszony, gdy komponent ma wystartowac, a jego sekretu nie ma w srodowisku."""


def _require_env(name: str, what: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise MissingSecretError(
            f"Brak zmiennej srodowiskowej {name} ({what}). "
            f"Ustaw ja w .env albo w sekrecie klastra — nie w config.yaml."
        )
    return value


class _Base(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NextDnsConfig(_Base):
    profile_id: str
    raw: bool = False
    server_side_device_filter: bool = False
    base_url: str = "https://api.nextdns.io"
    backoff_max_seconds: float = 60.0
    #: NextDNS zamyka strumien mniej wiecej co minute i przez kilkadziesiat
    #: sekund odpowiada 429 na ponowne otwarcie (bez Retry-After; zmierzone
    #: 2026-10-02). Lomotanie co 1-2-4-8 s tylko przedluzalo blokade i
    #: zasmiecalo log bledami. Pierwsze czekanie po 429 jest wiec dluzsze.
    rate_limit_wait_seconds: float = 20.0
    #: Minimalny odstep miedzy otwarciami strumieni, WSPOLNY dla wszystkich
    #: profili. Przy dwoch profilach (osobny na dziecko) oba strumienie sa
    #: zamykane przez serwer mniej wiecej w tym samym rytmie; otwierane razem
    #: wpadalyby w 429 parami i przedluzaly sobie nawzajem blokade.
    connect_spacing_seconds: float = Field(default=5.0, ge=0)

    def api_key(self) -> str:
        return _require_env("NEXTDNS_API_KEY", "klucz API NextDNS")


class AdGuardConfig(_Base):
    base_url: str
    username: str
    poll_interval_seconds: float = 15.0
    page_limit: int = Field(default=500, ge=10, le=10000)
    max_backfill_minutes: int = Field(default=5, ge=0)

    def password(self) -> str:
        return _require_env("ADGUARD_PASSWORD", "haslo do AdGuard Home")


class SourceConfig(_Base):
    kind: Literal["nextdns", "adguard"] = "nextdns"
    nextdns: NextDnsConfig | None = None
    adguard: AdGuardConfig | None = None

    @model_validator(mode="after")
    def _active_section_present(self) -> SourceConfig:
        if self.kind == "nextdns" and self.nextdns is None:
            raise ValueError("source.kind=nextdns, ale brakuje sekcji source.nextdns")
        if self.kind == "adguard" and self.adguard is None:
            raise ValueError("source.kind=adguard, ale brakuje sekcji source.adguard")
        return self


class DeviceConfig(_Base):
    display_name: str
    child: str
    source_ids: list[str] = Field(min_length=1)

    # --- odczyt wprost z iPada (opcjonalny; bez tego dziala sama warstwa DNS)
    #: UDID urzadzenia. Identyfikujemy WYLACZNIE po nim — nazwy zwodza: te same
    #: iPady zglaszaly sie przez usbmux jako "Jan Kowalski's iPad" i
    #: "iPad (2)", a przez bonjour jako "iPad (Dziecko 1)" i "iPad (Dziecko 2)".
    udid: str | None = None
    #: ADRES IPv4 iPada w TEJ SAMEJ sieci lokalnej, w ktorej chodzi odczyt
    #: (iOS odrzuca lockdown przez VPN — Tailscale i WireGuard: ConnectionReset).
    #: NIE adres IPv6 (po IPv6 lista aplikacji i stan ekranu padaja —
    #: sprawdzone na sprzecie).
    host: str | None = None
    #: AWARYJNA lista aplikacji {bundle_id: nazwa}, uzywana TYLKO gdy zywy odczyt
    #: inwentarza nie dziala i nie ma nic zapisanego w bazie.
    #:
    #: Po co: bez listy aplikacji nie da sie NAZWAC procesu — `Asphalt9` to tylko
    #: napis, dopoki nie wiadomo, ze istnieje apka "Asphalt". Na iPadzie Dziecka 2
    #: `installation_proxy` po sieci pada, a lista procesow dziala, wiec bez tego
    #: pola dostawalibysmy uruchomienia BEZ NAZW. Lista jest statyczna i rzadko
    #: sie zmienia; gdy zywy odczyt zadziala, nadpisuje ja.
    #:
    #: Zrzut z dzialajacego odczytu (np. po kablu):
    #:   pymobiledevice3 apps list --udid <UDID>
    known_apps: dict[str, str] = Field(default_factory=dict)
    #: MAC iPada w domowym Wi-Fi (UniFi). Tylko do czujki "profil DNS usuniety"
    #: i do znacznika "w domu / poza domem" w panelu. UWAGA: iOS domyslnie
    #: uzywa PRYWATNEGO adresu Wi-Fi per siec — tu wpisujesz ten, ktory iPad
    #: pokazuje w Ustawienia -> Wi-Fi -> (i) przy domowej sieci, nie sprzetowy.
    unifi_mac: str | None = None
    #: Alternatywnie stale IP iPada w domowej sieci (rezerwacja DHCP na UDM).
    #: Dopasowanie po MAC ma pierwszenstwo; IP przydaje sie, gdy iOS zmieni
    #: prywatny adres Wi-Fi, a rezerwacja zostala przepieta recznie.
    unifi_ip: str | None = None
    #: Profil NextDNS, przez ktory chodzi ten iPad. Puste = profil glowny
    #: (`source.nextdns.profile_id`). Osobny profil na dziecko jest potrzebny
    #: do "czasu gry": blokady uslug w NextDNS sa ustawieniem PROFILU, wiec
    #: na wspolnym profilu zablokowanie gier jednemu dziecku blokuje je obu.
    nextdns_profile: str | None = None

    @field_validator("nextdns_profile")
    @classmethod
    def _profile_id(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        if not re.fullmatch(r"[0-9a-z]+", v.strip()):
            raise ValueError(
                f"nextdns_profile {v!r} nie wyglada na ID profilu NextDNS "
                f"(male litery i cyfry, np. abc123 — z adresu my.nextdns.io/<ID>)"
            )
        return v.strip()

    @field_validator("unifi_mac")
    @classmethod
    def _mac_format(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        mac = v.strip().lower().replace("-", ":")
        if not re.fullmatch(r"[0-9a-f]{2}(:[0-9a-f]{2}){5}", mac):
            raise ValueError(f"unifi_mac {v!r} nie wyglada na adres MAC (aa:bb:cc:dd:ee:ff)")
        return mac

    @field_validator("unifi_ip")
    @classmethod
    def _ipv4(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        ip = v.strip()
        if not re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", ip):
            raise ValueError(f"unifi_ip {v!r} to nie adres IPv4")
        return ip

    @field_validator("source_ids")
    @classmethod
    def _lowercase(cls, v: list[str]) -> list[str]:
        return [s.strip().lower() for s in v if s.strip()]

    @field_validator("host")
    @classmethod
    def _host_must_not_be_ipv6(cls, v: str | None) -> str | None:
        """IPv6 jest ODRZUCANY, i to nie z ostroznosci.

        Sprawdzone na dwoch iPadach (2026-09-27, pymobiledevice3 11.19.3): przez
        polaczenie IPv6 usluga `os_trace` (lista procesow) dziala, ale
        `installation_proxy` (lista aplikacji) i `diagnostics` (stan ekranu)
        padaja na ConnectionTerminatedError. TEN SAM iPad po IPv4 oddaje wszystkie
        trzy odczyty.

        Bonjour czesto zglasza iPada wlasnie pod adresem IPv6 (fd00:...), wiec
        latwo wkleic go do konfiguracji i dostac warstwe okaleczona w sposob
        wygladajacy na przypadkowa awarie sieci.

        Uzyj adresu IPv4 z rezerwacji DHCP w domowej sieci.
        """
        if v is None:
            return v
        candidate = v.strip().strip("[]")
        if ":" in candidate:
            raise ValueError(
                f"host {v!r} to adres IPv6. Po IPv6 lista aplikacji i stan ekranu "
                f"padaja na ConnectionTerminatedError (sprawdzone na sprzecie) — "
                f"uzyj adresu IPv4 iPada w sieci lokalnej (rezerwacja DHCP)"
            )
        return candidate

    @model_validator(mode="after")
    def _udid_and_host_go_together(self) -> DeviceConfig:
        if bool(self.udid) != bool(self.host):
            raise ValueError(
                f"{self.display_name}: 'udid' i 'host' musza byc podane RAZEM "
                f"(albo oba pominiete, wtedy dziala sama warstwa DNS)"
            )
        return self

    @property
    def reads_device(self) -> bool:
        return bool(self.udid and self.host)


class QuietHours(_Base):
    start: time
    end: time
    session_start_priority: int = Field(default=5, ge=1, le=5)

    def contains(self, t: time) -> bool:
        """Obsluguje przedzialy przechodzace przez polnoc (21:30 -> 07:00)."""
        if self.start <= self.end:
            return self.start <= t < self.end
        return t >= self.start or t < self.end


class NightConfig(_Base):
    """Alarm nocnego uzywania iPada.

    Bez `start`/`end` okno nocy = `engine.quiet_hours` (jesli ustawione). To
    jedno powiadomienie z cichymi godzinami: start sesji w nocy dostaje forme
    nocna ("uzywa iPada w nocy") ZAMIAST dopisku o cichych godzinach, a nie
    drugi push obok.
    """

    enabled: bool = True
    start: time | None = None
    end: time | None = None
    #: Co tyle minut trwania sesji w nocy przypomnienie. 0 = tylko pierwszy push.
    reminder_minutes: int = Field(default=30, ge=0)
    #: Bez wartosci: `quiet_hours.session_start_priority`, a bez cichych godzin 5.
    priority: int | None = Field(default=None, ge=1, le=5)

    @model_validator(mode="after")
    def _both_or_none(self) -> NightConfig:
        if (self.start is None) != (self.end is None):
            raise ValueError("engine.night: 'start' i 'end' podaje sie razem (albo oba pomin)")
        return self


class WeeklyReportConfig(_Base):
    enabled: bool = True
    #: 0 = poniedzialek ... 6 = niedziela (jak date.weekday()).
    weekday: int = Field(default=6, ge=0, le=6)
    time: dt_time = dt_time(19, 0)


class EngineConfig(_Base):
    idle_minutes: int = Field(default=10, ge=1)
    app_cooldown_minutes: int = Field(default=15, ge=0)
    #: Nieuzywane od wprowadzenia potwierdzania sesji (confirm_minutes):
    #: potwierdzenie trwa co najmniej minute, wiec nazwa aplikacji zawsze
    #: zdazy dojsc. Zostaje, zeby istniejace konfiguracje nie padaly na
    #: extra=forbid.
    session_start_merge_seconds: int = Field(default=20, ge=0)
    #: Sesja jest POTWIERDZONA dopiero, gdy w oknie tylu minut aktywnosc
    #: (aplikacja albo nieznana domena) ma `confirm_moments` odrebnych chwil
    #: (zapytania w odstepie ponad 10 s) rozpietych na co najmniej minute —
    #: albo gdy trwa co najmniej 3 minuty. Wczesniej nie ma pusha startu ani
    #: alarmu nocnego, a sesja niepotwierdzona zamyka sie po cichu i nie
    #: liczy sie nigdzie (szczegoly: engine.Engine._confirmed_start).
    #: Zmierzone 2026-10: iPad lezacy na biurku dal trzy sesje "0 min" z mailami
    #: start+koniec — pojedyncze zapytanie YouTube (odswiezenie w tle), OCSP
    #: certyfikatu i Happy Color (powiadomienie).
    #: 5, nie 3: gra w trakcie rozgrywki odzywa sie do wlasnego zaplecza co
    #: ~3-3,5 min (Asphalt w tests/fixtures/day.jsonl, nagrany z zywego
    #: ruchu) — przy oknie 3 min prawdziwa 34-minutowa sesja nigdy by sie nie
    #: potwierdzila. Samotne zapytanie w tle i tak nie ma pary w 5 min.
    confirm_minutes: int = Field(default=5, ge=1, le=30)
    #: 3, nie 2: odswiezenie aplikacji w tle to pakiet zapytan w jednej
    #: sekundzie i czasem pojedyncze zapytanie CDN po 1-2 minutach — dwie
    #: chwile. Ogladanie (segmenty co kilkanascie sekund) ma trzy po ~30 s,
    #: gra z ruchem co 30-60 s po 1-2 minutach. 1 = kazde zdarzenie
    #: aplikacji potwierdza od razu (tylko testy innych regul).
    confirm_moments: int = Field(default=3, ge=1, le=20)
    #: Nieuzywane od wprowadzenia confirm_moments: liczyla surowe zapytania
    #: w ciagu minuty, a odswiezenie w tle wysyla ich kilka w jednej sekundzie.
    #: Zostaje, zeby istniejace konfiguracje nie padaly na extra=forbid.
    confirm_burst_events: int = Field(default=5, ge=0, le=100)
    # Jak dlugo ruch wspoldzielony (CDN, SDK reklamowe) moze przedluzac sesje,
    # liczac od ostatniego ROZPOZNANEGO zdarzenia. Kompromis w dwie strony:
    #   za malo -> godzinna gra, ktora rzadko gada z wlasnym zapleczem, zostaje
    #              posiekana na kilka krotkich sesji i dostajesz kilka pushy;
    #   za duzo -> odswiezanie aplikacji w tle po odlozeniu iPada sztucznie
    #              wydluza sesje (o max tyle minut).
    shared_extend_minutes: int = Field(default=30, ge=0)
    daily_summary_time: time = time(20, 30)
    max_notifications_per_hour: int = Field(default=12, ge=1)
    quiet_hours: QuietHours | None = None
    #: Push "Przegladarka / inne: <domeny>" dla ruchu, ktorego mapa nie zna.
    #: Domyslnie WYLACZONE: pierwszy dzien na zywo (2026-10-02) pokazal, ze to
    #: prawie wylacznie zaplecze aplikacji (Google, analityka, reklamy), a nie
    #: przegladanie stron. Ruch i tak trafia do bazy i panelu, sesje liczy sie
    #: dalej — znika tylko push.
    notify_unknown: bool = False
    night: NightConfig = Field(default_factory=NightConfig)
    weekly_report: WeeklyReportConfig = Field(default_factory=WeeklyReportConfig)

    def night_window(self) -> QuietHours | None:
        """Okno nocy jako QuietHours (dla `contains`) albo None, gdy wylaczone."""
        if not self.night.enabled:
            return None
        if self.night.start is not None and self.night.end is not None:
            return QuietHours(start=self.night.start, end=self.night.end)
        return self.quiet_hours


class WatchdogConfig(_Base):
    """Czujka wlasnej niesprawnosci.

    Na iPadach bez nadzoru dziecko moze zdjac profil DNS. Jego urzadzenie znika
    wtedy z logow, co jest nieodroznialne od "iPad lezy wylaczony". Traktujemy
    cisze jako awarie do zgloszenia, nie jako brak aktywnosci.
    """

    enabled: bool = True
    stream_silence_minutes: int = Field(default=20, ge=1)
    device_silence_minutes: int = Field(default=180, ge=1)
    device_silence_ignore_quiet_hours: bool = True
    repeat_backoff_max_minutes: int = Field(default=480, ge=1)


class NtfyConfig(_Base):
    enabled: bool = True
    server: str = "https://ntfy.sh"
    # Wymagany tylko przy wlaczonym kanale — wylaczony ntfy nie ma potrzeby
    # znac tematu, a pusty temat przy wlaczonym to cicha awaria wysylki.
    topic: str = ""
    default_priority: int = Field(default=3, ge=1, le=5)
    timeout_seconds: float = 10.0

    @model_validator(mode="after")
    def _topic_from_env_when_empty(self) -> NtfyConfig:
        """Puste `topic` bierze wartosc z NTFY_TOPIC.

        Nazwa tematu na ntfy.sh JEST HASLEM — ntfy.sh nie ma kontroli dostepu,
        kto zna nazwe, czyta wszystkie powiadomienia i moze wysylac falszywe.
        Dlatego nie trzymamy jej w repozytorium, a w Sekrecie klastra.
        """
        if not self.topic.strip():
            object.__setattr__(self, "topic", os.environ.get("NTFY_TOPIC", "").strip())
        if self.enabled and not self.topic:
            raise ValueError(
                "notifiers.ntfy.enabled=true wymaga 'topic' albo zmiennej NTFY_TOPIC"
            )
        return self

    def token(self) -> str | None:
        """Token jest opcjonalny — publiczne tematy na ntfy.sh go nie wymagaja."""
        return os.environ.get("NTFY_TOKEN", "").strip() or None


class HomeAssistantConfig(_Base):
    enabled: bool = False
    base_url: str = ""
    timeout_seconds: float = 10.0

    @model_validator(mode="after")
    def _base_url_required_when_enabled(self) -> HomeAssistantConfig:
        if self.enabled and not self.base_url.strip():
            raise ValueError("notifiers.homeassistant.enabled=true wymaga 'base_url'")
        return self

    def webhook_id(self) -> str:
        return _require_env("HA_WEBHOOK_ID", "identyfikator webhooka Home Assistant")


class BramkaConfig(_Base):
    """Wspolna bramka powiadomien w klastrze (WhatsApp, a bez niego e-mail)."""

    enabled: bool = True
    url: str = "http://bramka.bramka.svc.cluster.local"
    #: Podpis w temacie maila: "[kidwatch] ...".
    zrodlo: str = "kidwatch"
    #: Dluzej niz najgorszy czas odpowiedzi bramki: sendText WAHA do 15 s,
    #: potem zapasowy mail do 15 s, plus do 3 s na status. Krotszy timeout
    #: konczyl sie ponowieniem z outboxa, choc mail juz wyszedl (K-12).
    timeout_seconds: float = 40.0

    def key(self) -> str:
        """Klucz WYSYLKOWY kidwatcha (po stronie bramki: BRAMKA_KLUCZ_KIDWATCH).
        Bramka rozpoznaje po nim aplikacje i sama podpisuje wiadomosci."""
        return _require_env("BRAMKA_KLUCZ", "klucz wysylkowy bramki powiadomien")

    def admin_key(self) -> tuple[str, bool]:
        """Klucz ADMINISTRACYJNY bramki (/v1/whatsapp*, /v1/test) dla panelu.

        Zwraca (klucz, czy_zapasowy). Bez BRAMKA_KLUCZ_ADMIN bierze
        BRAMKA_KLUCZ: do konca migracji to stary wspolny klucz, ktory bramka
        przyjmuje takze na zarzadzaniu. Po migracji BRAMKA_KLUCZ jest juz
        tylko wysylkowy i bramka odpowie na nim 403 - panel pokaze blad
        zamiast po cichu dzialac na zbyt szerokim kluczu.
        """
        admin = os.environ.get("BRAMKA_KLUCZ_ADMIN", "").strip()
        if admin:
            return admin, False
        return _require_env("BRAMKA_KLUCZ", "klucz administracyjny bramki"), True


class NotifiersConfig(_Base):
    ntfy: NtfyConfig | None = None
    homeassistant: HomeAssistantConfig | None = None
    bramka: BramkaConfig | None = None


class DeviceReadConfig(_Base):
    """Odczyt stanu iPadow wprost z urzadzen (lockdown po TCP).

    Warstwa niezalezna od DNS. Daje wiecej szczegolow (lista zainstalowanych
    aplikacji, co odpalone, stan ekranu), ale wymaga osiagalnosci iPada — a iPad
    odpada od sieci, gdy zasnie. DNS zostaje jako zrodlo dzialajace zawsze.
    """

    enabled: bool = False
    #: Katalog z rekordami parowania <UDID>.plist, wygenerowanymi JEDNORAZOWO
    #: przy parowaniu po kablu. Rekordy sa przenosne miedzy maszynami.
    pair_record_dir: str = "~/.pymobiledevice3"
    poll_seconds: float = Field(default=60.0, ge=5.0)
    timeout_seconds: float = Field(default=20.0, ge=1.0)
    #: Budzet godzinowy WARSTWY URZADZEN, oddzielony od engine.max_notifications_
    #: per_hour. Wspolny licznik sprawial, ze godzina przelaczania aplikacji
    #: zaglodzila powiadomienia o sesjach DNS.
    max_notifications_per_hour: int = Field(default=30, ge=1)
    #: Po tylu godzinach BEZ ANI JEDNEGO udanego odczytu zglos to jako awarie.
    #: iPad spi wiekszosc doby, wiec cisza jest normalna — ale warstwa, ktora
    #: nie zadzialala ANI RAZU, wyglada dokladnie tak samo jak spiacy iPad.
    unreachable_alert_hours: float = Field(default=24.0, ge=1.0)
    #: proces -> bundle ID, dla nazw bez zwiazku z nazwa aplikacji.
    #: Disney+ chodzi jako `Dominguez`, "Logika i Matematyka" jako `academy`.
    process_aliases: dict[str, str] = Field(default_factory=dict)

    @property
    def records_path(self) -> Path:
        return Path(self.pair_record_dir).expanduser()


class TvConfig(_Base):
    """Czujnik telewizora (Google TV) po ADB/TCP.

    Telewizor NIE jest urzadzeniem z `devices`: tamte identyfikuje DNS i kazde
    nalezy do dziecka. Telewizor oglada cala rodzina, wiec w panelu i w API
    jest urzadzeniem z `child: null` — widocznym przy "Wszyscy", ukrytym przy
    wybranym dziecku.
    """

    enabled: bool = False
    #: Nazwa w pushach i w panelu.
    name: str = "TV salon"
    #: Adres IPv4 telewizora w domowym LAN (pod dochodzi tunelem WireGuard).
    host: str = ""
    port: int = Field(default=5555, ge=1, le=65535)
    poll_seconds: float = Field(default=30.0, ge=5.0)
    timeout_seconds: float = Field(default=10.0, ge=1.0)
    #: Katalog z kluczem `adbkey` (+ `adbkey.pub`) — w klastrze Sekret
    #: kidwatch-adb. Ten sam klucz, ktory telewizor raz zaakceptowal.
    adb_key_dir: str = "/adb"
    #: Koniec ogladania po tylu minutach bez odtwarzania. Uspienie telewizora
    #: konczy od razu. Pauza na siku nie powinna rozcinac odcinka na dwa.
    idle_minutes: int = Field(default=10, ge=1)
    #: Telewizor wylaczony z pradu jest nieosiagalny — to norma. Alarm dopiero
    #: po tylu godzinach bez JEDNEGO udanego odczytu.
    unreachable_alert_hours: float = Field(default=24.0, ge=1.0)
    #: Dodatkowe nazwy aplikacji {pakiet: nazwa}, nadpisuja wbudowana mape.
    apps: dict[str, str] = Field(default_factory=dict)
    #: Co ile minut czytac `dumpsys usagestats` — dokladny czas aplikacji na
    #: pierwszym planie wedlug samego Androida. Statystyki sa liczone w
    #: interwalach dziennych i zerowane przy ich zmianie, wiec zapisujemy
    #: przyrosty miedzy odczytami. 0 = wylaczone.
    usage_poll_minutes: int = Field(default=15, ge=0, le=180)

    @model_validator(mode="after")
    def _host_when_enabled(self) -> TvConfig:
        if self.enabled and not self.host.strip():
            raise ValueError("tv.enabled=true wymaga tv.host (adres telewizora w LAN)")
        return self


class UnifiConfig(_Base):
    """Lokalne API kontrolera UniFi (UDM) — obecnosc iPadow w domowym Wi-Fi
    i czujka "profil DNS usuniety".

    Klucz API idzie z UNIFI_API_KEY (Sekret). Bez klucza albo bez odcisku
    certyfikatu zrodlo sie NIE uruchamia — z ostrzezeniem w logu.
    """

    enabled: bool = False
    url: str = "https://192.168.1.1"
    site: str = "default"
    #: Odcisk SHA-256 certyfikatu UDM. UDM ma certyfikat samopodpisany, wiec
    #: zwykla weryfikacja TLS nie przejdzie — a wylaczenie jej oddaloby klucz
    #: API kazdemu, kto podszyje sie pod adres w sieci. Przypiety odcisk jest
    #: sprawdzany przy KAZDYM polaczeniu, ZANIM poleci naglowek z kluczem.
    #: Format dowolny z `openssl x509 -fingerprint -sha256` (z dwukropkami albo
    #: bez, z prefiksem "sha256 Fingerprint=" albo bez).
    cert_sha256: str = ""
    poll_seconds: float = Field(default=60.0, ge=10.0)
    timeout_seconds: float = Field(default=10.0, ge=1.0)
    #: Okno czujki i prog: tyle MB w oknie przy ZERO zapytan DNS = alarm.
    window_minutes: int = Field(default=15, ge=5)
    alarm_mb: float = Field(default=20.0, gt=0)
    #: Sufit odstepu przypomnien alarmu (podwajany od window_minutes).
    repeat_backoff_max_minutes: int = Field(default=480, ge=15)

    @field_validator("cert_sha256")
    @classmethod
    def _fingerprint(cls, v: str) -> str:
        raw = v.strip().lower()
        if "=" in raw:
            raw = raw.split("=", 1)[1]
        raw = raw.replace(":", "").replace(" ", "")
        if raw and not re.fullmatch(r"[0-9a-f]{64}", raw):
            raise ValueError("unifi.cert_sha256 to nie odcisk SHA-256 (64 znaki hex)")
        return raw

    def api_key(self) -> str | None:
        return os.environ.get("UNIFI_API_KEY", "").strip() or None


#: Identyfikatory uslug kontroli rodzicielskiej NextDNS. API nie ma endpointu
#: z katalogiem, wiec lista jest przepisana (2026-10-02) z biblioteki
#: `nextdns` (bieniu/nextdns, model.py: ParentalControlServices), z ktorej
#: korzysta integracja Home Assistant — to te same id, ktore zwraca
#: GET /profiles/:id/parentalControl. NextDNS DOKLADA uslugi (chatgpt, bereal
#: przybyly niedawno), wiec id spoza listy jest OSTRZEZENIEM, nie bledem:
#: twardy blad zablokowalby start po dopisaniu nowej, poprawnej uslugi. Id,
#: ktorego NextDNS naprawde nie zna, odrzuci samo API przy pierwszym zapisie
#: — z bledem widocznym w panelu i w logu.
NEXTDNS_SERVICES = frozenset({
    "9gag", "amazon", "bereal", "blizzard", "chatgpt", "dailymotion", "discord",
    "disneyplus", "ebay", "facebook", "fortnite", "google-chat", "hbomax", "hulu",
    "imgur", "instagram", "leagueoflegends", "mastodon", "messenger", "minecraft",
    "netflix", "pinterest", "playstation-network", "primevideo", "reddit", "roblox",
    "signal", "skype", "snapchat", "spotify", "steam", "telegram", "tiktok", "tinder",
    "tumblr", "twitch", "twitter", "vimeo", "vk", "whatsapp", "xboxlive", "youtube",
    "zoom",
})
#: Kategorie to zbior zamkniety i niezmienny od lat — tu literowka jest
#: BLEDEM walidacji, bo inaczej "gaming" wpisane jako "games" po cichu nic
#: by nie blokowalo.
NEXTDNS_CATEGORIES = frozenset({
    "dating", "gambling", "gaming", "piracy", "porn", "social-networks", "video-streaming",
})

_SLUG = re.compile(r"[0-9a-z][0-9a-z-]*")


class GameBlockSchedule(_Base):
    """Codzienna blokada gier, np. 20:00-07:00. Na poczatku okna petla gry
    blokuje; na koncu odblokowuje TYLKO to, co sama zablokowala — reczna
    blokada z panelu nie znika o 7 rano."""

    start: time
    end: time

    def contains(self, t: time) -> bool:
        return QuietHours(start=self.start, end=self.end).contains(t)


class GameTimeConfig(_Base):
    """"Czas gry": blokada uslug w kontroli rodzicielskiej NextDNS sterowana
    z panelu (gametime.py). Dziala per PROFIL NextDNS — patrz
    DeviceConfig.nextdns_profile."""

    enabled: bool = False
    services: list[str] = Field(
        default_factory=lambda: ["youtube", "roblox", "minecraft", "fortnite", "tiktok", "twitch"]
    )
    categories: list[str] = Field(default_factory=lambda: ["gaming"])
    default_bonus_minutes: int = Field(default=30, ge=1, le=24 * 60)
    #: Bonus nie moze rosnac w nieskonczonosc od klikania "+30 min".
    max_bonus_minutes: int = Field(default=180, ge=1, le=24 * 60)
    #: Co ile minut stan jest czytany z NextDNS (GET). Zmiana zrobiona recznie
    #: w my.nextdns.io pojawi sie w panelu najpozniej po tylu minutach.
    sync_minutes: int = Field(default=5, ge=1, le=60)
    #: Jak czesto petla zaglada do kolejki zadan z panelu.
    poll_seconds: float = Field(default=3.0, ge=0.5, le=60)
    block_schedule: GameBlockSchedule | None = None
    timeout_seconds: float = Field(default=10.0, ge=1.0)

    @field_validator("services", "categories")
    @classmethod
    def _slugs(cls, v: list[str]) -> list[str]:
        out = [s.strip().lower() for s in v if s.strip()]
        for s in out:
            if not _SLUG.fullmatch(s):
                raise ValueError(f"game_time: {s!r} to nie identyfikator NextDNS")
        return list(dict.fromkeys(out))

    @field_validator("categories")
    @classmethod
    def _known_categories(cls, v: list[str]) -> list[str]:
        unknown = sorted(set(v) - NEXTDNS_CATEGORIES)
        if unknown:
            raise ValueError(
                f"game_time.categories: nieznane kategorie NextDNS {unknown}. "
                f"Dozwolone: {', '.join(sorted(NEXTDNS_CATEGORIES))}"
            )
        return v

    @model_validator(mode="after")
    def _something_to_block(self) -> GameTimeConfig:
        if self.enabled and not (self.services or self.categories):
            raise ValueError("game_time.enabled=true, ale lista services i categories jest pusta")
        return self

    def unknown_services(self) -> list[str]:
        return sorted(set(self.services) - NEXTDNS_SERVICES)


class StoreConfig(_Base):
    path: str = "kidwatch.db"
    retention_days: int = Field(default=30, ge=0)
    #: Historia powiadomien w panelu. Osobno od zdarzen DNS, bo jest malutka,
    #: a to ona odpowiada na "co sie dzialo w zeszlym miesiacu". 0 = bez limitu.
    notifications_retention_days: int = Field(default=365, ge=0)
    #: Agregaty dzienne (daily_rollup: minuty, sesje, top aplikacje, noc, TV)
    #: dla trendow i eksportu CSV. Kilkaset bajtow na urzadzenie dziennie, wiec
    #: domyslnie BEZ LIMITU — to one przechowuja historie, gdy surowe zdarzenia
    #: i sesje znikaja po retention_days. 0 = bez limitu.
    rollup_retention_days: int = Field(default=0, ge=0)


class PanelConfig(_Base):
    """Panel WWW z historia powiadomien i sesji.

    Jedzie w procesie serwisu, w osobnym watku, na WLASNYM polaczeniu SQLite
    otwartym tylko do odczytu. Osobny kontener bylby drugim procesem na tej
    samej bazie — a ten serwis celowo ma jednego pisarza.

    Logowanie jest wlasne: haslo Argon2id + opcjonalny TOTP + sesja
    w ciasteczku (panel_auth.py). Klucz szyfrujacy sekrety TOTP idzie ze
    zmiennej PANEL_TOTP_KEY, nie z tego pliku. Dane logowania leza w OSOBNEJ
    bazie `auth_db`, bo glowna baza jest dla panelu tylko do odczytu.
    Domyslnie panel slucha tylko na petli zwrotnej, a w klastrze trzeba to
    jawnie zmienic na 0.0.0.0.
    """

    enabled: bool = False
    host: str = "127.0.0.1"
    #: 0 = losowy wolny port (testy).
    port: int = Field(default=8080, ge=0, le=65535)
    #: Zbudowany front (web/dist). W obrazie: /app/web.
    static_dir: str = "web/dist"
    #: Baza uzytkownikow i sesji panelu. Puste = `panel-auth.db` obok bazy
    #: glownej, czyli w klastrze na tym samym wolumenie /data — inaczej restart
    #: poda kasowalby konta i wylogowywal wszystkich.
    auth_db: str = ""
    #: Jak dlugo trwa sesja. Tydzien, nie 12 h jak w Traderze: ogladany jest
    #: glownie z telefonu, gdzie codzienne logowanie skonczyloby sie haslem
    #: zapamietanym w notatkach. Sama sesja (z CSRF) zmienia czas gry i pauze
    #: TV. Zmiany o szerszym zasiegu wymagaja ponownego potwierdzenia haslem
    #: albo kodem 2FA: haslo, 2FA, odbiorcy i nadawca WhatsAppa oraz QR bota
    #: (ten po swiezym potwierdzeniu, panel_auth.REAUTH_FRESH_SECONDS).
    session_hours: int = Field(default=168, ge=1, le=24 * 90)
    #: Atrybut Secure ciasteczek. W klastrze ruch idzie przez Traefika z TLS.
    #: Wylacz tylko lokalnie, gdy panel jest pod http:// innym niz localhost.
    cookie_secure: bool = True


@dataclass(frozen=True, slots=True)
class WatchedDevice:
    """Urzadzenie widziane przez panel. `child=None` = wspolne (telewizor)."""

    name: str
    child: str | None
    kind: str  # "ipad" | "tv"
    reads_device: bool


class Config(_Base):
    timezone: str = "Europe/Warsaw"
    source: SourceConfig
    devices: list[DeviceConfig] = Field(min_length=1)
    engine: EngineConfig = Field(default_factory=EngineConfig)
    watchdog: WatchdogConfig = Field(default_factory=WatchdogConfig)
    notifiers: NotifiersConfig = Field(default_factory=NotifiersConfig)
    device_read: DeviceReadConfig = Field(default_factory=DeviceReadConfig)
    store: StoreConfig = Field(default_factory=StoreConfig)
    panel: PanelConfig = Field(default_factory=PanelConfig)
    tv: TvConfig = Field(default_factory=TvConfig)
    unifi: UnifiConfig = Field(default_factory=UnifiConfig)
    game_time: GameTimeConfig = Field(default_factory=GameTimeConfig)
    app_map_path: str = "app_map.yaml"

    @field_validator("timezone")
    @classmethod
    def _known_timezone(cls, v: str) -> str:
        try:
            ZoneInfo(v)
        except ZoneInfoNotFoundError as exc:
            raise ValueError(f"Nieznana strefa czasowa: {v!r}") from exc
        return v

    @model_validator(mode="after")
    def _device_read_needs_targets(self) -> Config:
        if self.device_read.enabled and not any(d.reads_device for d in self.devices):
            raise ValueError(
                "device_read.enabled=true, ale zadne urzadzenie nie ma 'udid' i 'host'"
            )
        seen: dict[str, str] = {}
        for dev in self.devices:
            if dev.udid and dev.udid in seen:
                raise ValueError(
                    f"UDID {dev.udid} przypisany dwa razy: "
                    f"{seen[dev.udid]}, {dev.display_name}"
                )
            if dev.udid:
                seen[dev.udid] = dev.display_name
        return self

    @model_validator(mode="after")
    def _device_ids_unique(self) -> Config:
        """Ten sam identyfikator u dwoch dzieci to cicha pomylka w atrybucji."""
        seen: dict[str, str] = {}
        for dev in self.devices:
            for sid in dev.source_ids:
                if sid in seen and seen[sid] != dev.display_name:
                    raise ValueError(
                        f"identyfikator {sid!r} przypisany do dwoch urzadzen: "
                        f"{seen[sid]!r} i {dev.display_name!r}"
                    )
                seen[sid] = dev.display_name
        return self

    @model_validator(mode="after")
    def _profiles_need_nextdns(self) -> Config:
        """Profil per urzadzenie ma sens tylko przy zrodle NextDNS. A dziecko
        z dwoma iPadami na roznych profilach nie da sie sterowac jednym
        przyciskiem — blokada trafilaby tylko w polowe jego urzadzen."""
        if self.source.kind != "nextdns":
            named = [d.display_name for d in self.devices if d.nextdns_profile]
            if named:
                raise ValueError(
                    f"nextdns_profile ustawione ({named}), a source.kind={self.source.kind}"
                )
            if self.game_time.enabled:
                raise ValueError("game_time wymaga source.kind=nextdns")
            return self
        per_child: dict[str, set[str]] = {}
        for dev in self.devices:
            per_child.setdefault(dev.child, set()).add(self.profile_of(dev))
        split = {c: sorted(p) for c, p in per_child.items() if len(p) > 1}
        if split:
            raise ValueError(
                f"urzadzenia jednego dziecka na roznych profilach NextDNS: {split}. "
                f"Ustaw wszystkim iPadom dziecka ten sam nextdns_profile"
            )
        return self

    @model_validator(mode="after")
    def _tv_name_unique(self) -> Config:
        if self.tv.enabled and any(d.display_name == self.tv.name for d in self.devices):
            raise ValueError(f"tv.name {self.tv.name!r} jest juz nazwa iPada w devices")
        return self

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    @property
    def watched(self) -> list[WatchedDevice]:
        """Wszystko, co panel pokazuje: iPady dzieci, potem telewizor."""
        out = [
            WatchedDevice(d.display_name, d.child, "ipad", d.reads_device) for d in self.devices
        ]
        if self.tv.enabled:
            out.append(WatchedDevice(self.tv.name, None, "tv", True))
        return out

    @property
    def panel_auth_path(self) -> str:
        """Sciezka bazy logowania panelu — jawna albo obok bazy glownej."""
        if self.panel.auth_db:
            return self.panel.auth_db
        return str(Path(self.store.path).parent / "panel-auth.db")

    # ------------------------------------------------------------- NextDNS
    def profile_of(self, dev: DeviceConfig) -> str:
        """Profil NextDNS urzadzenia: wlasny albo glowny."""
        if dev.nextdns_profile:
            return dev.nextdns_profile
        assert self.source.nextdns is not None
        return self.source.nextdns.profile_id

    @property
    def nextdns_profiles(self) -> list[str]:
        """Wszystkie profile do czytania, glowny pierwszy. Glowny zostaje
        nawet wtedy, gdy kazde urzadzenie ma juz wlasny — na nim moga
        zostac inne sprzety domu, a to on byl zrodlem do tej pory."""
        if self.source.nextdns is None:
            return []
        out = [self.source.nextdns.profile_id]
        out += [d.nextdns_profile for d in self.devices if d.nextdns_profile]
        return list(dict.fromkeys(out))

    def child_profiles(self) -> dict[str, str]:
        """{dziecko: profil}. Walidacja gwarantuje jeden profil na dziecko."""
        return {d.child: self.profile_of(d) for d in self.devices}

    def device_for(self, source_id: str) -> DeviceConfig | None:
        needle = source_id.strip().lower()
        for dev in self.devices:
            if needle in dev.source_ids:
                return dev
        return None

    @classmethod
    def load(cls, path: str | Path) -> Config:
        p = Path(path)
        if not p.is_file():
            raise FileNotFoundError(
                f"Nie ma pliku konfiguracji: {p}. Skopiuj config.example.yaml do config.yaml."
            )
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        cfg = cls.model_validate(data)
        # KIDWATCH_STORE_PATH nadpisuje store.path: docker compose kieruje baze
        # na wolumen /data bez osobnego config.yaml (K-2). Obok niej laduje
        # panel-auth.db (panel_auth_path).
        override = os.environ.get("KIDWATCH_STORE_PATH", "").strip()
        if override:
            cfg.store.path = override
        # Sciezki relatywne liczymy wzgledem katalogu z config.yaml, nie cwd —
        # inaczej serwis uruchomiony z innego katalogu cicho tworzy druga baze.
        base = p.parent
        if not Path(cfg.store.path).is_absolute():
            cfg.store.path = str(base / cfg.store.path)
        if cfg.panel.auth_db and not Path(cfg.panel.auth_db).is_absolute():
            cfg.panel.auth_db = str(base / cfg.panel.auth_db)
        if not Path(cfg.app_map_path).is_absolute():
            candidate = base / cfg.app_map_path
            if candidate.is_file():
                cfg.app_map_path = str(candidate)
        return cfg
