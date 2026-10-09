"""Czujnik telewizora: Google TV (Sony BRAVIA, Android 12) po ADB/TCP.

## Co i jak czytamy

Co `poll_seconds` trzy polecenia powloki przez ADB (biblioteka adb-shell,
czysty Python — bez binarki `adb` w obrazie):

    dumpsys media_session                           sesje odtwarzaczy
    dumpsys activity activities | grep mResumed...  aplikacja na pierwszym planie
    dumpsys power | grep mWakefulness               czy ekran nie spi

Co `usage_poll_minutes` (15) dodatkowo `dumpsys usagestats -c` — patrz
"Dokladny czas z usagestats" nizej.

`media_session` to to samo, z czego korzysta pilot i Google Home: kazda
aplikacja z odtwarzaczem publikuje sesje z pakietem, stanem odtwarzania
(PlaybackState: 3 = gra, 2 = pauza) i opisem MediaDescription
"tytul, podtytul, opis". YouTube podaje tytul i kanal ("Myjka okien | Fiksiki
| ..., Fiksiki, null"), Disney+ sam tytul ("Bluey, null, null"), Netflix nic
(metadata null) — wtedy zostaje nazwa aplikacji.

## Co znaczy "gra"

Sesja ze stanem 3 (PLAYING) albo `active=true` aplikacji, ktora jest na
pierwszym planie. Drugi warunek lapie pauze: dziecko, ktore zatrzymalo bajke
na dwie minuty, dalej oglada. Sama `active=true` nie wystarcza — aplikacja
w tle trzyma aktywna sesje godzinami po zamknieciu. Uspiony ekran
(mWakefulness inny niz Awake, takze wygaszacz "Dreaming") to zawsze "nie gra".

## Dokladny czas z usagestats

Sesje z media_session to szacunek z dokladnoscia do odczytu (30 s). Android
sam liczy czas aplikacji na pierwszym planie (UsageStatsService). Format
sprawdzony w zrodlach AOSP android12-release (UserUsageStatsService
.printIntervalStats): z `-c` (compact) liczby sa surowe, w milisekundach:

    In-memory daily stats
      beginTime=1696197600000 endTime=1696240800000
        packages
          package=com.google.android.youtube.tv totalTimeUsed=4805000 lastTimeUsed=1696239000000 ...

Bez `-c` te same pola sa "sformatowane" ("1:20:05", data) — parser przyjmuje
oba. Przed tym blokiem dump wypisuje zdarzenia z 24 h (dlugie), wiec grep
na telewizorze zostawia tylko potrzebne linie.

Interwal "daily" NIE jest dniem kalendarzowym: zaczyna sie od ostatniego
przelaczenia (beginTime) i przy kolejnym zeruje liczniki. Dlatego zapisujemy
PRZYROSTY miedzy odczytami (tabela tv_usage), przypisane do lokalnego dnia
lastTimeUsed. Przy zmianie interwalu liczymy caly nowy licznik od zera; czas
miedzy ostatnim odczytem a przelaczeniem (do 15 min) przepada — wolimy
niedoszacowac niz liczyc dwa razy. Czas aplikacji, ktora wciaz jest na
pierwszym planie, Android dolicza dopiero po jej zamknieciu.

## Klucz ADB

Telewizor wpuszcza tylko klucz, ktory raz zaakceptowano na ekranie ("Zezwolic
na debugowanie?" + "Zawsze zezwalaj"). Klucz (`adbkey`, `adbkey.pub`) lezy
w Sekrecie kidwatch-adb montowanym w /adb. Bez niego obserwator sie nie
uruchamia, z bledem w logu — reszta serwisu dziala.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol

from ..engine import tv_titles
from ..formatting import payload, section, sections_text
from ..models import Notification, NotifyKind
from ..store import Store, from_iso, to_iso
from .base import Unreachable

log = logging.getLogger(__name__)

#: Pakiety Google TV -> nazwa dla czlowieka. Nadpisywalne z konfiguracji
#: (tv.apps). Pakiet spoza mapy pokazujemy jako ostatni czlon nazwy pakietu.
DEFAULT_APPS = {
    "com.google.android.youtube.tv": "YouTube",
    "com.google.android.youtube.tvkids": "YouTube Kids",
    "com.disney.disneyplus": "Disney+",
    "com.netflix.ninja": "Netflix",
    "com.amazon.amazonvideo.livingroom": "Prime Video",
    "com.hbo.hbonow": "Max",
    "com.wbd.stream": "Max",
    "com.spotify.tv.android": "Spotify",
    "pl.tvn.player.tv": "Player",
    "pl.redefine.ipla": "Polsat Box Go",
    "pl.tvp.vod.tv": "TVP VOD",
    "com.apple.atve.androidtv.appletv": "Apple TV",
    "com.sony.dtv.tvx": "Telewizja",
    "com.google.android.tvlauncher": "Ekran główny",
    "com.google.android.apps.tv.launcherx": "Ekran główny",
}

PLAYBACK_PLAYING = 3

COMMANDS = {
    "media": "dumpsys media_session",
    "activity": "dumpsys activity activities | grep mResumedActivity",
    "power": "dumpsys power | grep mWakefulness",
}


USAGE_COMMAND = (
    "dumpsys usagestats -c | "
    "grep -E '^ *(In-memory |beginTime=|package=[^ ]+ totalTimeUsed=)'"
)

#: Pakiety, ktorych czas na pierwszym planie nie jest ogladaniem: ekran
#: glowny, wygaszacz, ustawienia, nakladki systemowe.
USAGE_IGNORE = frozenset({
    "com.google.android.tvlauncher",
    "com.google.android.apps.tv.launcherx",
    "com.google.android.apps.tv.dreamx",
    "com.android.systemui",
    "com.android.tv.settings",
    "com.google.android.katniss",
    "com.google.android.tv",
    "com.sony.dtv.tvx",
    "android",
})


class TvUnavailable(Unreachable):
    """Telewizor nie odpowiada — wyjety z pradu, gleboki sen, zerwany tunel.
    Normalny stan; alarm dopiero po tv.unreachable_alert_hours."""


# ================================================================== parsowanie
@dataclass(frozen=True, slots=True)
class MediaSession:
    package: str
    active: bool
    state: int | None
    title: str | None
    channel: str | None


@dataclass(frozen=True, slots=True)
class Playing:
    package: str
    app: str
    title: str | None
    channel: str | None

    @property
    def label(self) -> str:
        """"Fiksiki: Myjka okien (YouTube)", "Bluey (Disney+)", "Netflix"."""
        if not self.title:
            return self.app
        head = f"{self.channel}: {self.title}" if self.channel else self.title
        return f"{head} ({self.app})"


@dataclass(frozen=True, slots=True)
class TvSnapshot:
    awake: bool
    foreground: str | None
    sessions: tuple[MediaSession, ...]
    #: "adb" albo "siec" (zapas z ruchu sieciowego, sources/tv_siec.py).
    zrodlo: str = "adb"
    #: Nazwa aplikacji podana wprost (odczyt z ruchu nie ma pakietu Androida).
    aplikacja: str | None = None

    def playing(self, apps: dict[str, str]) -> Playing | None:
        if not self.awake:
            return None
        chosen = next((s for s in self.sessions if s.state == PLAYBACK_PLAYING), None)
        if chosen is None:
            chosen = next(
                (s for s in self.sessions if s.active and s.package == self.foreground), None
            )
        if chosen is None:
            return None
        return Playing(chosen.package, self.aplikacja or app_name(chosen.package, apps),
                       chosen.title, chosen.channel)


def app_name(package: str, apps: dict[str, str]) -> str:
    return apps.get(package) or DEFAULT_APPS.get(package) or package.rsplit(".", 1)[-1]


def _null(value: str | None) -> str | None:
    value = (value or "").strip()
    return None if not value or value == "null" else value


def parse_description(raw: str | None) -> tuple[str | None, str | None]:
    """MediaDescription.toString() to "tytul, podtytul, opis".

    Dzielimy OD PRAWEJ: tytul moze zawierac przecinki ("Myjka okien | Fiksiki
    | Zabawa, Nauka"), a podtytul i opis zwykle nie. Podtytul to u YouTube
    kanal, u innych bywa null.
    """
    raw = _null(raw)
    if raw is None:
        return None, None
    parts = raw.rsplit(", ", 2)
    if len(parts) < 3:
        return _null(parts[0]), None
    return _null(parts[0]), _null(parts[1])


_STATE = re.compile(r"state=PlaybackState \{state=(\d+)")
_DESCRIPTION = re.compile(r"metadata:.*?description=(.*)$")


def parse_media_sessions(text: str) -> list[MediaSession]:
    """Bloki sesji z `dumpsys media_session`.

    Granica bloku to linia `package=` — pojawia sie raz na sesje, przed
    `active=`, `state=` i `metadata:`. Naglowki blokow roznia sie miedzy
    wersjami Androida, ta linia nie.
    """
    out: list[MediaSession] = []
    current: dict | None = None

    def flush() -> None:
        if current is not None:
            title, channel = parse_description(current.get("description"))
            out.append(MediaSession(current["package"], current.get("active", False),
                                    current.get("state"), title, channel))

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("package="):
            flush()
            current = {"package": stripped.split("=", 1)[1].strip()}
            continue
        if current is None:
            continue
        if stripped.startswith("active="):
            current["active"] = stripped.split("=", 1)[1].strip() == "true"
        elif m := _STATE.search(stripped):
            current["state"] = int(m.group(1))
        elif stripped.startswith("metadata:"):
            m = _DESCRIPTION.search(stripped)
            current["description"] = m.group(1) if m else None
    flush()
    return out


_RESUMED = re.compile(r"mResumedActivity: ActivityRecord\{\S+ \S+ ([\w.]+)/")


def parse_foreground(text: str) -> str | None:
    m = _RESUMED.search(text)
    return m.group(1) if m else None


def parse_awake(text: str) -> bool:
    """`mWakefulness=Awake`. Asleep, Dozing i Dreaming (wygaszacz) to sen."""
    m = re.search(r"mWakefulness=(\w+)", text)
    return bool(m and m.group(1) == "Awake")


def parse_snapshot(media: str, activity: str, power: str) -> TvSnapshot:
    return TvSnapshot(
        awake=parse_awake(power),
        foreground=parse_foreground(activity),
        sessions=tuple(parse_media_sessions(media)),
    )


# ================================================================ usagestats
@dataclass(frozen=True, slots=True)
class UsageSnapshot:
    begin: int  # ms od epoki: poczatek biezacego interwalu dziennego
    packages: dict[str, tuple[int, int]]  # pakiet -> (totalTimeUsed ms, lastTimeUsed ms)


_PKG_USAGE = re.compile(
    r'package=(\S+)\s+totalTimeUsed=(?:"([^"]*)"|(\S+))\s+lastTimeUsed=(?:"([^"]*)"|(\S+))'
)


def _elapsed_ms(raw: str) -> int:
    """"4805000" (ms, z -c) albo "1:20:05" / "20:05" (DateUtils.formatElapsedTime)."""
    if ":" not in raw:
        return int(raw)
    seconds = 0
    for part in raw.split(":"):
        seconds = seconds * 60 + int(part)
    return seconds * 1000


def _when_ms(raw: str) -> int:
    if raw.lstrip("-").isdigit():
        return int(raw)
    try:
        return int(datetime.strptime(raw, "%Y-%m-%d %H:%M:%S").timestamp() * 1000)
    except ValueError:
        return 0


def parse_usagestats(text: str) -> UsageSnapshot | None:
    """Pierwszy blok "In-memory daily stats" (uzytkownik 0). None, gdy go nie ma."""
    section = None
    begin: int | None = None
    pkgs: dict[str, tuple[int, int]] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("In-memory "):
            if section == "daily":
                break
            section = stripped.split()[1]
            continue
        if section != "daily":
            continue
        if begin is None and (m := re.match(r"beginTime=(\d+)", stripped)):
            begin = int(m.group(1))
            continue
        if begin is None and stripped.startswith("timeRange="):
            begin = 0  # format bez -c: poczatku interwalu nie da sie odczytac
            continue
        if m := _PKG_USAGE.search(stripped):
            total = m.group(2) if m.group(2) is not None else m.group(3)
            last = m.group(4) if m.group(4) is not None else m.group(5)
            pkgs[m.group(1)] = (_elapsed_ms(total), _when_ms(last))
    if begin is None:
        return None
    return UsageSnapshot(begin, pkgs)


def usage_deltas(
    prev: dict | None, snap: UsageSnapshot
) -> tuple[list[tuple[str, int, int]], dict]:
    """([(pakiet, przyrost ms, lastTimeUsed ms)], nowy stan do meta).

    Ten sam interwal: przyrost = biezacy - poprzedni. Nowy interwal albo
    pierwszy odczyt: caly biezacy licznik — to czas od poczatku interwalu,
    ktorego jeszcze nie liczylismy.

    Spadek licznika przy TYM SAMYM beginTime to nie zerowanie, tylko powrot
    do starszego zapisu: TV wyjety z pradu wczytuje stan utrwalony do ~20 min
    wczesniej. Liczenie wtedy calego licznika dublowalo godziny w tv_usage.
    Przyrost 0, a punktem odniesienia zostaje wyzszy z odczytow — czas miedzy
    zapisem a utrata zasilania jest juz policzony.

    Bez beginTime (begin == 0, format bez -c) nie wiadomo, czy to ten sam
    interwal — pomijamy odczyt zamiast liczyc caly licznik przy kazdym.
    """
    if snap.begin == 0:
        return [], {"begin": 0, "totals": {}}
    same = prev is not None and prev.get("begin") == snap.begin
    seen = prev.get("totals", {}) if same else {}
    out = []
    totals: dict[str, int] = {}
    for pkg, (total, last) in snap.packages.items():
        before = int(seen.get(pkg, 0))
        delta = total - before
        totals[pkg] = max(before, total)
        if delta > 0:
            out.append((pkg, delta, last))
    # Pakiet znikniety z odczytu (np. po powrocie do starszego zapisu) nie
    # moze zgubic punktu odniesienia — inaczej przy powrocie liczylby sie od 0.
    for pkg, before in seen.items():
        totals.setdefault(pkg, int(before))
    state = {"begin": snap.begin, "totals": totals}
    return out, state


# ======================================================================= ADB
class TvShell(Protocol):
    async def shell(self, command: str) -> str: ...
    async def aclose(self) -> None: ...


class AdbTcpShell:
    """Polaczenie ADB trzymane miedzy odczytami, odnawiane po bledzie.

    Kazdy blad sieci i protokolu zamienia sie w TvUnavailable — dla petli to
    jeden stan: "telewizor nie odpowiada".
    """

    def __init__(self, host: str, port: int, key_dir: str | Path, timeout: float) -> None:
        from adb_shell.auth.sign_pythonrsa import PythonRSASigner  # noqa: PLC0415

        folder = Path(key_dir).expanduser()
        priv, pub = folder / "adbkey", folder / "adbkey.pub"
        if not priv.is_file():
            raise FileNotFoundError(
                f"brak klucza ADB {priv} — Sekret kidwatch-adb (adbkey, adbkey.pub)"
            )
        self.signer = PythonRSASigner(
            pub.read_text() if pub.is_file() else "", priv.read_text()
        )
        self.host, self.port, self.timeout = host, port, timeout
        self._dev = None
        # Jedno polaczenie ADB, dwoch uzytkownikow: odczyt co 30 s i instalacja
        # aplikacji Kidwatch TV z panelu. adb-shell nie przeplata polecen.
        self._zamek = asyncio.Lock()

    async def _device(self):
        from adb_shell.adb_device_async import AdbDeviceTcpAsync  # noqa: PLC0415

        if self._dev is None or not self._dev.available:
            dev = AdbDeviceTcpAsync(self.host, self.port, default_transport_timeout_s=self.timeout)
            await dev.connect(rsa_keys=[self.signer], auth_timeout_s=self.timeout,
                              read_timeout_s=self.timeout)
            self._dev = dev
        return self._dev

    async def shell(self, command: str, limit_s: float | None = None) -> str:
        t = limit_s or self.timeout
        return await self._wykonaj(
            lambda dev: dev.shell(command, read_timeout_s=t), t * 2)

    async def push(self, local: str, remote: str, limit_s: float = 120.0) -> None:
        """Plik na telewizor (instalacja aplikacji Kidwatch TV, tv_app.py)."""
        await self._wykonaj(
            lambda dev: dev.push(local, remote, read_timeout_s=limit_s,
                                 transport_timeout_s=limit_s), limit_s * 2)

    async def _wykonaj(self, akcja, limit: float):
        from adb_shell import exceptions as adb_exc  # noqa: PLC0415

        try:
            async with self._zamek:
                dev = await self._device()
                return await asyncio.wait_for(akcja(dev), limit)
        except adb_exc.DeviceAuthError as exc:
            await self.aclose()
            raise TvUnavailable(
                "telewizor odrzucil klucz ADB — zaakceptuj go na ekranie TV "
                "(Zezwolic na debugowanie? -> Zawsze zezwalaj)"
            ) from exc
        except (OSError, TimeoutError, adb_exc.AdbConnectionError, adb_exc.AdbTimeoutError,
                adb_exc.TcpTimeoutException, adb_exc.InvalidResponseError,
                adb_exc.InvalidCommandError, adb_exc.InvalidChecksumError) as exc:
            await self.aclose()
            raise TvUnavailable(f"{type(exc).__name__}: {exc}") from exc

    async def aclose(self) -> None:
        dev, self._dev = self._dev, None
        if dev is not None:
            try:
                await dev.close()
            except Exception:  # noqa: BLE001 — zamykamy zerwane polaczenie
                log.debug("tv: blad przy zamykaniu ADB", exc_info=True)


class BrakAdb:
    """Telewizor bez klucza ADB: kazde polecenie to TvUnavailable. Odczyt idzie
    wtedy z aplikacji Kidwatch TV i zapasow (tv_siec.py)."""

    def __init__(self, powod: str) -> None:
        self.powod = powod

    async def shell(self, command: str, limit_s: float | None = None) -> str:
        raise TvUnavailable(f"brak ADB: {self.powod}")

    async def aclose(self) -> None:
        pass


class TvProbe:
    def __init__(self, shell: TvShell) -> None:
        self.shell = shell

    async def raw(self) -> dict[str, str]:
        return {k: await self.shell.shell(cmd) for k, cmd in COMMANDS.items()}

    async def usage(self) -> str:
        return await self.shell.shell(USAGE_COMMAND)

    async def snapshot(self, now: datetime | None = None) -> TvSnapshot:
        # `now` uzywa tylko HybridProbe (zapas z ruchu sieci, tv_siec.py).
        raw = await self.raw()
        return parse_snapshot(raw["media"], raw["activity"], raw["power"])

    async def aclose(self) -> None:
        await self.shell.aclose()


# ================================================================== obserwator
def plural_tytuly(n: int) -> str:
    if n == 1:
        return "tytuł"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return "tytuły"
    return "tytułów"


def _duration(delta: timedelta) -> str:
    minutes = max(0, int(delta.total_seconds() // 60))
    if minutes < 60:
        return f"{minutes} min"
    h, m = divmod(minutes, 60)
    return f"{h} h" if m == 0 else f"{h} h {m} min"


class TvWatcher:
    """Zamienia kolejne odczyty telewizora w sesje ogladania i pushe.

    Sesja ogladania to wiersz w `sessions` (device = nazwa TV, child NULL) —
    dzieki temu panel, /api/usage i podsumowanie dnia licza ja tym samym
    kodem co sesje iPadow. Minuty aplikacji ida do `session_apps`, a tytuly
    do `tv_watch`.

    Push tylko na start i koniec. Zmiana tytulu w trakcie (kolejny odcinek,
    autoodtwarzanie YouTube) trafia tylko do panelu — inaczej sobotni ranek
    z bajkami to kilkadziesiat pushy.
    """

    unreachable_hint = (
        "Sprawdz: telewizor wlaczony do pradu, tunel WireGuard VPS->dom, "
        "debugowanie sieciowe w TV i klucz w Sekrecie kidwatch-adb."
    )

    def __init__(
        self,
        probe: TvProbe,
        device_name: str,
        store: Store,
        *,
        tz=None,
        idle_minutes: int = 10,
        apps: dict[str, str] | None = None,
        quiet_hours=None,
        usage_minutes: int = 0,
        adb_alert_minutes: int = 30,
    ) -> None:
        self.probe = probe
        #: Alarm "ADB nie dziala", gdy ruch pokazuje ogladanie, a ADB milczy
        #: od tylu minut. Czujka dobowa nie widzi tego stanu: odczyt z ruchu
        #: jest udanym odczytem.
        self.adb_alert = timedelta(minutes=adb_alert_minutes)
        self._zrodlo = "adb"
        self.usage_every = timedelta(minutes=usage_minutes)
        self.device_name = device_name
        self.store = store
        self.tz = tz
        self.idle = timedelta(minutes=idle_minutes)
        self.apps = dict(apps or {})
        self.quiet_hours = quiet_hours
        #: Zgodnosc z device_loop (iPady zbieraja tu nieznane procesy).
        self.unmatched: set[str] = set()

    def paused(self, now: datetime) -> bool:
        """Pauza monitoringu TV (tvpause.py): w niej telewizora w ogole nie
        odpytujemy — device_loop pomija obserwatora, a czujka milczy."""
        return self.store.tv_paused_at(now) is not None

    def resumed_at(self) -> datetime | None:
        """Koniec ostatniej pauzy — od niego czujka liczy brak odczytu."""
        return self.store.last_tv_pause_end()

    async def poll(self, now: datetime) -> list[Notification]:
        if self.paused(now):
            return []
        snap = await self.probe.snapshot(now)
        notes = self.observe(snap, now)
        if snap.zrodlo == "aplikacja":
            # Tytuly z aplikacji Kidwatch TV; usagestats czyta tylko ADB.
            return notes
        if snap.zrodlo != "adb":
            # ADB nie odpowiada - usagestats tez nie; pomijamy zamiast logowac
            # nieudany odczyt co kwadrans.
            return notes + self._adb_alarm(snap, now)
        try:
            await self._maybe_usage(now)
        except Unreachable as exc:
            # observe() zajal juz klucze dedupu startu/konca. Wyjatek stad
            # gubil te pushe na zawsze — a usagestats to tylko dodatek.
            log.info("%s: odczyt usagestats nieudany: %s", self.device_name, exc)
        except Exception:
            log.exception("%s: blad odczytu usagestats", self.device_name)
        return notes

    async def _maybe_usage(self, now: datetime) -> None:
        if not self.usage_every:
            return
        key = f"tvusage_at:{self.device_name}"
        last = self.store.get_meta(key)
        if last is not None and now - from_iso(last) < self.usage_every:
            return
        self.store.set_meta(key, to_iso(now))
        text = await self.probe.usage()
        snap = parse_usagestats(text)
        if snap is None:
            log.warning("%s: dumpsys usagestats bez bloku daily — pomijam", self.device_name)
            return
        # Liczniki Androida rosly takze w pauzie (tvpause.py). Odczyt, ktorego
        # okres od poprzedniego zahacza o pauze, tylko ustawia punkt odniesienia
        # — inaczej ogladanie z pauzy wpadloby do tv_usage w pierwszym odczycie.
        since = from_iso(last) if last is not None else None
        rebase = since is not None and bool(self.store.tv_pauses_between(since, now))
        self.record_usage(snap, now, count=not rebase)

    def record_usage(self, snap: UsageSnapshot, now: datetime, count: bool = True) -> int:
        """Zapisuje przyrosty do tv_usage. Zwraca sume zapisanych ms.
        `count=False` zapamietuje tylko stan licznikow (punkt odniesienia)."""
        key = f"tvusage:{self.device_name}"
        prev = self.store.get_json(key)
        deltas, state = usage_deltas(prev if isinstance(prev, dict) else None, snap)
        if not count:
            self.store.set_json(key, state)
            return 0
        total = 0
        for pkg, ms, last_ms in deltas:
            if pkg in USAGE_IGNORE:
                continue
            last = datetime.fromtimestamp(last_ms / 1000, UTC) if last_ms > 0 else None
            # Dzien konca uzycia, nie odczytu: film skonczony o 23:50 i
            # odczytany o 00:05 nalezy do wczoraj.
            when = min(last, now) if last else now
            day = self._local(when).date().isoformat()
            self.store.add_tv_usage(self.device_name, day, pkg, app_name(pkg, self.apps), ms,
                                    last)
            total += ms
        self.store.set_json(key, state)
        return total

    def observe(self, snap: TvSnapshot, now: datetime) -> list[Notification]:
        """Logika bez I/O — testowana na nagranych odczytach."""
        if self.paused(now):
            # Pauza wlaczona w trakcie odczytu (tik dziala miedzy await-ami):
            # wynik idzie do kosza, sesje domknal juz TvPause.
            return []
        if snap.zrodlo != self._zrodlo:
            log.info("%s: zrodlo odczytu %s -> %s", self.device_name, self._zrodlo, snap.zrodlo)
            self._zrodlo = snap.zrodlo
        playing = snap.playing(self.apps)
        session = self.store.get_open_session(self.device_name)
        if playing is None:
            if session is None:
                return []
            last = from_iso(session["last_activity_at"])
            if not snap.awake or now - last >= self.idle:
                return self._finish(session, last, now)
            return []

        if session is None:
            sid = self.store.open_session(self.device_name, None, now)
            self.store.open_tv_segment(sid, self.device_name, now, playing.package,
                                       playing.app, playing.title, playing.channel)
            self.store.record_app_minute(sid, playing.app, now)
            self.store.mark_start_notified(sid)
            return self._start(sid, playing, now)

        sid = int(session["id"])
        self.store.touch_session(sid, now)
        self.store.record_app_minute(sid, playing.app, now)
        seg = self.store.current_tv_segment(self.device_name)
        if seg is None or (seg["package"], seg["title"]) != (playing.package, playing.title):
            self.store.close_tv_segments(self.device_name, now)
            self.store.open_tv_segment(sid, self.device_name, now, playing.package,
                                       playing.app, playing.title, playing.channel)
        return []

    def on_unreachable(self, now: datetime) -> list[Notification]:
        """Telewizor wyjety z pradu w trakcie ogladania — domykamy po `idle`
        od ostatniego odtwarzania, jak przy zwyklej przerwie."""
        if self.paused(now):
            return []
        session = self.store.get_open_session(self.device_name)
        if session is None:
            return []
        last = from_iso(session["last_activity_at"])
        if now - last < self.idle:
            return []
        return self._finish(session, last, now)

    def _adb_alarm(self, snap: TvSnapshot, now: datetime) -> list[Notification]:
        """Raz na dobe: ruch pokazuje ogladanie, a ADB milczy od `adb_alert`.

        To jest dokladnie stan z 2026-10-07 (port otwarty, uzgadnianie ADB
        wisi) - wtedy wiadomo, ze telewizor JEST wlaczony, wiec cisza ADB
        to awaria, nie sen.
        """
        padl = getattr(self.probe, "adb_padl", None)
        if padl is None or now - padl < self.adb_alert or snap.playing(self.apps) is None:
            return []
        blad = getattr(self.probe, "ostatni_blad", None) or "brak odpowiedzi"
        return self._emit(Notification(
            kind=NotifyKind.WATCHDOG,
            title=f"{self.device_name} — ADB nie odpowiada, monitoring zapasowy",
            text=(
                f"Od {self._local(padl):%H:%M} brak odczytu po ADB ({blad}), a telewizor "
                "jest włączony. Start i koniec oglądania idą z API telewizora "
                "i ruchu sieci, bez tytułów z aplikacji.\nNa TV: okno „Zezwolić na "
                "debugowanie?” -> Zawsze zezwalaj; "
                "albo wyłącz i włącz debugowanie sieciowe w Opcjach programisty."
            ),
            dedup_key=f"tv-adb-down:{self.device_name}:{self._local(now):%Y%m%d}",
            ts=now,
            device=self.device_name,
            priority=3,
            tags=("warning",),
        ))

    # ------------------------------------------------------------- pushe
    def _local(self, ts: datetime) -> datetime:
        return ts.astimezone(self.tz) if self.tz else ts

    def _quiet(self, ts: datetime) -> bool:
        return self.quiet_hours is not None and self.quiet_hours.contains(
            self._local(ts).time()
        )

    def _start(self, sid: int, playing: Playing, now: datetime) -> list[Notification]:
        title = f"{self.device_name}: start — {playing.label}"
        if self._quiet(now):
            title = f"{self.device_name} W CICHYCH GODZINACH: start — {playing.label}"
        text = f"{self._local(now):%H:%M}"
        if self._zrodlo == "siec":
            text += " · wykryte z ruchu sieci (bez tytułu)"
        elif self._zrodlo == "sony":
            text += " · z API telewizora"
        return self._emit(Notification(
            kind=NotifyKind.TV_START,
            title=title,
            text=text,
            dedup_key=f"tv-start:{sid}",
            ts=now,
            device=self.device_name,
            app=playing.app,
            tags=("tv",),
        ))

    def _finish(self, session, last: datetime, now: datetime) -> list[Notification]:
        sid = int(session["id"])
        self.store.close_session(sid, last)
        self.store.close_tv_segments(self.device_name, last)
        started = from_iso(session["started_at"])
        segments = self.store.tv_segments(sid)
        titles = tv_titles(segments)
        n = len(titles)
        sec = section("", f"{self._local(started):%H:%M}\u2013{self._local(last):%H:%M}",
                      kind="tv", titles=titles)
        return self._emit(Notification(
            kind=NotifyKind.TV_END,
            title=(f"{self.device_name}: koniec — {n} {plural_tytuly(n)}, "
                   f"{_duration(last - started)}"),
            text=sections_text([sec]),
            data=payload("tv_end", [sec]),
            dedup_key=f"tv-end:{sid}",
            ts=now,
            device=self.device_name,
            priority=2,
            tags=("tv", "sleeping"),
        ))

    def _emit(self, note: Notification) -> list[Notification]:
        if not self.store.mark_sent(note.dedup_key, note.ts):
            return []
        if self._quiet(note.ts):
            # Nocy nie wyciszamy — to wlasnie wtedy chcesz wiedziec.
            note = replace(note, priority=max(note.priority, 4))
        self.store.log_notification(note.device, note.ts, note.kind.value)
        return [note]
