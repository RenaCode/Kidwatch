"""Telewizor z ruchu sieciowego: zapas, gdy ADB nie odpowiada.

## Po co

ADB daje tytul i dokladny stan odtwarzacza, ale stoi na kluczu, ktory telewizor
raz zaakceptowal. Po aktualizacji Google TV potrafi te zgode zgubic albo ADB
wisi na uzgadnianiu (2026-10-07: port 5555 otwarty, `TcpTimeoutException` od
rana, a wieczorem ogladanie bez jednego pusha). Wtedy kidwatch milczal az do
czujki dobowej.

Ruch sieciowy nie potrzebuje niczego na telewizorze:

- **UniFi** (`stat/sta`) — bajty telewizora. Streaming to kilka-kilkadziesiat
  MB na minute, ekran glowny i czuwanie praktycznie zero. Telewizor dopasowany
  po `tv.host` (ten sam adres, pod ktorym czytamy ADB) albo `tv.unifi_mac`.
- **NextDNS** (opcja, `tv.nextdns_ids`) — ktory serwis: ostatnie zapytanie
  telewizora rozpoznane przez app_map (googlevideo.com -> YouTube itd.).
  Bez tego sesja nazywa sie "Streaming".

## Hybryda

`HybridProbe` najpierw pyta ADB. Dopiero gdy ADB jest nieosiagalne, sklada
`TvSnapshot` z ruchu: telewizor w sieci = ekran nie spi, ruch w oknie powyzej
progu = gra. `TvWatcher` liczy z tego sesje i pushe tym samym kodem co z ADB,
wiec start/koniec, panel i podsumowania dzialaja dalej - bez tytulow.

Telewizora nie ma w `stat/sta` (wyjety z pradu, gleboki sen) - to dalej
`TvUnavailable`, jak dotad.

## Czego ruch NIE widzi

Antena i wejscia HDMI (dekoder, konsola) nie przechodza przez siec
telewizora. Aktualizacja aplikacji w tle moze przekroczyc prog - sesja bedzie
wtedy "Streaming" bez serwisu z DNS.
"""

from __future__ import annotations

import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta

from ..store import Store
from .sony import SonyAuthError, SonyClient, SonyError, Zrodlo
from .tv import USAGE_IGNORE, MediaSession, TvProbe, TvSnapshot, TvUnavailable, app_name

log = logging.getLogger(__name__)

#: Nazwa sesji z ruchu, gdy DNS nie powie, jaki to serwis.
STREAMING = "Streaming"
#: Pseudo-pakiet sesji z ruchu (segmenty w `tv_watch` maja jakis pakiet).
PAKIET_SIEC = "kidwatch.siec"


def _bajty(sta: dict) -> int:
    """Wi-Fi: tx/rx_bytes. Klient po kablu ma je w `wired-tx/rx_bytes`."""
    wifi = int(sta.get("tx_bytes") or 0) + int(sta.get("rx_bytes") or 0)
    kabel = int(sta.get("wired-tx_bytes") or 0) + int(sta.get("wired-rx_bytes") or 0)
    return max(wifi, kabel)


@dataclass(frozen=True, slots=True)
class Odczyt:
    w_sieci: bool
    bajty_w_oknie: float
    #: Okno w calosci pokryte probkami. Swiezo po starcie nie mamy jeszcze
    #: punktu odniesienia - wtedy nie twierdzimy, ze "gra".
    pokryte: bool


class LicznikRuchu:
    """Bajty telewizora w kroczacym oknie, z UniFi.

    Kontroler pytamy najwyzej co `odswiez_s` (petla TV chodzi co 30 s, ale
    zapas uruchamia sie tylko przy martwym ADB, a kontrolera nie ma po co
    meczyc czesciej niz czujka iPadow).
    """

    def __init__(self, client, ip: str | None, mac: str | None, *,
                 okno_min: float = 3.0, odswiez_s: float = 60.0) -> None:
        self.client = client
        self.ip = (ip or "").strip() or None
        self.mac = (mac or "").strip().lower() or None
        self.okno = timedelta(minutes=okno_min)
        self.odswiez = timedelta(seconds=odswiez_s)
        self.probki: deque[tuple[datetime, int]] = deque()
        self._ostatni: tuple[datetime, Odczyt] | None = None

    def _stacja(self, stations: list[dict]) -> dict | None:
        for sta in stations:
            if self.mac and str(sta.get("mac", "")).lower() == self.mac:
                return sta
        if self.ip:
            return next((s for s in stations if str(s.get("ip", "")) == self.ip), None)
        return None

    async def odczyt(self, now: datetime) -> Odczyt:
        if self._ostatni is not None and now - self._ostatni[0] < self.odswiez:
            return self._ostatni[1]
        wynik = self.zmierz(await self.client.stations(), now)
        self._ostatni = (now, wynik)
        return wynik

    def zmierz(self, stations: list[dict], now: datetime) -> Odczyt:
        """Logika bez I/O. Licznik UniFi zeruje sie po ponownym polaczeniu
        z AP - spadek znaczy "od zera", jak w czujce iPadow."""
        sta = self._stacja(stations)
        if sta is None:
            self.probki.clear()
            return Odczyt(False, 0.0, False)
        q = self.probki
        q.append((now, _bajty(sta)))
        start = now - self.okno
        while len(q) >= 2 and q[1][0] <= start:
            q.popleft()
        ruch = 0
        for (_, a), (_, b) in zip(q, list(q)[1:], strict=False):
            ruch += b - a if b >= a else b
        return Odczyt(True, float(ruch), q[0][0] <= start)


class HybridProbe(TvProbe):
    """ADB, a przy martwym ADB - ruch sieciowy. Patrz docstring modulu."""

    def __init__(self, adb: TvProbe, licznik: LicznikRuchu | None, store: Store, *,
                 prog_mb: float = 10.0, nextdns_ids: list[str] | tuple[str, ...] = (),
                 device_name: str = "TV", sony: SonyClient | None = None,
                 pilot=None, apps: dict[str, str] | None = None) -> None:
        super().__init__(adb.shell)
        self.adb = adb
        self.licznik = licznik
        #: Sony BRAVIA REST (sony.py): zasilanie zawsze, tuner/HDMI z kluczem PSK.
        self.sony = sony
        #: Pilot Google TV (tv_pilot.py): zasilanie i aplikacja, bez ADB.
        self.pilot = pilot
        self.apps = dict(apps or {})
        self._sony_auth_zgloszone = False
        self.store = store
        self.prog = prog_mb * 1_000_000
        self.nextdns_ids = tuple(nextdns_ids)
        self.device_name = device_name
        #: Od kiedy ADB nie odpowiada (None = dziala). Czyta TvWatcher do alarmu.
        self.adb_padl: datetime | None = None
        self.ostatni_blad: str | None = None

    async def snapshot(self, now: datetime | None = None) -> TvSnapshot:
        try:
            snap = await self.adb.snapshot()
        except TvUnavailable as exc:
            if now is None:
                raise
            return await self._z_sieci(now, exc)
        if self.adb_padl is not None:
            log.info("%s: ADB znowu odpowiada — koniec odczytu zapasowego",
                     self.device_name)
        self.adb_padl, self.ostatni_blad = None, None
        if snap.awake and snap.playing({}) is None and self.sony is not None:
            # ADB nie widzi anteny ani HDMI (to nie sesje odtwarzacza Androida).
            zr = await self._sony_zrodlo()
            if zr is not None:
                return self._z_sony(zr)
        return snap

    async def _sony_zrodlo(self) -> Zrodlo | None:
        if self.sony is None or not self.sony.psk:
            return None
        try:
            return await self.sony.zrodlo()
        except SonyAuthError as exc:
            if not self._sony_auth_zgloszone:
                log.warning("%s: %s", self.device_name, exc)
                self._sony_auth_zgloszone = True
        except SonyError as exc:
            log.debug("%s: Sony getPlayingContentInfo: %s", self.device_name, exc)
        return None

    @staticmethod
    def _z_sony(zr: Zrodlo) -> TvSnapshot:
        """Antena: "Telewizja" z kanalem i programem; HDMI: nazwa wejscia."""
        if zr.rodzaj == "tuner":
            pakiet, app = "kidwatch.sony.tuner", "Telewizja"
            title, channel = (zr.program, zr.nazwa) if zr.program else (zr.nazwa, None)
        else:
            pakiet, app, title, channel = f"kidwatch.sony.{zr.nazwa}", zr.nazwa, None, None
        return TvSnapshot(
            awake=True,
            foreground=pakiet,
            sessions=(MediaSession(pakiet, True, 3, title, channel),),
            zrodlo="sony",
            aplikacja=app,
        )

    async def _z_sieci(self, now: datetime, exc: TvUnavailable) -> TvSnapshot:
        from .unifi import UnifiError  # noqa: PLC0415

        if self.adb_padl is None:
            self.adb_padl = now
        self.ostatni_blad = str(exc)
        wlaczony: bool | None = None
        pakiet: str | None = None
        st = self.pilot.stan() if self.pilot is not None else None
        if st is not None and st.polaczony and st.wlaczony is not None:
            # Pilot mowi o zasilaniu i aplikacji wprost - pierwszenstwo przed Sony.
            if not st.wlaczony:
                return TvSnapshot(awake=False, foreground=None, sessions=(), zrodlo="pilot")
            wlaczony, pakiet = True, st.aplikacja
            zr = await self._sony_zrodlo()
            if zr is not None:
                return self._z_sony(zr)
        elif self.sony is not None:
            try:
                wlaczony = await self.sony.wlaczony()
            except SonyError as sexc:
                log.debug("%s: Sony getPowerStatus: %s", self.device_name, sexc)
            if wlaczony is False:
                # Czuwanie wedlug samego telewizora - pewniejsze niz cisza w sieci.
                return TvSnapshot(awake=False, foreground=None, sessions=(), zrodlo="sony")
            if wlaczony:
                zr = await self._sony_zrodlo()
                if zr is not None:
                    return self._z_sony(zr)
        if pakiet is not None:
            return await self._z_pilota(now, pakiet)
        # Aplikacja na ekranie (albo Sony nieznany): o odtwarzaniu decyduje ruch.
        if self.licznik is None:
            if wlaczony:
                return TvSnapshot(awake=True, foreground=None, sessions=(), zrodlo="sony")
            raise exc
        try:
            odczyt = await self.licznik.odczyt(now)
        except UnifiError as uexc:
            log.debug("%s: zapas z ruchu niedostepny: %s", self.device_name, uexc)
            raise exc from uexc
        if not odczyt.w_sieci:
            if wlaczony:
                return TvSnapshot(awake=True, foreground=None, sessions=(), zrodlo="sony")
            # Telewizora nie ma w sieci: wyjety z pradu albo gleboki sen.
            raise exc
        gra = odczyt.pokryte and odczyt.bajty_w_oknie >= self.prog
        if not gra:
            return TvSnapshot(awake=True, foreground=None, sessions=(), zrodlo="siec")
        aplikacja = self._serwis_z_dns(now) or STREAMING
        return TvSnapshot(
            awake=True,
            foreground=PAKIET_SIEC,
            sessions=(MediaSession(PAKIET_SIEC, True, 3, None, None),),
            zrodlo="siec",
            aplikacja=aplikacja,
        )

    async def _z_pilota(self, now: datetime, pakiet: str) -> TvSnapshot:
        """Aplikacja wedlug pilota. Ekran glowny, ustawienia, wygaszacz - nie
        ogladanie. Aplikacja z odtwarzaczem - ogladanie, jesli ruch to
        potwierdza (otwarty, ale zatrzymany YouTube to nie ogladanie); bez
        UniFi sama aplikacja na pierwszym planie."""
        from .unifi import UnifiError  # noqa: PLC0415

        if pakiet in USAGE_IGNORE:
            return TvSnapshot(awake=True, foreground=pakiet, sessions=(), zrodlo="pilot")
        gra = True
        if self.licznik is not None:
            try:
                odczyt = await self.licznik.odczyt(now)
                # Niepelne okno (swiezy start) to brak dowodu ogladania - jak
                # przy samym ruchu: start najwyzej o jedno okno pozniej.
                gra = odczyt.pokryte and odczyt.bajty_w_oknie >= self.prog
            except UnifiError as uexc:
                log.debug("%s: ruch niedostepny, decyduje sam pilot: %s",
                          self.device_name, uexc)
        if not gra:
            return TvSnapshot(awake=True, foreground=pakiet, sessions=(), zrodlo="pilot")
        return TvSnapshot(
            awake=True,
            foreground=pakiet,
            sessions=(MediaSession(pakiet, True, 3, None, None),),
            zrodlo="pilot",
            aplikacja=app_name(pakiet, self.apps),
        )

    def _serwis_z_dns(self, now: datetime) -> str | None:
        if not self.nextdns_ids:
            return None
        return self.store.last_app_for_sources(self.nextdns_ids, now - self.licznik.okno * 2)

    async def usage(self) -> str:
        return await self.adb.usage()

    async def aclose(self) -> None:
        await self.adb.aclose()
        if self.sony is not None:
            await self.sony.aclose()
