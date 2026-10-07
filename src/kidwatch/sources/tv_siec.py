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
from .tv import MediaSession, TvProbe, TvSnapshot, TvUnavailable

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

    def __init__(self, adb: TvProbe, licznik: LicznikRuchu, store: Store, *,
                 prog_mb: float = 10.0, nextdns_ids: list[str] | tuple[str, ...] = (),
                 device_name: str = "TV") -> None:
        super().__init__(adb.shell)
        self.adb = adb
        self.licznik = licznik
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
            log.info("%s: ADB znowu odpowiada — koniec odczytu z ruchu sieci",
                     self.device_name)
        self.adb_padl, self.ostatni_blad = None, None
        return snap

    async def _z_sieci(self, now: datetime, exc: TvUnavailable) -> TvSnapshot:
        from .unifi import UnifiError  # noqa: PLC0415

        if self.adb_padl is None:
            self.adb_padl = now
        self.ostatni_blad = str(exc)
        try:
            odczyt = await self.licznik.odczyt(now)
        except UnifiError as uexc:
            log.debug("%s: zapas z ruchu niedostepny: %s", self.device_name, uexc)
            raise exc from uexc
        if not odczyt.w_sieci:
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

    def _serwis_z_dns(self, now: datetime) -> str | None:
        if not self.nextdns_ids:
            return None
        return self.store.last_app_for_sources(self.nextdns_ids, now - self.licznik.okno * 2)

    async def usage(self) -> str:
        return await self.adb.usage()

    async def aclose(self) -> None:
        await self.adb.aclose()
