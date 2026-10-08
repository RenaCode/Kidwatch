"""Aplikacja Kidwatch TV na telewizorze (tv-app/): tytuly bez ADB.

## Po co

Tytuly zna tylko system telewizora (sesje odtwarzaczy). Do 2026-10 czytal je
Kidwatch przez ADB, a ADB gubi zgode na kluczu (Android 11+ cofa ja po
7 dniach bez polaczenia; 2026-10-07 i 08 bez jednego pusha). Aplikacja na TV
czyta te same sesje przez MediaSessionManager - jako wlaczony "nasluchiwacz
powiadomien", ktorego system sam uruchamia po starcie - i wystawia je w sieci
domowej:

    GET  http://<tv>:8765/zdrowie   wersja, uprawnienie, sparowany
    POST http://<tv>:8765/paruj     {"kod": "123456"} -> {"token": ...}
    GET  http://<tv>:8765/stan      Bearer <token> -> ekran, sesje

## Instalacja i parowanie (panel, Ustawienia -> Telewizor)

1. "Zainstaluj na TV" - przez DZIALAJACE jeszcze ADB: APK z obrazu
   (`/app/tv-app/kidwatch-tv.apk`, budowany w CI), `pm install -r`,
   uprawnienie nasluchiwacza (`cmd notification allow_listener` - Google TV
   nie ma do tego ekranu) i otwarcie aplikacji, ktora pokazuje kod.
2. "Sparuj" - 6 cyfr z ekranu TV -> token na wolumenie (`tv-app/token`).

Potem ADB nie jest potrzebne.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx

from .tv import MediaSession, TvSnapshot, TvUnavailable

log = logging.getLogger(__name__)

PORT = 8765
PAKIET = "pl.renacode.kidwatch.tv"
NASLUCH = f"{PAKIET}/{PAKIET}.KidwatchListener"
AKTYWNOSC = f"{PAKIET}/.MainActivity"
APK_W_OBRAZIE = "/app/tv-app/kidwatch-tv.apk"
APK_NA_TV = "/data/local/tmp/kidwatch-tv.apk"

#: Aplikacja dzialajaca w tym procesie - czyta ja panel (osobny watek).
AKTYWNA: AplikacjaTv | None = None


class AppError(RuntimeError):
    pass


def snapshot_z_json(dane: dict, foreground: str | None = None) -> TvSnapshot:
    """Odpowiedz /stan -> ten sam TvSnapshot, ktory dawal `dumpsys` przez ADB.
    `foreground` (pakiet z pilota) rozroznia pauze na pierwszym planie od
    sesji wiszacej w tle - aplikacja na TV pierwszego planu nie zna."""
    sesje = []
    for s in dane.get("sesje") or []:
        if not isinstance(s, dict) or not s.get("pakiet"):
            continue
        stan = s.get("stan")
        sesje.append(MediaSession(
            package=str(s["pakiet"]),
            active=stan in (2, 3, 6),     # PAUSED, PLAYING, BUFFERING
            state=int(stan) if isinstance(stan, int) else None,
            title=s.get("tytul") or None,
            channel=s.get("podtytul") or None,
        ))
    return TvSnapshot(awake=bool(dane.get("ekran")), foreground=foreground,
                      sessions=tuple(sesje), zrodlo="aplikacja")


@dataclass(frozen=True, slots=True)
class StanAplikacji:
    sparowana: bool
    wersja: str | None
    uprawnienie: bool | None
    ostatni_odczyt: datetime | None
    blad: str | None


class AplikacjaTv:
    def __init__(self, host: str, katalog: str | Path, *, timeout: float = 5.0,
                 http: httpx.AsyncClient | None = None, apk: str = APK_W_OBRAZIE) -> None:
        self.base = f"http://{host}:{PORT}"
        self.katalog = Path(katalog)
        self.http = http or httpx.AsyncClient(timeout=timeout)
        self.apk = apk
        self.loop: asyncio.AbstractEventLoop | None = None
        self.adb = None  # AdbTcpShell - ustawia build_tv_watcher
        self.wersja: str | None = None
        self.uprawnienie: bool | None = None
        self.ostatni_odczyt: datetime | None = None
        self.blad: str | None = None

    # ------------------------------------------------------------------ token
    @property
    def _plik_tokenu(self) -> Path:
        return self.katalog / "token"

    def _token(self) -> str | None:
        try:
            return self._plik_tokenu.read_text().strip() or None
        except OSError:
            return None

    @property
    def sparowana(self) -> bool:
        return self._token() is not None

    def stan(self) -> StanAplikacji:
        return StanAplikacji(self.sparowana, self.wersja, self.uprawnienie,
                             self.ostatni_odczyt, self.blad)

    # ------------------------------------------------------------------ odczyt
    async def snapshot(self, foreground: str | None = None) -> TvSnapshot:
        """TvUnavailable, gdy aplikacji nie ma, nie odpowiada albo token
        odrzucony - wtedy HybridProbe idzie dalej (ADB, pilot, Sony, ruch)."""
        self.loop = asyncio.get_running_loop()
        token = self._token()
        if token is None:
            raise TvUnavailable("aplikacja Kidwatch TV niesparowana")
        try:
            r = await self.http.get(f"{self.base}/stan",
                                    headers={"Authorization": f"Bearer {token}"})
        except httpx.HTTPError as exc:
            self.blad = f"{type(exc).__name__}"
            raise TvUnavailable(f"aplikacja Kidwatch TV: {type(exc).__name__}: {exc}") from exc
        if r.status_code == 401:
            self.blad = "token odrzucony - sparuj ponownie"
            raise TvUnavailable("aplikacja Kidwatch TV odrzucila token - sparuj ponownie")
        if r.status_code != 200:
            self.blad = f"HTTP {r.status_code}"
            raise TvUnavailable(f"aplikacja Kidwatch TV: HTTP {r.status_code}")
        dane = r.json()
        self.wersja = dane.get("wersja")
        self.uprawnienie = dane.get("uprawnienie")
        if not self.uprawnienie:
            self.blad = "brak dostepu do odtwarzaczy (uprawnienie nasluchiwacza)"
            raise TvUnavailable("aplikacja Kidwatch TV bez uprawnienia nasluchiwacza")
        self.ostatni_odczyt, self.blad = datetime.now(UTC), None
        return snapshot_z_json(dane, foreground)

    async def zdrowie(self) -> dict:
        r = await self.http.get(f"{self.base}/zdrowie")
        dane = r.json()
        self.wersja, self.uprawnienie = dane.get("wersja"), dane.get("uprawnienie")
        return dane

    # -------------------------------------------------- akcje z panelu (watek)
    def _w_petli(self, coro, timeout: float):
        if self.loop is None:
            coro.close()
            raise AppError("czujnik TV jeszcze nie wystartowal - sprobuj za minute")
        try:
            return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)
        except AppError:
            raise
        except Exception as exc:  # noqa: BLE001 - komunikat idzie do panelu
            raise AppError(f"{type(exc).__name__}: {exc}") from exc

    def paruj(self, kod: str) -> None:
        kod = kod.strip()
        if len(kod) != 6 or not kod.isdigit():
            raise AppError("kod ma 6 cyfr - widać go na ekranie aplikacji Kidwatch TV")
        self._w_petli(self._paruj(kod), 15)

    async def _paruj(self, kod: str) -> None:
        try:
            r = await self.http.post(f"{self.base}/paruj", json={"kod": kod})
        except httpx.HTTPError as exc:
            raise AppError("aplikacja Kidwatch TV nie odpowiada - zainstalowana i "
                           "z uprawnieniem?") from exc
        if r.status_code == 403:
            raise AppError("zły kod (po 5 błędnych telewizor pokaże nowy)")
        token = r.json().get("token") if r.status_code == 200 else None
        if not token:
            raise AppError(f"parowanie nieudane (HTTP {r.status_code})")
        self.katalog.mkdir(parents=True, exist_ok=True)
        self._plik_tokenu.write_text(token)
        self._plik_tokenu.chmod(0o600)
        log.info("aplikacja Kidwatch TV: sparowana")

    def instaluj(self) -> str:
        """Instalacja/aktualizacja przez ADB. Zwraca opis dla panelu."""
        return self._w_petli(self._instaluj(), 180)

    async def _instaluj(self) -> str:
        if self.adb is None:
            raise AppError("ADB nie jest skonfigurowane (klucz kidwatch-adb)")
        if not await asyncio.to_thread(Path(self.apk).is_file):
            raise AppError(f"brak APK w obrazie ({self.apk})")
        try:
            await self.adb.push(self.apk, APK_NA_TV)
            wynik = (await self.adb.shell(f"pm install -r {APK_NA_TV}", limit_s=120)).strip()
            if "Success" not in wynik:
                raise AppError(f"pm install: {wynik[-200:]}")
            await self.adb.shell(f"rm -f {APK_NA_TV}")
            uprawnienie = (
                await self.adb.shell(f"cmd notification allow_listener {NASLUCH}")).strip()
            await self.adb.shell(f"am start -n {AKTYWNOSC}")
        except TvUnavailable as exc:
            raise AppError(f"ADB nie odpowiada: {exc}") from exc
        log.info("aplikacja Kidwatch TV: zainstalowana przez ADB%s",
                 f" (uprawnienie: {uprawnienie})" if uprawnienie else "")
        return ("Zainstalowano. Telewizor pokazuje kod parowania - wpisz go poniżej."
                + (f" Uwaga z uprawnienia: {uprawnienie}" if uprawnienie else ""))

    async def aclose(self) -> None:
        await self.http.aclose()
