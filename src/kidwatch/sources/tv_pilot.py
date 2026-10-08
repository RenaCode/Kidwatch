"""Pilot Google TV (Android TV Remote v2): zasilanie i aplikacja bez ADB.

## Po co

ADB zgubilo zgode na kluczu (2026-10-07/08) i telewizor milczal, dopoki ktos
nie zatwierdzil okna "Zezwolic na debugowanie?" przy wlaczonym ekranie.
Protokol pilota to ten sam szyfrowany kanal, ktorego uzywa aplikacja Google TV
w telefonie: usluga jest wbudowana w telewizor, nie wymaga opcji programisty,
a parowanie (6 znakow z ekranu TV) robi sie raz.

Daje: wlaczony/wylaczony i pakiet aplikacji na pierwszym planie. NIE daje
tytulow - te zostaja ADB (YouTube, Disney+).

## Porty i pliki

6466 (polecenia), 6467 (parowanie) na `tv.host`. Certyfikat klienta, ktory
telewizor zapamietuje przy parowaniu, lezy na wolumenie danych
(`tv.pilot_dir`, domyslnie obok bazy): restart poda nie zrywa parowania.

## Parowanie

Z panelu (Ustawienia -> Telewizor): "Sparuj pilota" wysyla `paruj_start` - telewizor
pokazuje kod - "Potwierdz" wysyla `paruj_kod`. Panel dziala w osobnym watku,
wiec obie metody przerzucaja korutyny na petle serwisu
(`run_coroutine_threadsafe`) i czekaja na wynik.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

log = logging.getLogger(__name__)

#: Pilot dzialajacy w tym procesie - czyta go panel (osobny watek).
AKTYWNY: PilotTv | None = None


@dataclass(frozen=True, slots=True)
class StanPilota:
    polaczony: bool
    sparowany: bool
    wlaczony: bool | None
    aplikacja: str | None
    zmiana: datetime | None


class PilotError(RuntimeError):
    pass


class PilotTv:
    def __init__(self, host: str, katalog: str | Path, *, nazwa: str = "kidwatch",
                 remote_factory=None) -> None:
        self.host = host
        self.katalog = Path(katalog)
        self.nazwa = nazwa
        self._factory = remote_factory
        self.loop: asyncio.AbstractEventLoop | None = None
        self.remote = None
        self.polaczony = False
        self.wlaczony: bool | None = None
        self.aplikacja: str | None = None
        self.zmiana: datetime | None = None
        self._paruje = False

    # ------------------------------------------------------------------ pliki
    @property
    def _cert(self) -> Path:
        return self.katalog / "cert.pem"

    @property
    def _key(self) -> Path:
        return self.katalog / "key.pem"

    @property
    def _znacznik(self) -> Path:
        # Certyfikat istnieje juz PRZED parowaniem (generuje go start), wiec
        # o tym, czy TV go zna, mowi osobny znacznik.
        return self.katalog / "sparowany"

    @property
    def sparowany(self) -> bool:
        return self._znacznik.is_file()

    def stan(self) -> StanPilota:
        return StanPilota(self.polaczony, self.sparowany, self.wlaczony, self.aplikacja,
                          self.zmiana)

    # ------------------------------------------------------------------ petla
    def _nowy_remote(self):
        if self._factory is not None:
            return self._factory(self)
        from androidtvremote2 import AndroidTVRemote  # noqa: PLC0415

        return AndroidTVRemote(self.nazwa, str(self._cert), str(self._key), self.host,
                               loop=self.loop, enable_ime=False)

    async def uruchom(self) -> None:
        """Zadanie serwisu: certyfikat, polaczenie, wznawianie. Nie konczy sie."""
        self.loop = asyncio.get_running_loop()
        self.katalog.mkdir(parents=True, exist_ok=True)
        self.remote = self._nowy_remote()
        await self.remote.async_generate_cert_if_missing()
        if self.sparowany:
            await self._polacz()
        else:
            log.info("pilot TV: niesparowany - sparuj w panelu (Ustawienia -> Telewizor)")
        await asyncio.Event().wait()

    async def _polacz(self) -> None:
        from androidtvremote2 import CannotConnect, ConnectionClosed, InvalidAuth  # noqa: PLC0415

        r = self.remote
        if not getattr(self, "_podpiete", False):
            r.add_is_on_updated_callback(self._on)
            r.add_current_app_updated_callback(self._app)
            r.add_is_available_updated_callback(self._dostepny)
            self._podpiete = True
        while True:
            try:
                await r.async_connect()
                break
            except InvalidAuth:
                self._utracone_parowanie()
                return
            except (CannotConnect, ConnectionClosed) as exc:
                log.debug("pilot TV: brak polaczenia (%s) - ponawiam za 60 s", exc)
                await asyncio.sleep(60)
        self._dostepny(True)
        self._on(bool(r.is_on))
        if r.current_app:
            self._app(r.current_app)
        r.keep_reconnecting(self._utracone_parowanie)

    def _utracone_parowanie(self) -> None:
        log.warning("pilot TV: telewizor nie zna juz certyfikatu - sparuj ponownie w panelu")
        self._znacznik.unlink(missing_ok=True)
        self.polaczony = False

    def _teraz(self) -> None:
        self.zmiana = datetime.now(UTC)

    def _on(self, wlaczony: bool) -> None:
        if wlaczony != self.wlaczony:
            log.info("pilot TV: %s", "wlaczony" if wlaczony else "wylaczony")
        self.wlaczony = wlaczony
        self._teraz()

    def _app(self, pakiet: str) -> None:
        if pakiet != self.aplikacja:
            log.info("pilot TV: aplikacja %s", pakiet)
        self.aplikacja = pakiet or None
        self._teraz()

    def _dostepny(self, ok: bool) -> None:
        if ok != self.polaczony:
            log.info("pilot TV: %s", "polaczony" if ok else "rozlaczony")
        self.polaczony = ok

    # -------------------------------------------------------------- parowanie
    def _w_petli(self, coro, timeout: float):
        if self.loop is None or self.remote is None:
            coro.close()
            raise PilotError("pilot TV jeszcze nie wystartowal")
        try:
            return asyncio.run_coroutine_threadsafe(coro, self.loop).result(timeout)
        except PilotError:
            raise
        except Exception as exc:  # noqa: BLE001 - komunikat idzie do panelu
            raise PilotError(f"{type(exc).__name__}: {exc}") from exc

    def paruj_start(self) -> None:
        """Telewizor pokazuje 6-znakowy kod. Wolane z watku panelu."""
        self._w_petli(self._paruj_start(), 20)

    async def _paruj_start(self) -> None:
        if self.sparowany and self.polaczony:
            raise PilotError("pilot jest juz sparowany i polaczony")
        await self.remote.async_start_pairing()
        self._paruje = True

    def paruj_kod(self, kod: str) -> None:
        kod = kod.strip().upper()
        if len(kod) != 6 or any(c not in "0123456789ABCDEF" for c in kod):
            raise PilotError("kod ma 6 znaków: cyfry i litery A–F")
        self._w_petli(self._paruj_kod(kod), 30)

    async def _paruj_kod(self, kod: str) -> None:
        if not self._paruje:
            raise PilotError("najpierw „Sparuj” - telewizor musi pokazać kod")
        await self.remote.async_finish_pairing(kod)
        self._paruje = False
        self._znacznik.write_text(datetime.now(UTC).isoformat())
        log.info("pilot TV: sparowany")
        asyncio.get_running_loop().create_task(self._polacz())
