"""Sony BRAVIA REST API ("Sterowanie IP") - stan i zrodlo telewizora bez ADB.

## Co daje

JSON-RPC po HTTP na porcie 80 telewizora:

    POST /sony/system     getPowerStatus          -> "active" | "standby"
    POST /sony/avContent  getPlayingContentInfo   -> zrodlo i program

`getPowerStatus` odpowiada BEZ klucza (sprawdzone na TV salon 2026-10-07).
`getPlayingContentInfo` wymaga naglowka `X-Auth-PSK` (bez niego 403): klucz
ustawia sie na TV (Ustawienia -> Siec -> Siec domowa -> Sterowanie IP ->
Uwierzytelnianie "Normalne i klucz wstepny") i w Sekrecie kidwatch-secrets
jako `TV_SONY_PSK`.

Odpowiedz `getPlayingContentInfo`:

- tuner: `source` "tv:dvbt" (dvbc, dvbs...), `title` = nazwa kanalu,
  `programTitle` = tytul z EPG, `dispNum` = numer kanalu;
- HDMI: `source` "extInput:hdmi", `title` = "HDMI 1" albo nazwa nadana wejsciu;
- aplikacja na ekranie: blad 7 "Illegal State" - Sony nie mowi, jaka. Wtedy
  o odtwarzaniu decyduje ruch sieciowy (tv_siec.py);
- ekran wylaczony: blad 40005 "Display Is Turned off".

## Czego NIE daje

Nazwy aplikacji ani tytulu w aplikacji. To zostaje ADB (tytuly) i NextDNS
(serwis).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

import httpx

log = logging.getLogger(__name__)

#: Bledy JSON-RPC Sony, ktore sa stanem, nie awaria.
ILLEGAL_STATE = 7
DISPLAY_OFF = 40005


class SonyError(RuntimeError):
    """Telewizor nie odpowiada po HTTP albo odpowiedzial czyms nieczytelnym."""


class SonyAuthError(SonyError):
    """403 - brak albo zly klucz PSK. Konfiguracja, nie stan telewizora."""


@dataclass(frozen=True, slots=True)
class Zrodlo:
    """Co gra wedlug Sony. `rodzaj`: "tuner" | "hdmi" | "inne"."""

    rodzaj: str
    nazwa: str
    program: str | None = None


class SonyClient:
    def __init__(self, host: str, psk: str | None, *, timeout: float = 5.0,
                 http: httpx.AsyncClient | None = None) -> None:
        self.base = f"http://{host}/sony"
        self.psk = psk or None
        self.http = http or httpx.AsyncClient(timeout=timeout)

    async def _rpc(self, service: str, method: str) -> tuple[list | None, list | None]:
        """(result, error) - jedno z nich jest None."""
        headers = {"X-Auth-PSK": self.psk} if self.psk else {}
        try:
            r = await self.http.post(
                f"{self.base}/{service}",
                json={"method": method, "id": 1, "params": [], "version": "1.0"},
                headers=headers,
            )
            body = r.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise SonyError(f"{type(exc).__name__}: {exc}") from exc
        if not isinstance(body, dict):
            raise SonyError("odpowiedz Sony nie jest obiektem JSON")
        err = body.get("error")
        if err and isinstance(err, list) and err and err[0] in (401, 403):
            raise SonyAuthError(
                "Sony odrzucil zapytanie (403) - ustaw TV_SONY_PSK i Sterowanie IP "
                "z kluczem wstepnym na telewizorze"
            )
        return body.get("result"), err

    async def wlaczony(self) -> bool:
        result, err = await self._rpc("system", "getPowerStatus")
        if err or not result or not isinstance(result[0], dict):
            raise SonyError(f"getPowerStatus: {err or result!r}")
        return result[0].get("status") == "active"

    async def zrodlo(self) -> Zrodlo | None:
        """Tuner/HDMI albo None (aplikacja na ekranie, ekran wylaczony)."""
        result, err = await self._rpc("avContent", "getPlayingContentInfo")
        if err:
            if err[0] in (ILLEGAL_STATE, DISPLAY_OFF):
                return None
            raise SonyError(f"getPlayingContentInfo: {err!r}")
        return parse_zrodlo(result[0] if result else None)

    async def aclose(self) -> None:
        await self.http.aclose()


def parse_zrodlo(info: dict | None) -> Zrodlo | None:
    """Logika bez I/O - testowana na odpowiedziach z dokumentacji Sony."""
    if not isinstance(info, dict):
        return None
    source = str(info.get("source") or "")
    title = (info.get("title") or "").strip()
    if source.startswith("tv:"):
        program = (info.get("programTitle") or "").strip() or None
        nazwa = title or (f"kanał {info['dispNum']}" if info.get("dispNum") else "Telewizja")
        return Zrodlo("tuner", nazwa, program)
    if source.startswith("extInput:"):
        if not title:
            uri = str(info.get("uri") or "")
            port = uri.rsplit("port=", 1)[-1] if "port=" in uri else ""
            title = f"HDMI {port}".strip() if "hdmi" in source else source.split(":", 1)[1]
        return Zrodlo("hdmi" if "hdmi" in source else "inne", title)
    return None
