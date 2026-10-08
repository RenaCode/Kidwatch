"""Kanal "bramka" — wspolna bramka powiadomien RenaCode w klastrze.

Bramka (renacode-infra: charts/bramka) sama wybiera droge: WhatsApp, gdy numer
jest podpiety, a w przeciwnym razie e-mail. Kidwatch nie wie, ktora z nich
poszla wiadomosc, i nie musi — podpiecie WhatsAppa nie wymaga tu zadnej zmiany.

Klucz WYSYLKOWY idzie ze zmiennej BRAMKA_KLUCZ (Sekret kidwatch-secrets), nigdy
z config.yaml. Bramka rozpoznaje po nim aplikacje i sama ustawia zrodlo -
pole `zrodlo` w ciele zostaje dla zgodnosci ze starsza bramka.

`priorytet`, `rodzaj` i `format` steruja tylko wygladem maila HTML (etykieta
alarm / wazne / informacja, podpis w naglowku, listy i sekcje z tekstu).
Starsza bramka ich nie czyta i wysyla jak dotad - pola sa zgodne wstecz.

`kategoria` steruje TRASA w bramce. Bez kategorii (trasa "kidwatch", ktora ma
rodzina) ida WYLACZNIE informacje o sesjach - patrz SESJA. Kazdy inny rodzaj
idzie jako "kidwatch:<kategoria>", ktora dostaje tylko odbiorca z "*" albo
z ta trasa wpisana jawnie. Starsza bramka pole ignoruje - wtedy wszystko idzie
do wszystkich, jak dotad.
"""

from __future__ import annotations

import logging

import httpx

from ..config import BramkaConfig
from ..models import Notification, NotifyKind
from .base import with_retry

log = logging.getLogger(__name__)

#: Podpis rodzaju w naglowku maila HTML ("kidwatch · podsumowanie dnia").
RODZAJE = {
    NotifyKind.SESSION_START: "start sesji",
    NotifyKind.APP: "aplikacja",
    NotifyKind.SESSION_END: "koniec sesji",
    NotifyKind.DAILY: "podsumowanie dnia",
    NotifyKind.THROTTLED: "zbiorczo",
    NotifyKind.WATCHDOG: "czujka",
    NotifyKind.DEVICE_LAUNCH: "iPad",
    NotifyKind.DEVICE_SCREEN: "iPad",
    NotifyKind.DEVICE_INVENTORY: "iPad",
    NotifyKind.TV_START: "telewizor",
    NotifyKind.TV_END: "telewizor",
    NotifyKind.TV_PAUSE: "telewizor",
    NotifyKind.DNS_PROFILE: "profil DNS",
    NotifyKind.NIGHT: "noc",
    NotifyKind.WEEKLY: "raport tygodnia",
    NotifyKind.GAME: "czas gry",
}

#: Informacje o sesjach: jedyne, co idzie bez kategorii, czyli do rodziny
#: (trasa "kidwatch"). Lista DOZWOLONA, nie blokowana: nowy rodzaj bez wpisu
#: tutaj trafia do kategorii "inne" i rodzina go nie dostanie, zamiast
#: dostac alarm tylko dlatego, ze nikt nie dopisal go do wyjatkow.
SESJA = frozenset({
    NotifyKind.SESSION_START,
    NotifyKind.APP,
    NotifyKind.SESSION_END,
    NotifyKind.THROTTLED,
    NotifyKind.DEVICE_LAUNCH,
    NotifyKind.DEVICE_SCREEN,
    NotifyKind.TV_START,
    NotifyKind.TV_END,
})

#: Reszta: trasy "kidwatch:<kategoria>", ktore dostaje tylko odbiorca z "*"
#: (albo z trasa wpisana jawnie) - patrz charts/bramka/README.md, "Trasy".
KATEGORIE = {
    # alarmy techniczne: cisza DNS, odczyt iPada nie dziala, kolejka porzucila push
    NotifyKind.WATCHDOG: "czujka",
    NotifyKind.DNS_PROFILE: "czujka",
    NotifyKind.TV_PAUSE: "czujka",
    # alarmy o dzieciach: iPad w nocy, nowa/usunieta aplikacja
    NotifyKind.NIGHT: "alarm",
    NotifyKind.DEVICE_INVENTORY: "alarm",
    NotifyKind.DAILY: "raport",
    NotifyKind.WEEKLY: "raport",
    NotifyKind.GAME: "gra",
}


def kategoria(kind: NotifyKind) -> str | None:
    """None = informacja o sesji (trasa "kidwatch"), inaczej kategoria trasy."""
    if kind in SESJA:
        return None
    return KATEGORIE.get(kind, "inne")


class BramkaNotifier:
    name = "bramka"

    def __init__(
        self,
        cfg: BramkaConfig,
        key: str,
        client: httpx.AsyncClient | None = None,
        sleep=None,
    ) -> None:
        self.cfg = cfg
        self._key = key
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=cfg.timeout_seconds)
        self._sleep_kwargs = {"sleep": sleep} if sleep is not None else {}

    @property
    def url(self) -> str:
        return self.cfg.url.rstrip("/") + "/v1/wyslij"

    def payload(self, note: Notification) -> dict:
        kat = kategoria(note.kind)
        extra = {"kategoria": kat} if kat else {}
        return {
            "temat": note.title,
            "tresc": note.text,
            "zrodlo": self.cfg.zrodlo,
            # Skala ntfy 1-5; bramka: 5 alarm, 4 wazne, reszta informacja.
            "priorytet": note.priority,
            "rodzaj": RODZAJE.get(note.kind, ""),
            # Tresc z formatting.py: punkty "•", naglowki sekcji w *gwiazdkach*.
            "format": "markdown-lite",
            **extra,
        }

    async def send(self, note: Notification) -> bool:
        return await with_retry(
            lambda: self._client.post(
                self.url, json=self.payload(note), headers={"X-Api-Key": self._key}
            ),
            what="bramka",
            **self._sleep_kwargs,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
