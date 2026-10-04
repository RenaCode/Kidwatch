"""Wspolny interfejs zrodel logow DNS."""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Protocol, runtime_checkable

from ..models import DnsEvent


@runtime_checkable
class Source(Protocol):
    """Zrodlo zdarzen DNS.

    `events()` to nieskonczony asynchroniczny iterator. Zrodlo samo radzi sobie
    z zerwaniem polaczenia i ponowieniem — nie przerywa iteracji z powodu bledu
    sieci, bo to zatrzymaloby caly serwis. Konczy sie tylko przez anulowanie.
    """

    name: str

    def events(self) -> AsyncIterator[DnsEvent]: ...

    async def aclose(self) -> None: ...


class Unreachable(RuntimeError):
    """Urzadzenie nie odpowiada: iPad spi, telewizor wyjety z pradu.

    Wspolna baza dla obserwatorow urzadzen, zeby jedna petla (scheduler.
    device_loop) obslugiwala iPady i telewizor tak samo: brak odpowiedzi to
    NORMALNY stan, a alarm dopiero po wielu godzinach bez udanego odczytu.
    """
