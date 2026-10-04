"""Zrodlo NextDNS — strumien SSE z /profiles/{id}/logs/stream.

Zweryfikowane w dokumentacji API (nextdns.github.io/api) 2026-09-27:
  * uwierzytelnianie naglowkiem `X-Api-Key`;
  * strumien w formacie Server-Sent Events, kazde zdarzenie ma linie `id:`;
  * wznowienie przez parametr zapytania `id=<ostatnie id>`, bez luk i duplikatow;
  * strumien przyjmuje te same parametry co /logs OPROCZ from, to, sort, limit
    i cursor — czyli `device`, `status`, `search`, `raw` sa dozwolone;
  * pole `device` to obiekt {id, name, model}; filtr `device` po stronie API
    dziala po device.ID, nie po nazwie.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime

import httpx

from ..config import NextDnsConfig
from ..models import DnsEvent

log = logging.getLogger(__name__)


@dataclass(frozen=True, slots=True)
class SseEvent:
    data: str
    id: str | None = None


@dataclass
class SseDecoder:
    """Dekoder Server-Sent Events, karmiony linia po linii.

    Trzymany osobno od HTTP, zeby dal sie przetestowac bez sieci. Obsluguje to,
    co realnie przychodzi z NextDNS: komentarze keep-alive (`:`), wieloliniowe
    `data:` i `id:`, ktory wedlug specyfikacji SSE obowiazuje takze dla kolejnych
    zdarzen, dopoki nie przyjdzie nowy.
    """

    _data: list[str] = field(default_factory=list)
    _id: str | None = None
    last_id: str | None = None

    def feed(self, line: str) -> SseEvent | None:
        line = line.rstrip("\r")

        if line == "":  # pusta linia = koniec zdarzenia
            if not self._data:
                self._id = None
                return None
            if self._id is not None:
                self.last_id = self._id
            event = SseEvent(data="\n".join(self._data), id=self.last_id)
            self._data = []
            self._id = None
            return event

        if line.startswith(":"):  # komentarz / keep-alive
            return None

        name, _, value = line.partition(":")
        if value.startswith(" "):
            value = value[1:]

        if name == "data":
            self._data.append(value)
        elif name == "id" and "\x00" not in value:
            self._id = value
        # pola `event` i `retry` NextDNS nie uzywa; swiadomie je pomijamy
        return None


def _text(value: object) -> str:
    """Pole tekstowe wpisu albo "". Liczba czy obiekt w miejscu napisu
    konczyly sie AttributeError na .strip(), ktory wywracal cale zrodlo
    (restart po 30 s) zamiast pominac jeden wpis."""
    return value.strip() if isinstance(value, str) else ""


def parse_log_entry(payload: str) -> DnsEvent | None:
    """Zamienia jedno `data:` w DnsEvent. Zwraca None dla wpisow bez tresci.

    Nieznane i nadmiarowe pola sa ignorowane — API moze je dodawac i to nie
    powod, zeby serwis padal.
    """
    try:
        raw = json.loads(payload)
    except json.JSONDecodeError:
        log.warning("nieparsowalny JSON w strumieniu SSE: %.200s", payload)
        return None
    if not isinstance(raw, dict):
        return None

    domain = _text(raw.get("domain"))
    timestamp = raw.get("timestamp")
    if not domain or not timestamp:
        return None

    try:
        ts = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        log.warning("nieparsowalny timestamp: %r", timestamp)
        return None
    if ts.tzinfo is None:
        log.warning("timestamp bez strefy: %r — pomijam", timestamp)
        return None

    device = raw.get("device") or {}
    if not isinstance(device, dict):
        device = {}
    name = _text(device.get("name"))
    dev_id = _text(device.get("id"))
    # Nazwa jest tym, co widac w panelu NextDNS i co ustawia sie w aplikacji na
    # iPadzie, wiec ja traktujemy jako glowny trop. ID zostaje zapasowym.
    primary = name or dev_id or "__UNIDENTIFIED__"
    alt = dev_id if name else None

    return DnsEvent(ts=ts, device_id=primary, domain=domain, device_alt=alt)


class ConnectGate:
    """Wspolna bramka otwierania strumieni dla kilku profili.

    NextDNS zamyka kazdy strumien mniej wiecej co minute, a szybkie ponowne
    otwarcie dostaje 429 (patrz NextDnsConfig.rate_limit_wait_seconds). Przy
    dwoch profilach oba strumienie zamykaja sie w podobnym rytmie — otwierane
    jednoczesnie lapaly 429 parami. Bramka pilnuje, zeby miedzy dowolnymi
    dwoma otwarciami minelo `spacing` sekund, a 429 na jednym strumieniu
    wstrzymuje WSZYSTKIE (`hold`) — limit jest na klucz API, nie na profil,
    wiec drugi strumien probujacy w tej chwili tylko przedluzylby blokade.
    """

    def __init__(self, spacing: float, clock=time.monotonic, sleep=asyncio.sleep) -> None:
        self.spacing = spacing
        self._clock = clock
        self._sleep = sleep
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        async with self._lock:
            delay = self._next - self._clock()
            if delay > 0:
                await self._sleep(delay)
            self._next = max(self._next, self._clock()) + self.spacing

    def hold(self, seconds: float) -> None:
        self._next = max(self._next, self._clock() + seconds)


class NextDnsSource:
    name = "nextdns"

    def __init__(
        self,
        cfg: NextDnsConfig,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        cursor: str | None = None,
        device_filter: str | None = None,
        sleep=asyncio.sleep,
        profile_id: str | None = None,
        cursor_key: str | None = None,
        gate: ConnectGate | None = None,
    ) -> None:
        self.cfg = cfg
        self._api_key = api_key
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=httpx.Timeout(10.0, read=None))
        self.cursor = cursor
        self._device_filter = device_filter
        self._sleep = sleep
        self.profile_id = profile_id or cfg.profile_id
        self.cursor_key = cursor_key
        self._gate = gate

    @property
    def url(self) -> str:
        return f"{self.cfg.base_url.rstrip('/')}/profiles/{self.profile_id}/logs/stream"

    def _params(self) -> dict[str, str]:
        params: dict[str, str] = {}
        if self.cursor:
            params["id"] = self.cursor
        if self.cfg.raw:
            params["raw"] = "true"
        if self._device_filter:
            params["device"] = self._device_filter
        return params

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def events(self) -> AsyncIterator[DnsEvent]:
        """Nieskonczony strumien. Zerwane polaczenie jest ponawiane, nie zglaszane wyjatkiem."""
        backoff = 1.0
        while True:
            if self._gate is not None:
                await self._gate.wait()
            try:
                async for event in self._one_connection():
                    backoff = 1.0  # udany odbior zeruje kare
                    yield event
                # Rutyna: NextDNS zamyka strumien co okolo minute. Kursor
                # wznawia odczyt bez strat, wiec to nie jest ostrzezenie.
                log.info(
                    "strumien NextDNS %s zamkniety przez serwer — lacze ponownie",
                    self.profile_id,
                )
            except asyncio.CancelledError:
                raise
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 429:
                    # Spodziewane po zamknieciu strumienia — patrz
                    # NextDnsConfig.rate_limit_wait_seconds. Zdarzenia nie
                    # gina, bo wznawiamy od kursora.
                    wait = max(backoff, self.cfg.rate_limit_wait_seconds)
                    log.info(
                        "NextDNS %s: limit polaczen (429) — ponawiam za %.0f s",
                        self.profile_id,
                        wait,
                    )
                    if self._gate is not None:
                        # Czeka bramka — i to wszystkie strumienie naraz.
                        self._gate.hold(wait)
                    else:
                        await self._sleep(wait)
                    backoff = min(wait * 2, self.cfg.backoff_max_seconds)
                    continue
                # 401/403 nie naprawia sie samo, ale i tak nie wolno nam zamilknac:
                # czujka w silniku zglosi cisze, a my probujemy dalej.
                log.error(
                    "NextDNS %s odpowiedzial %s — ponawiam za %.0f s",
                    self.profile_id,
                    exc.response.status_code,
                    backoff,
                )
            except (httpx.HTTPError, json.JSONDecodeError) as exc:
                log.warning(
                    "blad strumienia NextDNS %s (%s) — ponawiam za %.0f s",
                    self.profile_id,
                    exc,
                    backoff,
                )

            await self._sleep(backoff)
            backoff = min(backoff * 2, self.cfg.backoff_max_seconds)

    async def _one_connection(self) -> AsyncIterator[DnsEvent]:
        decoder = SseDecoder(last_id=self.cursor)
        headers = {"X-Api-Key": self._api_key, "Accept": "text/event-stream"}
        async with self._client.stream(
            "GET", self.url, params=self._params(), headers=headers
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                sse = decoder.feed(line)
                if sse is None:
                    continue
                if sse.id:
                    # Kursor zapisujemy zawsze, takze gdy wpisu nie da sie
                    # sparsowac — inaczej po restarcie utknelibysmy na nim.
                    self.cursor = sse.id
                event = parse_log_entry(sse.data)
                if event is not None:
                    yield DnsEvent(
                        ts=event.ts,
                        device_id=event.device_id,
                        domain=event.domain,
                        cursor=sse.id,
                        device_alt=event.device_alt,
                        cursor_key=self.cursor_key,
                    )


class _Failed:
    __slots__ = ("exc",)

    def __init__(self, exc: BaseException) -> None:
        self.exc = exc


_DONE = object()


class MultiNextDnsSource:
    """Kilka profili NextDNS jako jedno zrodlo (osobny profil na dziecko).

    Kazdy profil ma wlasny strumien i WLASNY kursor (cursor:nextdns:<profil>),
    bo id zdarzen SSE nie sa porownywalne miedzy profilami. Zdarzenia leca do
    silnika w kolejnosci nadejscia: jedno urzadzenie jest zawsze w jednym
    profilu, wiec kolejnosc per urzadzenie sie zachowuje.

    Wyjatek, ktorego pojedynczy strumien nie obsluzyl, konczy cale zrodlo —
    source_loop otworzy je ponownie (kursory zostaja w pamieci strumieni).
    """

    name = "nextdns"

    def __init__(self, sources: list[NextDnsSource]) -> None:
        if not sources:
            raise ValueError("MultiNextDnsSource bez zadnego profilu")
        self.sources = sources
        #: Zdarzenia odebrane z sieci, ale jeszcze nie oddane silnikowi, gdy
        #: zrodlo padlo. Kursory strumieni sa juz ZA nimi, wiec ponowne
        #: otwarcie bez tej listy gubilo je bez sladu.
        self._carry: list[DnsEvent] = []

    async def events(self) -> AsyncIterator[DnsEvent]:
        while self._carry:
            yield self._carry.pop(0)
        if len(self.sources) == 1:
            async for event in self.sources[0].events():
                yield event
            return

        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)

        async def pump(src: NextDnsSource) -> None:
            try:
                async for event in src.events():
                    await queue.put(event)
            except asyncio.CancelledError:
                raise
            except BaseException as exc:  # noqa: BLE001 — oddajemy wyjatek czytelnikowi
                await queue.put(_Failed(exc))
            await queue.put(_DONE)

        tasks = [asyncio.create_task(pump(s), name=f"nextdns:{s.profile_id}") for s in self.sources]
        finished = 0
        try:
            while finished < len(tasks):
                item = await queue.get()
                if item is _DONE:
                    finished += 1
                elif isinstance(item, _Failed):
                    raise item.exc
                else:
                    yield item
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            while not queue.empty():
                item = queue.get_nowait()
                if isinstance(item, DnsEvent):
                    self._carry.append(item)

    async def aclose(self) -> None:
        for src in self.sources:
            await src.aclose()
