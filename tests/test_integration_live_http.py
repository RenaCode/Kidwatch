"""Testy integracyjne na PRAWDZIWYM stosie sieciowym (loopback TCP).

Pozostale testy zrodel i kanalow jada na `httpx.MockTransport`, czyli na atrapie
transportu: zadne gniazdo sie nie otwiera. To nie dowodzi, ze po **faktycznym
zerwaniu polaczenia TCP** zrodlo wznowi strumien od wlasciwego kursora, ani ze
wysylka do ntfy przechodzi przez realny HTTP.

Tu stawiamy dwa prawdziwe serwery na efemerycznych portach i przepuszczamy przez
nie pelna sciezke: gniazdo -> SSE -> parser -> silnik -> HTTP POST -> odbiornik.
Serwery mowia surowym HTTP/1.1, zeby dalo sie sterowac momentem rozlaczenia.
"""

from __future__ import annotations

import asyncio
import contextlib
import json

from conftest import make_config
from kidwatch.classifier import Classifier
from kidwatch.config import NextDnsConfig, NtfyConfig
from kidwatch.engine import Engine
from kidwatch.models import NotifyKind
from kidwatch.notifiers.base import Dispatcher
from kidwatch.notifiers.ntfy import NtfyNotifier
from kidwatch.sources.nextdns import NextDnsSource
from kidwatch.store import Store


async def read_http_request(reader: asyncio.StreamReader) -> tuple[str, dict[str, str], bytes]:
    """Czyta jedno zapytanie HTTP/1.1: linia startu, naglowki, cialo."""
    start = await reader.readline()
    if not start:
        raise ConnectionResetError("klient zamknal polaczenie")
    request_line = start.decode().strip()

    headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        if line in (b"\r\n", b"\n", b""):
            break
        name, _, value = line.decode().partition(":")
        headers[name.strip().lower()] = value.strip()

    body = b""
    length = int(headers.get("content-length", 0))
    if length:
        body = await reader.readexactly(length)
    return request_line, headers, body


# ====================================================== atrapa serwera NextDNS
class FakeNextDns:
    """Serwer SSE, ktory ROZLACZA sie w polowie strumienia.

    Pierwsze polaczenie oddaje jedno zdarzenie i zamyka gniazdo. Drugie musi
    przyjsc z parametrem `id` rownym ostatniemu wyslanemu identyfikatorowi —
    inaczej po kazdym zerwaniu sieci dostawalibysmy te same wpisy od nowa.
    """

    def __init__(self) -> None:
        self.requests: list[str] = []
        self.api_keys: list[str] = []
        self.server: asyncio.Server | None = None

    async def start(self) -> str:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        host, port = self.server.sockets[0].getsockname()[:2]
        return f"http://{host}:{port}"

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            request_line, headers, _ = await read_http_request(reader)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            writer.close()
            return

        self.requests.append(request_line)
        self.api_keys.append(headers.get("x-api-key", ""))
        attempt = len(self.requests)

        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Cache-Control: no-cache\r\n"
            b"Connection: close\r\n"
            b"\r\n"
        )
        # Komentarz keep-alive — realny NextDNS je wysyla i parser musi je znosic.
        writer.write(b": keep-alive\n\n")
        await writer.drain()

        if attempt == 1:
            await self._send(writer, "evt-1", "2026-09-27T08:00:00.000Z", "www.youtube.com")
            # ROZLACZENIE w polowie strumienia — to jest sedno tego testu.
            writer.close()
            return

        await self._send(writer, "evt-2", "2026-09-27T08:01:00.000Z", "ecsv3.roblox.com")
        await self._send(writer, "evt-3", "2026-09-27T08:02:00.000Z", "api.minecraft.net")
        # Trzymamy otwarte, dopoki klient nie odejdzie.
        with contextlib.suppress(ConnectionResetError, asyncio.CancelledError):
            await reader.read()
        writer.close()

    async def _send(
        self, writer: asyncio.StreamWriter, event_id: str, ts: str, domain: str
    ) -> None:
        payload = json.dumps(
            {
                "timestamp": ts,
                "domain": domain,
                "root": domain,
                "encrypted": True,
                "protocol": "DNS-over-HTTPS",
                "client": "apple-profile",
                "device": {"id": "AAA11", "name": "iPad-Kuby", "model": "iPad"},
                "status": "default",
            }
        )
        writer.write(f"id: {event_id}\ndata: {payload}\n\n".encode())
        await writer.drain()


# ========================================================= atrapa serwera ntfy
class FakeNtfy:
    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.auth: list[str | None] = []
        self.server: asyncio.Server | None = None

    async def start(self) -> str:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        host, port = self.server.sockets[0].getsockname()[:2]
        return f"http://{host}:{port}"

    async def stop(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            _, headers, body = await read_http_request(reader)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            writer.close()
            return
        # Dekodujemy jawnie z UTF-8: gdyby wysylka szla naglowkami, polskie znaki
        # nigdy by tu nie dotarly.
        self.messages.append(json.loads(body.decode("utf-8")))
        self.auth.append(headers.get("authorization"))
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}")
        await writer.drain()
        writer.close()


# ==================================================================== testy
async def test_pelna_sciezka_przez_prawdziwe_gniazda(app_map, tmp_path):
    """Gniazdo -> SSE -> parser -> silnik -> HTTP POST -> odbiornik."""
    nextdns, ntfy = FakeNextDns(), FakeNtfy()
    dns_url = await nextdns.start()
    ntfy_url = await ntfy.start()

    store = Store(tmp_path / "live.db")
    cfg = make_config()
    engine = Engine(cfg, store, Classifier(app_map))
    notifier = NtfyNotifier(
        NtfyConfig(topic="temat-integracyjny", server=ntfy_url), token="tk_test"
    )
    dispatcher = Dispatcher([notifier])

    source = NextDnsSource(
        cfg=NextDnsConfig(profile_id="prof123", base_url=dns_url, backoff_max_seconds=0.05),
        api_key="klucz-integracyjny",
        sleep=asyncio.sleep,
    )

    produced = []
    try:
        async for event in source.events():
            produced += engine.handle(event)
            store.set_cursor(source.name, event.cursor or "")
            if len(produced) >= 3:
                break
    finally:
        await source.aclose()
        await dispatcher.aclose()

    # --- strumien przezyl rozlaczenie i wznowil sie od wlasciwego kursora
    assert len(nextdns.requests) >= 2, "serwer rozlaczyl, wiec musialo byc ponowne polaczenie"
    assert "/profiles/prof123/logs/stream" in nextdns.requests[0]
    assert "id=evt-1" in nextdns.requests[1], (
        f"wznowienie bez wlasciwego kursora: {nextdns.requests[1]}"
    )
    assert set(nextdns.api_keys) == {"klucz-integracyjny"}

    # --- kursor przetrwal w bazie, wiec restart procesu tez by go znalazl
    assert store.get_cursor("nextdns") == "evt-3"
    store.close()


async def test_wysylka_do_ntfy_przez_prawdziwy_http_z_polskimi_znakami(app_map, tmp_path):
    """Regresja dla decyzji o JSON zamiast naglowkow — tym razem po gniazdku."""
    ntfy = FakeNtfy()
    ntfy_url = await ntfy.start()

    cfg = make_config()
    cfg.devices[0].display_name = "iPad Michała"
    cfg.devices[0].child = "Michał"

    store = Store(":memory:")
    engine = Engine(cfg, store, Classifier(app_map))
    notifier = NtfyNotifier(NtfyConfig(topic="temat", server=ntfy_url), token="tk_test")
    dispatcher = Dispatcher([notifier])

    from datetime import UTC, datetime  # noqa: PLC0415

    from kidwatch.models import DnsEvent  # noqa: PLC0415

    notes = engine.handle(
        DnsEvent(
            ts=datetime(2026, 9, 27, 8, 0, tzinfo=UTC),
            device_id="ipad-kuby",
            domain="www.youtube.com",
        )
    )
    await dispatcher.send_all(notes)
    await dispatcher.aclose()
    await ntfy.stop()
    store.close()

    assert len(ntfy.messages) == 1
    message = ntfy.messages[0]
    assert message["topic"] == "temat"
    assert message["title"] == "iPad Michała aktywny"
    assert "YouTube" in message["message"]
    assert ntfy.auth[0] == "Bearer tk_test"


async def test_niedostepny_ntfy_nie_zatrzymuje_przetwarzania(app_map, tmp_path):
    """Kanal padniety na poziomie TCP (odmowa polaczenia) nie moze zablokowac
    silnika — sesje musza byc liczone dalej."""
    # Port, na ktorym nikt nie nasluchuje: serwer zamkniety natychmiast po starcie.
    dead = FakeNtfy()
    dead_url = await dead.start()
    await dead.stop()

    cfg = make_config()
    store = Store(":memory:")
    engine = Engine(cfg, store, Classifier(app_map))
    notifier = NtfyNotifier(
        NtfyConfig(topic="t", server=dead_url), sleep=lambda _s: asyncio.sleep(0)
    )
    dispatcher = Dispatcher([notifier])

    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from kidwatch.models import DnsEvent  # noqa: PLC0415

    base = datetime(2026, 9, 27, 8, 0, tzinfo=UTC)
    notes = engine.handle(
        DnsEvent(ts=base, device_id="ipad-kuby", domain="www.youtube.com")
    )
    results = await dispatcher.send(notes[0])
    assert results == {"ntfy": False}, "nieudana wysylka musi byc zgloszona jako porazka"

    # A silnik dziala dalej: sesja zyje i domyka sie normalnie.
    later = engine.tick(base + timedelta(minutes=30))
    assert any(n.kind is NotifyKind.SESSION_END for n in later)
    store.close()
