"""Testy zrodla NextDNS: dekoder SSE, parser wpisow i zachowanie strumienia."""

from __future__ import annotations

import asyncio
import contextlib
import json
from datetime import UTC, datetime

import httpx
import pytest

from kidwatch.config import NextDnsConfig
from kidwatch.sources.nextdns import (
    NextDnsSource,
    SseDecoder,
    parse_log_entry,
)


# =================================================================== dekoder SSE
def feed_all(lines: list[str]) -> list:
    dec = SseDecoder()
    return [e for line in lines if (e := dec.feed(line)) is not None]


def test_pojedyncze_zdarzenie():
    events = feed_all(["id: abc", 'data: {"a":1}', ""])
    assert len(events) == 1
    assert events[0].id == "abc"
    assert events[0].data == '{"a":1}'


def test_wieloliniowe_data_jest_zlaczone_znakiem_nowej_linii():
    events = feed_all(["id: x", "data: pierwsza", "data: druga", ""])
    assert events[0].data == "pierwsza\ndruga"


def test_komentarze_i_keepalive_sa_pomijane():
    events = feed_all([":", ": keep-alive", "id: a", 'data: {"x":1}', "", ":", ""])
    assert len(events) == 1


def test_pusta_linia_bez_data_nie_tworzy_zdarzenia():
    assert feed_all(["", "", ":", ""]) == []


def test_brak_spacji_po_dwukropku_jest_dozwolony():
    events = feed_all(["id:abc", "data:{}", ""])
    assert events[0].id == "abc"
    assert events[0].data == "{}"


def test_id_obowiazuje_dla_kolejnych_zdarzen_dopoki_nie_przyjdzie_nowe():
    """Tak mowi specyfikacja SSE: ostatnie id jest pamietane."""
    dec = SseDecoder()
    got = []
    for line in ["id: pierwsze", "data: a", "", "data: b", "", "id: drugie", "data: c", ""]:
        e = dec.feed(line)
        if e:
            got.append((e.id, e.data))
    assert got == [("pierwsze", "a"), ("pierwsze", "b"), ("drugie", "c")]


def test_znaki_powrotu_karetki_sa_obcinane():
    events = feed_all(["id: a\r", "data: {}\r", "\r"])
    assert events[0].id == "a"


# ==================================================================== parser
ENTRY = {
    "timestamp": "2026-09-27T08:15:30.338Z",
    "domain": "r1.googlevideo.com",
    "root": "googlevideo.com",
    "encrypted": True,
    "protocol": "DNS-over-HTTPS",
    "clientIp": "2a01:e0a::1",
    "client": "apple-profile",
    "device": {"id": "8TD1G", "name": "iPad-Kuby", "model": "iPad"},
    "status": "default",
}


def test_parser_wyciaga_czas_domene_i_urzadzenie():
    event = parse_log_entry(json.dumps(ENTRY))
    assert event is not None
    assert event.domain == "r1.googlevideo.com"
    assert event.ts == datetime(2026, 9, 27, 8, 15, 30, 338000, tzinfo=UTC)
    # Nazwa jest glownym tropem, ID zapasowym.
    assert event.device_id == "iPad-Kuby"
    assert event.device_alt == "8TD1G"


def test_parser_uzywa_id_gdy_brak_nazwy():
    entry = ENTRY | {"device": {"id": "8TD1G", "model": "iPad"}}
    event = parse_log_entry(json.dumps(entry))
    assert event.device_id == "8TD1G"
    assert event.device_alt is None


def test_parser_oznacza_urzadzenia_nierozpoznane():
    event = parse_log_entry(json.dumps(ENTRY | {"device": {}}))
    assert event.device_id == "__UNIDENTIFIED__"


def test_parser_ignoruje_nieznane_pola():
    """API moze dodac pole i to nie powod, zeby serwis padl."""
    event = parse_log_entry(json.dumps(ENTRY | {"zupelnie_nowe_pole": {"cos": 1}}))
    assert event is not None


@pytest.mark.parametrize(
    "payload",
    [
        "{ to nie jest json",
        "[]",
        '"napis"',
        json.dumps({"domain": "a.pl"}),  # brak timestamp
        json.dumps({"timestamp": "2026-09-27T08:00:00Z"}),  # brak domeny
        json.dumps({"timestamp": "wczoraj", "domain": "a.pl"}),  # zly czas
        json.dumps({"timestamp": "2026-09-27T08:00:00", "domain": "a.pl"}),  # bez strefy
        json.dumps({"timestamp": "2026-09-27T08:00:00Z", "domain": "   "}),  # pusta domena
    ],
)
def test_parser_odrzuca_bezuzyteczne_wpisy_nie_wybuchajac(payload):
    assert parse_log_entry(payload) is None


# ================================================================== strumien
def sse_body(entries: list[tuple[str, dict]]) -> bytes:
    out = [": keep-alive\n\n"]
    for event_id, entry in entries:
        out.append(f"id: {event_id}\ndata: {json.dumps(entry)}\n\n")
    return "".join(out).encode()


class Recorder:
    """Oddaje kolejne przygotowane odpowiedzi i zapamietuje zapytania."""

    def __init__(self, bodies: list[bytes]) -> None:
        self.bodies = bodies
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        index = min(len(self.requests) - 1, len(self.bodies) - 1)
        return httpx.Response(
            200, content=self.bodies[index], headers={"content-type": "text/event-stream"}
        )


def make_source(recorder: Recorder, **kwargs) -> NextDnsSource:
    client = httpx.AsyncClient(transport=httpx.MockTransport(recorder))
    return NextDnsSource(
        cfg=NextDnsConfig(profile_id="abc123"),
        api_key="klucz-testowy",
        client=client,
        sleep=_no_sleep,
        **kwargs,
    )


async def _no_sleep(_seconds: float) -> None:
    return None


async def collect(source: NextDnsSource, count: int) -> list:
    got = []
    async for event in source.events():
        got.append(event)
        if len(got) >= count:
            break
    return got


async def test_strumien_oddaje_zdarzenia_i_naglowek_uwierzytelnienia():
    rec = Recorder([sse_body([("e1", ENTRY), ("e2", ENTRY | {"domain": "ecsv3.roblox.com"})])])
    src = make_source(rec)
    got = await collect(src, 2)
    await src.aclose()

    assert [e.domain for e in got] == ["r1.googlevideo.com", "ecsv3.roblox.com"]
    assert rec.requests[0].headers["x-api-key"] == "klucz-testowy"
    assert rec.requests[0].url.path == "/profiles/abc123/logs/stream"
    assert "id" not in rec.requests[0].url.params


async def test_kursor_jedzie_za_ostatnim_zdarzeniem():
    rec = Recorder([sse_body([("e1", ENTRY), ("e2", ENTRY)])])
    src = make_source(rec)
    got = await collect(src, 2)
    await src.aclose()
    assert got[-1].cursor == "e2"
    assert src.cursor == "e2"


async def test_zerwany_strumien_wznawia_sie_od_ostatniego_id():
    """Sedno odpornosci na restart: nie gubimy i nie dublujemy zdarzen."""
    rec = Recorder(
        [
            sse_body([("e1", ENTRY)]),  # pierwsze polaczenie: jedno zdarzenie i koniec
            sse_body([("e2", ENTRY | {"domain": "api.minecraft.net"})]),
        ]
    )
    src = make_source(rec)
    got = await collect(src, 2)
    await src.aclose()

    assert [e.domain for e in got] == ["r1.googlevideo.com", "api.minecraft.net"]
    assert len(rec.requests) >= 2
    # Drugie zapytanie MUSI podac id, inaczej dostalibysmy te same wpisy od nowa.
    assert rec.requests[1].url.params["id"] == "e1"


async def test_kursor_z_poprzedniego_uruchomienia_jest_uzyty_od_razu():
    rec = Recorder([sse_body([("e9", ENTRY)])])
    src = make_source(rec, cursor="zapisane-wczoraj")
    await collect(src, 1)
    await src.aclose()
    assert rec.requests[0].url.params["id"] == "zapisane-wczoraj"


async def test_blad_http_nie_przerywa_strumienia_tylko_go_ponawia():
    """401 nie naprawi sie sam, ale zamilkniecie byloby gorsze: czujka w silniku
    zglosi cisze, a zrodlo ma probowac dalej."""
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] <= 2:
            return httpx.Response(401, json={"errors": [{"code": "unauthorized"}]})
        return httpx.Response(
            200, content=sse_body([("e1", ENTRY)]), headers={"content-type": "text/event-stream"}
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    src = NextDnsSource(
        cfg=NextDnsConfig(profile_id="abc123"),
        api_key="zly-klucz",
        client=client,
        sleep=_no_sleep,
    )
    got = await collect(src, 1)
    await src.aclose()
    assert len(got) == 1
    assert calls["n"] == 3


async def test_backoff_rosnie_i_ma_sufit():
    waits: list[float] = []

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        if len(waits) < 8:
            return httpx.Response(500)
        return httpx.Response(
            200, content=sse_body([("e1", ENTRY)]), headers={"content-type": "text/event-stream"}
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    src = NextDnsSource(
        cfg=NextDnsConfig(profile_id="abc", backoff_max_seconds=8.0),
        api_key="k",
        client=client,
        sleep=record_sleep,
    )
    await collect(src, 1)
    await src.aclose()

    assert waits[:5] == [1.0, 2.0, 4.0, 8.0, 8.0]
    assert max(waits) == 8.0


async def test_parametr_raw_jest_przekazywany():
    rec = Recorder([sse_body([("e1", ENTRY)])])
    client = httpx.AsyncClient(transport=httpx.MockTransport(rec))
    src = NextDnsSource(
        cfg=NextDnsConfig(profile_id="abc", raw=True),
        api_key="k",
        client=client,
        sleep=_no_sleep,
        device_filter="8TD1G",
    )
    await collect(src, 1)
    await src.aclose()
    assert rec.requests[0].url.params["raw"] == "true"
    assert rec.requests[0].url.params["device"] == "8TD1G"


async def test_429_czeka_dluzej_zamiast_lomotac_co_sekunde():
    """Zmierzone 2026-10-02: po zamknieciu strumienia NextDNS przez kilkadziesiat
    sekund odpowiada 429 bez Retry-After. Ponawianie co 1-2-4 s tylko to
    przedluzalo i sypalo bledami do logu."""
    waits: list[float] = []

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    def handler(request: httpx.Request) -> httpx.Response:
        if len(waits) < 2:
            return httpx.Response(429)
        return httpx.Response(
            200, content=sse_body([("e1", ENTRY)]), headers={"content-type": "text/event-stream"}
        )

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    src = NextDnsSource(
        cfg=NextDnsConfig(profile_id="abc", rate_limit_wait_seconds=20.0, backoff_max_seconds=60.0),
        api_key="k",
        client=client,
        sleep=record_sleep,
    )
    events = await collect(src, 1)
    await src.aclose()

    assert waits[:2] == [20.0, 40.0]
    assert len(events) == 1


# ========================================================= kilka profili NextDNS
async def test_kilka_profili_laczy_strumienie_z_osobnymi_kursorami():
    from kidwatch.sources.nextdns import MultiNextDnsSource  # noqa: PLC0415

    def handler(request: httpx.Request) -> httpx.Response:
        profile = request.url.path.split("/")[2]
        body = sse_body([(f"{profile}-1", ENTRY | {"domain": f"{profile}.example"})])
        return httpx.Response(200, content=body, headers={"content-type": "text/event-stream"})

    async def yielding_sleep(_seconds: float) -> None:
        # Oddaje petle — inaczej pierwszy strumien krecilby sie bez przerwy.
        await asyncio.sleep(0)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    sources = [
        NextDnsSource(cfg=NextDnsConfig(profile_id="glowny"), api_key="k", client=client,
                      sleep=yielding_sleep, profile_id=p, cursor_key=f"nextdns:{p}")
        for p in ("glowny", "zosia1")
    ]
    multi = MultiNextDnsSource(sources)
    got: dict[str, object] = {}
    async with contextlib.aclosing(multi.events()) as stream:
        async for event in stream:
            got[event.domain] = event
            if len(got) == 2:
                break
    assert got["glowny.example"].cursor_key == "nextdns:glowny"
    assert got["zosia1.example"].cursor_key == "nextdns:zosia1"
    assert got["zosia1.example"].cursor == "zosia1-1"
    await client.aclose()


async def test_blad_jednego_strumienia_konczy_cale_zrodlo():
    """source_loop otworzy je ponownie — ale nie moze tkwic w polowie slepe."""
    from kidwatch.sources.nextdns import MultiNextDnsSource  # noqa: PLC0415

    class Broken:
        profile_id = "zly"

        async def events(self):
            raise ValueError("nieznany format")
            yield  # pragma: no cover

    class Silent:
        profile_id = "cichy"

        async def events(self):
            await asyncio.sleep(3600)
            yield  # pragma: no cover

    with pytest.raises(ValueError, match="nieznany format"):
        async for _ in MultiNextDnsSource([Silent(), Broken()]).events():
            pass


async def test_bramka_rozklada_otwarcia_i_429_wstrzymuje_wszystkich():
    from kidwatch.sources.nextdns import ConnectGate  # noqa: PLC0415

    now = {"t": 100.0}
    slept: list[float] = []

    async def sleep(s: float) -> None:
        slept.append(s)
        now["t"] += s

    gate = ConnectGate(5.0, clock=lambda: now["t"], sleep=sleep)
    await gate.wait()
    await gate.wait()  # drugi profil zaraz po pierwszym — czeka 5 s
    assert slept == [5.0]
    gate.hold(20.0)  # 429 na jednym strumieniu
    await gate.wait()
    assert slept == [5.0, 20.0]


async def test_429_z_bramka_czeka_w_bramce_nie_w_strumieniu():
    from kidwatch.sources.nextdns import ConnectGate  # noqa: PLC0415

    holds: list[float] = []

    class Gate(ConnectGate):
        def hold(self, seconds):
            holds.append(seconds)

    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(429)
        return httpx.Response(
            200, content=sse_body([("e1", ENTRY)]), headers={"content-type": "text/event-stream"}
        )

    waits: list[float] = []

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    src = NextDnsSource(
        cfg=NextDnsConfig(profile_id="abc", rate_limit_wait_seconds=20.0),
        api_key="k",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=record_sleep,
        gate=Gate(0.0),
    )
    await collect(src, 1)
    await src.aclose()
    assert holds == [20.0]
    assert 20.0 not in waits


def test_kursor_profilu_glownego_czyta_stary_klucz():
    from kidwatch.__main__ import nextdns_cursor  # noqa: PLC0415
    from kidwatch.store import Store  # noqa: PLC0415

    store = Store(":memory:")
    store.set_cursor("nextdns", "stary")
    assert nextdns_cursor(store, "glowny", "glowny") == "stary"
    assert nextdns_cursor(store, "zosia1", "glowny") is None
    store.set_cursor("nextdns:glowny", "nowy")
    assert nextdns_cursor(store, "glowny", "glowny") == "nowy"
