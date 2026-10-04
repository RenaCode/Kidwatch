"""Testy zrodla AdGuard Home: parser, deduplikacja i limit historii."""

from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from kidwatch.config import AdGuardConfig
from kidwatch.sources.adguard import AdGuardSource, fingerprint, parse_item
from kidwatch.store import Store

NOW = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)


def item(minutes_ago: float = 0, domain: str = "www.youtube.com", **over) -> dict:
    ts = NOW - timedelta(minutes=minutes_ago)
    base = {
        "time": ts.isoformat().replace("+00:00", "Z"),
        "question": {"name": domain, "type": "A", "class": "IN"},
        "client": "192.168.1.55",
        "client_id": "ipad-kuby",
        "reason": "NotFilteredNotFound",
        "status": "NOERROR",
        "elapsedMs": "12.3",
        "cached": False,
    }
    base.update(over)
    return base


# ==================================================================== parser
def test_parser_wyciaga_czas_domene_i_klienta():
    parsed = parse_item(item())
    assert parsed is not None
    event, fp = parsed
    assert event.domain == "www.youtube.com"
    assert event.ts == NOW
    # ClientID jest stabilny, IP moze sie zmienic przy odnowieniu DHCP.
    assert event.device_id == "ipad-kuby"
    assert event.device_alt == "192.168.1.55"
    assert fp == fingerprint(item()["time"], "192.168.1.55", "www.youtube.com")


def test_parser_spada_na_ip_gdy_brak_client_id():
    event, _ = parse_item(item(client_id=""))
    assert event.device_id == "192.168.1.55"
    assert event.device_alt is None


@pytest.mark.parametrize(
    "raw",
    [
        {},
        {"time": "2026-09-27T10:00:00Z"},                         # brak question
        {"question": {"name": "a.pl"}},                            # brak time
        {"time": "kiedys", "question": {"name": "a.pl"}},           # zly czas
        {"time": "2026-09-27T10:00:00", "question": {"name": "a.pl"}},  # bez strefy
        {"time": "2026-09-27T10:00:00Z", "question": "to nie slownik"},
        {"time": "2026-09-27T10:00:00Z", "question": {"name": ""}},
    ],
)
def test_parser_odrzuca_bezuzyteczne_wpisy(raw):
    assert parse_item(raw) is None


def test_odcisk_nie_zalezy_od_wielkosci_liter_w_domenie():
    a = fingerprint("t", "1.2.3.4", "WWW.Youtube.COM")
    b = fingerprint("t", "1.2.3.4", "www.youtube.com")
    assert a == b


# ============================================================ odpytywanie
def make_source(handler, store: Store, **over) -> AdGuardSource:
    kwargs = {"base_url": "http://ag.local:3000", "username": "admin", "max_backfill_minutes": 5}
    kwargs.update(over)
    return AdGuardSource(
        cfg=AdGuardConfig(**kwargs),
        password="sekret",
        store=store,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        now=lambda: NOW,
    )


async def test_basic_auth_i_adres(store):
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"oldest": "", "data": [item()]})

    src = make_source(handler, store)
    await src.poll_once()
    await src.aclose()

    expected = base64.b64encode(b"admin:sekret").decode()
    assert seen[0].headers["authorization"] == f"Basic {expected}"
    assert seen[0].url.path == "/control/querylog"
    assert seen[0].url.params["limit"] == "500"


async def test_drugie_odpytanie_nie_powtarza_tych_samych_wpisow(store):
    """AdGuard zawsze oddaje najnowsza strone, wiec bez dedupu kazdy przebieg
    zglaszalby te same zapytania od nowa."""
    payload = {"oldest": "", "data": [item(1), item(2, domain="ecsv3.roblox.com")]}
    src = make_source(handler=lambda r: httpx.Response(200, json=payload), store=store)

    first = await src.poll_once()
    assert len(first) == 2

    second = await src.poll_once()
    assert second == []
    await src.aclose()


async def test_nowy_wpis_w_znanej_stronie_jest_wychwycony(store):
    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        data = [item(1)]
        if state["n"] > 1:
            data.insert(0, item(0, domain="api.minecraft.net"))
        return httpx.Response(200, json={"oldest": "", "data": data})

    src = make_source(handler, store)
    assert len(await src.poll_once()) == 1
    second = await src.poll_once()
    await src.aclose()
    assert [e.domain for e in second] == ["api.minecraft.net"]


async def test_pierwsze_odpytanie_odcina_stara_historie(store):
    """Po restarcie querylog ma cala historie. Bez progu dostalbys lawine pushy
    o aktywnosci, ktora dawno minela."""
    payload = {
        "oldest": "",
        "data": [
            item(1),
            item(3, domain="a.pl"),
            item(30, domain="stare.pl"),
            item(600, domain="bardzo-stare.pl"),
        ],
    }
    src = make_source(lambda r: httpx.Response(200, json=payload), store, max_backfill_minutes=5)
    fresh = await src.poll_once()
    await src.aclose()
    domains = [e.domain for e in fresh]
    assert "stare.pl" not in domains and "bardzo-stare.pl" not in domains
    assert len(fresh) == 2


async def test_kolejne_odpytania_nie_odcinaja_juz_niczego(store):
    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(200, json={"oldest": "", "data": [item(1)]})
        # Wpis sprzed 30 minut, ale POJAWIL sie dopiero teraz — nie odcinamy go.
        return httpx.Response(200, json={"oldest": "", "data": [item(30, domain="spozniony.pl")]})

    src = make_source(handler, store, max_backfill_minutes=5)
    await src.poll_once()
    second = await src.poll_once()
    await src.aclose()
    assert [e.domain for e in second] == ["spozniony.pl"]


async def test_limit_backfillu_da_sie_wylaczyc(store):
    payload = {"oldest": "", "data": [item(600, domain="bardzo-stare.pl")]}
    src = make_source(lambda r: httpx.Response(200, json=payload), store, max_backfill_minutes=0)
    assert len(await src.poll_once()) == 1
    await src.aclose()


async def test_wyniki_sa_w_kolejnosci_rosnacej(store):
    """AdGuard oddaje najnowsze najpierw; silnik oczekuje porzadku chronologicznego."""
    payload = {
        "oldest": "",
        "data": [
            item(0, domain="trzeci.pl"),
            item(1, domain="drugi.pl"),
            item(2, domain="pierwszy.pl"),
        ],
    }
    src = make_source(lambda r: httpx.Response(200, json=payload), store, max_backfill_minutes=0)
    fresh = await src.poll_once()
    await src.aclose()
    assert [e.domain for e in fresh] == ["pierwszy.pl", "drugi.pl", "trzeci.pl"]
    assert fresh == sorted(fresh, key=lambda e: e.ts)


async def test_odpowiedz_bez_tablicy_data_nie_wybucha(store):
    src = make_source(lambda r: httpx.Response(200, json={"blad": "cos nie tak"}), store)
    assert await src.poll_once() == []
    await src.aclose()


async def test_blad_http_jest_zglaszany_przez_poll_once(store):
    src = make_source(lambda r: httpx.Response(403, json={}), store)
    with pytest.raises(httpx.HTTPStatusError):
        await src.poll_once()
    await src.aclose()


async def test_petla_events_przezywa_blad_i_ponawia(store):
    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        if state["n"] <= 2:
            return httpx.Response(500)
        return httpx.Response(200, json={"oldest": "", "data": [item(0)]})

    waits: list[float] = []

    async def record_sleep(seconds: float) -> None:
        waits.append(seconds)

    src = AdGuardSource(
        cfg=AdGuardConfig(
            base_url="http://ag.local:3000", username="admin", max_backfill_minutes=0
        ),
        password="x",
        store=store,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=record_sleep,
        now=lambda: NOW,
    )
    got = []
    async for event in src.events():
        got.append(event)
        break
    await src.aclose()

    assert len(got) == 1
    assert waits[:2] == [1.0, 2.0]


async def test_petla_events_przezywa_odpowiedz_ktora_nie_jest_JSON_em(store):
    """Regresja: strona bledu proxy z kodem 200 (HTML zamiast JSON-a) wywalala
    ValueError z generatora — konczyl sie strumien, a z nim caly proces."""
    state = {"n": 0}

    def handler(request):
        state["n"] += 1
        if state["n"] == 1:
            return httpx.Response(200, text="<html>502 Bad Gateway</html>")
        return httpx.Response(200, json={"oldest": "", "data": [item(0)]})

    async def no_sleep(_seconds: float) -> None:
        return None

    src = AdGuardSource(
        cfg=AdGuardConfig(
            base_url="http://ag.local:3000", username="admin", max_backfill_minutes=0
        ),
        password="x",
        store=store,
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=no_sleep,
        now=lambda: NOW,
    )
    got = []
    async for event in src.events():
        got.append(event)
        break
    await src.aclose()
    assert len(got) == 1
