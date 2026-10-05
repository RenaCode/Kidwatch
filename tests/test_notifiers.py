"""Testy kanalow powiadomien: tresc zapytania, ponawianie i izolacja bledow."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from kidwatch.config import HomeAssistantConfig, NtfyConfig
from kidwatch.models import Notification, NotifyKind
from kidwatch.notifiers.base import Dispatcher, with_retry
from kidwatch.notifiers.homeassistant import HomeAssistantNotifier
from kidwatch.notifiers.ntfy import NtfyNotifier

TS = datetime(2026, 9, 27, 10, 0, tzinfo=UTC)


def note(**over) -> Notification:
    base = {
        "kind": NotifyKind.SESSION_START,
        "title": "iPad Kuby aktywny",
        "text": "10:00 — YouTube",
        "dedup_key": "start:1",
        "ts": TS,
        "device": "iPad Kuby",
        "app": "YouTube",
        "priority": 4,
        "tags": ("iphone", "ipad"),
    }
    base.update(over)
    return Notification(**base)


async def _no_sleep(_s: float) -> None:
    return None


# ======================================================================== ntfy
async def test_ntfy_wysyla_poprawny_json_na_korzen_serwera():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200, json={"id": "x"})

    n = NtfyNotifier(
        NtfyConfig(topic="temat-testowy", server="https://ntfy.example"),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    assert await n.send(note()) is True
    await n.aclose()

    import json  # noqa: PLC0415

    body = json.loads(seen[0].content)
    assert seen[0].url == httpx.URL("https://ntfy.example/")
    assert body["topic"] == "temat-testowy"
    assert body["title"] == "iPad Kuby aktywny"
    assert body["message"] == "10:00 — YouTube"
    assert body["priority"] == 4
    assert body["tags"] == ["iphone", "ipad"]


async def test_ntfy_dodaje_token_gdy_jest():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200)

    n = NtfyNotifier(
        NtfyConfig(topic="t"),
        token="tk_sekret",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await n.send(note())
    await n.aclose()
    assert seen[0].headers["authorization"] == "Bearer tk_sekret"


async def test_ntfy_bez_tokenu_nie_dodaje_naglowka():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200)

    n = NtfyNotifier(
        NtfyConfig(topic="t"), client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    await n.send(note())
    await n.aclose()
    assert "authorization" not in seen[0].headers


async def test_ntfy_przenosi_polskie_znaki():
    """Regresja: postac z naglowkami HTTP wywalala sie tu na UnicodeEncodeError,
    bo httpx koduje naglowki kodekiem ascii. Imiona dzieci to wlasnie te napisy."""
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200)

    n = NtfyNotifier(
        NtfyConfig(topic="t"), client=httpx.AsyncClient(transport=httpx.MockTransport(handler))
    )
    polish = note(title="iPad Michała aktywny", text="Zażółć gęślą jaźń — Roblox")
    assert await n.send(polish) is True
    await n.aclose()

    import json  # noqa: PLC0415

    body = json.loads(seen[0].content.decode("utf-8"))
    assert body["title"] == "iPad Michała aktywny"
    assert "gęślą" in body["message"]


def test_naglowki_http_naprawde_nie_przenosza_polskich_znakow():
    """Dowod na to, ze odejscie od pierwotnego planu bylo konieczne, a nie
    kwestia gustu."""
    with pytest.raises(UnicodeEncodeError):
        httpx.Request("POST", "http://x/t", headers={"Title": "Michał"})


# ================================================================ ponawianie
async def test_ponawia_trzy_razy_i_w_koncu_sie_udaje():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200 if calls["n"] == 3 else 503)

    n = NtfyNotifier(
        NtfyConfig(topic="t"),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=_no_sleep,
    )
    assert await n.send(note()) is True
    assert calls["n"] == 3
    await n.aclose()


async def test_po_trzech_nieudanych_probach_zwraca_false_bez_wyjatku():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(503)

    n = NtfyNotifier(
        NtfyConfig(topic="t"),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=_no_sleep,
    )
    assert await n.send(note()) is False
    assert calls["n"] == 3
    await n.aclose()


async def test_blad_sieci_tez_jest_ponawiany():
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        if calls["n"] < 3:
            raise httpx.ConnectError("siec padla")
        return httpx.Response(200)

    n = NtfyNotifier(
        NtfyConfig(topic="t"),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=_no_sleep,
    )
    assert await n.send(note()) is True
    assert calls["n"] == 3
    await n.aclose()


@pytest.mark.parametrize("status", [400, 401, 403, 404])
async def test_bledy_klienta_nie_sa_ponawiane(status):
    """Zly token albo zla nazwa tematu nie naprawia sie przez powtorzenie —
    ponawianie tylko zjadaloby limity serwera."""
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(status)

    n = NtfyNotifier(
        NtfyConfig(topic="t"),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=_no_sleep,
    )
    assert await n.send(note()) is False
    assert calls["n"] == 1
    await n.aclose()


@pytest.mark.parametrize("status", [408, 429, 500, 502, 503])
async def test_bledy_przejsciowe_sa_ponawiane(status):
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(status)

    n = NtfyNotifier(
        NtfyConfig(topic="t"),
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        sleep=_no_sleep,
    )
    await n.send(note())
    assert calls["n"] == 3
    await n.aclose()


async def test_odstep_miedzy_probami_rosnie():
    waits: list[float] = []

    async def record(seconds: float) -> None:
        waits.append(seconds)

    ok = await with_retry(
        lambda: _always_503(), what="test", sleep=record
    )
    assert ok is False
    assert waits == [1.0, 2.0]


async def _always_503() -> httpx.Response:
    return httpx.Response(503, request=httpx.Request("POST", "http://x"))


# =========================================================== home assistant
async def test_home_assistant_wysyla_pola_strukturalne():
    seen: list[httpx.Request] = []

    def handler(request):
        seen.append(request)
        return httpx.Response(200)

    n = HomeAssistantNotifier(
        HomeAssistantConfig(enabled=True, base_url="http://ha.local:8123"),
        webhook_id="abcdef123",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    assert await n.send(note()) is True
    await n.aclose()

    import json  # noqa: PLC0415

    assert seen[0].url.path == "/api/webhook/abcdef123"
    body = json.loads(seen[0].content)
    # Automatyzacja w HA ma warunkowac na polach, nie parsowac tekst.
    assert body["device"] == "iPad Kuby"
    assert body["event"] == "session_start"
    assert body["app"] == "YouTube"
    assert body["text"] == "10:00 — YouTube"


# ================================================================ dispatcher
class FailingNotifier:
    name = "psuje-sie"

    async def send(self, note):
        raise RuntimeError("cos peklo w kanale")

    async def aclose(self):
        raise RuntimeError("i przy zamykaniu tez")


class OkNotifier:
    name = "dziala"

    def __init__(self):
        self.sent = []

    async def send(self, note):
        self.sent.append(note)
        return True

    async def aclose(self):
        pass


async def test_wysypany_kanal_nie_blokuje_pozostalych():
    """Kluczowe: blad powiadomienia nie moze zatrzymac przetwarzania."""
    good = OkNotifier()
    d = Dispatcher([FailingNotifier(), good])
    results = await d.send(note())
    assert results == {"psuje-sie": False, "dziala": True}
    assert len(good.sent) == 1


async def test_zamykanie_przezywa_wysypany_kanal():
    good = OkNotifier()
    d = Dispatcher([FailingNotifier(), good])
    await d.aclose()  # nie moze podniesc wyjatku


async def test_send_all_wysyla_wszystko():
    good = OkNotifier()
    d = Dispatcher([good])
    await d.send_all([note(dedup_key="a"), note(dedup_key="b")])
    assert len(good.sent) == 2


# ================================================================== bramka
async def test_bramka_wysyla_temat_tresc_i_zrodlo_z_kluczem():
    from kidwatch.config import BramkaConfig
    from kidwatch.notifiers.bramka import BramkaNotifier

    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["key"] = request.headers["X-Api-Key"]
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"ok": True, "kanal": "email"})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    n = BramkaNotifier(BramkaConfig(url="http://bramka.test/"), key="k1", client=client)
    note = Notification(
        kind=NotifyKind.SESSION_START, title="iPad Michała aktywny", text="15:12 — Roblox",
        dedup_key="x", ts=datetime.now(UTC),
    )
    assert await n.send(note) is True
    assert seen["url"] == "http://bramka.test/v1/wyslij"
    assert seen["key"] == "k1"
    assert seen["body"] == {"temat": "iPad Michała aktywny", "tresc": "15:12 — Roblox",
                            "zrodlo": "kidwatch", "priorytet": 3, "rodzaj": "start sesji",
                            "format": "markdown-lite"}
    await client.aclose()


async def test_bramka_czujka_idzie_z_kategoria_a_zwykle_bez():
    """Trasy w bramce: alarm techniczny (WATCHDOG) to "kidwatch:czujka", ktorej
    rodzina z trasa "kidwatch" nie dostaje. Zwykle powiadomienia bez kategorii."""
    from kidwatch.config import BramkaConfig
    from kidwatch.notifiers.bramka import BramkaNotifier

    n = BramkaNotifier(BramkaConfig(url="http://bramka.test/"), key="k1",
                       client=httpx.AsyncClient())
    ts = datetime.now(UTC)
    assert n.payload(Notification(kind=NotifyKind.WATCHDOG, title="Cisza DNS", text="x",
                                  dedup_key="w", ts=ts))["kategoria"] == "czujka"
    for kind in set(NotifyKind) - {NotifyKind.WATCHDOG}:
        body = n.payload(Notification(kind=kind, title="t", text="x", dedup_key="d", ts=ts))
        assert "kategoria" not in body, kind
    await n.aclose()


def test_bramka_kazdy_rodzaj_ma_podpis_w_mailu():
    from kidwatch.notifiers.bramka import RODZAJE

    assert set(RODZAJE) == set(NotifyKind)


def test_bramka_bez_klucza_w_srodowisku_mowi_ktora_zmienna(monkeypatch):
    from kidwatch.config import BramkaConfig, MissingSecretError

    monkeypatch.delenv("BRAMKA_KLUCZ", raising=False)
    monkeypatch.delenv("BRAMKA_KLUCZ_ADMIN", raising=False)
    with pytest.raises(MissingSecretError, match="BRAMKA_KLUCZ"):
        BramkaConfig().key()
    with pytest.raises(MissingSecretError, match="BRAMKA_KLUCZ"):
        BramkaConfig().admin_key()


def test_bramka_wysylka_NIGDY_nie_bierze_klucza_admina(monkeypatch):
    from kidwatch.config import BramkaConfig

    monkeypatch.setenv("BRAMKA_KLUCZ", "wysylkowy")
    monkeypatch.setenv("BRAMKA_KLUCZ_ADMIN", "admin")
    assert BramkaConfig().key() == "wysylkowy"
    assert BramkaConfig().admin_key() == ("admin", False)
    monkeypatch.delenv("BRAMKA_KLUCZ_ADMIN")
    assert BramkaConfig().admin_key() == ("wysylkowy", True)
