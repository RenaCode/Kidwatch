"""Czas gry: sterowanie blokadami NextDNS z panelu. Bez prawdziwego NextDNS —
API udaje httpx.MockTransport z profilem trzymanym w slowniku."""

from __future__ import annotations

import http.client
import json
from datetime import UTC, datetime, time

import httpx
import pytest
from pydantic import ValidationError

from conftest import local, make_config, panel_login
from kidwatch.config import (
    DeviceConfig,
    GameTimeConfig,
    NextDnsConfig,
    PanelConfig,
    SourceConfig,
    StoreConfig,
)
from kidwatch.gametime import (
    GameRequests,
    GameTime,
    ParentalControlClient,
    TooManyRequests,
    game_loop,
    observed_state,
)
from kidwatch.models import NotifyKind
from kidwatch.panel import start_panel
from kidwatch.panel_auth import PanelAuth
from kidwatch.store import Store

SERVICES = ["youtube", "roblox"]
CATEGORIES = ["gaming"]


# ================================================================ atrapa NextDNS
class FakeNextDns:
    """Profile {id: {"services": [...], "categories": [...]}} i semantyka
    pozycji z dokumentacji: PATCH na pozycje, POST dopisuje do tablicy."""

    def __init__(self, profiles: dict[str, dict] | None = None) -> None:
        self.profiles = profiles or {}
        self.calls: list[tuple[str, str, dict | None]] = []
        self.fail_writes = 0
        self.unknown = {"nie-ma-takiej"}

    def profile(self, pid: str) -> dict:
        return self.profiles.setdefault(pid, {"services": [], "categories": []})

    def __call__(self, request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        self.calls.append((request.method, request.url.path, body))
        assert request.headers["x-api-key"] == "klucz"
        parts = request.url.path.strip("/").split("/")
        assert parts[0] == "profiles" and parts[2] == "parentalControl"
        prof = self.profile(parts[1])
        if request.method == "GET":
            return httpx.Response(200, json={"data": prof})
        if self.fail_writes:
            self.fail_writes -= 1
            return httpx.Response(503, json={"errors": [{"code": "unavailable"}]})
        kind = parts[3]
        if request.method == "POST":
            if body["id"] in self.unknown:
                return httpx.Response(
                    400, json={"errors": [{"code": "invalid", "detail": "unknown id",
                                           "source": {"parameter": "id"}}]}
                )
            prof[kind].append({"recreation": False, **body})
            return httpx.Response(200, json={"data": body})
        if request.method == "PATCH":
            item = next(i for i in prof[kind] if i["id"] == parts[4])
            item.update(body)
            return httpx.Response(204)
        return httpx.Response(405)

    def active(self, pid: str) -> dict[str, bool]:
        prof = self.profile(pid)
        return {i["id"]: i["active"] for i in prof["services"] + prof["categories"]}


class Sent:
    def __init__(self) -> None:
        self.notes = []

    async def send_all(self, notes):
        self.notes.extend(notes)


def two_profile_config(**game):
    cfg = make_config(game_time=GameTimeConfig(
        enabled=True, services=SERVICES, categories=CATEGORIES, **game
    ))
    cfg.devices[1] = DeviceConfig(
        display_name="iPad Zosi", child="Zosia", source_ids=["ipad-zosi"],
        nextdns_profile="zosia1",
    )
    return cfg


@pytest.fixture
def rig(tmp_path):
    cfg = two_profile_config()
    store = Store(":memory:")
    fake = FakeNextDns()
    clock = {"t": datetime(2026, 10, 2, 12, 0, tzinfo=UTC).timestamp()}
    requests = GameRequests(tmp_path / "panel-auth.db", clock=lambda: clock["t"])
    client = ParentalControlClient(
        "https://api.nextdns.io", "klucz",
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake)),
    )
    sent = Sent()
    game = GameTime(cfg, store, requests, client, sent)
    yield game, fake, requests, sent, clock
    store.close()


def at(hh, mm=0):
    return local(2026, 10, 2, hh, mm).astimezone(UTC)


# ================================================================== stan widziany
def test_stan_z_pozycji_profilu():
    data = {"services": [{"id": "youtube", "active": True}, {"id": "roblox", "active": True}],
            "categories": [{"id": "gaming", "active": True}]}
    assert observed_state(data, SERVICES, CATEGORIES) == "blocked"
    data["services"][1]["active"] = False
    assert observed_state(data, SERVICES, CATEGORIES) == "mixed"
    # Brak pozycji na liscie profilu = nieblokowana.
    assert observed_state({}, SERVICES, CATEGORIES) == "allowed"
    # Zablokowane, ale wolne w oknie rekreacji NextDNS — to nie jest blokada.
    rec = {"services": [{"id": s, "active": True, "recreation": True} for s in SERVICES],
           "categories": [{"id": "gaming", "active": True}]}
    assert observed_state(rec, SERVICES, CATEGORIES) == "mixed"


# ===================================================================== akcje
async def test_blokada_z_panelu_dopisuje_pozycje_i_wysyla_push(rig):
    game, fake, requests, sent, _ = rig
    rid = requests.submit("Kuba", "block", None, "rodzic")
    await game.step(at(15))

    assert fake.active("test") == {"youtube": True, "roblox": True, "gaming": True}
    # Profil Zosi nietkniety — kazde dziecko ma wlasny.
    assert fake.active("zosia1") == {}
    st = game.state("test")
    assert st["mode"] == "blocked" and st["observed"] == "blocked" and not st["dirty"]
    assert requests.latest("Kuba") | {"created_at": None} == {
        "id": rid, "action": "block", "pending": False, "ok": True, "error": None,
        "created_at": None,
    }
    [note] = sent.notes
    assert note.kind is NotifyKind.GAME
    assert note.title == "\U0001F3AE Czas gry dla Kuba: zablokowany"
    assert note.device == "iPad Kuby"
    assert "rodzic" in note.text
    # Zapis przez endpointy pozycji, nie PATCH calego obiektu z tablicami.
    writes = [(m, p) for m, p, _ in fake.calls if m != "GET"]
    assert ("POST", "/profiles/test/parentalControl/services") in writes
    assert ("POST", "/profiles/test/parentalControl/categories") in writes


async def test_odblokowanie_patchuje_istniejace_pozycje_i_nie_rusza_innych(rig):
    game, fake, requests, sent, _ = rig
    fake.profiles["test"] = {
        "services": [{"id": "youtube", "active": True, "recreation": True},
                     {"id": "tiktok", "active": True, "recreation": False}],
        "categories": [{"id": "gaming", "active": True}, {"id": "porn", "active": True}],
    }
    requests.submit("Kuba", "allow", None, "rodzic")
    await game.step(at(15))
    assert fake.active("test") == {
        "youtube": False, "tiktok": True, "gaming": False, "porn": True,
    }
    # roblox nie byl na liscie — przy odblokowaniu nie trzeba go dopisywac.
    assert not any(m == "POST" for m, _, _ in fake.calls)
    assert fake.profiles["test"]["services"][0]["recreation"] is False
    assert sent.notes[0].title.endswith("odblokowany")


async def test_bonus_przedluza_ma_sufit_i_po_czasie_wraca_blokada(rig):
    game, fake, requests, sent, clock = rig
    requests.submit("Kuba", "block", None, "rodzic")
    await game.step(at(18, 0))
    requests.submit("Kuba", "bonus", 30, "rodzic")
    await game.step(at(18, 10))
    st = game.state("test")
    assert st["mode"] == "bonus" and st["observed"] == "allowed"
    assert sent.notes[-1].title == "\U0001F3AE Czas gry dla Kuba: +30 min (do 18:40)"

    # Drugie "+30" liczy sie od konca biezacego bonusu, nie od teraz.
    requests.submit("Kuba", "bonus", 30, "rodzic")
    await game.step(at(18, 20))
    assert sent.notes[-1].title.endswith("+30 min (do 19:10)")
    # Sufit max_bonus_minutes (180) od TERAZ.
    for _ in range(4):
        requests.submit("Kuba", "bonus", 60, "rodzic")
    await game.step(at(18, 21))
    assert game.state("test")["bonus_until"] == (at(21, 21)).strftime("%Y-%m-%dT%H:%M:%S.%f%z")

    await game.step(at(21, 20))
    assert game.state("test")["mode"] == "bonus"
    await game.step(at(21, 22))
    assert game.state("test")["mode"] == "blocked"
    assert fake.active("test")["youtube"] is True
    assert sent.notes[-1].title.endswith("koniec bonusu — zablokowany")


async def test_reczna_zmiana_w_NextDNS_jest_widoczna_po_synchronizacji(rig):
    game, fake, requests, sent, _ = rig
    requests.submit("Kuba", "block", None, "rodzic")
    await game.step(at(15, 0))
    for item in fake.profiles["test"]["services"] + fake.profiles["test"]["categories"]:
        item["active"] = False
    # Przed uplywem sync_minutes nic sie nie dzieje...
    await game.step(at(15, 2))
    assert game.state("test")["mode"] == "blocked"
    # ...a potem panel pokazuje to, co jest naprawde.
    await game.step(at(15, 6))
    st = game.state("test")
    assert st["mode"] == "allowed" and st["source"] == "nextdns"
    # Zmiana poza kidwatch nie jest ponownie nadpisywana.
    await game.step(at(15, 12))
    assert fake.active("test")["youtube"] is False


async def test_nieudany_zapis_jest_ponawiany_a_nie_brany_za_reczna_zmiane(rig):
    game, fake, requests, sent, _ = rig
    fake.fail_writes = 1
    requests.submit("Kuba", "block", None, "rodzic")
    await game.step(at(15, 0))
    st = game.state("test")
    assert st["dirty"] and "503" in st["error"]
    assert requests.latest("Kuba")["ok"] is False
    assert "NIE UDALO SIE" in sent.notes[-1].title
    await game.step(at(15, 1))
    st = game.state("test")
    assert st["mode"] == "blocked" and not st["dirty"] and st["error"] is None
    assert fake.active("test")["roblox"] is True


async def test_nieistniejace_id_uslugi_wraca_czytelnym_bledem(rig):
    game, fake, requests, sent, _ = rig
    game.gt = game.gt.model_copy(update={"services": ["youtube", "nie-ma-takiej"]})
    requests.submit("Kuba", "block", None, "rodzic")
    await game.step(at(15))
    assert "unknown id (id)" in game.state("test")["error"]


async def test_przeterminowane_zadanie_nie_jest_wykonywane(rig):
    game, fake, requests, sent, clock = rig
    requests.submit("Kuba", "allow", None, "rodzic")
    clock["t"] += 3600
    await game.step(at(15))
    assert requests.latest("Kuba")["ok"] is False
    assert not any(m != "GET" for m, _, _ in fake.calls)


def test_kolejka_ma_limit_oczekujacych(rig):
    _, _, requests, _, _ = rig
    for _ in range(5):
        requests.submit("Kuba", "block", None, "x")
    with pytest.raises(TooManyRequests):
        requests.submit("Kuba", "block", None, "x")
    requests.submit("Zosia", "block", None, "x")


async def test_harmonogram_blokuje_wieczorem_i_zdejmuje_tylko_swoja_blokade(tmp_path):
    cfg = two_profile_config(block_schedule={"start": time(20, 0), "end": time(7, 0)})
    fake = FakeNextDns()
    store = Store(":memory:")
    requests = GameRequests(tmp_path / "a.db")
    client = ParentalControlClient(
        "https://api.nextdns.io", "klucz",
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake)),
    )
    sent = Sent()
    game = GameTime(cfg, store, requests, client, sent)

    await game.step(at(19, 0))
    assert game.state("test")["mode"] == "allowed"
    await game.step(at(20, 1))
    assert game.state("test")["mode"] == "blocked"
    assert game.state("zosia1")["mode"] == "blocked"
    assert any("harmonogram" in n.title for n in sent.notes)

    # Zosia: rodzic sam zablokowal w nocy — rano blokada zostaje.
    requests.submit("Zosia", "block", None, "rodzic")
    await game.step(at(22, 0))
    morning = local(2026, 10, 3, 7, 1).astimezone(UTC)
    await game.step(morning)
    assert game.state("test")["mode"] == "allowed"
    assert game.state("zosia1")["mode"] == "blocked"
    store.close()


def _schedule_rig(tmp_path, clock):
    cfg = two_profile_config(block_schedule={"start": time(20, 0), "end": time(7, 0)})
    fake = FakeNextDns()
    store = Store(":memory:")
    requests = GameRequests(tmp_path / "a.db", clock=lambda: clock["t"])
    client = ParentalControlClient(
        "https://api.nextdns.io", "klucz",
        client=httpx.AsyncClient(transport=httpx.MockTransport(fake)),
    )
    sent = Sent()
    return GameTime(cfg, store, requests, client, sent), fake, requests, sent, store


async def test_harmonogram_bonus_przy_dozwolonych_grach_nie_blokuje_na_stale(tmp_path):
    # Audyt runda 4, pkt 2: "+30 min" o 15:00 przy dozwolonych grach konczyl
    # sie blokada z source="bonus", ktorej harmonogram rano nie zdejmowal.
    clock = {"t": 0.0}
    game, fake, requests, sent, store = _schedule_rig(tmp_path, clock)
    await game.step(at(12, 0))
    assert game.state("test")["mode"] == "allowed"
    clock["t"] = at(15, 0).timestamp()
    requests.submit("Kuba", "bonus", 30, "rodzic")
    await game.step(at(15, 0))
    assert game.state("test")["mode"] == "bonus"
    await game.step(at(15, 31))
    assert game.state("test")["mode"] == "allowed"
    assert not any(fake.active("test").values())
    assert sent.notes[-1].title.endswith("koniec bonusu — odblokowany")
    # Wieczorem harmonogram blokuje, rano zdejmuje — jak bez bonusu.
    await game.step(at(20, 1))
    assert game.state("test")["mode"] == "blocked"
    await game.step(local(2026, 10, 3, 7, 1).astimezone(UTC))
    assert game.state("test")["mode"] == "allowed"
    await game.step(local(2026, 10, 3, 12, 0).astimezone(UTC))
    assert game.state("test")["mode"] == "allowed"
    store.close()


async def test_harmonogram_bonus_z_rana_konczacy_sie_po_oknie_zostawia_gry_dozwolone(tmp_path):
    clock = {"t": 0.0}
    game, fake, requests, sent, store = _schedule_rig(tmp_path, clock)
    await game.step(at(20, 1))
    assert game.state("test")["mode"] == "blocked"
    morning = local(2026, 10, 3, 6, 45).astimezone(UTC)
    clock["t"] = morning.timestamp()
    requests.submit("Kuba", "bonus", 30, "rodzic")
    await game.step(morning)
    await game.step(local(2026, 10, 3, 7, 1).astimezone(UTC))
    assert game.state("test")["mode"] == "bonus"
    await game.step(local(2026, 10, 3, 7, 16).astimezone(UTC))
    assert game.state("test")["mode"] == "allowed"
    # Bonus konczacy sie W oknie harmonogramu dalej oddaje blokade harmonogramowi.
    evening = local(2026, 10, 3, 21, 0).astimezone(UTC)
    clock["t"] = evening.timestamp()
    requests.submit("Kuba", "bonus", 30, "rodzic")
    await game.step(evening)
    await game.step(local(2026, 10, 3, 21, 31).astimezone(UTC))
    st = game.state("test")
    assert st["mode"] == "blocked" and st["source"] == "schedule"
    store.close()


async def test_koniec_bonusu_przy_bledzie_NextDNS_nie_melduje_blokady(rig):
    # Audyt runda 4, pkt 9: push "zablokowany" mimo nieudanego zapisu.
    game, fake, requests, sent, _ = rig
    requests.submit("Kuba", "block", None, "rodzic")
    await game.step(at(18, 0))
    requests.submit("Kuba", "bonus", 30, "rodzic")
    await game.step(at(18, 10))
    fake.fail_writes = 10
    await game.step(at(18, 41))
    assert "NIE UDALO SIE (koniec bonusu — zablokowany)" in sent.notes[-1].title
    assert "ponowi" in sent.notes[-1].text


async def test_harmonogram_przy_bledzie_NextDNS_nie_melduje_blokady(tmp_path):
    clock = {"t": 0.0}
    game, fake, requests, sent, store = _schedule_rig(tmp_path, clock)
    await game.step(at(19, 0))
    fake.fail_writes = 10
    await game.step(at(20, 1))
    assert any(n.title.endswith("NIE UDALO SIE (zablokowany (harmonogram))")
               for n in sent.notes)
    assert not any(n.title.endswith(": zablokowany (harmonogram)") for n in sent.notes)
    store.close()


async def test_petla_przezywa_blad(rig):
    game, *_ = rig

    async def boom(now):
        raise RuntimeError("awaria")

    game.step = boom
    slept = []

    async def sleep(s):
        slept.append(s)

    await game_loop(game, 3.0, sleep=sleep, max_iterations=2)
    assert slept == [3.0, 3.0]


# ================================================================== konfiguracja
def test_nieznana_kategoria_to_blad_walidacji():
    with pytest.raises(ValidationError, match="nieznane kategorie"):
        GameTimeConfig(enabled=True, categories=["games"])


def test_nieznana_usluga_to_tylko_ostrzezenie():
    gt = GameTimeConfig(enabled=True, services=["youtube", "nowa-usluga"])
    assert gt.unknown_services() == ["nowa-usluga"]


def test_dziecko_z_iPadami_na_roznych_profilach_to_blad():
    with pytest.raises(ValidationError, match="roznych profilach"):
        _config_with_devices([
            DeviceConfig(display_name="A", child="Kuba", source_ids=["a"]),
            DeviceConfig(display_name="B", child="Kuba", source_ids=["b"], nextdns_profile="x1"),
        ])


def _config_with_devices(devices):
    from kidwatch.config import Config  # noqa: PLC0415

    return Config(
        source=SourceConfig(kind="nextdns", nextdns=NextDnsConfig(profile_id="glowny")),
        devices=devices,
    )


def test_lista_profili_glowny_pierwszy_bez_powtorzen():
    cfg = _config_with_devices([
        DeviceConfig(display_name="A", child="Kuba", source_ids=["a"]),
        DeviceConfig(display_name="B", child="Zosia", source_ids=["b"], nextdns_profile="z1"),
        DeviceConfig(display_name="C", child="Zosia", source_ids=["c"], nextdns_profile="z1"),
    ])
    assert cfg.nextdns_profiles == ["glowny", "z1"]
    assert cfg.child_profiles() == {"Kuba": "glowny", "Zosia": "z1"}


def test_zly_format_profilu():
    with pytest.raises(ValidationError, match="nie wyglada na ID profilu"):
        DeviceConfig(display_name="A", child="K", source_ids=["a"], nextdns_profile="ZLE ID")


# ======================================================================== panel
def call(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Content-Type": "application/json", **(headers or {})}
    conn.request(method, path, json.dumps(body) if body is not None else None, h)
    r = conn.getresponse()
    data = json.loads(r.read() or b"null")
    conn.close()
    return r.status, data


def test_panel_przyjmuje_zadanie_tylko_z_sesja_i_CSRF_i_pokazuje_stan(tmp_path):
    cfg = two_profile_config()
    cfg.panel = PanelConfig(enabled=True, port=0, static_dir=str(tmp_path / "web"),
                            cookie_secure=False)
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    store = Store(cfg.store.path)
    store.set_json("game:test", {
        "mode": "bonus", "observed": "allowed", "bonus_until": "2026-10-02T16:40:00.000000+0000",
        "confirmed_at": "2026-10-02T16:10:00.000000+0000", "source": "panel",
    })
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    port = server.server_address[1]
    try:
        body = {"child": "Kuba", "action": "bonus", "minutes": 30}
        assert call(port, "POST", "/api/game", body)[0] == 401
        cookie = panel_login(port, "rodzic", "dlugie-haslo-testowe")
        assert call(port, "POST", "/api/game", body, {"Cookie": cookie})[0] == 403
        csrf = next(c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("kidwatch_csrf"))
        h = {"Cookie": cookie, "X-CSRF-Token": csrf}
        assert call(port, "POST", "/api/game", {**body, "child": "Obcy"}, h)[0] == 400
        assert call(port, "POST", "/api/game", {**body, "minutes": 9999}, h)[0] == 400
        assert call(port, "POST", "/api/game", {**body, "action": "rm -rf"}, h)[0] == 400
        status, data = call(port, "POST", "/api/game", body, h)
        assert status == 202 and data["id"] == 1

        # Zadanie w kolejce, kidwatch.db nietkniety przez panel.
        assert GameRequests(cfg.panel_auth_path).pending()[0]["login"] == "rodzic"
        status, devices = call(port, "GET", "/api/devices", headers={"Cookie": cookie})
        kuba = devices[0]["game"]
        assert kuba["mode"] == "bonus"
        assert kuba["bonus_until"].startswith("2026-10-02T18:40")
        assert kuba["request"]["pending"] is True
        assert kuba["shared_with"] == []
        assert "test" not in json.dumps(kuba)
    finally:
        server.shutdown()
        store.close()


def test_panel_bez_czasu_gry_nie_ma_akcji(tmp_path):
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path),
                                        cookie_secure=False))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    port = server.server_address[1]
    try:
        cookie = panel_login(port, "rodzic", "dlugie-haslo-testowe")
        csrf = next(c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("kidwatch_csrf"))
        h = {"Cookie": cookie, "X-CSRF-Token": csrf}
        assert call(port, "POST", "/api/game", {"child": "Kuba", "action": "block"}, h)[0] == 404
        devices = call(port, "GET", "/api/devices", headers={"Cookie": cookie})[1]
        assert devices[0]["game"] is None
    finally:
        server.shutdown()
