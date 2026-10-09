"""Kidwatch <-> kidwatch-mdm: czujka i zakladka panelu na PRAWDZIWYM serwerze MDM.

Serwer MDM startuje na porcie 0 z atrapa APNs, a Kidwatch laczy sie z nim
przez wlasciwe API admina z tokenem — ta sama droga co w klastrze.
"""

from __future__ import annotations

import http.client
import json
from datetime import UTC, datetime, timedelta

import pytest

from conftest import make_config, panel_login
from kidwatch.config import MdmConfig, PanelConfig, StoreConfig
from kidwatch.mdm import CURSOR_KEY, MdmApi, MdmWatcher
from kidwatch.models import NotifyKind
from kidwatch.notifiers.bramka import kategoria
from kidwatch.panel import start_panel
from kidwatch.panel_auth import PanelAuth
from kidwatch.store import Store
from kidwatch_mdm import server as mdm_server
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import DevicePolicy, Policy
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.store import Store as MdmStore
from kidwatch_mdm.store import iso
from test_mdm_service import TOPIC, FakeIpad, FakePusher

TOKEN = "k" * 40
UDID = "00008030-0000AAAA0000BBBB"


@pytest.fixture
def mdm(tmp_path):
    svc = MDMService(
        store=MdmStore(tmp_path / "mdm.db"),
        ca=CA.create(tmp_path / "ca", org="RenaCode"),
        policy=Policy(devices={"dziecko1": DevicePolicy(name="iPad Dziecka")}),
        public_url="https://mdm.example.com",
        pusher=FakePusher(),
    )
    admin = mdm_server.start(mdm_server.make_admin_handler(svc, TOKEN), 0, "127.0.0.1")
    yield svc, f"http://127.0.0.1:{admin.server_port}"
    admin.shutdown()


def enroll(svc: MDMService) -> FakeIpad:
    token = svc.create_enrollment("dziecko1")["token"]
    ipad = FakeIpad(svc.enrollment_profile(token).body, UDID)
    svc.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC))
    svc.checkin(*ipad.msg(MessageType="TokenUpdate", Topic=TOPIC, Token=b"\x01", PushMagic="M"))
    return ipad


@pytest.fixture
def watcher(mdm, tmp_path):
    svc, url = mdm
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(tmp_path / "k.db")
    yield svc, MdmWatcher(MdmApi(cfg, TOKEN), store, cfg), store
    store.close()


def test_first_poll_does_not_replay_history(watcher):
    svc, w, store = watcher
    enroll(svc)
    assert w.poll(datetime.now(UTC)) == []
    assert int(store.get_meta(CURSOR_KEY)) > 0


def test_checkout_and_new_app_become_notifications(watcher):
    svc, w, _ = watcher
    ipad = enroll(svc)
    w.poll(datetime.now(UTC))  # kursor
    svc.store.event("apps_installed", UDID, {"apps": [{"id": "com.free.vpn", "name": "Free VPN"}]})
    svc.checkin(*ipad.msg(MessageType="CheckOut", Topic=TOPIC))
    notes = w.poll(datetime.now(UTC))
    by_kind = {n.kind: n for n in notes}
    assert by_kind[NotifyKind.MDM].priority == 5
    assert "iPad Dziecka" in by_kind[NotifyKind.MDM].title
    assert by_kind[NotifyKind.DEVICE_INVENTORY].text == "Free VPN"
    # Drugi odczyt: nic nowego.
    assert w.poll(datetime.now(UTC)) == []


def test_silent_ipad_alarm_once_per_day(watcher):
    svc, w, _ = watcher
    enroll(svc)
    now = datetime.now(UTC)
    svc.store.update_device(UDID, last_seen_at=iso(now - timedelta(hours=30)))
    w.poll(now)  # pierwszy odczyt dziennika — ale cisza liczy sie od razu
    notes = [n for n in w.poll(now) if "brak kontaktu" in n.title]
    assert len(notes) == 1
    assert notes[0].dedup_key.endswith(now.date().isoformat())


def test_certificate_warning_cadence(watcher):
    _, w, _ = watcher
    now = datetime(2026, 10, 9, tzinfo=UTC)
    health = {"apns": {"configured": True, "days_left": 40}}
    assert w._certificate(health, now) == []
    weekly = w._certificate({"apns": {"configured": True, "days_left": 20}}, now)
    assert weekly[0].dedup_key == "mdm-cert:2026-w41" and weekly[0].priority == 4
    daily = w._certificate({"apns": {"configured": True, "days_left": 5}}, now)
    assert daily[0].dedup_key == "mdm-cert:2026-10-09" and daily[0].priority == 5


def test_mdm_alarms_route_to_technical_category_not_family():
    assert kategoria(NotifyKind.MDM) == "czujka"


def test_wrong_token_is_reported_not_crashed(mdm):
    _, url = mdm
    api = MdmApi(MdmConfig(enabled=True, url=url), "zly-token")
    with pytest.raises(Exception) as exc:
        api.devices()
    assert getattr(exc.value, "status", None) == 401


# ===================================================================== panel
def call(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Content-Type": "application/json", **(headers or {})}
    conn.request(method, path, json.dumps(body) if body is not None else None, h)
    r = conn.getresponse()
    data = json.loads(r.read() or b"null")
    conn.close()
    return r.status, data


@pytest.fixture
def panel(mdm, tmp_path, monkeypatch):
    svc, url = mdm
    monkeypatch.setenv("MDM_ADMIN_TOKEN", TOKEN)
    cfg = make_config(
        panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path), cookie_secure=False)
    )
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    cfg.mdm = MdmConfig(enabled=True, url=url)
    Store(cfg.store.path).close()
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    port = server.server_address[1]
    cookie = panel_login(port, "rodzic", "dlugie-haslo-testowe")
    csrf = next(c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("kidwatch_csrf"))
    yield svc, port, {"Cookie": cookie}, {"Cookie": cookie, "X-CSRF-Token": csrf}
    server.shutdown()


def test_panel_requires_session(panel):
    _, port, _, _ = panel
    assert call(port, "GET", "/api/mdm")[0] == 401


def test_panel_shows_mdm_state(panel):
    svc, port, get_h, _ = panel
    enroll(svc)
    status, data = call(port, "GET", "/api/mdm", headers=get_h)
    assert status == 200 and data["available"] is True
    assert data["devices"][0]["name"] == "iPad Dziecka"
    assert data["health"]["apns"]["configured"] is True
    status, detail = call(port, "GET", f"/api/mdm/devices/{UDID}", headers=get_h)
    assert status == 200 and detail["udid"] == UDID


def test_panel_actions_need_csrf_and_whitelist(panel):
    svc, port, get_h, post_h = panel
    enroll(svc)
    lock = {"udid": UDID, "request_type": "DeviceLock", "Message": "Czas spac"}
    assert call(port, "POST", "/api/mdm/command", lock, get_h)[0] == 403
    assert (
        call(port, "POST", "/api/mdm/command", {**lock, "request_type": "EraseDevice"}, post_h)[0]
        == 400
    )
    assert call(port, "POST", "/api/mdm/command", {**lock, "udid": "../../x"}, post_h)[0] == 400
    status, data = call(port, "POST", "/api/mdm/command", lock, post_h)
    assert status == 200 and data["command_uuid"]
    assert svc.store.command(data["command_uuid"])["request_type"] == "DeviceLock"


def test_panel_enroll_and_os_update(panel):
    _, port, _, post_h = panel
    status, data = call(port, "POST", "/api/mdm/enroll", {"label": "dziecko1"}, post_h)
    assert status == 200 and data["url"].startswith("https://mdm.example.com/mdm/enroll/")
    bad = call(
        port, "POST", "/api/mdm/os-update", {"target_version": "27.1", "deadline": "jutro"}, post_h
    )
    assert bad[0] == 400
    ok = call(
        port,
        "POST",
        "/api/mdm/os-update",
        {"target_version": "27.1", "deadline": "2026-10-20T20:00:00"},
        post_h,
    )
    assert ok[0] == 200 and ok[1]["effective"]["target_version"] == "27.1"


def test_panel_without_mdm_says_unavailable(tmp_path, monkeypatch):
    monkeypatch.delenv("MDM_ADMIN_TOKEN", raising=False)
    cfg = make_config(
        panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path), cookie_secure=False)
    )
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    port = server.server_address[1]
    try:
        cookie = panel_login(port, "rodzic", "dlugie-haslo-testowe")
        status, data = call(port, "GET", "/api/mdm", headers={"Cookie": cookie})
        assert status == 200 and data["available"] is False
    finally:
        server.shutdown()


async def test_loop_uses_store_only_from_loop_thread(mdm, tmp_path):
    """Regresja: produkcyjna petla (mdm_loop) z PRAWDZIWYM Store Kidwatch,
    otwartym w watku petli. Pierwsza wersja wolala poll w to_thread i kazdy
    odczyt padal na „SQLite objects created in a thread can only be used in
    that same thread" — testy wolaly poll wprost i tego nie widzialy."""
    from kidwatch.mdm import mdm_loop

    svc, url = mdm
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(tmp_path / "petla.db")
    enroll(svc)

    class Zbieracz:
        def __init__(self):
            self.notes = []

        async def send_all(self, notes):
            self.notes += notes

    async def nie_czekaj(_):
        return None

    sent = Zbieracz()
    watcher = MdmWatcher(MdmApi(cfg, TOKEN), store, cfg)
    await mdm_loop(watcher, sent, 60, sleep=nie_czekaj, max_iterations=1)
    assert int(store.get_meta(CURSOR_KEY)) > 0  # pierwszy obieg doszedl do bazy
    svc.store.event("apps_installed", UDID, {"apps": [{"id": "x.y", "name": "Gra"}]})
    await mdm_loop(watcher, sent, 60, sleep=nie_czekaj, max_iterations=1)
    assert [n.text for n in sent.notes] == ["Gra"]
    store.close()
