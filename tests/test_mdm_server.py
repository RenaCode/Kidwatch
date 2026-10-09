"""Warstwa HTTP kidwatch-mdm: rozdzial portow, token, kody odpowiedzi."""

from __future__ import annotations

import plistlib

import httpx
import pytest

from kidwatch_mdm import server
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import DevicePolicy, Policy
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.store import Store
from test_mdm_service import TOPIC, FakeIpad, FakePusher

TOKEN = "t" * 32


@pytest.fixture
def servers(tmp_path):
    svc = MDMService(
        store=Store(tmp_path / "mdm.db"),
        ca=CA.create(tmp_path / "ca", org="RenaCode"),
        policy=Policy(devices={"dziecko1": DevicePolicy(name="iPad Dziecka")}),
        public_url="https://mdm.example.com",
        pusher=FakePusher(),
    )
    mdm = server.start(server.make_mdm_handler(svc), 0, "127.0.0.1")
    admin = server.start(server.make_admin_handler(svc, TOKEN), 0, "127.0.0.1")
    yield (
        svc,
        httpx.Client(base_url=f"http://127.0.0.1:{mdm.server_port}"),
        httpx.Client(base_url=f"http://127.0.0.1:{admin.server_port}"),
    )
    mdm.shutdown()
    admin.shutdown()


AUTH = {"Authorization": f"Bearer {TOKEN}"}


def test_admin_requires_token_except_health(servers):
    _, _, admin = servers
    assert admin.get("/api/health").status_code == 200
    assert admin.get("/api/devices").status_code == 401
    assert admin.get("/api/devices", headers={"Authorization": "Bearer zly"}).status_code == 401
    assert admin.get("/api/devices", headers=AUTH).json() == []


def test_mdm_port_does_not_expose_admin_api(servers):
    _, mdm, _ = servers
    assert mdm.get("/api/devices", headers=AUTH).status_code == 404


def test_enroll_flow_over_http(servers):
    svc, mdm, admin = servers
    out = admin.post("/api/enrollments", json={"label": "dziecko1"}, headers=AUTH)
    assert out.status_code == 201
    path = out.json()["url"].removeprefix("https://mdm.example.com")
    resp = mdm.get(path)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/x-apple-aspen-config"
    ipad = FakeIpad(resp.content, "00008030-0000CCCC0000DDDD")

    for fields in (
        {"MessageType": "Authenticate", "Topic": TOPIC},
        {"MessageType": "TokenUpdate", "Topic": TOPIC, "Token": b"\x01", "PushMagic": "M"},
    ):
        body, sig = ipad.msg(**fields)
        assert (
            mdm.put("/mdm/checkin", content=body, headers={"Mdm-Signature": sig}).status_code == 200
        )

    body, sig = ipad.msg(Status="Idle")
    resp = mdm.put("/mdm/connect", content=body, headers={"Mdm-Signature": sig})
    assert plistlib.loads(resp.content)["Command"]["RequestType"] == "DeviceInformation"

    devices = admin.get("/api/devices", headers=AUTH).json()
    assert devices[0]["label"] == "dziecko1" and devices[0]["name"] == "iPad Dziecka"
    detail = admin.get("/api/devices/00008030-0000CCCC0000DDDD", headers=AUTH).json()
    assert detail["commands"]


def test_unsigned_connect_is_401(servers):
    _, mdm, _ = servers
    resp = mdm.put("/mdm/connect", content=plistlib.dumps({"UDID": "X", "Status": "Idle"}))
    assert resp.status_code == 401


def test_only_whitelisted_commands_from_api(servers):
    svc, mdm, admin = servers
    out = admin.post("/api/enrollments", json={"label": "dziecko1"}, headers=AUTH).json()
    ipad = FakeIpad(
        mdm.get(out["url"].removeprefix("https://mdm.example.com")).content,
        "00008030-0000EEEE0000FFFF",
    )
    body, sig = ipad.msg(MessageType="Authenticate", Topic=TOPIC)
    mdm.put("/mdm/checkin", content=body, headers={"Mdm-Signature": sig})
    bad = admin.post(
        "/api/devices/00008030-0000EEEE0000FFFF/commands",
        json={"request_type": "EraseDevice"},
        headers=AUTH,
    )
    assert bad.status_code == 400
    ok = admin.post(
        "/api/devices/00008030-0000EEEE0000FFFF/commands",
        json={"request_type": "DeviceLock", "Message": "Czas na sen"},
        headers=AUTH,
    )
    assert ok.status_code == 202


def test_os_update_validation(servers):
    _, _, admin = servers
    bad = admin.put(
        "/api/os-update", json={"target_version": "27", "deadline": "jutro"}, headers=AUTH
    )
    assert bad.status_code == 400
    ok = admin.put(
        "/api/os-update",
        json={"target_version": "27.1", "deadline": "2026-10-20T20:00:00"},
        headers=AUTH,
    )
    assert ok.json()["effective"]["target_version"] == "27.1"
    cleared = admin.put("/api/os-update", json={"clear": True}, headers=AUTH)
    assert cleared.json()["effective"] is None


def test_bad_enrollment_label_rejected(servers):
    _, _, admin = servers
    resp = admin.post("/api/enrollments", json={"label": "../etc"}, headers=AUTH)
    assert resp.status_code == 400
