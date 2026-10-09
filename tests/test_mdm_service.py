"""Serwer MDM od zapisu do DDM — z atrapa iPada, ktora podpisuje wiadomosci jak iOS.

Atrapa bierze tozsamosc Z PRAWDZIWEGO profilu zapisu (PKCS#12 z payloadu)
i podpisuje kazde cialo odlaczonym CMS, tak jak iPad przy SignMessage=true.
Dzieki temu test przechodzi te sama sciezke weryfikacji co produkcja.
"""

from __future__ import annotations

import base64
import json
import plistlib
from datetime import timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from kidwatch_mdm import profiles
from kidwatch_mdm.apns import PushResult
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import DEFAULT_RESTRICTIONS, DevicePolicy, OsUpdate, Policy
from kidwatch_mdm.service import MDMService, ServiceError
from kidwatch_mdm.store import Store, iso, now_utc

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "tools" / "apple_schema_index.json").read_text(encoding="utf-8"))
TOPIC = "com.apple.mgmt.External.11111111-2222-4333-8444-555555555555"
DOH = "https://dns.nextdns.io/abc123/iPad-Dziecka"
TYPES = {"boolean": bool, "string": str, "integer": int, "dictionary": dict, "array": list}
META = {
    "PayloadType",
    "PayloadVersion",
    "PayloadIdentifier",
    "PayloadUUID",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
}


def schema_problems(keys: dict, payload: dict, where: str) -> list[str]:
    """Jak w test_profile_schema, plus tablice slownikow (np. StatusItems)."""
    out: list[str] = []
    for name, value in payload.items():
        if name in META:
            continue
        spec = keys.get(name)
        if spec is None:
            out.append(f"{where}.{name}: brak w schemacie Apple")
            continue
        expected = TYPES.get(spec["type"])
        if expected and not isinstance(value, expected):
            out.append(f"{where}.{name}: schemat {spec['type']}, jest {type(value).__name__}")
        if spec.get("allowed") and value not in spec["allowed"]:
            out.append(f"{where}.{name}: {value!r} poza {spec['allowed']}")
        sub = spec.get("subkeys") or {}
        if isinstance(value, dict) and sub:
            out += schema_problems(sub, value, f"{where}.{name}")
        if isinstance(value, list) and len(sub) == 1:
            item = next(iter(sub.values()))
            for i, element in enumerate(value):
                if isinstance(element, dict) and item.get("subkeys"):
                    out += schema_problems(item["subkeys"], element, f"{where}.{name}[{i}]")
    return out


class FakePusher:
    topic = TOPIC

    def __init__(self) -> None:
        self.pushes: list[tuple[bytes, str]] = []
        self.next_result = PushResult(True, 200)

    def push(self, token: bytes, magic: str) -> PushResult:
        self.pushes.append((token, magic))
        return self.next_result

    def expires_at(self):
        return None


def unwrap_profile(data: bytes) -> bytes:
    """Profil podpisany (CMS SignedData) albo goly plist — jak iOS przy instalacji."""
    if data.lstrip().startswith(b"<?xml") or data.startswith(b"bplist"):
        return data
    from asn1crypto import cms

    return cms.ContentInfo.load(data)["content"]["encap_content_info"]["content"].native


class FakeIpad:
    def __init__(self, profile_bytes: bytes, udid: str = "00008030-0000AAAA0000BBBB") -> None:
        profile = plistlib.loads(unwrap_profile(profile_bytes))
        ident = next(
            p for p in profile["PayloadContent"] if p["PayloadType"] == "com.apple.security.pkcs12"
        )
        key, cert, _ = pkcs12.load_key_and_certificates(
            ident["PayloadContent"], ident["Password"].encode()
        )
        self.key, self.cert, self.udid = key, cert, udid
        self.profile = profile

    def sign(self, body: bytes) -> str:
        der = (
            pkcs7.PKCS7SignatureBuilder()
            .set_data(body)
            .add_signer(self.cert, self.key, hashes.SHA256())
            .sign(
                serialization.Encoding.DER,
                [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary],
            )
        )
        return base64.b64encode(der).decode()

    def msg(self, **fields) -> tuple[bytes, str]:
        body = plistlib.dumps({"UDID": self.udid, **fields})
        return body, self.sign(body)


@pytest.fixture
def ca(tmp_path):
    return CA.create(tmp_path / "ca", org="RenaCode")


@pytest.fixture
def policy():
    return Policy(devices={"dziecko1": DevicePolicy(name="iPad Dziecka", dns_url=DOH)})


@pytest.fixture
def svc(tmp_path, ca, policy):
    return MDMService(
        store=Store(tmp_path / "mdm.db"),
        ca=ca,
        policy=policy,
        public_url="https://mdm.example.com",
        pusher=FakePusher(),
    )


def enroll(svc: MDMService, label="dziecko1", udid="00008030-0000AAAA0000BBBB") -> FakeIpad:
    token = svc.create_enrollment(label)["token"]
    ipad = FakeIpad(svc.enrollment_profile(token).body, udid)
    body, sig = ipad.msg(
        MessageType="Authenticate",
        Topic=TOPIC,
        SerialNumber="SN1",
        ProductName="iPad13,2",
        OSVersion="27.0",
        BuildVersion="24A1",
    )
    assert svc.checkin(body, sig).status == 200
    body, sig = ipad.msg(
        MessageType="TokenUpdate", Topic=TOPIC, Token=b"\x01\x02", PushMagic="MAGIC"
    )
    assert svc.checkin(body, sig).status == 200
    return ipad


def run_commands(svc: MDMService, ipad: FakeIpad, responder=None, limit=20) -> list[dict]:
    """Petla iPada: Idle, potem odpowiedz na kazda komende, az kolejka pusta."""
    seen: list[dict] = []
    body, sig = ipad.msg(Status="Idle")
    resp = svc.connect(body, sig)
    while resp.body and len(seen) < limit:
        cmd = plistlib.loads(resp.body)
        seen.append(cmd)
        extra = (responder or default_responder)(cmd)
        body, sig = ipad.msg(CommandUUID=cmd["CommandUUID"], **extra)
        resp = svc.connect(body, sig)
    return seen


def default_responder(cmd: dict) -> dict:
    rt = cmd["Command"]["RequestType"]
    if rt == "DeviceInformation":
        return {
            "Status": "Acknowledged",
            "QueryResponses": {
                "DeviceName": "iPad (Dziecko)",
                "OSVersion": "27.0",
                "IsSupervised": True,
                "SerialNumber": "SN1",
            },
        }
    if rt == "InstalledApplicationList":
        return {
            "Status": "Acknowledged",
            "InstalledApplicationList": [
                {"Identifier": "com.gameloft.asphalt9", "Name": "Asphalt 9", "ShortVersion": "4.1"}
            ],
        }
    if rt == "ProfileList":
        return {"Status": "Acknowledged", "ProfileList": []}
    return {"Status": "Acknowledged"}


# ================================================================== zapis
def test_enrollment_profile_matches_apple_schema(svc):
    token = svc.create_enrollment("dziecko1")["token"]
    profile = plistlib.loads(svc.enrollment_profile(token).body)
    top = {k: v for k, v in profile.items() if k != "PayloadContent"}
    problems = schema_problems(SCHEMA["profiles"]["TopLevel"]["keys"], top, "profil")
    for p in profile["PayloadContent"]:
        problems += schema_problems(
            SCHEMA["profiles"][p["PayloadType"]]["keys"], p, p["PayloadType"]
        )
    assert problems == [], "\n".join(problems)
    mdm = next(p for p in profile["PayloadContent"] if p["PayloadType"] == "com.apple.mdm")
    ident = next(p for p in profile["PayloadContent"] if p["PayloadType"] != "com.apple.mdm")
    assert mdm["IdentityCertificateUUID"] == ident["PayloadUUID"]
    assert mdm["Topic"] == TOPIC and mdm["SignMessage"] is True
    assert mdm["ServerURL"] == "https://mdm.example.com/mdm/connect"


def test_enrollment_refused_without_apns_certificate(tmp_path, ca, policy):
    svc = MDMService(
        store=Store(tmp_path / "x.db"), ca=ca, policy=policy, public_url="https://mdm.example.com"
    )
    token = svc.create_enrollment("dziecko1")["token"]
    with pytest.raises(ServiceError) as exc:
        svc.enrollment_profile(token)
    assert exc.value.status == 503


def test_full_enrollment_queues_refresh_and_pushes(svc):
    ipad = enroll(svc)
    events = [e["kind"] for e in svc.store.events()]
    assert "enrolled" in events
    assert svc.flush_kicks() == 1
    assert svc.pusher.pushes == [(b"\x01\x02", "MAGIC")]
    seen = [c["Command"]["RequestType"] for c in run_commands(svc, ipad)]
    assert seen == ["DeviceInformation", "SecurityInfo", "ProfileList", "InstalledApplicationList"]
    dev = svc.store.device(ipad.udid)
    assert dev["supervised"] == 1 and dev["device_name"] == "iPad (Dziecko)"
    assert json.loads(dev["apps_json"])[0]["id"] == "com.gameloft.asphalt9"


def test_used_or_expired_invitation_gives_no_new_identity(svc):
    token = svc.create_enrollment("dziecko1")["token"]
    ipad = FakeIpad(svc.enrollment_profile(token).body)
    svc.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC))
    with pytest.raises(ServiceError) as exc:
        svc.enrollment_profile(token)
    assert exc.value.status == 410


def test_invitation_cannot_enroll_second_device(svc):
    token = svc.create_enrollment("dziecko1")["token"]
    first = FakeIpad(svc.enrollment_profile(token).body, "UDID-A-000001")
    second = FakeIpad(svc.enrollment_profile(token).body, "UDID-B-000002")
    svc.checkin(*first.msg(MessageType="Authenticate", Topic=TOPIC))
    with pytest.raises(ServiceError) as exc:
        svc.checkin(*second.msg(MessageType="Authenticate", Topic=TOPIC))
    assert exc.value.status == 403


# ========================================================= bezpieczenstwo
def test_tampered_body_is_rejected(svc):
    ipad = enroll(svc)
    body, sig = ipad.msg(Status="Idle")
    with pytest.raises(ServiceError) as exc:
        svc.connect(body.replace(b"Idle", b"Idlf"), sig)
    assert exc.value.status == 401


def test_missing_signature_is_rejected(svc):
    ipad = enroll(svc)
    body, _ = ipad.msg(Status="Idle")
    with pytest.raises(ServiceError) as exc:
        svc.connect(body, None)
    assert exc.value.status == 401


def test_foreign_ca_is_rejected(svc, tmp_path):
    enroll(svc)
    evil_ca = CA.create(tmp_path / "evil", org="Evil")
    key, cert = evil_ca.issue_identity("x")
    p12, pw = __import__("kidwatch_mdm.pki", fromlist=["x"]).identity_pkcs12(key, cert, "x")
    fake = {
        "PayloadContent": [
            {"PayloadType": "com.apple.security.pkcs12", "PayloadContent": p12, "Password": pw}
        ]
    }
    evil = FakeIpad(plistlib.dumps(fake))
    with pytest.raises(ServiceError) as exc:
        svc.connect(*evil.msg(Status="Idle"))
    assert exc.value.status == 401
    # Odrzucony juz na podpisie, a nie dopiero na powiazaniu z urzadzeniem —
    # inaczej druga warstwa zaslanialaby brak pierwszej.
    assert svc.store.events()[-1]["kind"] == "signature_rejected"


def test_one_ipad_cannot_speak_for_another(svc):
    first = enroll(svc, "dziecko1", "UDID-DZIECKO1-01")
    enroll(svc, "dziecko2", "UDID-DZIECKO2-01")
    # Pierwszy iPad podpisuje poprawnie, ale podaje UDID drugiego.
    body = plistlib.dumps({"UDID": "UDID-DZIECKO2-01", "Status": "Idle"})
    with pytest.raises(ServiceError) as exc:
        svc.connect(body, first.sign(body))
    assert exc.value.status == 401
    assert "cert_mismatch" in [e["kind"] for e in svc.store.events()]


# ============================================================ kolejka komend
def test_not_now_is_retried_only_after_next_idle(svc):
    ipad = enroll(svc)
    svc.store.query("UPDATE commands SET status='cancelled'")
    first = svc.store.enqueue(ipad.udid, "SecurityInfo", {})
    second = svc.store.enqueue(ipad.udid, "ProfileList", {})
    resp = svc.connect(*ipad.msg(Status="Idle"))
    assert plistlib.loads(resp.body)["CommandUUID"] == first
    resp = svc.connect(*ipad.msg(Status="NotNow", CommandUUID=first))
    assert plistlib.loads(resp.body)["CommandUUID"] == second  # NotNow nie wraca od razu
    resp = svc.connect(*ipad.msg(Status="Acknowledged", CommandUUID=second, ProfileList=[]))
    assert resp.body == b""
    resp = svc.connect(*ipad.msg(Status="Idle"))
    assert plistlib.loads(resp.body)["CommandUUID"] == first


def test_command_error_is_recorded_as_event(svc):
    ipad = enroll(svc)
    seen = run_commands(
        svc,
        ipad,
        lambda c: {
            "Status": "Error",
            "ErrorChain": [{"ErrorCode": 12021, "ErrorDomain": "MCMDMErrorDomain"}],
        },
    )
    assert seen
    kinds = [e["kind"] for e in svc.store.events()]
    assert kinds.count("command_error") == len(seen)


def test_checkout_cancels_queue_and_raises_event(svc):
    ipad = enroll(svc)
    svc.checkin(*ipad.msg(MessageType="CheckOut", Topic=TOPIC))
    assert svc.store.device(ipad.udid)["checked_out_at"]
    assert not svc.store.pending(ipad.udid, "DeviceInformation")
    assert "checkout" in [e["kind"] for e in svc.store.events()]
    assert svc.reconcile()["devices"] == 0


# ========================================================== polityka i DDM
def test_reconcile_installs_restrictions_profile_once(svc):
    ipad = enroll(svc)
    run_commands(svc, ipad)
    stats = svc.reconcile()
    assert stats["pushed"] == 1
    cmds = run_commands(svc, ipad)
    install = [c for c in cmds if c["Command"]["RequestType"] == "InstallProfile"]
    assert len(install) == 1
    profile = plistlib.loads(install[0]["Command"]["Payload"])
    restr = profile["PayloadContent"][0]
    assert restr["allowVPNCreation"] is False and restr["allowHostPairing"] is True
    state = svc.store.profile_states(ipad.udid)[profiles.RESTRICTIONS_ID]
    assert state["installed_at"] is not None
    run_commands(svc, ipad)
    assert not svc.store.pending(ipad.udid, "InstallProfile")
    svc.reconcile()
    assert not svc.store.pending(ipad.udid, "InstallProfile")


def test_failed_profile_install_backs_off(svc):
    ipad = enroll(svc)
    run_commands(svc, ipad)
    svc.reconcile()
    run_commands(
        svc,
        ipad,
        lambda c: (
            {"Status": "Error", "ErrorChain": []}
            if c["Command"]["RequestType"] == "InstallProfile"
            else {"Status": "Acknowledged"}
        ),
    )
    state = svc.store.profile_states(ipad.udid)[profiles.RESTRICTIONS_ID]
    assert state["failures"] == 1 and state["installed_at"] is None
    svc.reconcile()
    assert not svc.store.pending(ipad.udid, "InstallProfile")  # jeszcze przed retry_after
    svc.reconcile(now=now_utc() + timedelta(minutes=16))
    assert svc.store.pending(ipad.udid, "InstallProfile")


def test_removed_profile_is_detected_and_reinstalled(svc):
    ipad = enroll(svc)
    run_commands(svc, ipad)
    svc.reconcile()
    run_commands(svc, ipad)
    svc.refresh(ipad.udid)
    run_commands(svc, ipad)  # ProfileList pusty -> profil zniknal
    assert "profile_missing" in [e["kind"] for e in svc.store.events()]
    svc.reconcile()
    assert svc.store.pending(ipad.udid, "InstallProfile")


def test_ddm_sync_cycle_and_resync_after_policy_change(svc):
    ipad = enroll(svc)
    run_commands(svc, ipad)
    svc.reconcile()
    run_commands(svc, ipad)

    def ddm(endpoint, data=None):
        fields = {"MessageType": "DeclarativeManagement", "Endpoint": endpoint}
        if data is not None:
            fields["Data"] = data
        resp = svc.checkin(*ipad.msg(**fields))
        assert resp.status == 200
        return json.loads(resp.body) if resp.body else None

    tokens = ddm("tokens")
    items = ddm("declaration-items")
    assert items["DeclarationsToken"] == tokens["SyncTokens"]["DeclarationsToken"]
    configs = items["Declarations"]["Configurations"]
    types = set()
    for ref in configs + items["Declarations"]["Activations"]:
        decl = ddm(f"declaration/x/{ref['Identifier']}")
        assert decl["ServerToken"] == ref["ServerToken"]
        types.add(decl["Type"])
        problems = schema_problems(
            SCHEMA["declarations"][decl["Type"]]["keys"], decl["Payload"], decl["Type"]
        )
        assert problems == [], "\n".join(problems)
    assert "com.apple.configuration.network.dns-settings" in types
    ddm(
        "status",
        json.dumps(
            {"StatusItems": {"device": {"operating-system": {"version": "27.0"}}}, "Errors": []}
        ).encode(),
    )
    assert json.loads(svc.store.device(ipad.udid)["ddm_status_json"])["device"]

    svc.reconcile()
    assert not svc.store.pending(ipad.udid, "DeclarativeManagement")
    svc.store.set_setting(
        "os_update", OsUpdate(target_version="27.1", deadline="2026-10-20T20:00:00").model_dump()
    )
    svc.reconcile()
    assert svc.store.pending(ipad.udid, "DeclarativeManagement")


def test_supervised_only_keys_only_for_supervised_ipad(policy):
    unsup = profiles.declarations(policy, "dziecko1", supervised=False, os_update=None)
    sup = profiles.declarations(policy, "dziecko1", supervised=True, os_update=None)

    def find(decls, t):
        return next(d for d in decls if d["Type"] == t)["Payload"]

    assert "ProhibitDisablement" not in find(unsup, "com.apple.configuration.network.dns-settings")
    assert find(sup, "com.apple.configuration.network.dns-settings")["ProhibitDisablement"] is True
    assert "AutomaticActions" not in find(unsup, "com.apple.configuration.softwareupdate.settings")
    assert "AutomaticActions" in find(sup, "com.apple.configuration.softwareupdate.settings")


def test_restriction_defaults_match_schema_and_are_supervised_only():
    keys = SCHEMA["profiles"]["com.apple.applicationaccess"]["keys"]
    assert schema_problems(keys, DEFAULT_RESTRICTIONS, "restrictions") == []
    # Kazde domyslne ograniczenie wymaga nadzoru — to jest powod calego projektu.
    assert all(keys[k]["supervised_ios"] for k in DEFAULT_RESTRICTIONS)


def test_commands_sent_match_apple_schema(svc):
    ipad = enroll(svc)
    run_commands(svc, ipad)
    svc.reconcile()
    run_commands(svc, ipad)
    for row in svc.store.query("SELECT command FROM commands"):
        cmd = plistlib.loads(row["command"])["Command"]
        rt = cmd.pop("RequestType")
        problems = schema_problems(SCHEMA["commands"][rt]["keys"], cmd, rt)
        assert problems == [], "\n".join(problems)


def test_push_failure_is_recorded(svc):
    ipad = enroll(svc)
    svc.pusher.next_result = PushResult(False, 410, "Unregistered")
    svc.flush_kicks()
    dev = svc.store.device(ipad.udid)
    assert dev["push_error"] == "410 Unregistered"
    assert "push_token_dead" in [e["kind"] for e in svc.store.events()]


def test_new_apps_are_reported(svc):
    ipad = enroll(svc)
    run_commands(svc, ipad)
    svc.refresh(ipad.udid)
    run_commands(
        svc,
        ipad,
        lambda c: (
            {
                "Status": "Acknowledged",
                "InstalledApplicationList": [
                    {"Identifier": "com.gameloft.asphalt9", "Name": "Asphalt 9"},
                    {"Identifier": "com.vpn.free", "Name": "Free VPN"},
                ],
            }
            if c["Command"]["RequestType"] == "InstalledApplicationList"
            else default_responder(c)
        ),
    )
    added = [e for e in svc.store.events() if e["kind"] == "apps_installed"]
    assert json.loads(added[-1]["detail"])["apps"][0]["id"] == "com.vpn.free"


def test_reenroll_same_ipad_rebinds_identity(svc):
    first = enroll(svc)
    second = enroll(svc)  # nowe zaproszenie, ten sam UDID
    assert len(svc.store.devices()) == 1
    with pytest.raises(ServiceError):
        svc.connect(*first.msg(Status="Idle"))  # stary certyfikat juz nie dziala
    assert svc.connect(*second.msg(Status="Idle")).status == 200


def test_last_seen_updates(svc):
    ipad = enroll(svc)
    svc.store.update_device(ipad.udid, last_seen_at=iso(now_utc() - timedelta(days=2)))
    svc.connect(*ipad.msg(Status="Idle"))
    assert svc.store.device(ipad.udid)["last_seen_at"] > iso(now_utc() - timedelta(minutes=1))


@pytest.mark.parametrize(
    ("failure", "alarm"),
    [
        ({"count": 0}, False),  # tak raportuje iPad bez zadnej awarii (iPadOS 27, 2026-10-09)
        ({"count": 2, "reason": "InsufficientStorage", "timestamp": "2026-10-09T09:00:00Z"}, True),
    ],
)
def test_os_update_alarm_only_on_real_failures(svc, failure, alarm):
    ipad = enroll(svc)
    report = {"StatusItems": {"softwareupdate": {"failure-reason": failure}}, "Errors": []}
    svc.checkin(
        *ipad.msg(
            MessageType="DeclarativeManagement", Endpoint="status", Data=json.dumps(report).encode()
        )
    )
    kinds = [e["kind"] for e in svc.store.events()]
    assert ("os_update_failed" in kinds) is alarm
