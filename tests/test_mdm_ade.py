"""Zapis automatyczny (ADE) z Apple Business: token, API, MachineInfo, synchronizacja.

Apple nie daje srodowiska testowego, wiec wszystko po stronie Apple jest atrapa:
token szyfrujemy sami do certyfikatu z `ade keypair`, MachineInfo podpisujemy
lancuchem z wlasnego „Apple Root CA" (test podmienia korzenie zaufania), API
odpowiada przez httpx.MockTransport. Prawdziwe certyfikaty Apple sprawdza osobny
test lancucha. Numery seryjne i UDID sa zmyslone (repo jest publiczne).
"""

from __future__ import annotations

import base64
import datetime as dt
import functools
import json
import plistlib
from types import SimpleNamespace

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from kidwatch.mdm import MdmWatcher, _describe
from kidwatch_mdm import ade, apple_ca, profiles
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import AdeSettings, DevicePolicy, Policy
from kidwatch_mdm.service import MDMService, ServiceError
from kidwatch_mdm.store import Store
from test_mdm_service import TOPIC, FakeIpad, FakePusher

SERIAL = "TESTSERIAL01"
UDID = "00008030-0000AAAA0000BBBB"
URL = "https://mdm.example.com"
TOKENS = ade.AdeTokens(
    consumer_key="CK_test",
    consumer_secret="CS_test",
    access_token="AT_test",
    access_secret="AS_test",
    access_token_expiry="2027-10-15T07:00:00Z",
)


# ================================================================ pomocnicze
def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject: str, key, issuer: str, issuer_key, *, ca: bool) -> x509.Certificate:
    now = dt.datetime.now(dt.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    return builder.sign(issuer_key, hashes.SHA256())


@pytest.fixture(scope="module")
def chain():
    """Atrapa lancucha Apple: korzen -> posredni -> certyfikat urzadzenia."""
    keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)]
    root = _cert("Test Root CA", keys[0], "Test Root CA", keys[0], ca=True)
    inter = _cert("Test Device CA", keys[1], "Test Root CA", keys[0], ca=True)
    leaf = _cert("device", keys[2], "Test Device CA", keys[1], ca=False)
    return SimpleNamespace(root=root, inter=inter, leaf=leaf, leaf_key=keys[2])


def machine_info(chain, *, serial=SERIAL, udid=UDID, with_inter=True, content=None) -> bytes:
    body = content or plistlib.dumps(
        {
            "SERIAL": serial,
            "UDID": udid,
            "PRODUCT": "iPad13,2",
            "OS_VERSION": "27.0",
            "VERSION": "24A1",
            "LANGUAGE": "pl",
        }
    )
    builder = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(body)
        .add_signer(chain.leaf, chain.leaf_key, hashes.SHA256())
    )
    if with_inter:
        builder = builder.add_certificate(chain.inter)
    return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])


def trusting(chain):
    return functools.partial(ade.parse_machine_info, roots=[chain.root], intermediates=[])


# ===================================================================== token
def _smime(der: bytes) -> bytes:
    b64 = base64.encodebytes(der)
    return (
        b'Content-Type: application/pkcs7-mime; name="smime.p7m"; smime-type=enveloped-data\n'
        b"Content-Transfer-Encoding: base64\n"
        b'Content-Disposition: attachment; filename="smime.p7m"\n\n' + b64
    )


def test_server_token_decrypts_with_generated_keypair(tmp_path):
    cert_path = ade.generate_keypair(tmp_path)
    assert (tmp_path / ade.KEY_FILE).stat().st_mode & 0o777 == 0o600
    inner = (
        "Content-Type: text/plain;charset=UTF8\nContent-Transfer-Encoding: 7bit\n\n"
        "-----BEGIN MESSAGE-----\n"
        + json.dumps(json.loads(TOKENS.to_json()))
        + "\n-----END MESSAGE-----\n"
    ).encode()
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    der = (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(inner)
        .add_recipient(cert)
        .encrypt(serialization.Encoding.DER, [])
    )
    tokens = ade.decrypt_server_token(_smime(der), cert_path, tmp_path / ade.KEY_FILE)
    assert tokens == TOKENS
    assert tokens.expires_at().year == 2027
    # Sekrety nie moga wyciec przez repr do logu ani wyjatku.
    assert "CS_test" not in repr(tokens) and "AS_test" not in repr(tokens)


def test_server_token_for_other_certificate_is_rejected(tmp_path):
    ade.generate_keypair(tmp_path / "a")
    other = ade.generate_keypair(tmp_path / "b")
    der = (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(b"{}")
        .add_recipient(x509.load_pem_x509_certificate(other.read_bytes()))
        .encrypt(serialization.Encoding.DER, [])
    )
    with pytest.raises(ade.AdeError):
        ade.decrypt_server_token(
            _smime(der), tmp_path / "a" / ade.CERT_FILE, tmp_path / "a" / ade.KEY_FILE
        )


def test_keypair_and_token_are_never_overwritten(tmp_path):
    ade.generate_keypair(tmp_path)
    with pytest.raises(FileExistsError):
        ade.generate_keypair(tmp_path)
    ade.write_private(tmp_path / "token.json", "1")
    with pytest.raises(FileExistsError):
        ade.write_private(tmp_path / "token.json", "2")
    ade.write_private(tmp_path / "token.json", "2", force=True)
    assert (tmp_path / "token.json").read_text() == "2"


# ==================================================================== OAuth1
def test_oauth1_signature_matches_rfc5849_example():
    """RFC 5849, rozdzial 1.2 — jedyny niezalezny wektor HMAC-SHA1."""
    tokens = ade.AdeTokens(
        "dpf43f3p2l4k3l03",
        "kd94hf93k423kf44",
        "nnch734d00sl2jdk",
        "pfkkdhi9sl3r4s00",
        "2030-01-01T00:00:00Z",
    )
    header = ade.oauth1_header(
        "GET",
        "http://photos.example.net/photos?file=vacation.jpg&size=original",
        tokens,
        nonce="chapoH",
        timestamp=137131202,
        with_version=False,
    )
    assert 'oauth_signature="MdpQcU8iPSUjWoN%2FUDMsK2sui9I%3D"' in header
    assert header.startswith("OAuth ")


# ===================================================================== klient
class FakeApple:
    """Atrapa mdmenrollment.apple.com z sesjami."""

    def __init__(self) -> None:
        self.sessions = 0
        self.valid_session: str | None = None
        self.requests: list[httpx.Request] = []
        self.devices: list[dict] = []
        self.assign_result = "SUCCESS"
        self.profiles: list[dict] = []
        self.sync_error: str | None = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        path = request.url.path
        if path == "/session":
            assert request.headers["Authorization"].startswith("OAuth ")
            assert 'oauth_signature_method="HMAC-SHA1"' in request.headers["Authorization"]
            self.sessions += 1
            self.valid_session = f"S{self.sessions}"
            return httpx.Response(200, json={"auth_session_token": self.valid_session})
        if request.headers.get("X-ADM-Auth-Session") != self.valid_session:
            return httpx.Response(401, text="UNAUTHORIZED")
        assert request.headers["X-Server-Protocol-Version"] == ade.SERVER_PROTOCOL_VERSION
        body = json.loads(request.content) if request.content else {}
        if path == "/account":
            return httpx.Response(200, json={"org_name": "Test", "server_name": "kidwatch-mdm"})
        if path == "/server/devices":
            # Dwie strony, zeby sprawdzic stronicowanie.
            if not body.get("cursor"):
                return httpx.Response(
                    200,
                    json={"devices": self.devices[:1], "cursor": "c1", "more_to_follow": True},
                )
            return httpx.Response(
                200, json={"devices": self.devices[1:], "cursor": "c2", "more_to_follow": False}
            )
        if path == "/devices/sync":
            if self.sync_error:
                return httpx.Response(400, text=self.sync_error)
            return httpx.Response(200, json={"devices": [], "cursor": "c3"})
        if path == "/profile":
            self.profiles.append(body)
            return httpx.Response(
                200, json={"profile_uuid": f"P{len(self.profiles)}", "devices": {}}
            )
        if path == "/profile/devices":
            for d in self.devices:
                if d["serial_number"] in body["devices"] and self.assign_result == "SUCCESS":
                    d.update(profile_uuid=body["profile_uuid"], profile_status="assigned")
            return httpx.Response(
                200,
                json={
                    "profile_uuid": body["profile_uuid"],
                    "devices": {s: self.assign_result for s in body["devices"]},
                },
                # Apple potrafi podmienic sesje w odpowiedzi.
                headers={"X-ADM-Auth-Session": "S-rotated"},
            )
        return httpx.Response(404)


@pytest.fixture
def apple():
    return FakeApple()


def client_for(apple: FakeApple) -> ade.AdeClient:
    return ade.AdeClient(
        TOKENS,
        base_url="https://ade.test",
        http=httpx.Client(transport=httpx.MockTransport(apple.handler)),
    )


def test_client_gets_session_and_renews_it_on_401(apple):
    client = client_for(apple)
    assert client.account()["server_name"] == "kidwatch-mdm"
    assert apple.sessions == 1
    apple.valid_session = "wygasla"  # Apple uniewaznia sesje
    assert client.account()["org_name"] == "Test"
    assert apple.sessions == 2


def test_client_takes_rotated_session_from_response(apple):
    apple.devices = [{"serial_number": SERIAL, "model": "iPad"}]
    client = client_for(apple)
    client.assign_profile("P1", [SERIAL])
    assert client.session == "S-rotated"


def test_fetch_devices_follows_cursor(apple):
    apple.devices = [{"serial_number": "AAAA00000001"}, {"serial_number": "AAAA00000002"}]
    devices, cursor = client_for(apple).fetch_devices()
    assert [d["serial_number"] for d in devices] == ["AAAA00000001", "AAAA00000002"]
    assert cursor == "c2"


def test_session_error_is_reported_without_secrets(apple):
    def handler(request):
        return httpx.Response(403, text="token_rejected")

    client = ade.AdeClient(TOKENS, http=httpx.Client(transport=httpx.MockTransport(handler)))
    with pytest.raises(ade.AdeError) as exc:
        client.account()
    assert "token_rejected" in str(exc.value)
    assert "CS_test" not in str(exc.value) and "AS_test" not in str(exc.value)


# ================================================================= MachineInfo
def test_machine_info_with_valid_chain(chain):
    info = ade.parse_machine_info(machine_info(chain), roots=[chain.root], intermediates=[])
    assert info["SERIAL"] == SERIAL and info["UDID"] == UDID


def test_machine_info_intermediate_from_local_pool(chain):
    """iPad nie zawsze dolacza posrednie — wtedy bierzemy je z apple_ca."""
    body = machine_info(chain, with_inter=False)
    with pytest.raises(ade.MachineInfoError):
        ade.parse_machine_info(body, roots=[chain.root], intermediates=[])
    info = ade.parse_machine_info(body, roots=[chain.root], intermediates=[chain.inter])
    assert info["SERIAL"] == SERIAL


def test_machine_info_from_foreign_root_is_rejected(chain):
    """Kazdy moze podpisac plist z cudzym numerem seryjnym — liczy sie lancuch."""
    with pytest.raises(ade.MachineInfoError, match="Apple Root CA"):
        ade.parse_machine_info(machine_info(chain))  # prawdziwe korzenie Apple


def test_machine_info_tampered_content_is_rejected(chain):
    body = machine_info(chain)
    forged = body.replace(SERIAL.encode(), b"OTHERSERIAL1")
    assert forged != body
    with pytest.raises(ade.MachineInfoError):
        ade.parse_machine_info(forged, roots=[chain.root], intermediates=[])


def test_machine_info_forged_digest_needs_device_key(chain):
    """Podmiana tresci RAZEM z atrybutem message_digest: wylapie ja dopiero
    podpis kluczem urzadzenia (sam skrot by przepuscil)."""
    import hashlib

    from asn1crypto import cms as asn1_cms

    info = asn1_cms.ContentInfo.load(machine_info(chain))
    forged_body = plistlib.dumps({"SERIAL": "OTHERSERIAL1", "UDID": UDID})
    signed = info["content"]
    signed["encap_content_info"]["content"] = forged_body
    for attr in signed["signer_infos"][0]["signed_attrs"]:
        if attr["type"].native == "message_digest":
            attr["values"] = [hashlib.sha256(forged_body).digest()]
    forged = asn1_cms.ContentInfo({"content_type": "signed_data", "content": signed}).dump(
        force=True
    )
    with pytest.raises(ade.MachineInfoError, match="podpis"):
        ade.parse_machine_info(forged, roots=[chain.root], intermediates=[])


def test_machine_info_garbage_is_rejected():
    with pytest.raises(ade.MachineInfoError):
        ade.parse_machine_info(b"nie cms")


def test_embedded_apple_chain_verifies():
    """Wpisane na sztywno certyfikaty Apple tworza poprawny lancuch (SHA-1)."""
    root = x509.load_pem_x509_certificate(apple_ca.APPLE_ROOT_CA.encode())
    ca = x509.load_pem_x509_certificate(apple_ca.APPLE_IPHONE_CERTIFICATION_AUTHORITY.encode())
    dev = x509.load_pem_x509_certificate(apple_ca.APPLE_IPHONE_DEVICE_CA.encode())
    assert ade._issued_by(ca, root) and ade._issued_by(dev, ca)
    assert not ade._issued_by(root, dev)
    assert root.fingerprint(hashes.SHA256()).hex().upper().startswith("B0B1730ECBC7FF45")
    # Certyfikat wydany przez Apple iPhone Device CA przechodzi do korzenia.
    ade.verify_apple_chain(dev, [])


# ================================================================== serwis
@pytest.fixture
def ade_policy():
    return Policy(
        devices={
            "dziecko1": DevicePolicy(name="iPad Dziecka", serial=SERIAL.lower()),
            "test": DevicePolicy(name="iPad testowy"),
        }
    )


@pytest.fixture
def svc(tmp_path, ade_policy, chain):
    service = MDMService(
        store=Store(tmp_path / "mdm.db"),
        ca=CA.create(tmp_path / "ca", org="RenaCode"),
        policy=ade_policy,
        public_url=URL,
        pusher=FakePusher(),
    )
    service.parse_machine_info = trusting(chain)
    return service


def events(svc, kind):
    return [r for r in svc.store.events(0, 500) if r["kind"] == kind]


def test_ade_enrollment_issues_profile_for_policy_serial(svc, chain):
    resp = svc.ade_enroll(machine_info(chain))
    assert resp.content_type == "application/x-apple-aspen-config"
    ipad = FakeIpad(resp.body, UDID)
    body, sig = ipad.msg(MessageType="Authenticate", Topic=TOPIC, SerialNumber=SERIAL)
    svc.checkin(body, sig)
    device = svc.store.device(UDID)
    assert device["label"] == "dziecko1"
    auth = json.loads(events(svc, "authenticate")[0]["detail"])
    assert auth["source"] == "ade"
    # Profil zapisu iPada: nie do zdjecia (nadzor z ADE).
    assert ipad.profile["PayloadRemovalDisallowed"] is True


def test_ade_profile_used_by_other_device_is_rejected(svc, chain):
    resp = svc.ade_enroll(machine_info(chain))
    thief = FakeIpad(resp.body, "00008030-0000EEEE0000FFFF")
    body, sig = thief.msg(MessageType="Authenticate", Topic=TOPIC)
    with pytest.raises(ServiceError) as exc:
        svc.checkin(body, sig)
    assert exc.value.status == 403
    assert events(svc, "ade_udid_mismatch")
    assert svc.store.device("00008030-0000EEEE0000FFFF") is None


def test_ade_unknown_serial_is_refused_with_event(svc, chain):
    with pytest.raises(ServiceError) as exc:
        svc.ade_enroll(machine_info(chain, serial="UNKNOWN00001"))
    assert exc.value.status == 403
    detail = json.loads(events(svc, "ade_unknown_serial")[0]["detail"])
    assert detail["serial"] == "UNKNOWN00001"


def test_ade_untrusted_signature_is_401(svc, chain):
    svc.parse_machine_info = ade.parse_machine_info  # prawdziwe korzenie Apple
    with pytest.raises(ServiceError) as exc:
        svc.ade_enroll(machine_info(chain))
    assert exc.value.status == 401
    assert events(svc, "ade_enroll_rejected")


def test_awaiting_configuration_gets_restrictions_then_device_configured(svc, chain):
    ipad = FakeIpad(svc.ade_enroll(machine_info(chain)).body, UDID)
    svc.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC))
    svc.checkin(
        *ipad.msg(
            MessageType="TokenUpdate",
            Topic=TOPIC,
            Token=b"\x01",
            PushMagic="M",
            AwaitingConfiguration=True,
        )
    )
    queue = [
        r["request_type"]
        for r in svc.store.query(
            "SELECT request_type FROM commands WHERE udid=? ORDER BY created_at, rowid", (UDID,)
        )
    ]
    assert queue[-2:] == ["InstallProfile", "DeviceConfigured"]
    # Powtorny TokenUpdate w kreatorze nie dubluje zwolnienia.
    svc.checkin(
        *ipad.msg(
            MessageType="TokenUpdate",
            Topic=TOPIC,
            Token=b"\x01",
            PushMagic="M",
            AwaitingConfiguration=True,
        )
    )
    count = svc.store.one(
        "SELECT COUNT(*) AS n FROM commands WHERE request_type='DeviceConfigured'"
    )["n"]
    assert count == 1
    # Uzgadnianie nie wgrywa drugi raz tego samego profilu.
    svc.reconcile()
    installs = svc.store.one(
        "SELECT COUNT(*) AS n FROM commands WHERE request_type='InstallProfile'"
    )["n"]
    assert installs == 1


def test_old_database_gets_new_enrollment_columns(tmp_path):
    import sqlite3

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE enrollments (token TEXT PRIMARY KEY, label TEXT NOT NULL, "
        "created_at TEXT NOT NULL, expires_at TEXT NOT NULL, udid TEXT, bound_at TEXT)"
    )
    conn.execute("INSERT INTO enrollments VALUES ('t', 'x', '2026', '2027', NULL, NULL)")
    conn.commit()
    conn.close()
    store = Store(path)
    row = store.enrollment("t")
    assert row["source"] == "link" and row["expected_udid"] is None


# =========================================================== synchronizacja
@pytest.fixture
def sync(tmp_path, ade_policy, apple):
    return ade.AdeSync(
        store=Store(tmp_path / "s.db"), policy=ade_policy, public_url=URL, client=client_for(apple)
    )


def sync_events(sync, kind):
    return [json.loads(r["detail"]) for r in sync.store.events(0, 500) if r["kind"] == kind]


def test_sync_defines_profile_once_and_assigns_device(sync, apple):
    apple.devices = [{"serial_number": SERIAL, "model": "iPad", "profile_status": "empty"}]
    stats = sync.sync()
    assert stats["assigned"] == 1
    assert apple.profiles[0]["url"] == f"{URL}{ade.ENROLL_PATH}"
    assert apple.profiles[0]["is_mdm_removable"] is False
    assert apple.profiles[0]["await_device_configured"] is True
    assert "AppleID" not in apple.profiles[0]["skip_setup_items"]
    assert sync.store.setting("ade_state:dziecko1") == ade.OK
    # Drugi obieg: profil bez zmian, bez ponownej definicji i przypisania.
    sync.next_sync = 0
    assert sync.sync()["assigned"] == 0
    assert len(apple.profiles) == 1
    assert sync.health()["devices"] == {"dziecko1": "ok"}


def test_sync_reports_missing_device_once(sync, apple):
    apple.devices = []
    sync.sync()
    sync.sync()
    missing = sync_events(sync, "ade_device_missing")
    assert len(missing) == 1 and missing[0]["label"] == "dziecko1"


def test_sync_reports_lost_profile_and_reassigns(sync, apple):
    apple.devices = [{"serial_number": SERIAL, "profile_status": "empty"}]
    sync.sync()
    # Ktos zmienil przypisanie w Apple Business: pelne pobranie widzi obcy profil.
    sync.store.set_setting("ade_full_fetch_at", None)
    apple.devices[0].update(profile_uuid="OBCY", profile_status="assigned")
    sync.sync()
    assert sync_events(sync, "ade_profile_lost")
    assert apple.devices[0]["profile_uuid"] == "P1"


def test_sync_assign_failure_is_an_event(sync, apple):
    apple.devices = [{"serial_number": SERIAL, "profile_status": "empty"}]
    apple.assign_result = "NOT_ACCESSIBLE"
    stats = sync.sync()
    assert stats["failed"] == 1
    assert sync_events(sync, "ade_assign_failed")[0]["status"] == "NOT_ACCESSIBLE"


def test_sync_unknown_device_reported_once(sync, apple):
    apple.devices = [
        {"serial_number": SERIAL, "profile_status": "empty"},
        {"serial_number": "STRANGER0001", "model": "iPhone"},
    ]
    sync.sync()
    sync.store.set_setting("ade_full_fetch_at", None)
    sync.sync()
    unknown = sync_events(sync, "ade_unknown_device")
    assert len(unknown) == 1 and unknown[0]["serial"] == "STRANGER0001"


def test_sync_uses_cursor_and_recovers_from_expired_one(sync, apple):
    apple.devices = [{"serial_number": SERIAL, "profile_status": "empty"}]
    sync.sync()
    before = sum(1 for r in apple.requests if r.url.path == "/server/devices")
    sync.sync()
    assert any(r.url.path == "/devices/sync" for r in apple.requests)
    assert sum(1 for r in apple.requests if r.url.path == "/server/devices") == before
    apple.sync_error = '{"code":"EXPIRED_CURSOR"}'
    sync.sync()
    assert sum(1 for r in apple.requests if r.url.path == "/server/devices") > before


def test_sync_step_survives_apple_outage(sync):
    def broken(request):
        return httpx.Response(503, text="maintenance")

    sync.client = ade.AdeClient(TOKENS, http=httpx.Client(transport=httpx.MockTransport(broken)))
    ade.sync_step(sync, 100.0)
    assert sync.last_error and "503" in sync.last_error
    assert sync.next_sync == 100.0 + ade.RETRY_SECONDS
    assert sync.health()["last_sync_error"]


def test_unconfigured_ade_with_serials_is_reported_once(tmp_path, ade_policy):
    store = Store(tmp_path / "u.db")
    ade.report_unconfigured(store, ade_policy)
    ade.report_unconfigured(store, ade_policy)
    rows = [r for r in store.events(0) if r["kind"] == "ade_not_configured"]
    assert len(rows) == 1
    ade.report_unconfigured(Store(tmp_path / "v.db"), Policy())
    assert not [r for r in Store(tmp_path / "v.db").events(0) if r["kind"].startswith("ade")]


# ==================================================================== polityka
def test_policy_serial_is_normalized_and_unique():
    p = Policy(devices={"a": DevicePolicy(name="A", serial=" abcd12345678 ")})
    assert p.devices["a"].serial == "ABCD12345678"
    assert p.label_for_serial("abcd12345678") == "a"
    assert p.label_for_serial(None) is None
    with pytest.raises(ValueError, match="serial"):
        Policy(
            devices={
                "a": DevicePolicy(name="A", serial="ABCD12345678"),
                "b": DevicePolicy(name="B", serial="abcd12345678"),
            }
        )
    with pytest.raises(ValueError):
        DevicePolicy(name="A", serial="zly numer!")


def test_policy_skip_items_validated():
    with pytest.raises(ValueError, match="nieznane"):
        AdeSettings(skip_setup_items=["Siri", "Sirii"])
    with pytest.raises(ValueError, match="AppleID"):
        AdeSettings(skip_setup_items=["AppleID"])
    with pytest.raises(ValueError, match="Restore"):
        AdeSettings(skip_setup_items=["Restore"])


def test_profile_is_stable_for_unchanged_policy(ade_policy):
    a = ade.build_profile(ade_policy, URL)
    b = ade.build_profile(ade_policy, URL + "/")
    assert profiles.content_hash(a) == profiles.content_hash(b)


# ================================================================== Kidwatch
def test_kidwatch_describes_ade_events():
    ev = {"kind": "ade_device_missing", "detail": json.dumps({"label": "dziecko1"})}
    kind, prio, title, _ = _describe(ev, "MDM")
    assert "dziecko1" in title and prio == 4
    assert (
        _describe({"kind": "ade_device_ready", "detail": {"label": "x", "before": None}}, "MDM")
        is None
    )
    assert _describe({"kind": "ade_enrollment", "detail": {}}, "MDM") is None
    assert _describe({"kind": "ade_unknown_serial", "detail": {"serial": "S"}}, "MDM")


class _Store:
    def __init__(self):
        self.sent = set()

    def mark_sent(self, key, now):
        if key in self.sent:
            return False
        self.sent.add(key)
        return True


def test_kidwatch_warns_about_expiring_ade_token():
    watcher = MdmWatcher(api=None, store=_Store(), cfg=SimpleNamespace(cert_warn_days=30))
    now = dt.datetime(2026, 10, 15, tzinfo=dt.UTC)
    health = {"ade": {"configured": True, "days_left": 12, "last_sync_ok_at": now.isoformat()}}
    out = watcher._ade(health, now)
    assert len(out) == 1 and "12 dni" in out[0].title
    health = {
        "ade": {
            "configured": True,
            "days_left": 200,
            "last_sync_error": "AdeError: 503",
            "last_sync_ok_at": (now - dt.timedelta(hours=7)).isoformat(),
        }
    }
    out = watcher._ade(health, now)
    assert len(out) == 1 and "synchronizacja" in out[0].title
    assert watcher._ade({"ade": {"configured": False}}, now) == []
    assert watcher._ade({}, now) == []


def test_http_route_and_health(svc, chain):
    from kidwatch_mdm import server

    mdm = server.start(server.make_mdm_handler(svc), 0, "127.0.0.1")
    admin = server.start(server.make_admin_handler(svc, "t" * 32), 0, "127.0.0.1")
    try:
        base = f"http://127.0.0.1:{mdm.server_port}"
        assert httpx.post(f"{base}{ade.ENROLL_PATH}", content=b"smieci").status_code == 401
        ok = httpx.post(
            f"{base}{ade.ENROLL_PATH}",
            content=machine_info(chain),
            headers={"Content-Type": "application/pkcs7-signature"},
        )
        assert ok.status_code == 200
        assert ok.headers["content-type"] == "application/x-apple-aspen-config"
        # GET na adres zapisu ADE nie wydaje niczego.
        assert httpx.get(f"{base}{ade.ENROLL_PATH}").status_code == 404
        health = httpx.get(f"http://127.0.0.1:{admin.server_port}/api/health").json()
        assert health["ade"] == {"configured": False}
    finally:
        mdm.shutdown()
        admin.shutdown()
