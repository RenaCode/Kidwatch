"""Podpis profilu zapisu certyfikatem TLS (kidwatch_mdm.signing)."""

from __future__ import annotations

import datetime as dt
import os
import plistlib
import shutil
import subprocess

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import DevicePolicy, Policy
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.signing import ProfileSigner, build
from kidwatch_mdm.store import Store
from test_mdm_service import TOPIC, FakeIpad, FakePusher, unwrap_profile


def _cert(subject, issuer, pub, signer, now, days, ca):
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
    return builder.sign(signer, hashes.SHA256())


def tls_pair(directory, cn="mdm.example.com", days=90):
    """Atrapa Sekretu cert-managera jak u Let's Encrypt: korzen -> posredni -> lisc.

    tls.crt = lisc + posredni (bez korzenia), ca.pem = SAM korzen — tak jak iPad
    zna ISRG, a posredniego YR1 nie. Bez posredniego w podpisie weryfikacja pada.
    """
    root_key, mid_key, key = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(3)
    )
    now = dt.datetime.now(dt.UTC)
    root = _cert("Atrapa Root", "Atrapa Root", root_key.public_key(), root_key, now, days, True)
    mid = _cert("Atrapa R1", "Atrapa Root", mid_key.public_key(), root_key, now, days, True)
    leaf = _cert(cn, "Atrapa R1", key.public_key(), mid_key, now, days, False)
    directory.mkdir(parents=True, exist_ok=True)
    pem = serialization.Encoding.PEM
    (directory / "tls.crt").write_bytes(leaf.public_bytes(pem) + mid.public_bytes(pem))
    (directory / "tls.key").write_bytes(
        key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    (directory / "ca.pem").write_bytes(root.public_bytes(pem))
    return directory


@pytest.fixture
def svc(tmp_path):
    tls = tls_pair(tmp_path / "tls")
    return MDMService(
        store=Store(tmp_path / "mdm.db"),
        ca=CA.create(tmp_path / "ca", org="RenaCode"),
        policy=Policy(devices={"dziecko1": DevicePolicy(name="iPad Dziecka")}),
        public_url="https://mdm.example.com",
        pusher=FakePusher(),
        signer=build(str(tls / "tls.crt"), str(tls / "tls.key")),
    ), tls


def test_profile_is_signed_and_still_enrolls(svc):
    service, _ = svc
    body = service.enrollment_profile(service.create_enrollment("dziecko1")["token"]).body
    assert not body.lstrip().startswith(b"<?xml")  # to juz nie goly plist
    profile = plistlib.loads(unwrap_profile(body))
    assert profile["PayloadIdentifier"] == "com.renacode.kidwatch.mdm"
    ipad = FakeIpad(body, "00008030-0000AAAA0000BBBB")
    assert service.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC)).status == 200


@pytest.mark.skipif(not shutil.which("openssl"), reason="brak openssl")
def test_openssl_verifies_signature_against_issuer(svc, tmp_path):
    """Niezalezna weryfikacja: openssl sprawdza podpis I lancuch do wystawcy."""
    service, tls = svc
    signed = tmp_path / "p.mobileconfig"
    signed.write_bytes(
        service.enrollment_profile(service.create_enrollment("dziecko1")["token"]).body
    )
    out = subprocess.run(
        [
            "openssl",
            "smime",
            "-verify",
            "-inform",
            "DER",
            "-in",
            str(signed),
            "-CAfile",
            str(tls / "ca.pem"),
            "-purpose",
            "any",
        ],
        capture_output=True,
        check=False,
        env={**os.environ, "LC_ALL": "C"},
    )
    assert out.returncode == 0, out.stderr.decode()
    assert plistlib.loads(out.stdout)["PayloadContent"]


def test_renewed_certificate_is_picked_up_without_restart(tmp_path):
    tls = tls_pair(tmp_path / "tls", cn="stary.example.com")
    signer = ProfileSigner(tls / "tls.crt", tls / "tls.key")
    signer.sign(b"<plist/>")
    first = signer._chain[0]
    tls_pair(tmp_path / "tls", cn="nowy.example.com")  # cert-manager odnowil
    os.utime(tls / "tls.crt", (1, 2_000_000_000))
    signer.sign(b"<plist/>")
    assert signer._chain[0] != first
    assert "nowy" in signer._chain[0].subject.rfc4514_string()


def test_missing_cert_files_give_unsigned_profile_and_event(svc):
    service, tls = svc
    (tls / "tls.key").unlink()
    body = service.enrollment_profile(service.create_enrollment("dziecko1")["token"]).body
    assert body.lstrip().startswith(b"<?xml")
    assert service.store.events()[-1]["kind"] == "profile_unsigned"


def test_mismatched_key_is_rejected(tmp_path):
    a = tls_pair(tmp_path / "a")
    b = tls_pair(tmp_path / "b")
    signer = ProfileSigner(a / "tls.crt", b / "tls.key")
    with pytest.raises(ValueError, match="nie pasuje"):
        signer.sign(b"<plist/>")


def test_build_without_files_returns_none(tmp_path):
    assert build(None, None) is None
    assert build(str(tmp_path / "x.crt"), str(tmp_path / "x.key")) is None
