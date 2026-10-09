"""Wniosek o certyfikat push APNs przez mdmcert.download (kidwatch_mdm.apns_cert)."""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import plistlib
import stat

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import NameOID

from kidwatch_mdm import apns_cert
from kidwatch_mdm.__main__ import main

EMAIL = "contact@example.com"


@pytest.fixture
def reqdir(tmp_path):
    out = tmp_path / "apns"
    apns_cert.new_request(out, email=EMAIL)
    return out


def fake_push_request() -> bytes:
    plist = {
        "PushCertRequestCSR": "csr",
        "PushCertCertificateChain": "chain",
        "PushCertSignature": "sig",
    }
    return base64.b64encode(plistlib.dumps(plist))


def envelope(content: bytes, cert_path) -> bytes:
    """Odpowiedz w formacie mdmcert: PKCS#7 EnvelopedData do certyfikatu wymiany, w hex."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    der = (
        pkcs7.PKCS7EnvelopeBuilder()
        .set_data(content)
        .add_recipient(cert)
        .encrypt(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])
    )
    return binascii.hexlify(der)


def test_new_writes_private_files_with_expected_subject(reqdir):
    for name in (apns_cert.PUSH_KEY, apns_cert.PKI_KEY, apns_cert.PUSH_CSR, apns_cert.PKI_CERT):
        mode = stat.S_IMODE((reqdir / name).stat().st_mode)
        assert mode == 0o600, name
    assert stat.S_IMODE(reqdir.stat().st_mode) == 0o700
    csr = x509.load_pem_x509_csr((reqdir / apns_cert.PUSH_CSR).read_bytes())
    assert csr.is_signature_valid
    assert csr.subject.get_attributes_for_oid(NameOID.EMAIL_ADDRESS)[0].value == EMAIL
    assert csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "PL"
    # CSR musi byc z KLUCZA PUSH — z niego Apple wystawi certyfikat.
    push_key = serialization.load_pem_private_key((reqdir / apns_cert.PUSH_KEY).read_bytes(), None)
    assert csr.public_key().public_numbers() == push_key.public_key().public_numbers()


def test_new_never_overwrites_push_key(reqdir):
    before = (reqdir / apns_cert.PUSH_KEY).read_bytes()
    with pytest.raises(apns_cert.CertError, match="nie nadpisuje"):
        apns_cert.new_request(reqdir, email=EMAIL)
    assert (reqdir / apns_cert.PUSH_KEY).read_bytes() == before


def test_request_body_matches_mdmctl_format(reqdir):
    body = apns_cert.sign_request_body(reqdir, EMAIL)
    assert set(body) == {"csr", "email", "key", "encrypt"}
    assert base64.b64decode(body["csr"]).startswith(b"-----BEGIN CERTIFICATE REQUEST-----")
    assert base64.b64decode(body["encrypt"]).startswith(b"-----BEGIN CERTIFICATE-----")
    assert body["key"] == apns_cert.MDMCERT_API_KEY


@pytest.mark.parametrize("payload", [{"result": "success"}, {"Result": "success"}])
def test_send_accepts_success(reqdir, payload):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json=payload)

    apns_cert.send_request(reqdir, client=httpx.Client(transport=httpx.MockTransport(handler)))
    assert seen["url"] == apns_cert.SIGN_URL
    assert seen["body"]["email"] == EMAIL


@pytest.mark.parametrize(
    ("status", "payload"),
    [(200, {"result": "failure", "reason": "email not registered"}), (500, {}), (200, [])],
)
def test_send_rejects_anything_but_success(reqdir, status, payload):
    transport = httpx.MockTransport(lambda r: httpx.Response(status, json=payload))
    with pytest.raises(apns_cert.CertError):
        apns_cert.send_request(reqdir, client=httpx.Client(transport=transport))


@pytest.mark.parametrize("encoding", ["hex", "base64", "der"])
def test_decrypt_roundtrip(reqdir, tmp_path, encoding):
    content = fake_push_request()
    hexed = envelope(content, reqdir / apns_cert.PKI_CERT)
    raw = {
        "hex": hexed,
        "base64": base64.b64encode(binascii.unhexlify(hexed)),
        "der": binascii.unhexlify(hexed),
    }[encoding]
    mail = tmp_path / "mdm_signed_request.plist.b64.p7"
    mail.write_bytes(raw)
    assert apns_cert.decrypt_response(reqdir, mail) == content
    assert (reqdir / apns_cert.PUSH_REQ).read_bytes() == content


def test_decrypt_accepts_mime_wrapped_base64(reqdir, tmp_path):
    """Tak przychodzi prawdziwa odpowiedz mdmcert: base64 lamany co 76 znakow CRLF."""
    raw = fake_push_request()
    wrapped = b"\r\n".join(raw[i : i + 76] for i in range(0, len(raw), 76)) + b"\r\n"
    mail = tmp_path / "x.p7"
    mail.write_bytes(envelope(wrapped, reqdir / apns_cert.PKI_CERT))
    assert apns_cert.decrypt_response(reqdir, mail) == wrapped


def test_decrypt_rejects_content_that_is_not_a_push_request(reqdir, tmp_path):
    mail = tmp_path / "x.p7"
    mail.write_bytes(envelope(base64.b64encode(b"not a plist"), reqdir / apns_cert.PKI_CERT))
    with pytest.raises(apns_cert.CertError, match="wnioskiem push"):
        apns_cert.decrypt_response(reqdir, mail)
    assert not (reqdir / apns_cert.PUSH_REQ).exists()


def test_decrypt_with_foreign_exchange_key_fails(reqdir, tmp_path):
    other = tmp_path / "other"
    apns_cert.new_request(other, email=EMAIL)
    mail = tmp_path / "x.p7"
    mail.write_bytes(envelope(fake_push_request(), other / apns_cert.PKI_CERT))
    with pytest.raises((apns_cert.CertError, ValueError)):
        apns_cert.decrypt_response(reqdir, mail)


def apple_cert(key, topic: str | None, days: int = 365) -> bytes:
    """Atrapa certyfikatu od Apple: UID w podmiocie niesie temat."""
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, "APSP:test")]
    if topic:
        attrs.append(x509.NameAttribute(NameOID.USER_ID, topic))
    name = x509.Name(attrs)
    issuer_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Apple")]))
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .sign(issuer_key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def test_check_reports_topic_and_expiry(reqdir):
    key_pem = (reqdir / apns_cert.PUSH_KEY).read_bytes()
    key = serialization.load_pem_private_key(key_pem, None)
    topic = "com.apple.mgmt.External.0b1c2d3e-0000-4000-8000-000000000000"
    info = apns_cert.check_push_cert(apple_cert(key, topic), key_pem)
    assert info.topic == topic


def test_check_rejects_cert_for_other_key(reqdir):
    stranger = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(apns_cert.CertError, match="NIE pasuje"):
        apns_cert.check_push_cert(
            apple_cert(stranger, "com.apple.mgmt.External.x"),
            (reqdir / apns_cert.PUSH_KEY).read_bytes(),
        )


def test_check_rejects_cert_without_mdm_topic(reqdir):
    key_pem = (reqdir / apns_cert.PUSH_KEY).read_bytes()
    key = serialization.load_pem_private_key(key_pem, None)
    with pytest.raises(apns_cert.CertError, match="bez tematu"):
        apns_cert.check_push_cert(apple_cert(key, None), key_pem)


def test_cli_new_returns_error_code_on_existing_dir(reqdir, capsys):
    assert main(["apns", "new", "--dir", str(reqdir), "--email", EMAIL]) == 2
    assert "nie nadpisuje" in capsys.readouterr().err
