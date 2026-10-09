"""Weryfikacja Mdm-Signature (kidwatch_mdm.pki) — kazdy warunek osobno."""

from __future__ import annotations

import base64
import datetime as dt

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12

from kidwatch_mdm.pki import CA, SignatureError, identity_pkcs12, verify_mdm_signature

BODY = b"<plist><dict><key>Status</key><string>Idle</string></dict></plist>"


@pytest.fixture
def ca(tmp_path):
    return CA.create(tmp_path / "ca", org="RenaCode")


def sign(cert, key, body=BODY, attributes=True) -> str:
    opts = [pkcs7.PKCS7Options.DetachedSignature, pkcs7.PKCS7Options.Binary]
    if not attributes:
        opts.append(pkcs7.PKCS7Options.NoAttributes)
    der = (
        pkcs7.PKCS7SignatureBuilder()
        .set_data(body)
        .add_signer(cert, key, hashes.SHA256())
        .sign(serialization.Encoding.DER, opts)
    )
    return base64.b64encode(der).decode()


@pytest.mark.parametrize("attributes", [True, False])
def test_valid_signature_returns_device_cert(ca, attributes):
    key, cert = ca.issue_identity("dev")
    assert verify_mdm_signature(sign(cert, key, attributes=attributes), BODY, ca) == cert


@pytest.mark.parametrize("attributes", [True, False])
def test_changed_body_fails(ca, attributes):
    key, cert = ca.issue_identity("dev")
    with pytest.raises(SignatureError):
        verify_mdm_signature(sign(cert, key, attributes=attributes), BODY + b" ", ca)


def test_cert_from_foreign_ca_fails_even_with_valid_signature(ca, tmp_path):
    other = CA.create(tmp_path / "other", org="RenaCode")  # ta sama nazwa wystawcy!
    key, cert = other.issue_identity("dev")
    with pytest.raises(SignatureError, match="naszego CA"):
        verify_mdm_signature(sign(cert, key), BODY, ca)


def test_expired_device_cert_fails(ca):
    key, cert = ca.issue_identity("dev", now=dt.datetime(2000, 1, 1, tzinfo=dt.UTC))
    with pytest.raises(SignatureError, match="okresem"):
        verify_mdm_signature(sign(cert, key), BODY, ca)


@pytest.mark.parametrize("header", ["", "nie-base64!!", base64.b64encode(b"smieci").decode()])
def test_garbage_header_fails_cleanly(ca, header):
    with pytest.raises(SignatureError):
        verify_mdm_signature(header, BODY, ca)


def test_pkcs12_opens_with_its_password(ca):
    key, cert = ca.issue_identity("dev")
    data, password = identity_pkcs12(key, cert, "dev")
    _, loaded, _ = pkcs12.load_key_and_certificates(data, password.encode())
    assert loaded == cert


def test_ca_is_never_overwritten(ca, tmp_path):
    before = (tmp_path / "ca" / "ca.key").read_bytes()
    with pytest.raises(FileExistsError):
        CA.create(tmp_path / "ca", org="RenaCode")
    assert (tmp_path / "ca" / "ca.key").read_bytes() == before
