"""Wlasne CA tozsamosci urzadzen i weryfikacja naglowka Mdm-Signature.

Kazdy iPad dostaje w profilu zapisu WLASNY certyfikat z kluczem (payload
PKCS#12) wystawiony przez to CA. Profil ma `SignMessage = true`, wiec kazda
wiadomosc iPada niesie naglowek `Mdm-Signature`: odlaczony podpis CMS
(SignedData) tresci zadania, z certyfikatem urzadzenia w srodku.

Dlaczego podpis w naglowku, a nie TLS z certyfikatem klienta: TLS konczy sie na
Traefiku, wiec serwer nie widzialby certyfikatu bez dodatkowej konfiguracji
ingressu. Podpis jest samowystarczalny — sprawdzamy go w aplikacji.

Weryfikacja ma trzy warunki i zaden nie moze byc pominiety:
  1. certyfikat podpisujacego wystawilo NASZE CA i jest wazny,
  2. podpis CMS jest poprawny dla DOKLADNIE tych bajtow ciala,
  3. odcisk certyfikatu jest powiazany z urzadzeniem (to sprawdza protocol.py).
Bez (1) kazdy moglby podpisac sie wlasnym certyfikatem, bez (2) przechwycony
naglowek pasowalby do dowolnej tresci.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import os
import secrets
from dataclasses import dataclass
from pathlib import Path

from asn1crypto import cms as asn1_cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT = "ca.crt"
CA_KEY = "ca.key"
DEVICE_CERT_DAYS = 3650

_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class SignatureError(ValueError):
    """Wiadomosc nie przeszla weryfikacji — odpowiadamy 401, niczego nie zapisujemy."""


@dataclass(frozen=True)
class CA:
    cert: x509.Certificate
    key: rsa.RSAPrivateKey

    @classmethod
    def load(cls, directory: Path) -> CA:
        cert = x509.load_pem_x509_certificate((directory / CA_CERT).read_bytes())
        key = serialization.load_pem_private_key((directory / CA_KEY).read_bytes(), None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("klucz CA musi byc RSA")
        return cls(cert, key)

    @classmethod
    def create(cls, directory: Path, *, org: str) -> CA:
        """Nowe CA. Nie nadpisuje istniejacego: zmiana CA odcina wszystkie iPady."""
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        for name in (CA_CERT, CA_KEY):
            if (directory / name).exists():
                raise FileExistsError(f"{directory / name} juz istnieje — CA sie nie nadpisuje")
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        name = x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                x509.NameAttribute(NameOID.COMMON_NAME, f"{org} kidwatch-mdm device CA"),
            ]
        )
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=DEVICE_CERT_DAYS + 365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=False,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
            .sign(key, hashes.SHA256())
        )
        _write_private(
            directory / CA_KEY,
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
        )
        _write_private(directory / CA_CERT, cert.public_bytes(serialization.Encoding.PEM))
        return cls(cert, key)

    def issue_identity(
        self, common_name: str, now: dt.datetime | None = None
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        """Klucz i certyfikat tozsamosci jednego iPada (podpis wiadomosci MDM)."""
        now = now or dt.datetime.now(dt.UTC)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(self.cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=DEVICE_CERT_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), False)
            .sign(self.key, hashes.SHA256())
        )
        return key, cert

    def verify_issued(self, cert: x509.Certificate, now: dt.datetime | None = None) -> None:
        """Certyfikat wystawilo to CA i jest teraz wazny — inaczej SignatureError."""
        now = now or dt.datetime.now(dt.UTC)
        if cert.issuer != self.cert.subject:
            raise SignatureError("certyfikat urzadzenia wystawil ktos inny niz nasze CA")
        try:
            self.cert.public_key().verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                cert.signature_hash_algorithm,
            )
        except InvalidSignature as exc:
            raise SignatureError(
                "podpis certyfikatu urzadzenia nie pochodzi od naszego CA"
            ) from exc
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise SignatureError("certyfikat urzadzenia jest poza okresem waznosci")


def _write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def identity_pkcs12(key: rsa.RSAPrivateKey, cert: x509.Certificate, name: str) -> tuple[bytes, str]:
    """PKCS#12 dla payloadu com.apple.security.pkcs12 i jego jednorazowe haslo.

    Szyfrowanie 3DES + SHA-1 celowo: domyslny dzis AES-256/PBES2 z OpenSSL 3
    iOS przez lata odrzucal z komunikatem o zlym hasle. Plik i tak jedzie wewnatrz
    profilu po HTTPS, a haslo lezy obok w tym samym profilu — szyfr niczego tu nie
    chroni, liczy sie tylko, zeby iOS go przyjal.
    """
    password = secrets.token_urlsafe(18)
    encryption = (
        serialization.PrivateFormat.PKCS12.encryption_builder()
        .kdf_rounds(2048)
        .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
        .hmac_hash(hashes.SHA1())
        .build(password.encode())
    )
    data = pkcs12.serialize_key_and_certificates(name.encode(), key, cert, None, encryption)
    return data, password


def verify_mdm_signature(header: str, body: bytes, ca: CA) -> x509.Certificate:
    """Sprawdza naglowek Mdm-Signature i zwraca certyfikat urzadzenia.

    Rzuca SignatureError przy kazdej niezgodnosci. Obsluguje podpis z atrybutami
    (to, co wysyla iOS) i bez nich (czysty podpis tresci).
    """
    try:
        der = base64.b64decode("".join(header.split()), validate=True)
        info = asn1_cms.ContentInfo.load(der)
        if info["content_type"].native != "signed_data":
            raise SignatureError("Mdm-Signature nie jest podpisem CMS SignedData")
        signed = info["content"]
        signers = signed["signer_infos"]
        if len(signers) != 1:
            raise SignatureError(f"oczekiwano jednego podpisujacego, jest {len(signers)}")
        signer = signers[0]
        certs = [c.chosen for c in signed["certificates"] if c.name == "certificate"]
    except (ValueError, binascii.Error, KeyError, TypeError) as exc:
        if isinstance(exc, SignatureError):
            raise
        raise SignatureError(f"nieczytelny Mdm-Signature: {exc}") from exc

    sid = signer["sid"]
    if sid.name != "issuer_and_serial_number":
        raise SignatureError("podpisujacy wskazany inaczej niz wystawca+numer seryjny")
    serial = sid.chosen["serial_number"].native
    issuer = sid.chosen["issuer"].dump()
    match = [c for c in certs if c.serial_number == serial and c.issuer.dump() == issuer]
    if not match:
        raise SignatureError("w podpisie brak certyfikatu podpisujacego")
    cert = x509.load_der_x509_certificate(match[0].dump())
    ca.verify_issued(cert)

    digest_name = signer["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        raise SignatureError(f"nieobslugiwany skrot {digest_name}")
    hash_cls = _HASHES[digest_name]

    signed_attrs = signer["signed_attrs"]
    if signed_attrs.native is not None and len(signed_attrs):
        digests = [
            a["values"][0].native for a in signed_attrs if a["type"].native == "message_digest"
        ]
        if len(digests) != 1:
            raise SignatureError("podpis bez atrybutu message_digest")
        if digests[0] != hashlib.new(hash_cls.name, body).digest():
            raise SignatureError("skrot w podpisie nie zgadza sie z trescia wiadomosci")
        # Atrybuty podpisuje sie jako SET OF (0x31), a w strukturze siedza pod
        # niejawnym [0] (0xA0). Zamiana pierwszego bajtu to standardowy zabieg.
        attrs_der = signed_attrs.dump()
        to_verify = b"\x31" + attrs_der[1:]
    else:
        to_verify = body

    public_key = cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise SignatureError("obslugujemy tylko klucze RSA (takie wystawia nasze CA)")
    try:
        public_key.verify(signer["signature"].native, to_verify, padding.PKCS1v15(), hash_cls())
    except InvalidSignature as exc:
        raise SignatureError("podpis CMS jest niepoprawny") from exc
    return cert
