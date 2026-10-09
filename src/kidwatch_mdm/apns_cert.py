"""Certyfikat push APNs dla MDM przez mdmcert.download.

Po co to w ogole: serwer MDM budzi iPada wylacznie przez APNs, a Apple wydaje
certyfikat push MDM tylko na wniosek PODPISANY przez dostawce MDM. Wlasnego
podpisu Apple nie przyjmie. mdmcert.download podpisuje wnioski dla serwerow
open source, ale tylko organizacjom z firmowym adresem e-mail.

Przeplyw (ten sam co `mdmctl mdmcert.download` w MicroMDM, z ktorego zrodla
wzieto format zapytania — cmd/mdmctl/mdmcert.download.go):

1. `new`     generuje dwa klucze RSA: klucz push (z niego CSR do podpisu) i klucz
             wymiany (samopodpisany certyfikat, ktorym mdmcert szyfruje odpowiedz)
2. `send`    wysyla CSR + certyfikat wymiany do API mdmcert.download
3. mail      mdmcert odsyla zaszyfrowany plik `*.plist.b64.p7` (hex PKCS#7)
4. `decrypt` odszyfrowuje go do `push.req` — to wgrywasz na identity.apple.com
5. Apple     wydaje `MDM_ ... .pem`
6. `check`   sprawdza, ze certyfikat pasuje do klucza push i podaje temat (Topic)

Klucz push to jedyna rzecz nie do odtworzenia: bez niego certyfikat od Apple
jest bezuzyteczny. Dlatego `new` nigdy nie nadpisuje istniejacych plikow.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import json
import os
import plistlib
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

import httpx
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SIGN_URL = "https://mdmcert.download/api/v1/signrequest"
#: Publiczny klucz API wpisany na sztywno w MicroMDM i Commandment — nie jest
#: sekretem, identyfikuje klienta, a nie uzytkownika. Uzytkownika identyfikuje
#: e-mail zarejestrowany na mdmcert.download.
MDMCERT_API_KEY = "f847aea2ba06b41264d587b229e2712c89b1490a1208b7ff1aafab5bb40d47bc"
#: Temat certyfikatu push MDM zawsze zaczyna sie od tego przedrostka
#: (mdm/profiles/com.apple.mdm.yaml, klucz Topic).
TOPIC_PREFIX = "com.apple.mgmt."

PUSH_KEY = "push.key"
PUSH_CSR = "push.csr"
PKI_KEY = "pki.key"
PKI_CERT = "pki.crt"
PUSH_REQ = "push.req"


class CertError(RuntimeError):
    pass


@dataclass(frozen=True)
class PushCertInfo:
    topic: str
    not_after: dt.datetime
    subject: str


def _write_private(path: Path, data: bytes) -> None:
    """Zapis 0600 i odmowa nadpisania: O_EXCL zamyka wyscig miedzy sprawdzeniem a zapisem."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def _pem_key(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )


def build_csr(
    key: rsa.RSAPrivateKey, email: str, country: str, cn: str
) -> x509.CertificateSigningRequest:
    # Ten sam podmiot co mdmcertutil.NewCSR: C, CN i emailAddress.
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
        ]
    )
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())


def build_exchange_cert(key: rsa.RSAPrivateKey, days: int = 365) -> x509.Certificate:
    """Samopodpisany certyfikat, ktorym mdmcert.download szyfruje odpowiedz."""
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mdmcert.download")])
    now = dt.datetime.now(dt.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(key, hashes.SHA256())
    )


def new_request(
    out: Path, *, email: str, country: str = "PL", cn: str = "kidwatch-mdm-push"
) -> None:
    """Krok 1: klucze, CSR i certyfikat wymiany w katalogu `out` (0700)."""
    if "@" not in email:
        raise CertError(f"to nie wyglada na adres e-mail: {email!r}")
    out.mkdir(mode=0o700, parents=True, exist_ok=True)
    existing = [n for n in (PUSH_KEY, PUSH_CSR, PKI_KEY, PKI_CERT) if (out / n).exists()]
    if existing:
        raise CertError(
            f"w {out} sa juz pliki {', '.join(existing)} — nie nadpisuje klucza push. "
            "Uzyj innego katalogu albo przenies stare pliki recznie."
        )
    push_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pki_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    csr = build_csr(push_key, email, country, cn)
    cert = build_exchange_cert(pki_key)
    _write_private(out / PUSH_KEY, _pem_key(push_key))
    _write_private(out / PKI_KEY, _pem_key(pki_key))
    _write_private(out / PUSH_CSR, csr.public_bytes(serialization.Encoding.PEM))
    _write_private(out / PKI_CERT, cert.public_bytes(serialization.Encoding.PEM))
    (out / "email").write_text(email + "\n", encoding="utf-8")


def sign_request_body(out: Path, email: str) -> dict[str, str]:
    """Cialo zapytania: CSR i certyfikat jako base64 z PEM-a — dokladnie jak w mdmctl."""
    return {
        "csr": base64.b64encode((out / PUSH_CSR).read_bytes()).decode("ascii"),
        "email": email,
        "key": MDMCERT_API_KEY,
        "encrypt": base64.b64encode((out / PKI_CERT).read_bytes()).decode("ascii"),
    }


def send_request(out: Path, *, client: httpx.Client | None = None) -> None:
    """Krok 2: wysylka do mdmcert.download. Odpowiedz przychodzi mailem."""
    email = (out / "email").read_text(encoding="utf-8").strip()
    own = client is None
    client = client or httpx.Client(timeout=30)
    try:
        resp = client.post(
            SIGN_URL,
            json=sign_request_body(out, email),
            headers={"User-Agent": "kidwatch-mdm/certhelper"},
        )
    finally:
        if own:
            client.close()
    if resp.status_code != 200:
        raise CertError(f"mdmcert.download odpowiedzial HTTP {resp.status_code}: {resp.text[:300]}")
    try:
        body = resp.json()
    except json.JSONDecodeError as exc:
        raise CertError(f"mdmcert.download zwrocil nie-JSON: {resp.text[:300]}") from exc
    # MicroMDM uznaje za sukces wylacznie result == "success". Cokolwiek innego
    # (np. niezarejestrowany e-mail) to porazka, nawet przy HTTP 200. Go dopasowuje
    # pola JSON bez wzgledu na wielkosc liter, wiec wielkosci liter nie znamy.
    fields = {str(k).lower(): v for k, v in body.items()} if isinstance(body, dict) else {}
    if fields.get("result") != "success":
        raise CertError(
            f"mdmcert.download odrzucil wniosek: result={fields.get('result')!r} "
            f"reason={fields.get('reason')!r}"
        )


def _decode_envelope(raw: bytes) -> bytes:
    """Plik z maila to hex (tak czyta go mdmctl). Przyjmujemy tez base64, PEM i DER."""
    text = raw.strip()
    if text.startswith(b"-----BEGIN"):
        return b"PEM:" + text
    try:
        return binascii.unhexlify(b"".join(text.split()))
    except (binascii.Error, ValueError):
        pass
    try:
        return base64.b64decode(b"".join(text.split()), validate=True)
    except (binascii.Error, ValueError):
        pass
    return raw


def _decrypt_openssl(der: bytes, cert_path: Path, key_path: Path) -> bytes:
    """Zapas na szyfr, ktorego nie obsluguje `cryptography` (np. 3DES)."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise CertError("szyfr nieobslugiwany przez cryptography, a openssl nie jest dostepny")
    proc = subprocess.run(  # noqa: S603
        [
            openssl,
            "smime",
            "-decrypt",
            "-inform",
            "DER",
            "-recip",
            str(cert_path),
            "-inkey",
            str(key_path),
        ],
        input=der,
        capture_output=True,
        check=False,
    )
    if proc.returncode != 0:
        raise CertError(
            f"openssl nie odszyfrowal odpowiedzi: {proc.stderr.decode(errors='replace')}"
        )
    return proc.stdout


def decrypt_response(out: Path, encrypted: Path) -> bytes:
    """Krok 4: odszyfrowanie odpowiedzi mdmcert do `push.req` i jego walidacja."""
    target = out / PUSH_REQ
    if target.exists():
        raise CertError(f"{target} juz istnieje — nie nadpisuje")
    cert = x509.load_pem_x509_certificate((out / PKI_CERT).read_bytes())
    key = serialization.load_pem_private_key((out / PKI_KEY).read_bytes(), password=None)
    blob = _decode_envelope(encrypted.read_bytes())
    try:
        if blob.startswith(b"PEM:"):
            content = pkcs7.pkcs7_decrypt_pem(blob[4:], cert, key, [])
            der = None
        else:
            der = blob
            content = pkcs7.pkcs7_decrypt_der(der, cert, key, [])
    except UnsupportedAlgorithm:
        if der is None:
            raise
        content = _decrypt_openssl(der, out / PKI_CERT, out / PKI_KEY)
    except ValueError as exc:
        raise CertError(
            f"to nie jest odpowiedz zaszyfrowana tym certyfikatem wymiany: {exc}"
        ) from exc
    describe_push_request(content)  # rzuca CertError, jesli tresc nie jest wnioskiem
    _write_private(target, content)
    return content


def describe_push_request(content: bytes) -> dict[str, object]:
    """`push.req` to base64 z plista z kluczami PushCertRequestCSR/…CertificateChain/…Signature."""
    try:
        # mdmcert lamie base64 na linie CRLF (styl MIME) — bialy znak usuwamy
        # przed walidacja, inaczej poprawny wniosek wyglada na smieci.
        plist = plistlib.loads(base64.b64decode(b"".join(content.split()), validate=True))
    except (binascii.Error, ValueError, plistlib.InvalidFileException) as exc:
        raise CertError(
            f"odszyfrowana tresc nie jest wnioskiem push (base64 plist): {exc}"
        ) from exc
    missing = {"PushCertRequestCSR", "PushCertCertificateChain", "PushCertSignature"} - set(plist)
    if missing:
        raise CertError(f"wniosek push bez kluczy: {', '.join(sorted(missing))}")
    return plist


def topic_of(cert: x509.Certificate) -> str:
    """Temat APNs to UID w podmiocie certyfikatu, np. com.apple.mgmt.External.<uuid>."""
    for attr in cert.subject.get_attributes_for_oid(NameOID.USER_ID):
        value = str(attr.value)
        if value.startswith(TOPIC_PREFIX):
            return value
    raise CertError(
        f"certyfikat bez tematu {TOPIC_PREFIX}* w UID podmiotu: {cert.subject.rfc4514_string()}"
    )


def check_push_cert(
    cert_pem: bytes, key_pem: bytes, now: dt.datetime | None = None
) -> PushCertInfo:
    """Krok 6: certyfikat od Apple pasuje do klucza push, ma temat i jest wazny."""
    cert = x509.load_pem_x509_certificate(cert_pem)
    key = serialization.load_pem_private_key(key_pem, password=None)
    if cert.public_key().public_numbers() != key.public_key().public_numbers():
        raise CertError("certyfikat NIE pasuje do klucza push — wgrano zly push.req albo zly klucz")
    now = now or dt.datetime.now(dt.UTC)
    if cert.not_valid_after_utc <= now:
        raise CertError(f"certyfikat wygasl {cert.not_valid_after_utc:%Y-%m-%d}")
    return PushCertInfo(
        topic=topic_of(cert),
        not_after=cert.not_valid_after_utc,
        subject=cert.subject.rfc4514_string(),
    )
