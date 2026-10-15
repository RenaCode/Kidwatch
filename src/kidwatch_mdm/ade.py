"""Automated Device Enrollment (ADE) przez Apple Business.

Po co: iPad dodany do organizacji i przypisany do tego serwera w Apple Business
sam pobiera profil zapisu w kreatorze konfiguracji — po KAZDYM wymazaniu,
takze po resecie z komputera. Nadzor i profil MDM wracaja bez kabla, a profilu
nie da sie zdjac (`is_mdm_removable: false`).

Trzy czesci:

1. Token serwera (`*.p7m` z panelu Apple Business). Szyfrowany S/MIME do
   certyfikatu, ktory wgrywa sie przy dodawaniu usługi zarzadzania. Po
   odszyfrowaniu: cztery sekrety OAuth1 i data wygasniecia (rok).
2. Klient API mdmenrollment.apple.com (format i obsluga sesji jak w nanodep:
   client/auth.go, client/transport.go). OAuth1 HMAC-SHA1 tylko do /session;
   dalej naglowek X-ADM-Auth-Session, ktory Apple potrafi podmienic w odpowiedzi.
3. Weryfikacja MachineInfo: iPad w kreatorze wysyla POST z plistem (UDID,
   SERIAL) podpisanym CMS certyfikatem urzadzenia od Apple. Podpis i lancuch
   do Apple Root CA sprawdzamy sami (jak MicroMDM mdm/enroll), inaczej znajomosc
   numeru seryjnego wystarczylaby do pobrania tozsamosci MDM iPada dziecka.

Synchronizacja (AdeSync) pilnuje, zeby kazdy iPad z polityki z polem `serial`
mial przypisany NASZ profil ADE, i zglasza zdarzenia, z ktorych Kidwatch robi
alarmy: iPad zniknal z organizacji, stracil profil, przypisanie nie wyszlo.
"""

from __future__ import annotations

import base64
import binascii
import email
import hashlib
import hmac
import json
import logging
import os
import plistlib
import secrets
import shutil
import subprocess
import time
import urllib.parse
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from asn1crypto import cms as asn1_cms
from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from . import apple_ca, profiles
from .policy import Policy, dom_etykiety
from .store import Store, from_iso, iso, now_utc

log = logging.getLogger(__name__)

APPLE_URL = "https://mdmenrollment.apple.com"
#: Wersja protokolu jak w nanodep (DefaultServerProtocolVersion).
SERVER_PROTOCOL_VERSION = "7"
MEDIA_TYPE = "application/json;charset=UTF8"
#: Sciezka, pod ktora iPad w kreatorze pobiera profil zapisu (url w profilu ADE).
ENROLL_PATH = "/mdm/ade/enroll"

KEY_FILE = "ade.key"
CERT_FILE = "kidwatch-mdm-ade.pem"
TOKEN_FILE = "token.json"
DEFAULT_DIR = Path.home() / ".kidwatch-mdm" / "ade"

#: Synchronizacja z Apple: co pol godziny, po bledzie po 5 min. Pelne pobranie
#: listy raz na dobe — kursor `devices/sync` potrafi wygasnac po cichu.
SYNC_SECONDS = 1800
RETRY_SECONDS = 300
FULL_FETCH_EVERY = timedelta(hours=24)

_HASHES = {
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}


class AdeError(RuntimeError):
    def __init__(self, message: str, status: int | None = None, body: str = "") -> None:
        super().__init__(message)
        self.status = status
        self.body = body


class MachineInfoError(ValueError):
    """Zadanie zapisu ADE nie przeszlo weryfikacji — odmawiamy, niczego nie wydajemy."""


# ================================================================== token
@dataclass(frozen=True, repr=False)
class AdeTokens:
    consumer_key: str
    consumer_secret: str
    access_token: str
    access_secret: str
    access_token_expiry: str

    @classmethod
    def from_json(cls, data: dict) -> AdeTokens:
        missing = [k for k in cls.__dataclass_fields__ if not data.get(k)]
        if missing:
            raise AdeError(f"token ADE bez pol: {', '.join(missing)}")
        return cls(**{k: str(data[k]) for k in cls.__dataclass_fields__})

    @classmethod
    def load(cls, path: str | Path) -> AdeTokens:
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2) + "\n"

    def expires_at(self) -> datetime:
        return datetime.fromisoformat(self.access_token_expiry.replace("Z", "+00:00"))

    def __repr__(self) -> str:  # sekrety nie moga trafic do logu przez repr
        return f"AdeTokens(expiry={self.access_token_expiry})"


def _smime_der(raw: bytes) -> bytes:
    """`smime.p7m` z panelu to wiadomosc MIME z cialem base64. Przyjmujemy tez
    goly PEM, base64 i DER — rozne przegladarki zapisuja plik roznie."""
    text = raw.strip()
    if text.startswith(b"-----BEGIN"):
        lines = [ln for ln in text.splitlines() if not ln.startswith(b"-----")]
        return base64.b64decode(b"".join(lines))
    if b"Content-Type:" in text[:400] or b"MIME-Version:" in text[:400]:
        msg = email.message_from_bytes(text)
        payload = msg.get_payload(decode=True)
        if isinstance(payload, bytes) and payload:
            return payload
    try:
        return base64.b64decode(b"".join(text.split()), validate=True)
    except (binascii.Error, ValueError):
        return raw


def _token_json(decrypted: bytes) -> dict:
    """Odszyfrowana tresc to znow MIME: naglowki, pusta linia, JSON miedzy
    -----BEGIN MESSAGE----- i -----END MESSAGE----- (nanodep tokenpki/parse.go)."""
    text = decrypted.decode("utf-8", errors="replace")
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise AdeError("odszyfrowany token nie zawiera JSON-a")
    try:
        data = json.loads(text[start : end + 1])
    except ValueError as exc:
        raise AdeError(f"odszyfrowany token nie jest poprawnym JSON-em: {exc}") from exc
    if not isinstance(data, dict):
        raise AdeError("odszyfrowany token nie jest obiektem JSON")
    return data


def decrypt_server_token(p7m: bytes, cert_path: Path, key_path: Path) -> AdeTokens:
    """Token serwera z panelu Apple Business -> sekrety OAuth1."""
    cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    der = _smime_der(p7m)
    try:
        content = pkcs7.pkcs7_decrypt_der(der, cert, key, [])
    except UnsupportedAlgorithm:
        content = _decrypt_openssl(der, cert_path, key_path)
    except ValueError as exc:
        # Apple koduje koperte BER z nieokreslona dlugoscia (30 80), a
        # cryptography przyjmuje tylko DER — openssl czyta oba.
        try:
            content = _decrypt_openssl(der, cert_path, key_path)
        except AdeError as exc2:
            raise AdeError(
                f"to nie jest token zaszyfrowany tym certyfikatem ({cert_path.name}): "
                f"{exc}; {exc2}"
            ) from exc
    return AdeTokens.from_json(_token_json(content))


def _decrypt_openssl(der: bytes, cert_path: Path, key_path: Path) -> bytes:
    """Zapas na szyfr albo kodowanie BER, ktorych nie obsluguje `cryptography`
    (np. 3DES, koperta z nieokreslona dlugoscia — tak przychodzi token Apple)."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise AdeError("szyfr tokenu nieobslugiwany przez cryptography, a openssl niedostepny")
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
        raise AdeError(f"openssl nie odszyfrowal tokenu: {proc.stderr.decode(errors='replace')}")
    return proc.stdout


def write_private(path: Path, data: str, *, force: bool = False) -> None:
    """Zapis 0600. Bez `force` nie nadpisuje — token odnawia sie raz w roku
    i nadpisanie przez pomylke to utrata dzialajacego tokenu."""
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if force else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(data)


# ================================================================= OAuth1
def _enc(value: str) -> str:
    return urllib.parse.quote(value, safe="~-._")


def oauth1_header(
    method: str,
    url: str,
    tokens: AdeTokens,
    *,
    nonce: str | None = None,
    timestamp: int | None = None,
    with_version: bool = True,
) -> str:
    """Naglowek Authorization OAuth 1.0a z podpisem HMAC-SHA1 (RFC 5849).
    Apple wymaga HMAC-SHA1 (nanodep client/auth.go)."""
    parsed = urllib.parse.urlsplit(url)
    base_url = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{parsed.path or '/'}"
    oauth = {
        "oauth_consumer_key": tokens.consumer_key,
        "oauth_nonce": nonce or secrets.token_hex(16),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(timestamp if timestamp is not None else int(time.time())),
        "oauth_token": tokens.access_token,
    }
    # oauth_version wysyla nanodep (gomodule/oauth1); False tylko dla wektora
    # testowego z RFC 5849, ktory go nie ma.
    if with_version:
        oauth["oauth_version"] = "1.0"
    params = [*urllib.parse.parse_qsl(parsed.query, keep_blank_values=True), *oauth.items()]
    normalized = "&".join(f"{k}={v}" for k, v in sorted((_enc(k), _enc(v)) for k, v in params))
    base = "&".join((method.upper(), _enc(base_url), _enc(normalized)))
    key = f"{_enc(tokens.consumer_secret)}&{_enc(tokens.access_secret)}"
    digest = hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()
    oauth["oauth_signature"] = base64.b64encode(digest).decode()
    return "OAuth " + ", ".join(f'{k}="{_enc(v)}"' for k, v in sorted(oauth.items()))


# ================================================================== klient
class AdeClient:
    """Klient API ADE. Sesja w pamieci: po restarcie poda bierzemy nowa."""

    def __init__(
        self,
        tokens: AdeTokens,
        *,
        base_url: str = APPLE_URL,
        http: httpx.Client | None = None,
    ) -> None:
        self.tokens = tokens
        self.base_url = base_url.rstrip("/")
        self.http = http or httpx.Client(timeout=30.0)
        self.session: str | None = None

    def _headers(self) -> dict[str, str]:
        return {
            "X-Server-Protocol-Version": SERVER_PROTOCOL_VERSION,
            "User-Agent": "kidwatch-mdm",
        }

    def _new_session(self) -> str:
        url = f"{self.base_url}/session"
        headers = {
            **self._headers(),
            "Authorization": oauth1_header("GET", url, self.tokens),
            "Content-Type": MEDIA_TYPE,
        }
        resp = self.http.get(url, headers=headers)
        if resp.status_code != 200:
            # Tresc bledu Apple to krotki kod (np. "token_rejected"), bez sekretow.
            raise AdeError(
                f"Apple odrzucil token ADE przy /session: {resp.status_code} {resp.text[:200]}",
                resp.status_code,
                resp.text[:500],
            )
        token = (resp.json() or {}).get("auth_session_token")
        if not token:
            raise AdeError("Apple nie zwrocil auth_session_token")
        self.session = str(token)
        return self.session

    def request(self, method: str, path: str, body: Any = None) -> Any:
        url = f"{self.base_url}{path}"
        content = None if body is None else json.dumps(body).encode()
        for attempt in (1, 2):
            if self.session is None:
                self._new_session()
            headers = {
                **self._headers(),
                "X-ADM-Auth-Session": self.session or "",
                "Accept": MEDIA_TYPE,
            }
            if content is not None:
                headers["Content-Type"] = MEDIA_TYPE
            resp = self.http.request(method, url, content=content, headers=headers)
            # Apple potrafi przedluzyc sesje, podajac nowy token w odpowiedzi.
            if renewed := resp.headers.get("X-ADM-Auth-Session"):
                self.session = renewed
            expired = resp.status_code == 401 or (
                resp.status_code == 403 and "FORBIDDEN" in resp.text
            )
            if expired and attempt == 1:
                self.session = None
                continue
            if resp.status_code != 200:
                raise AdeError(
                    f"{method} {path}: {resp.status_code} {resp.text[:200]}",
                    resp.status_code,
                    resp.text[:500],
                )
            return resp.json() if resp.content else None
        raise AdeError(f"{method} {path}: sesja odrzucona dwa razy")  # pragma: no cover

    # --------------------------------------------------------- wywolania
    def account(self) -> dict:
        return self.request("GET", "/account")

    def fetch_devices(self) -> tuple[list[dict], str | None]:
        """Pelna lista urzadzen przypisanych do tego serwera i kursor do sync."""
        devices: list[dict] = []
        cursor: str | None = None
        for _ in range(1000):
            body: dict[str, Any] = {"limit": 1000}
            if cursor:
                body["cursor"] = cursor
            out = self.request("POST", "/server/devices", body) or {}
            devices += out.get("devices") or []
            cursor = out.get("cursor") or cursor
            if not out.get("more_to_follow"):
                return devices, cursor
        raise AdeError("server/devices: nie konczy sie stronicowanie")

    def sync_devices(self, cursor: str) -> tuple[list[dict], str]:
        """Zmiany od kursora (op_type: added/modified/deleted)."""
        devices: list[dict] = []
        for _ in range(1000):
            out = self.request("POST", "/devices/sync", {"cursor": cursor, "limit": 1000}) or {}
            devices += out.get("devices") or []
            cursor = out.get("cursor") or cursor
            if not out.get("more_to_follow"):
                return devices, cursor
        raise AdeError("devices/sync: nie konczy sie stronicowanie")

    def define_profile(self, profile: dict) -> str:
        out = self.request("POST", "/profile", profile) or {}
        uuid = out.get("profile_uuid")
        if not uuid:
            raise AdeError("Apple nie zwrocil profile_uuid")
        return str(uuid)

    def assign_profile(self, profile_uuid: str, serials: list[str]) -> dict[str, str]:
        out = (
            self.request(
                "PUT", "/profile/devices", {"profile_uuid": profile_uuid, "devices": serials}
            )
            or {}
        )
        return {str(k): str(v) for k, v in (out.get("devices") or {}).items()}


def is_cursor_error(exc: AdeError) -> bool:
    return exc.status == 400 and any(
        code in exc.body for code in ("EXHAUSTED_CURSOR", "EXPIRED_CURSOR", "INVALID_CURSOR")
    )


# ================================================================ profil ADE
def build_profile(policy: Policy, public_url: str) -> dict:
    """Profil ADE: dokad iPad ma sie zapisac i jak. Pola: Apple `Profile`
    (nanodep godep/schema.go)."""
    ade = policy.ade
    profile: dict[str, Any] = {
        "profile_name": f"{policy.org} kidwatch-mdm",
        "url": f"{public_url.rstrip('/')}{ENROLL_PATH}",
        "is_supervised": True,
        "is_mandatory": True,
        # Profilu MDM nie da sie zdjac w Ustawieniach (dziala tylko z nadzorem).
        "is_mdm_removable": False,
        # Kreator czeka, az serwer wgra ograniczenia i wysle DeviceConfigured —
        # dziecko nie dostaje ekranu domowego bez blokad.
        "await_device_configured": True,
        "skip_setup_items": list(ade.skip_setup_items),
        "department": ade.department or policy.org,
    }
    if ade.support_phone_number:
        profile["support_phone_number"] = ade.support_phone_number
    if ade.support_email_address:
        profile["support_email_address"] = ade.support_email_address
    return profile


# ============================================================ MachineInfo
def _load_pem_list(pems: tuple[str, ...]) -> list[x509.Certificate]:
    return [x509.load_pem_x509_certificate(p.encode()) for p in pems]


_APPLE_ROOTS = _load_pem_list(apple_ca.ROOTS)
_APPLE_INTERMEDIATES = _load_pem_list(apple_ca.INTERMEDIATES)


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    """Podpis certyfikatu kluczem wystawcy. Recznie, bo `cryptography`
    odmawia SHA-1 w verify_directly_issued_by, a lancuch iPhone Device CA
    jest SHA-1. Daty ignorujemy: Apple iPhone Device CA wygaslo w 2014,
    a iOS dalej nim podpisuje (tak samo MicroMDM)."""
    if cert.issuer != issuer.subject:
        return False
    key = issuer.public_key()
    algo = cert.signature_hash_algorithm
    if algo is None:
        return False
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), algo)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(algo))
        else:
            return False
    except InvalidSignature:
        return False
    return True


def verify_apple_chain(
    leaf: x509.Certificate,
    extra: list[x509.Certificate],
    roots: list[x509.Certificate] | None = None,
    intermediates: list[x509.Certificate] | None = None,
) -> None:
    """Lancuch od certyfikatu urzadzenia do jednego z korzeni Apple."""
    roots = _APPLE_ROOTS if roots is None else roots
    pool = [*extra, *(_APPLE_INTERMEDIATES if intermediates is None else intermediates)]
    cert = leaf
    for _ in range(6):
        if any(_issued_by(cert, root) for root in roots):
            return
        parent = next((c for c in pool if c != cert and _issued_by(cert, c)), None)
        if parent is None:
            raise MachineInfoError(
                f"certyfikat {cert.subject.rfc4514_string()} nie prowadzi do Apple Root CA"
            )
        cert = parent
    raise MachineInfoError("za dlugi lancuch certyfikatow")


def _verify_signer(signer, cert: x509.Certificate, content: bytes) -> None:
    digest_name = signer["digest_algorithm"]["algorithm"].native
    if digest_name not in _HASHES:
        raise MachineInfoError(f"nieobslugiwany skrot {digest_name}")
    hash_cls = _HASHES[digest_name]
    signed_attrs = signer["signed_attrs"]
    if signed_attrs.native is not None and len(signed_attrs):
        digests = [
            a["values"][0].native for a in signed_attrs if a["type"].native == "message_digest"
        ]
        if len(digests) != 1 or digests[0] != hashlib.new(hash_cls.name, content).digest():
            raise MachineInfoError("skrot w podpisie nie zgadza sie z MachineInfo")
        to_verify = b"\x31" + signed_attrs.dump()[1:]
    else:
        to_verify = content
    key = cert.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            key.verify(signer["signature"].native, to_verify, padding.PKCS1v15(), hash_cls())
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signer["signature"].native, to_verify, ec.ECDSA(hash_cls()))
        else:
            raise MachineInfoError("nieobslugiwany typ klucza urzadzenia")
    except InvalidSignature as exc:
        raise MachineInfoError("podpis MachineInfo jest niepoprawny") from exc


def parse_machine_info(
    body: bytes,
    *,
    roots: list[x509.Certificate] | None = None,
    intermediates: list[x509.Certificate] | None = None,
) -> dict:
    """POST z kreatora -> slownik MachineInfo. Rzuca MachineInfoError."""
    try:
        info = asn1_cms.ContentInfo.load(body)
        if info["content_type"].native != "signed_data":
            raise MachineInfoError("cialo nie jest podpisem CMS SignedData")
        signed = info["content"]
        content = signed["encap_content_info"]["content"].native
        signers = signed["signer_infos"]
        if len(signers) != 1:
            raise MachineInfoError(f"oczekiwano jednego podpisujacego, jest {len(signers)}")
        signer = signers[0]
        raw_certs = [c.chosen for c in signed["certificates"] if c.name == "certificate"]
    except MachineInfoError:
        raise
    except (ValueError, TypeError, KeyError) as exc:
        raise MachineInfoError(f"nieczytelne zadanie zapisu ADE: {exc}") from exc
    if not isinstance(content, bytes) or not content:
        raise MachineInfoError("podpis bez tresci MachineInfo")
    sid = signer["sid"]
    if sid.name != "issuer_and_serial_number":
        raise MachineInfoError("podpisujacy wskazany inaczej niz wystawca+numer seryjny")
    serial = sid.chosen["serial_number"].native
    issuer_der = sid.chosen["issuer"].dump()
    # Dopasowanie na strukturach asn1crypto (jak pki.verify_mdm_signature):
    # ponowne kodowanie nazwy przez cryptography moglo by sie roznic bajtowo.
    match = [c for c in raw_certs if c.serial_number == serial and c.issuer.dump() == issuer_der]
    if not match:
        raise MachineInfoError("w podpisie brak certyfikatu urzadzenia")
    leaf = x509.load_der_x509_certificate(match[0].dump())
    others = [x509.load_der_x509_certificate(c.dump()) for c in raw_certs if c is not match[0]]
    _verify_signer(signer, leaf, content)
    verify_apple_chain(leaf, others, roots, intermediates)
    try:
        machine = plistlib.loads(content)
    except (plistlib.InvalidFileException, ValueError) as exc:
        raise MachineInfoError(f"MachineInfo nie jest plistem: {exc}") from exc
    if not isinstance(machine, dict) or not machine.get("SERIAL") or not machine.get("UDID"):
        raise MachineInfoError("MachineInfo bez SERIAL albo UDID")
    return machine


# ========================================================= synchronizacja
#: Stany iPada z polityki wzgledem ADE (setting `ade_state:<etykieta>`).
OK, MISSING, UNASSIGNED, ASSIGN_FAILED = "ok", "missing", "unassigned", "assign_failed"


class AdeSync:
    """Uzgadnianie organizacji z polityka. Bez sekretow w zdarzeniach i logu."""

    def __init__(
        self,
        *,
        store: Store,
        policy: Policy,
        public_url: str,
        client: AdeClient,
    ) -> None:
        self.store = store
        self.policy = policy
        self.public_url = public_url
        self.client = client
        self.next_sync = 0.0
        self.last_error: str | None = None

    @property
    def tokens(self) -> AdeTokens:
        return self.client.tokens

    def health(self, now: datetime | None = None) -> dict:
        now = now or now_utc()
        expires = self.tokens.expires_at()
        return {
            "configured": True,
            "expires_at": expires.isoformat(),
            "days_left": (expires - now).days,
            "profile_uuid": self.store.setting("ade_profile_uuid"),
            "last_sync_ok_at": self.store.setting("ade_last_sync_ok_at"),
            "last_sync_error": self.last_error,
            # Same liczby: /api/health jest bez tokenu, a etykiety dzieci innych
            # domow nie wychodza poza ich dom (E3b). Szczegoly ida zdarzeniami.
            "devices": self._state_counts(),
        }

    def _state_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for label, dev in self.policy.devices.items():
            if dev.serial:
                state = self.store.setting(f"ade_state:{label}") or "unknown"
                counts[state] = counts.get(state, 0) + 1
        return counts

    def _ensure_profile(self) -> str:
        profile = build_profile(self.policy, self.public_url)
        digest = profiles.content_hash(profile)
        uuid = self.store.setting("ade_profile_uuid")
        if uuid and self.store.setting("ade_profile_hash") == digest:
            return uuid
        uuid = self.client.define_profile(profile)
        self.store.set_setting("ade_profile_uuid", uuid)
        self.store.set_setting("ade_profile_hash", digest)
        # Nowy profil = kazdy iPad trzeba przypisac od nowa (stary UUID w Apple
        # zostaje, ale nie ma juz naszej tresci).
        self.store.event("ade_profile_defined", detail={"profile_uuid": uuid})
        log.info("ADE: zdefiniowany profil %s", uuid)
        return uuid

    def _devices(self, now: datetime) -> dict[str, dict]:
        cache: dict[str, dict] = self.store.setting("ade_devices") or {}
        cursor = self.store.setting("ade_cursor")
        full_at = from_iso(self.store.setting("ade_full_fetch_at"))
        changes: list[dict] | None = None
        if cursor and full_at and now - full_at < FULL_FETCH_EVERY:
            try:
                changes, cursor = self.client.sync_devices(cursor)
            except AdeError as exc:
                if not is_cursor_error(exc):
                    raise
                log.info("ADE: kursor nieaktualny (%s) — pelne pobranie", exc.status)
        if changes is None:
            devices, cursor = self.client.fetch_devices()
            cache = {}
            changes = devices
            self.store.set_setting("ade_full_fetch_at", iso(now))
        for dev in changes:
            serial = str(dev.get("serial_number") or "").upper()
            if not serial:
                continue
            if dev.get("op_type") == "deleted":
                cache.pop(serial, None)
            else:
                cache[serial] = {
                    k: dev.get(k)
                    for k in (
                        "model",
                        "device_family",
                        "os",
                        "profile_status",
                        "profile_uuid",
                        "profile_assign_time",
                        "op_type",
                    )
                }
        self.store.set_setting("ade_devices", cache)
        if cursor:
            self.store.set_setting("ade_cursor", cursor)
        return cache

    def _transition(self, label: str, serial: str, state: str, detail: dict | None = None) -> None:
        key = f"ade_state:{label}"
        before = self.store.setting(key)
        if before == state:
            return
        self.store.set_setting(key, state)
        info = {"label": label, "serial": serial, "before": before, **(detail or {})}
        # Zdarzenie w domu wpisu (E3b): alarm dostaje czujka tego domu, nie
        # wszystkie domy instancji.
        dom = dom_etykiety(label)
        kind = {
            MISSING: "ade_device_missing",
            ASSIGN_FAILED: "ade_assign_failed",
            OK: "ade_device_ready",
        }.get(state)
        if state == UNASSIGNED and before == OK:
            kind = "ade_profile_lost"
        if kind:
            self.store.event(kind, detail=info, dom_id=dom)

    def sync(self, now: datetime | None = None) -> dict[str, int]:
        now = now or now_utc()
        stats = {"devices": 0, "assigned": 0, "missing": 0, "failed": 0}
        uuid = self._ensure_profile()
        cache = self._devices(now)
        stats["devices"] = len(cache)
        to_assign: dict[str, str] = {}
        for label, dev in self.policy.devices.items():
            if not dev.serial:
                continue
            entry = cache.get(dev.serial)
            if entry is None:
                stats["missing"] += 1
                self._transition(label, dev.serial, MISSING)
                continue
            if entry.get("profile_uuid") == uuid and entry.get("profile_status") in (
                "assigned",
                "pushed",
            ):
                self._transition(label, dev.serial, OK)
                continue
            if self.store.setting(f"ade_state:{label}") == OK:
                self._transition(
                    label, dev.serial, UNASSIGNED, {"profile_status": entry.get("profile_status")}
                )
            to_assign[dev.serial] = label
        if to_assign:
            result = self.client.assign_profile(uuid, sorted(to_assign))
            for serial, label in to_assign.items():
                status = result.get(serial) or result.get(serial.lower()) or "?"
                if status == "SUCCESS":
                    stats["assigned"] += 1
                    cache[serial] = {
                        **cache[serial],
                        "profile_uuid": uuid,
                        "profile_status": "assigned",
                    }
                    self._transition(label, serial, OK, {"assigned": True})
                else:
                    stats["failed"] += 1
                    self._transition(label, serial, ASSIGN_FAILED, {"status": status})
            self.store.set_setting("ade_devices", cache)
        known = {d.serial for d in self.policy.devices.values() if d.serial}
        reported = set(self.store.setting("ade_unknown_reported") or [])
        for serial in sorted(set(cache) - known - reported):
            # Urzadzenie przypisane do tego serwera w Apple Business, ale nie
            # w polityce: zapis i tak zostanie odrzucony (brak etykiety).
            self.store.event(
                "ade_unknown_device", detail={"serial": serial, "model": cache[serial].get("model")}
            )
            reported.add(serial)
        self.store.set_setting("ade_unknown_reported", sorted(reported & set(cache)))
        self.store.set_setting("ade_last_sync_ok_at", iso(now))
        return stats


def sync_step(ade: AdeSync, now_mono: float) -> None:
    """Krok petli serwera: synchronizacja co SYNC_SECONDS, po bledzie szybciej."""
    if now_mono < ade.next_sync:
        return
    try:
        stats = ade.sync()
    except Exception as exc:
        # Blad Apple nie moze zatrzymac petli MDM — iPady juz zapisane dzialaja
        # bez ADE. Stan bledu idzie do /api/health (czujka Kidwatch).
        log.exception("ADE: synchronizacja nieudana")
        ade.last_error = f"{type(exc).__name__}: {exc}"[:300]
        ade.next_sync = now_mono + RETRY_SECONDS
        return
    log.info("ADE: %s", stats)
    ade.last_error = None
    ade.next_sync = now_mono + SYNC_SECONDS


def report_unconfigured(store: Store, policy: Policy) -> None:
    """Polityka ma numery seryjne, a tokenu ADE brak: iPad po wymazaniu nie
    wroci do MDM. Zdarzenie raz na zmiane listy etykiet."""
    labels = sorted(label for label, d in policy.devices.items() if d.serial)
    before = store.setting("ade_unconfigured_reported")
    if labels and before != labels:
        store.event("ade_not_configured", detail={"labels": labels})
    store.set_setting("ade_unconfigured_reported", labels or None)


def tokens_from_file(path: str | None) -> AdeTokens | None:
    """Sekret jest opcjonalny: brak pliku = ADE wylaczone, serwer dziala dalej."""
    if not path or not Path(path).is_file():
        return None
    return AdeTokens.load(path)


def generate_keypair(directory: Path, org: str = "RenaCode") -> Path:
    """Klucz i certyfikat do wgrania w Apple Business (gdyby trzeba od nowa)."""
    from cryptography.x509.oid import NameOID

    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    key_path, cert_path = directory / KEY_FILE, directory / CERT_FILE
    for p in (key_path, cert_path):
        if p.exists():
            raise FileExistsError(f"{p} juz istnieje — nie nadpisuje")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, "kidwatch-mdm ADE"),
        ]
    )
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    write_private(
        key_path,
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode(),
    )
    write_private(cert_path, cert.public_bytes(serialization.Encoding.PEM).decode())
    return cert_path


__all__ = [
    "AdeClient",
    "AdeError",
    "AdeSync",
    "AdeTokens",
    "MachineInfoError",
    "build_profile",
    "decrypt_server_token",
    "parse_machine_info",
]
