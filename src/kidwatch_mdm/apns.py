"""Budzenie iPadow przez APNs.

Push MDM nie niesie zadnej tresci poza PushMagic: mowi tylko „polacz sie
z serwerem". Komendy iPad pobiera sam z /mdm/connect. Dlatego nieudany push
nie gubi komendy — zostaje w kolejce do nastepnego polaczenia.

APNs przyjmuje wylacznie HTTP/2 i uwierzytelnienie certyfikatem klienta
(certyfikat push MDM z identity.apple.com + jego klucz).
"""

from __future__ import annotations

import datetime as dt
import json
import logging
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

import httpx
from cryptography import x509

from .apns_cert import topic_of

log = logging.getLogger(__name__)

PRODUCTION = "https://api.push.apple.com"


@dataclass(frozen=True)
class PushResult:
    ok: bool
    status: int | None
    reason: str | None = None

    @property
    def token_dead(self) -> bool:
        # 410 Unregistered / 400 BadDeviceToken: token nie wroci sam. iPad poda
        # nowy przy nastepnym TokenUpdate (np. po ponownym zapisie).
        return self.status == 410 or self.reason in ("BadDeviceToken", "Unregistered")


class Pusher(Protocol):
    topic: str | None

    def push(self, token: bytes, push_magic: str) -> PushResult: ...

    def expires_at(self) -> dt.datetime | None: ...


class NoPusher:
    """Brak certyfikatu push: serwer dziala (zapis, kolejka), ale nikogo nie budzi."""

    topic = None

    def push(self, token: bytes, push_magic: str) -> PushResult:
        return PushResult(False, None, "brak certyfikatu APNs")

    def expires_at(self) -> dt.datetime | None:
        return None


class ApnsPusher:
    def __init__(
        self,
        cert_path: Path,
        key_path: Path,
        *,
        base_url: str = PRODUCTION,
        client: httpx.Client | None = None,
    ) -> None:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        self.topic = topic_of(cert)
        self._expires = cert.not_valid_after_utc
        self.base_url = base_url.rstrip("/")
        if client is None:
            ctx = ssl.create_default_context()
            ctx.load_cert_chain(str(cert_path), str(key_path))
            client = httpx.Client(http2=True, verify=ctx, timeout=15)
        self._client = client

    def expires_at(self) -> dt.datetime | None:
        return self._expires

    def push(self, token: bytes, push_magic: str) -> PushResult:
        url = f"{self.base_url}/3/device/{token.hex()}"
        headers = {
            "apns-topic": self.topic,
            "apns-push-type": "mdm",
            "apns-priority": "10",
            # Push starszy niz dobe nie ma sensu: iPad i tak polaczy sie sam
            # przy nastepnym pushu albo uzgadnianiu.
            "apns-expiration": str(int(dt.datetime.now(dt.UTC).timestamp()) + 86400),
        }
        try:
            resp = self._client.post(url, headers=headers, content=json.dumps({"mdm": push_magic}))
        except httpx.HTTPError as exc:
            log.warning("APNs: blad polaczenia: %s", exc)
            return PushResult(False, None, f"{type(exc).__name__}: {exc}")
        if resp.status_code == 200:
            return PushResult(True, 200)
        try:
            reason = resp.json().get("reason")
        except ValueError:
            reason = resp.text[:200]
        log.warning("APNs odrzucil push: HTTP %s %s", resp.status_code, reason)
        return PushResult(False, resp.status_code, reason)

    def close(self) -> None:
        self._client.close()
