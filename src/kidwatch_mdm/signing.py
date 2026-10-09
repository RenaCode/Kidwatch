"""Podpis profilu zapisu certyfikatem TLS serwera (mdm.renacode.com).

Bez podpisu iOS pokazuje profil jako „Niezweryfikowany". Z podpisem
certyfikatem z zaufanego CA (Let's Encrypt przez cert-manager) — jako
„Zweryfikowany" z nazwa domeny. Ten sam pomysl co tools/podpisz_profil.sh dla
profilu DNS, ale tu profil powstaje przy KAZDYM pobraniu (nowa tozsamosc
urzadzenia), wiec podpisujemy w locie.

Certyfikat i klucz czytamy z zamontowanego Sekretu przy kazdym podpisie
(z pamiecia po czasie modyfikacji): cert-manager odnawia certyfikat co ok.
60 dni, a Sekret zamontowany bez subPath kubelet podmienia w dzialajacym
podzie. Wczytanie raz przy starcie podpisywaloby po odnowieniu wygaslym
certyfikatem.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs7

log = logging.getLogger(__name__)


class ProfileSigner:
    def __init__(self, cert_path: Path, key_path: Path) -> None:
        self.cert_path = cert_path
        self.key_path = key_path
        self._lock = threading.Lock()
        self._loaded: tuple[float, float] | None = None
        self._chain: list[x509.Certificate] = []
        self._key = None

    def _load(self) -> None:
        stamp = (self.cert_path.stat().st_mtime, self.key_path.stat().st_mtime)
        if stamp == self._loaded:
            return
        chain = x509.load_pem_x509_certificates(self.cert_path.read_bytes())
        key = serialization.load_pem_private_key(self.key_path.read_bytes(), None)
        if chain[0].public_key().public_numbers() != key.public_key().public_numbers():
            raise ValueError("klucz nie pasuje do certyfikatu podpisu")
        self._chain, self._key, self._loaded = chain, key, stamp
        log.info(
            "podpis profili: %s, wazny do %s",
            chain[0].subject.rfc4514_string(),
            chain[0].not_valid_after_utc,
        )

    def sign(self, data: bytes) -> bytes:
        """CMS SignedData (DER) z trescia w srodku i calym lancuchem certyfikatow."""
        with self._lock:
            self._load()
            builder = (
                pkcs7.PKCS7SignatureBuilder()
                .set_data(data)
                .add_signer(self._chain[0], self._key, hashes.SHA256())
            )
            # Posrednie CA w podpisie: iPad nie musi ich miec, zeby zbudowac
            # sciezke do zaufanego korzenia.
            for cert in self._chain[1:]:
                builder = builder.add_certificate(cert)
            return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])


def build(cert: str | None, key: str | None) -> ProfileSigner | None:
    if cert and key and Path(cert).is_file() and Path(key).is_file():
        return ProfileSigner(Path(cert), Path(key))
    return None
