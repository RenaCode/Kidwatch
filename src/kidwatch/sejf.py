"""Sejf sekretow domow: szyfrowanie kopertowe KEK -> DEK -> sekrety integracji.

Projekt: renacode-infra: docs/projekty/kidwatch/architektura-domy.md §3, runbook:
renacode-infra: docs/projekty/kidwatch/sejf-domow.md.

    KEK (32 B, Sekret k8s: kidwatch-secrets/KIDWATCH_KEK, base64)
     └─ DEK domu (32 B, losowy)    domy.dek_zaszyfrowany
         = AES-GCM(KEK, aad="kidwatch:dom:<id>:dek:<kek_id>")
         └─ sekrety integracji     integracje.sekrety
             = AES-GCM(DEK, aad="kidwatch:dom:<id>:integracja:<typ>")

Format szyfrogramu jak `panel_auth.SecretBox`: 12 B nonce + szyfrogram z tagiem.

AAD wiaze szyfrogram z domem i typem integracji: blob z wiersza Domu 1
wklejony do Domu 2 (blad w kodzie, reczna edycja bazy) konczy sie bledem,
a nie cichym uzyciem cudzego klucza. `kek_id` w AAD DEK-a wiaze go z kluczem,
ktorym go zapakowano — podmiana samej kolumny `kek_id` tez nie przejdzie.

Rotacja: `KIDWATCH_KEK_POPRZEDNI` (opcjonalny) otwiera DEK-i zapakowane
starym kluczem; `kidwatch klucze-rotuj` przepakowuje je nowym (sekrety
integracji zostaja nietkniete), potem klucz poprzedni usuwa sie z Sekretu.

Zaden komunikat bledu nie zawiera klucza ani wartosci sekretu.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
from collections.abc import Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEK_ENV = "KIDWATCH_KEK"
KEK_POPRZEDNI_ENV = "KIDWATCH_KEK_POPRZEDNI"
_NONCE = 12


class SejfError(RuntimeError):
    """Sekretu nie da sie zapakowac ani odpakowac. Bez wartosci w tresci."""


class BrakKek(SejfError):
    """Brak KIDWATCH_KEK — domy w trybie `baza` nie startuja (§3.1)."""


def kek_id(klucz: bytes) -> str:
    """Pierwsze 8 znakow SHA-256 klucza: rozpoznaje klucz, nie zdradza go."""
    return hashlib.sha256(klucz).hexdigest()[:8]


def _klucz_z_base64(tekst: str, nazwa: str) -> bytes:
    try:
        klucz = base64.b64decode(tekst.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SejfError(f"{nazwa} nie jest poprawnym base64") from exc
    if len(klucz) != 32:
        raise SejfError(f"{nazwa} musi miec 32 bajty (openssl rand -base64 32), "
                        f"ma {len(klucz)}")
    return klucz


def aad_dek(dom_id: int, kid: str) -> bytes:
    return f"kidwatch:dom:{int(dom_id)}:dek:{kid}".encode()


def aad_integracji(dom_id: int, typ: str) -> bytes:
    return f"kidwatch:dom:{int(dom_id)}:integracja:{typ}".encode()


def _szyfruj(klucz: bytes, dane: bytes, aad: bytes) -> bytes:
    nonce = os.urandom(_NONCE)
    return nonce + AESGCM(klucz).encrypt(nonce, dane, aad)


def _odszyfruj(klucz: bytes, blob: bytes, aad: bytes) -> bytes:
    if not isinstance(blob, (bytes, bytearray)) or len(blob) <= _NONCE:
        raise InvalidTag
    return AESGCM(klucz).decrypt(bytes(blob[:_NONCE]), bytes(blob[_NONCE:]), aad)


class Sejf:
    """Klucze KEK procesu: biezacy (nim pakujemy) i opcjonalny poprzedni
    (tylko do odpakowania DEK-ow sprzed rotacji)."""

    def __init__(self, biezacy: bytes, poprzedni: bytes | None = None) -> None:
        if len(biezacy) != 32 or (poprzedni is not None and len(poprzedni) != 32):
            raise SejfError("klucz KEK musi miec 32 bajty")
        self._klucze: dict[str, bytes] = {kek_id(biezacy): biezacy}
        if poprzedni is not None and poprzedni != biezacy:
            self._klucze.setdefault(kek_id(poprzedni), poprzedni)
        self.kek_id = kek_id(biezacy)

    def __repr__(self) -> str:  # nigdy z kluczem
        return f"Sejf(kek_id={self.kek_id!r}, klucze={sorted(self._klucze)})"

    @classmethod
    def z_srodowiska(cls, env: Mapping[str, str] | None = None) -> Sejf:
        """KIDWATCH_KEK (+ KIDWATCH_KEK_POPRZEDNI). BrakKek, gdy nie ma
        klucza; SejfError, gdy jest, ale zly."""
        env = os.environ if env is None else env
        tekst = (env.get(KEK_ENV) or "").strip()
        if not tekst:
            raise BrakKek(f"brak {KEK_ENV} w srodowisku (Sekret kidwatch-secrets)")
        poprzedni_tekst = (env.get(KEK_POPRZEDNI_ENV) or "").strip()
        poprzedni = (_klucz_z_base64(poprzedni_tekst, KEK_POPRZEDNI_ENV)
                     if poprzedni_tekst else None)
        return cls(_klucz_z_base64(tekst, KEK_ENV), poprzedni)

    @property
    def znane_kek_id(self) -> frozenset[str]:
        return frozenset(self._klucze)

    # ------------------------------------------------------------------ DEK
    def nowy_dek(self, dom_id: int) -> tuple[bytes, bytes, str]:
        """(DEK jawny, DEK zapakowany biezacym KEK, kek_id)."""
        dek = AESGCM.generate_key(bit_length=256)
        return dek, self.zapakuj_dek(dom_id, dek), self.kek_id

    def zapakuj_dek(self, dom_id: int, dek: bytes) -> bytes:
        return _szyfruj(self._klucze[self.kek_id], dek, aad_dek(dom_id, self.kek_id))

    def odpakuj_dek(self, dom_id: int, blob: bytes | None, kid: str | None) -> bytes:
        if not blob or not kid:
            raise SejfError(f"dom {dom_id} nie ma klucza danych (DEK)")
        klucz = self._klucze.get(kid)
        if klucz is None:
            raise SejfError(
                f"DEK domu {dom_id} zapakowany kluczem {kid}, a proces zna "
                f"{', '.join(sorted(self._klucze))} — brakuje {KEK_ENV} albo "
                f"{KEK_POPRZEDNI_ENV} sprzed rotacji")
        try:
            dek = _odszyfruj(klucz, blob, aad_dek(dom_id, kid))
        except InvalidTag as exc:
            raise SejfError(f"DEK domu {dom_id} nie odszyfrowuje sie (zly klucz albo "
                            f"szyfrogram z innego domu)") from exc
        if len(dek) != 32:
            raise SejfError(f"DEK domu {dom_id} ma zla dlugosc")
        return dek

    def przepakuj_dek(self, dom_id: int, blob: bytes | None,
                      kid: str | None) -> tuple[bytes, str] | None:
        """DEK zapakowany biezacym KEK albo None, gdy juz jest."""
        if kid == self.kek_id:
            # Sprawdzamy, ze sie otwiera — rotacja nie moze przepuscic zepsutego.
            self.odpakuj_dek(dom_id, blob, kid)
            return None
        return self.zapakuj_dek(dom_id, self.odpakuj_dek(dom_id, blob, kid)), self.kek_id


# ============================================================ sekrety integracji
def zaszyfruj_sekrety(dek: bytes, dom_id: int, typ: str, sekrety: Mapping[str, str]) -> bytes:
    dane = json.dumps(dict(sorted(sekrety.items())), ensure_ascii=False).encode()
    return _szyfruj(dek, dane, aad_integracji(dom_id, typ))


def odszyfruj_sekrety(dek: bytes, dom_id: int, typ: str, blob: bytes | None) -> dict[str, str]:
    if not blob:
        return {}
    try:
        dane = _odszyfruj(dek, blob, aad_integracji(dom_id, typ))
    except InvalidTag as exc:
        raise SejfError(f"sekrety integracji {typ} domu {dom_id} nie odszyfrowuja sie "
                        f"(inny klucz domu albo szyfrogram z innego domu/typu)") from exc
    wynik = json.loads(dane)
    if not isinstance(wynik, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in wynik.items()):
        raise SejfError(f"sekrety integracji {typ} domu {dom_id} maja zly ksztalt")
    return wynik


def maska(wartosc: str) -> str:
    """Do panelu i CLI: ostatnie 4 znaki dlugich wartosci, dlugosc krotkich.
    Klucz PEM (wielolinijkowy) — tylko dlugosc."""
    if "\n" in wartosc or len(wartosc) < 16:
        return f"({len(wartosc)} znakow)"
    return f"…{wartosc[-4:]}"
