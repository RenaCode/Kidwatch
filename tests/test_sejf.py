"""Sejf domow (E2, renacode-infra: docs/projekty/kidwatch/architektura-domy.md §3): KEK/DEK, AAD,
rotacja.

Klucze i sekrety wylacznie losowane w tescie (§3.4)."""

from __future__ import annotations

import base64
import secrets

import pytest

from kidwatch import sejf as sejf_mod
from kidwatch.sejf import (
    BrakKek,
    Sejf,
    SejfError,
    kek_id,
    maska,
    odszyfruj_sekrety,
    zaszyfruj_sekrety,
)

pytestmark = pytest.mark.usefixtures("bez_sieci")


def _b64(klucz: bytes) -> str:
    return base64.b64encode(klucz).decode()


def test_kek_ze_srodowiska_i_bledy_bez_wartosci():
    klucz = secrets.token_bytes(32)
    sejf = Sejf.z_srodowiska({"KIDWATCH_KEK": _b64(klucz)})
    assert sejf.kek_id == kek_id(klucz) and len(sejf.kek_id) == 8
    assert _b64(klucz) not in repr(sejf) and klucz.hex() not in repr(sejf)

    with pytest.raises(BrakKek):
        Sejf.z_srodowiska({})
    with pytest.raises(BrakKek):
        Sejf.z_srodowiska({"KIDWATCH_KEK": "  "})
    zly = "to-nie-jest-base64!" + secrets.token_hex(4)
    with pytest.raises(SejfError) as exc:
        Sejf.z_srodowiska({"KIDWATCH_KEK": zly})
    assert zly not in str(exc.value)
    krotki = _b64(secrets.token_bytes(16))
    with pytest.raises(SejfError, match="32 bajty") as exc:
        Sejf.z_srodowiska({"KIDWATCH_KEK": krotki})
    assert krotki not in str(exc.value)


def test_dek_zwiazany_z_domem_i_kluczem():
    sejf = Sejf(secrets.token_bytes(32))
    dek, blob, kid = sejf.nowy_dek(1)
    assert sejf.odpakuj_dek(1, blob, kid) == dek
    # DEK Domu 1 wklejony do Domu 2 — AAD sie nie zgadza.
    with pytest.raises(SejfError, match="nie odszyfrowuje"):
        sejf.odpakuj_dek(2, blob, kid)
    # Podmiana samej kolumny kek_id: klucza o tym id proces nie zna.
    with pytest.raises(SejfError, match="brakuje"):
        sejf.odpakuj_dek(1, blob, "00000000")
    with pytest.raises(SejfError):
        sejf.odpakuj_dek(1, None, kid)


def test_sekrety_zwiazane_z_domem_i_typem():
    dek = secrets.token_bytes(32)
    kanarek = secrets.token_urlsafe(24)
    blob = zaszyfruj_sekrety(dek, 1, "nextdns", {"api_key": kanarek})
    assert kanarek.encode() not in blob
    assert odszyfruj_sekrety(dek, 1, "nextdns", blob) == {"api_key": kanarek}
    for dom, typ in ((2, "nextdns"), (1, "unifi")):
        with pytest.raises(SejfError) as exc:
            odszyfruj_sekrety(dek, dom, typ, blob)
        assert kanarek not in str(exc.value)
    with pytest.raises(SejfError):
        odszyfruj_sekrety(secrets.token_bytes(32), 1, "nextdns", blob)
    assert odszyfruj_sekrety(dek, 1, "nextdns", None) == {}


def test_rotacja_kek_z_kluczem_poprzednim():
    stary, nowy = secrets.token_bytes(32), secrets.token_bytes(32)
    dek, blob, kid = Sejf(stary).nowy_dek(3)
    # Po podmianie KIDWATCH_KEK bez poprzedniego DEK sie nie otwiera...
    with pytest.raises(SejfError, match="KIDWATCH_KEK_POPRZEDNI"):
        Sejf(nowy).odpakuj_dek(3, blob, kid)
    # ...z poprzednim — tak, i przepakowanie daje DEK na nowym kluczu.
    sejf = Sejf.z_srodowiska({"KIDWATCH_KEK": _b64(nowy), "KIDWATCH_KEK_POPRZEDNI": _b64(stary)})
    assert sejf.odpakuj_dek(3, blob, kid) == dek
    nowy_blob, nowy_kid = sejf.przepakuj_dek(3, blob, kid)
    assert nowy_kid == kek_id(nowy)
    assert Sejf(nowy).odpakuj_dek(3, nowy_blob, nowy_kid) == dek
    assert sejf.przepakuj_dek(3, nowy_blob, nowy_kid) is None


def test_maska_nie_zdradza_wartosci():
    klucz = secrets.token_hex(20)
    assert maska(klucz) == f"…{klucz[-4:]}" and klucz[:-4] not in maska(klucz)
    psk = secrets.token_hex(4)
    assert maska(psk) == f"({len(psk)} znakow)"
    pem = "-----BEGIN PRIVATE KEY-----\n" + secrets.token_hex(30) + "\n-----END PRIVATE KEY-----"
    assert maska(pem) == f"({len(pem)} znakow)"


def test_format_jak_secretbox():
    """12 B nonce + szyfrogram z tagiem — jak panel_auth.SecretBox."""
    dek = secrets.token_bytes(32)
    blob = zaszyfruj_sekrety(dek, 1, "ntfy", {"topic": "x"})
    assert len(blob) == sejf_mod._NONCE + len(b'{"topic": "x"}') + 16
