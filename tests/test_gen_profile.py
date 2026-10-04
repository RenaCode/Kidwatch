"""Testy generatora profilu .mobileconfig.

Najwazniejszy test w tym pliku to ten, ktory pilnuje, ze profil BEZ --supervised
nie zawiera kluczy dzialajacych tylko z nadzorem. Wstawienie ich tam nie jest
nieszkodliwe: iPad je zignoruje, a Ty bys myslal, ze DNS jest nieusuwalny.
"""

from __future__ import annotations

import json
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

from gen_profile import (  # noqa: E402
    build_declaration,
    build_profile,
    main,
    slug,
    validate_doh_url,
)

DOH = "https://dns.nextdns.io/abc123/iPad-Kuby"

#: Klucze, ktore wedlug schematu Apple dzialaja WYLACZNIE na urzadzeniu
#: nadzorowanym. Zrodlo podane w docstringu gen_profile.py.
SUPERVISED_ONLY = (
    "ProhibitDisablement",
    "PayloadRemovalDisallowed",
    "allowCloudPrivateRelay",
    "allowVPNCreation",
    "allowUIConfigurationProfileInstallation",
)


def flatten(obj) -> list[str]:
    """Wszystkie nazwy kluczy w calym drzewie plista."""
    keys: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.append(k)
            keys += flatten(v)
    elif isinstance(obj, list):
        for v in obj:
            keys += flatten(v)
    return keys


# ==================================================================== slug
@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("iPad Kuby", "ipad-kuby"),
        ("iPad Michała", "ipad-michala"),
        ("iPad Zosi (nowy)", "ipad-zosi-nowy"),
        ("ŻÓŁĆ", "zolc"),
        ("!!!", "urzadzenie"),
    ],
)
def test_slug_radzi_sobie_z_polskimi_znakami(raw, expected):
    assert slug(raw) == expected


def test_adres_doh_musi_byc_https():
    with pytest.raises(Exception, match="https"):
        validate_doh_url("http://dns.nextdns.io/abc/iPad")
    assert validate_doh_url(DOH) == DOH


# ============================================================ tryb zwykly
def test_profil_bez_nadzoru_ma_payload_dns():
    p = build_profile(name="iPad Kuby", doh_url=DOH)
    assert p["PayloadType"] == "Configuration"
    payloads = p["PayloadContent"]
    assert len(payloads) == 1
    dns = payloads[0]
    assert dns["PayloadType"] == "com.apple.dnsSettings.managed"
    assert dns["DNSSettings"]["DNSProtocol"] == "HTTPS"
    assert dns["DNSSettings"]["ServerURL"] == DOH
    # Jawne false, zeby iPad nie zjechal cicho na DNS operatora.
    assert dns["DNSSettings"]["AllowFailover"] is False


def test_profil_bez_nadzoru_NIE_zawiera_kluczy_wymagajacych_nadzoru():
    """Gdyby je zawieral, iPad by je zignorowal, a Ty bys sadzil, ze dziecko
    nie zdejmie DNS-a."""
    keys = flatten(build_profile(name="iPad Kuby", doh_url=DOH))
    for key in SUPERVISED_ONLY:
        assert key not in keys, f"{key} wymaga nadzoru, a trafil do zwyklego profilu"


def test_opis_profilu_mowi_wprost_ze_da_sie_go_usunac():
    p = build_profile(name="iPad Kuby", doh_url=DOH)
    assert "usuni" in p["PayloadDescription"]


# ======================================================== tryb nadzorowany
def test_profil_nadzorowany_dodaje_wszystkie_blokady():
    p = build_profile(name="iPad Kuby", doh_url=DOH, supervised=True)
    keys = flatten(p)
    for key in SUPERVISED_ONLY:
        assert key in keys, f"brak {key} w profilu nadzorowanym"

    assert p["PayloadRemovalDisallowed"] is True
    dns, restrictions = p["PayloadContent"]
    # ProhibitDisablement jest kluczem POZIOMU PAYLOADU, rodzenstwem DNSSettings —
    # nie jego subkeyem. Poziom pilnuje tests/test_profile_schema.py przeciw
    # oficjalnemu schematowi Apple.
    assert dns["ProhibitDisablement"] is True
    assert "ProhibitDisablement" not in dns["DNSSettings"]
    assert restrictions["PayloadType"] == "com.apple.applicationaccess"
    # Private Relay i VPN to dwie najprostsze drogi obejscia naszego DNS-a.
    assert restrictions["allowCloudPrivateRelay"] is False
    assert restrictions["allowVPNCreation"] is False
    assert restrictions["allowUIConfigurationProfileInstallation"] is False


# ==================================================================== UUID
def test_kazdy_payload_ma_wlasny_unikalny_uuid():
    p = build_profile(name="iPad Kuby", doh_url=DOH, supervised=True)
    uuids = [p["PayloadUUID"]] + [c["PayloadUUID"] for c in p["PayloadContent"]]
    assert len(uuids) == len(set(uuids))


def test_identyfikator_i_uuid_sa_powtarzalne_dla_tego_samego_urzadzenia():
    """Dzieki temu ponowna instalacja AKTUALIZUJE profil, a nie dokleja drugi."""
    a = build_profile(name="iPad Kuby", doh_url=DOH)
    b = build_profile(name="iPad Kuby", doh_url=DOH)
    assert a["PayloadIdentifier"] == b["PayloadIdentifier"]
    assert a["PayloadUUID"] == b["PayloadUUID"]
    assert a["PayloadContent"][0]["PayloadUUID"] == b["PayloadContent"][0]["PayloadUUID"]


def test_rozne_urzadzenia_dostaja_rozne_identyfikatory():
    a = build_profile(name="iPad Kuby", doh_url=DOH)
    b = build_profile(name="iPad Zosi", doh_url="https://dns.nextdns.io/abc123/iPad-Zosi")
    assert a["PayloadIdentifier"] != b["PayloadIdentifier"]
    assert a["PayloadUUID"] != b["PayloadUUID"]


def test_zmiana_adresu_doh_zmienia_uuid_payloadu_dns():
    a = build_profile(name="iPad Kuby", doh_url=DOH)
    b = build_profile(name="iPad Kuby", doh_url="https://dns.nextdns.io/inny/iPad-Kuby")
    assert a["PayloadContent"][0]["PayloadUUID"] != b["PayloadContent"][0]["PayloadUUID"]


# ================================================================ serializacja
def test_plist_zapisuje_sie_i_odczytuje(tmp_path):
    out = tmp_path / "kuba.mobileconfig"
    assert main(["--name", "iPad Kuby", "--doh-url", DOH, "--out", str(out)]) == 0
    loaded = plistlib.loads(out.read_bytes())
    assert loaded["PayloadIdentifier"] == "com.renacode.kidwatch.ipad-kuby"
    assert loaded["PayloadContent"][0]["DNSSettings"]["ServerURL"] == DOH


def test_polskie_znaki_przezywaja_zapis_do_plista(tmp_path):
    out = tmp_path / "michal.mobileconfig"
    main(["--name", "iPad Michała", "--doh-url", DOH, "--out", str(out)])
    loaded = plistlib.loads(out.read_bytes())
    assert "Michała" in loaded["PayloadDisplayName"]


@pytest.mark.skipif(shutil.which("plutil") is None, reason="plutil jest tylko na macOS")
@pytest.mark.parametrize("supervised", [False, True])
def test_plutil_lint_przechodzi(tmp_path, supervised):
    out = tmp_path / "p.mobileconfig"
    argv = ["--name", "iPad Kuby", "--doh-url", DOH, "--out", str(out)]
    if supervised:
        argv.append("--supervised")
    main(argv)
    result = subprocess.run(
        ["plutil", "-lint", str(out)], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "OK" in result.stdout


# =============================================================== deklaracja DDM
def test_deklaracja_ddm_ma_ksztalt_z_przykladu_apple():
    d = build_declaration(name="iPad Kuby", doh_url=DOH)
    assert d["Type"] == "com.apple.configuration.network.dns-settings"
    assert d["Payload"]["DNSSettings"]["DNSProtocol"] == "HTTPS"
    assert d["Payload"]["DNSSettings"]["ServerURL"] == DOH
    assert d["Payload"]["DNSSettings"]["AllowFailover"] is False
    assert "VisibleName" in d["Payload"]  # wymagane przez schemat
    assert "ProhibitDisablement" not in d["Payload"]["DNSSettings"]


def test_deklaracja_ddm_z_nadzorem_dodaje_prohibit():
    d = build_declaration(name="iPad Kuby", doh_url=DOH, supervised=True)
    # Jak w profilu: poziom Payload, nie wnetrze DNSSettings.
    assert d["Payload"]["ProhibitDisablement"] is True
    assert "ProhibitDisablement" not in d["Payload"]["DNSSettings"]


def test_flaga_also_declaration_zapisuje_plik_json(tmp_path):
    out = tmp_path / "kuba.mobileconfig"
    main(["--name", "iPad Kuby", "--doh-url", DOH, "--out", str(out), "--also-declaration"])
    decl = tmp_path / "kuba.mobileconfig.json"
    assert decl.is_file()
    loaded = json.loads(decl.read_text(encoding="utf-8"))
    assert loaded["Type"] == "com.apple.configuration.network.dns-settings"
