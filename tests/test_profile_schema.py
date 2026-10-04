"""Walidacja wygenerowanego profilu przeciw OFICJALNEMU schematowi Apple.

Po co, skoro jest `plutil -lint`: lint sprawdza wylacznie **skladnie plista**.
Klucz o zlej nazwie, w zlym miejscu drzewa albo zlego typu przechodzi lint bez
mrugniecia, a iOS **milczaco go ignoruje** — profil instaluje sie „poprawnie",
tylko nie robi tego, co obiecuje. Przy profilu, ktorego cala rola jest blokowanie
obejsc DNS, to najgorszy mozliwy tryb awarii: fałszywe poczucie wgladu.

Ten plik faktycznie wykryl blad w gen_profile.py — ProhibitDisablement byl
wsadzony do wnetrza DNSSettings, a wedlug schematu jest jego RODZENSTWEM na
poziomie payloadu.

Indeks schematu: tools/apple_schema_index.json, generowany przez
tools/fetch_apple_schema.py z github.com/apple/device-management.
"""

from __future__ import annotations

import json
import plistlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

from gen_profile import build_declaration, build_profile  # noqa: E402

SCHEMA = json.loads((ROOT / "tools" / "apple_schema_index.json").read_text(encoding="utf-8"))
DNS_PROFILE = SCHEMA["profiles"]["com.apple.dnsSettings.managed"]
RESTRICTIONS = SCHEMA["profiles"]["com.apple.applicationaccess"]
TOPLEVEL = SCHEMA["profiles"]["TopLevel"]
DDM = SCHEMA["declarations"]["com.apple.configuration.network.dns-settings"]

DOH = "https://dns.nextdns.io/abc123/iPad-Kuby"

#: Klucze, ktore dodaje sam format profilu, a nie schemat danego payloadu.
PAYLOAD_META = {
    "PayloadType",
    "PayloadVersion",
    "PayloadIdentifier",
    "PayloadUUID",
    "PayloadDisplayName",
    "PayloadDescription",
    "PayloadOrganization",
}

TYPES = {
    "boolean": bool,
    "string": str,
    "integer": int,
    "real": float,
    "dictionary": dict,
    "array": list,
}


def check_against(keys: dict, payload: dict, where: str) -> list[str]:
    """Rekurencyjnie sprawdza payload przeciw fragmentowi schematu."""
    problems: list[str] = []
    for name, value in payload.items():
        if name in PAYLOAD_META:
            continue
        spec = keys.get(name)
        if spec is None:
            problems.append(
                f"{where}.{name}: klucza NIE MA w schemacie Apple "
                f"(iOS zignoruje go bez ostrzezenia)"
            )
            continue
        expected = TYPES.get(spec["type"])
        if expected is not None and not isinstance(value, expected):
            problems.append(
                f"{where}.{name}: schemat mowi {spec['type']}, "
                f"a jest {type(value).__name__}"
            )
        if spec.get("allowed") and value not in spec["allowed"]:
            problems.append(
                f"{where}.{name}: wartosc {value!r} poza dozwolonymi {spec['allowed']}"
            )
        if isinstance(value, dict) and spec.get("subkeys"):
            problems += check_against(spec["subkeys"], value, f"{where}.{name}")
    return problems


# ============================================================ zgodnosc kluczy
@pytest.mark.parametrize("supervised", [False, True])
def test_payload_dns_zgadza_sie_ze_schematem(supervised):
    profile = build_profile(name="iPad Kuby", doh_url=DOH, supervised=supervised)
    dns = profile["PayloadContent"][0]
    assert dns["PayloadType"] == "com.apple.dnsSettings.managed"
    problems = check_against(DNS_PROFILE["keys"], dns, "dnsSettings")
    assert problems == [], "\n".join(problems)


def test_payload_restrykcji_zgadza_sie_ze_schematem():
    profile = build_profile(name="iPad Kuby", doh_url=DOH, supervised=True)
    restrictions = profile["PayloadContent"][1]
    assert restrictions["PayloadType"] == "com.apple.applicationaccess"
    problems = check_against(RESTRICTIONS["keys"], restrictions, "applicationaccess")
    assert problems == [], "\n".join(problems)


@pytest.mark.parametrize("supervised", [False, True])
def test_klucze_poziomu_profilu_zgadzaja_sie_ze_schematem(supervised):
    profile = build_profile(name="iPad Kuby", doh_url=DOH, supervised=supervised)
    top = {k: v for k, v in profile.items() if k != "PayloadContent"}
    problems = check_against(TOPLEVEL["keys"], top, "profil")
    assert problems == [], "\n".join(problems)


def test_deklaracja_ddm_zgadza_sie_ze_schematem():
    for supervised in (False, True):
        decl = build_declaration(name="iPad Kuby", doh_url=DOH, supervised=supervised)
        problems = check_against(DDM["keys"], decl["Payload"], "ddm")
        assert problems == [], "\n".join(problems)


# =================================================== wlasciwy poziom zagniezdzenia
def test_prohibit_disablement_jest_RODZENSTWEM_DNSSettings_nie_jego_subkeyem():
    """Regresja. Wsadzony do wnetrza DNSSettings jest nieznanym subkeyem, ktory
    iOS milczaco ignoruje: profil instaluje sie bez bledu, a DNS-a nadal da sie
    wylaczyc — czyli tryb --supervised obiecywalby blokade, ktorej nie ma."""
    assert "ProhibitDisablement" in DNS_PROFILE["keys"]
    assert "ProhibitDisablement" not in DNS_PROFILE["keys"]["DNSSettings"]["subkeys"]

    dns = build_profile(name="iPad Kuby", doh_url=DOH, supervised=True)["PayloadContent"][0]
    assert dns["ProhibitDisablement"] is True
    assert "ProhibitDisablement" not in dns["DNSSettings"]


def test_to_samo_w_deklaracji_ddm():
    assert "ProhibitDisablement" in DDM["keys"]
    assert "ProhibitDisablement" not in DDM["keys"]["DNSSettings"]["subkeys"]

    payload = build_declaration(name="iPad Kuby", doh_url=DOH, supervised=True)["Payload"]
    assert payload["ProhibitDisablement"] is True
    assert "ProhibitDisablement" not in payload["DNSSettings"]


# ================================================== wymog nadzoru wg schematu
def test_schemat_potwierdza_ze_payload_dns_NIE_wymaga_nadzoru():
    """Na tym stoi cala rekomendacja: iPadow nie trzeba wymazywac."""
    assert DNS_PROFILE["ios"]["supervised"] is False
    assert DNS_PROFILE["ios"]["allowmanualinstall"] is True


def test_zwykly_profil_nie_zawiera_ZADNEGO_klucza_wymagajacego_nadzoru():
    """Liczone ze schematu, nie z listy pisanej z pamieci — gdyby Apple zmienilo
    wymog dla ktoregos klucza, ten test to wychwyci po odswiezeniu indeksu."""
    profile = build_profile(name="iPad Kuby", doh_url=DOH, supervised=False)

    def supervised_keys(keys: dict, payload: dict, where: str) -> list[str]:
        found = []
        for name, value in payload.items():
            spec = keys.get(name)
            if spec is None:
                continue
            if spec.get("supervised_ios") is True:
                found.append(f"{where}.{name}")
            if isinstance(value, dict) and spec.get("subkeys"):
                found += supervised_keys(spec["subkeys"], value, f"{where}.{name}")
        return found

    leaked = supervised_keys(
        TOPLEVEL["keys"], {k: v for k, v in profile.items() if k != "PayloadContent"}, "profil"
    )
    for payload in profile["PayloadContent"]:
        schema = SCHEMA["profiles"].get(payload["PayloadType"])
        if schema:
            leaked += supervised_keys(schema["keys"], payload, payload["PayloadType"])

    assert leaked == [], (
        f"klucze wymagajace nadzoru w zwyklym profilu: {leaked}\n"
        "iOS je zignoruje, dajac zludzenie zabezpieczenia"
    )


def test_profil_nadzorowany_uzywa_dokladnie_tych_kluczy_ktore_wymagaja_nadzoru():
    profile = build_profile(name="iPad Kuby", doh_url=DOH, supervised=True)
    dns, restrictions = profile["PayloadContent"]

    assert TOPLEVEL["keys"]["PayloadRemovalDisallowed"]["supervised_ios"] is True
    assert DNS_PROFILE["keys"]["ProhibitDisablement"]["supervised_ios"] is True
    for key in (
        "allowCloudPrivateRelay",
        "allowVPNCreation",
        "allowUIConfigurationProfileInstallation",
    ):
        assert RESTRICTIONS["keys"][key]["supervised_ios"] is True, key
        assert restrictions[key] is False

    assert profile["PayloadRemovalDisallowed"] is True
    assert dns["ProhibitDisablement"] is True


# ============================================================= indeks schematu
def test_indeks_jest_generowany_a_nie_pisany_recznie():
    assert "GENEROWANY" in SCHEMA["_uwaga"]
    assert SCHEMA["_zrodlo"].startswith("https://github.com/apple/device-management")


def test_schemat_zna_deprecjacje_payloadu():
    """Stary payload jest deprecated od OS 27, nastepca DDM wprowadzony w 27.0.
    Gdy Apple go USUNIE, ten test przypomni, ze trzeba przejsc na deklaracje."""
    assert DNS_PROFILE["ios"]["deprecated"] == "27.0"
    assert DDM["ios"]["introduced"] == "27.0"


def test_plist_sie_serializuje_po_zmianie_poziomu_klucza():
    data = plistlib.dumps(build_profile(name="iPad Kuby", doh_url=DOH, supervised=True))
    reloaded = plistlib.loads(data)
    assert reloaded["PayloadContent"][0]["ProhibitDisablement"] is True
