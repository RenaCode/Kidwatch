"""Profile konfiguracyjne i deklaracje DDM budowane z polityki.

Nazwy kluczy wziete ze schematow apple/device-management (galaz release,
2026-09-17); tests/test_mdm_profiles.py sprawdza je wzgledem
tools/apple_schema_index.json.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
import uuid
from dataclasses import dataclass
from typing import Any

from .pki import CA, fingerprint, identity_pkcs12
from .policy import Policy

BASE_ID = "com.renacode.kidwatch.mdm"
NAMESPACE = uuid.UUID("2f1c7a1e-4b8e-4c1e-9d3a-6b6d0c8f5e21")

#: Wszystkie prawa MDM (mdm/profiles/com.apple.mdm.yaml, AccessRights: OR bitow 1..4096).
ACCESS_RIGHTS_ALL = 8191


def stable_uuid(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "|".join(parts))).upper()


def content_hash(obj: Any) -> str:
    """Skrot tresci niezalezny od kolejnosci kluczy — do wykrywania zmian."""
    return hashlib.sha256(
        json.dumps(obj, sort_keys=True, ensure_ascii=False, default=str).encode()
    ).hexdigest()


# =============================================================== profil zapisu
@dataclass(frozen=True)
class EnrollmentProfile:
    data: bytes
    cert_fingerprint: str


def enrollment_profile(
    *,
    ca: CA,
    public_url: str,
    topic: str,
    org: str,
    label: str,
    device_name: str,
) -> EnrollmentProfile:
    """Profil zapisu: tozsamosc urzadzenia (PKCS#12) + payload com.apple.mdm.

    Kazde wywolanie wystawia NOWY certyfikat. Nie trzymamy kluczy prywatnych
    urzadzen na serwerze — zyja tylko w profilu i na iPadzie.
    """
    key, cert = ca.issue_identity(f"kidwatch-mdm {label}")
    p12, password = identity_pkcs12(key, cert, f"kidwatch-mdm {label}")
    base = public_url.rstrip("/")
    identity_uuid = str(uuid.uuid4()).upper()
    identity = {
        "PayloadType": "com.apple.security.pkcs12",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.identity",
        "PayloadUUID": identity_uuid,
        "PayloadDisplayName": "Tozsamosc urzadzenia",
        "PayloadContent": p12,
        "Password": password,
        "PayloadCertificateFileName": "kidwatch-mdm.p12",
    }
    mdm = {
        "PayloadType": "com.apple.mdm",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.mdm",
        "PayloadUUID": stable_uuid("mdm", label),
        "PayloadDisplayName": "Zarzadzanie urzadzeniem",
        "IdentityCertificateUUID": identity_uuid,
        # Topic, ServerURL i CheckInURL nie moga sie zmienic przy aktualizacji
        # profilu (schemat: „Any change is an error"). Zmiana domeny = ponowny zapis.
        "Topic": topic,
        "ServerURL": f"{base}/mdm/connect",
        "CheckInURL": f"{base}/mdm/checkin",
        "SignMessage": True,
        "CheckOutWhenRemoved": True,
        "AccessRights": ACCESS_RIGHTS_ALL,
        # Certyfikat push z identity.apple.com dziala tylko z produkcyjnym APNs.
        "UseDevelopmentAPNS": False,
    }
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": BASE_ID,
        "PayloadUUID": stable_uuid("enroll", label),
        "PayloadDisplayName": f"{org} — zarzadzanie ({device_name})",
        "PayloadDescription": "Nadzor rodzicielski Kidwatch: ograniczenia, DNS i aktualizacje.",
        "PayloadOrganization": org,
        "PayloadContent": [identity, mdm],
        # Na iOS dziala WYLACZNIE na urzadzeniu nadzorowanym (TopLevel.yaml).
        # Na zwyklym iPadzie profil da sie zdjac mimo tego klucza.
        "PayloadRemovalDisallowed": True,
    }
    return EnrollmentProfile(
        data=plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True),
        cert_fingerprint=fingerprint(cert),
    )


# =========================================================== profil ograniczen
RESTRICTIONS_ID = f"{BASE_ID}.restrictions"


def restrictions_profile(policy: Policy, label: str) -> tuple[dict, str]:
    """Profil ograniczen i skrot jego tresci (bez UUID-ow, ktore sa stale)."""
    restrictions = policy.restrictions_for(label)
    payload = {
        "PayloadType": "com.apple.applicationaccess",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{RESTRICTIONS_ID}.payload",
        "PayloadUUID": stable_uuid("restrictions-payload", label),
        "PayloadDisplayName": "Ograniczenia",
        **restrictions,
    }
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": RESTRICTIONS_ID,
        "PayloadUUID": stable_uuid("restrictions", label),
        "PayloadDisplayName": f"{policy.org} — ograniczenia",
        "PayloadDescription": "Blokada VPN, Private Relay, wymazania i instalacji profili.",
        "PayloadOrganization": policy.org,
        "PayloadContent": [payload],
    }
    return profile, content_hash(profile)


# ================================================================ deklaracje DDM
def _declaration(dtype: str, ident: str, payload: dict) -> dict:
    # ServerToken musi sie zmieniac przy KAZDEJ zmianie tresci (schemat
    # DeclarationItemsResponse) i miec do 64 bajtow.
    return {
        "Type": dtype,
        "Identifier": f"{BASE_ID}.{ident}",
        "ServerToken": content_hash([dtype, payload])[:40],
        "Payload": payload,
    }


def declarations(
    policy: Policy, label: str, *, supervised: bool, os_update: dict | None
) -> list[dict]:
    """Deklaracje dla jednego iPada.

    Klucze dozwolone tylko pod nadzorem dokladamy dopiero, gdy iPad zglosi
    IsSupervised = true. Nienadzorowany iPad (np. testowy) dostaje wersje bez
    nich — inaczej moglby odrzucic cala deklaracje przez jeden klucz.
    """
    dev = policy.device(label)
    configs: list[dict] = [
        _declaration(
            "com.apple.configuration.management.status-subscriptions",
            "status",
            {"StatusItems": [{"Name": n} for n in policy.status_items]},
        )
    ]

    su = dict(policy.software_update)
    if not supervised:
        for key in ("AutomaticActions", "Deferrals", "RapidSecurityResponse"):
            su.pop(key, None)
        if isinstance(su.get("Beta"), dict):
            su["Beta"] = {k: v for k, v in su["Beta"].items() if k != "ProgramEnrollment"}
            if not su["Beta"]:
                su.pop("Beta")
    if su:
        configs.append(
            _declaration("com.apple.configuration.softwareupdate.settings", "softwareupdate", su)
        )

    if os_update:
        payload = {
            "TargetOSVersion": os_update["target_version"],
            "TargetLocalDateTime": os_update["deadline"],
        }
        if os_update.get("target_build"):
            payload["TargetBuildVersion"] = os_update["target_build"]
        if os_update.get("details_url"):
            payload["DetailsURL"] = os_update["details_url"]
        configs.append(
            _declaration(
                "com.apple.configuration.softwareupdate.enforcement.specific",
                "osupdate",
                payload,
            )
        )

    if dev.dns_url:
        # iOS 27+. Zasieg wedlug schematu: nadzorowane = WSZYSTKIE sieci,
        # zapis urzadzenia bez nadzoru = tylko sieci zarzadzane. Na iPadzie
        # testowym bez nadzoru DNS w domowym Wi-Fi wiec NIE zadziala — to
        # zachowanie iOS, nie blad serwera.
        dns: dict[str, Any] = {
            "VisibleName": f"Kidwatch DNS — {dev.name}",
            "DNSSettings": {
                "DNSProtocol": "HTTPS",
                "ServerURL": dev.dns_url,
                "AllowFailover": False,
            },
        }
        if supervised:
            dns["ProhibitDisablement"] = True
        configs.append(_declaration("com.apple.configuration.network.dns-settings", "dns", dns))

    activation = _declaration(
        "com.apple.activation.simple",
        "activation",
        {"StandardConfigurations": [c["Identifier"] for c in configs]},
    )
    return [activation, *configs]


def declarations_token(decls: list[dict]) -> str:
    return content_hash(sorted((d["Identifier"], d["ServerToken"]) for d in decls))[:40]


def declaration_items(decls: list[dict]) -> dict:
    """Odpowiedz na Endpoint `declaration-items` (DeclarationItemsResponse)."""
    groups: dict[str, list[dict]] = {
        "Activations": [],
        "Configurations": [],
        "Assets": [],
        "Management": [],
    }
    for d in decls:
        kind = d["Type"].split(".")[2]  # com.apple.<activation|configuration|asset|management>
        key = {
            "activation": "Activations",
            "configuration": "Configurations",
            "asset": "Assets",
            "management": "Management",
        }[kind]
        groups[key].append({"Identifier": d["Identifier"], "ServerToken": d["ServerToken"]})
    return {"Declarations": groups, "DeclarationsToken": declarations_token(decls)}
