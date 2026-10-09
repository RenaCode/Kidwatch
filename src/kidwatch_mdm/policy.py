"""Polityka: czego serwer pilnuje na iPadach.

Plik YAML (ConfigMap w klastrze) opisuje ograniczenia, DNS, aktualizacje
i urzadzenia. Docelowa wersja systemu moze byc dodatkowo nadpisana z Kidwatch
przez API (store.settings["os_update"]) — wtedy wygrywa nadpisanie.

Klucze ograniczen sa walidowane wzgledem OFICJALNEGO schematu Apple przy
starcie. Literowka w nazwie klucza jest przez iOS milczaco ignorowana:
profil instaluje sie „poprawnie", a blokady nie ma. Dlatego nieznany klucz
zatrzymuje start serwera — lepiej glosno nie dzialac niz cicho nie chronic.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator

#: Ograniczenia domyslne. Kazde dziala WYLACZNIE na nadzorowanym iPadzie
#: (schemat: supervised: true) — na zwyklym iOS je ignoruje.
DEFAULT_RESTRICTIONS: dict[str, Any] = {
    # Darmowy VPN z App Store omija DNS, a z nim caly wglad Kidwatch.
    # Od iOS 18 blokuje takze aplikacje niezarzadzane (schemat Apple).
    "allowVPNCreation": False,
    # Private Relay tuneluje ruch Safari obok naszego DNS.
    "allowCloudPrivateRelay": False,
    # Bez tego dziecko wymaze iPada w Ustawieniach i zniknie nadzor.
    "allowEraseContentAndSettings": False,
    # Bez tego doinstaluje wlasny profil DNS albo VPN obok naszego.
    "allowUIConfigurationProfileInstallation": False,
    # Przestawienie zegara obchodzi limity czasu z Rodziny.
    "forceAutomaticDateAndTime": True,
    # JAWNIE true: false zerwaloby parowanie, na ktorym Kidwatch czyta liste
    # procesow (pymobiledevice3). Domyslnie i tak true, ale zapisane wprost,
    # zeby nikt tego nie „zaostrzyl" bez swiadomosci skutkow.
    "allowHostPairing": True,
}

#: NIE ustawiac na false — psuja „Popros o zakup" i konta w Rodzinie
#: (ustalone przy planowaniu nadzoru, notatki Kidwatch 2026-10-09).
FORBIDDEN_FALSE = frozenset(
    {"allowAppInstallation", "allowInAppPurchases", "allowAccountModification"}
)

#: Automatyczne aktualizacje (com.apple.configuration.softwareupdate.settings,
#: iOS 18+). AutomaticActions dziala tylko z nadzorem.
DEFAULT_SOFTWARE_UPDATE: dict[str, Any] = {
    "Notifications": True,
    "AutomaticActions": {
        "Download": "AlwaysOn",
        "InstallOSUpdates": "AlwaysOn",
        "InstallSecurityUpdate": "AlwaysOn",
    },
    "Beta": {"ProgramEnrollment": "AlwaysOff"},
}

#: Statusy, ktore iPad ma raportowac sam przy kazdej zmianie (DDM).
DEFAULT_STATUS_ITEMS = [
    "device.operating-system.version",
    "device.operating-system.build-version",
    "device.model.identifier",
    "softwareupdate.pending-version",
    "softwareupdate.install-state",
    "softwareupdate.failure-reason",
    "mdm.enrollment-type",
    "passcode.is-present",
]

LOCAL_DT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")


class OsUpdate(BaseModel):
    """Wymuszona aktualizacja: do `deadline` (czas lokalny iPada) ma byc `target_version`."""

    target_version: str
    deadline: str
    target_build: str | None = None
    details_url: str | None = None

    @field_validator("target_version")
    @classmethod
    def _version(cls, v: str) -> str:
        if not re.fullmatch(r"\d+(\.\d+){1,2}", v):
            raise ValueError(f"wersja systemu w postaci 27.1 albo 27.1.2, dostalem {v!r}")
        return v

    @field_validator("deadline")
    @classmethod
    def _deadline(cls, v: str) -> str:
        # Format wymagany przez Apple: bez strefy i bez ulamkow sekund.
        if not LOCAL_DT.match(v):
            raise ValueError(f"termin w postaci RRRR-MM-DDTHH:MM:SS (czas lokalny), dostalem {v!r}")
        return v


class DevicePolicy(BaseModel):
    name: str
    #: Adres DNS-over-HTTPS (np. NextDNS z nazwa urzadzenia). Brak = bez DNS z MDM.
    dns_url: str | None = None
    restrictions: dict[str, Any] = Field(default_factory=dict)
    blocked_apps: list[str] | None = None

    @field_validator("dns_url")
    @classmethod
    def _doh(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith("https://"):
            raise ValueError(f"dns_url musi byc adresem https (RFC 8484), dostalem {v!r}")
        return v


class Policy(BaseModel):
    org: str = "RenaCode"
    #: Nadpisania DOKLADANE do DEFAULT_RESTRICTIONS, nie zamiast nich — wpisanie
    #: jednego klucza w YAML nie moze po cichu zdjac blokady VPN.
    restrictions: dict[str, Any] = Field(default_factory=dict)
    #: Aplikacje ukryte i niedajace sie uruchomic (np. przegladarki z wbudowanym
    #: proxy). Klucz Apple blockedAppBundleIDs: nadzor wymagany, deprecated w 27.0.
    blocked_apps: list[str] = Field(default_factory=list)
    software_update: dict[str, Any] = Field(default_factory=lambda: dict(DEFAULT_SOFTWARE_UPDATE))
    os_update: OsUpdate | None = None
    status_items: list[str] = Field(default_factory=lambda: list(DEFAULT_STATUS_ITEMS))
    #: Klucz = etykieta podana przy tworzeniu zaproszenia (np. "dziecko1").
    devices: dict[str, DevicePolicy] = Field(default_factory=dict)
    refresh_hours: float = 6.0

    def device(self, label: str) -> DevicePolicy:
        return self.devices.get(label) or DevicePolicy(name=label)

    def restrictions_for(self, label: str) -> dict[str, Any]:
        dev = self.device(label)
        merged = {**DEFAULT_RESTRICTIONS, **self.restrictions, **dev.restrictions}
        blocked = dev.blocked_apps if dev.blocked_apps is not None else self.blocked_apps
        if blocked:
            merged["blockedAppBundleIDs"] = list(blocked)
        return merged


class PolicyError(ValueError):
    pass


def load_schema(path: str | os.PathLike | None) -> dict | None:
    if not path:
        return None
    return json.loads(Path(path).read_text(encoding="utf-8"))


def validate(policy: Policy, schema: dict | None) -> list[str]:
    """Bledy polityki. Pusta lista = mozna startowac."""
    errors: list[str] = []
    labels = ["(wspolne)", *policy.devices]
    for label in labels:
        restr = (
            {**DEFAULT_RESTRICTIONS, **policy.restrictions}
            if label == "(wspolne)"
            else policy.restrictions_for(label)
        )
        for key, value in restr.items():
            if key in FORBIDDEN_FALSE and value is False:
                errors.append(f"{label}: {key}=false psuje Popros o zakup / konta Rodziny")
        if schema is not None:
            keys = schema["profiles"]["com.apple.applicationaccess"]["keys"]
            types = {"boolean": bool, "integer": int, "array": list, "string": str}
            for key, value in restr.items():
                spec = keys.get(key)
                if spec is None:
                    errors.append(f"{label}: nieznany klucz ograniczen {key!r} (literowka?)")
                    continue
                expected = types.get(spec["type"])
                if expected and not (
                    isinstance(value, expected)
                    and not (expected is int and isinstance(value, bool))
                ):
                    errors.append(f"{label}: {key} ma typ {spec['type']}, dostalem {value!r}")
    if schema is not None:
        su_keys = schema["declarations"]["com.apple.configuration.softwareupdate.settings"]["keys"]
        for key in policy.software_update:
            if key not in su_keys:
                errors.append(f"software_update: nieznany klucz {key!r}")
    return errors


def load(path: str | os.PathLike, schema: dict | None = None) -> Policy:
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    policy = Policy.model_validate(raw)
    errors = validate(policy, schema)
    if errors:
        raise PolicyError("polityka odrzucona:\n  " + "\n  ".join(errors))
    return policy
