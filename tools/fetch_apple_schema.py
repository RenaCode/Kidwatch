#!/usr/bin/env python3
"""Destyluje oficjalne schematy Apple do zwiezlego indeksu dla walidatora.

Zrodlo: https://github.com/apple/device-management (galaz `release`) — jedyna
maszynowo czytelna specyfikacja kluczy profili i deklaracji Apple. Strona
developer.apple.com jest aplikacja jednostronicowa i nie da sie z niej nic
pobrac programowo.

Po co indeks, a nie same pliki YAML: `com.apple.applicationaccess.yaml` ma
124 KB i 210 kluczy, z ktorych uzywamy trzech. Indeks zachowuje to, co
potrzebne do walidacji (nazwa, typ, wymog nadzoru, dozwolone wartosci,
zagniezdzenie) i wazy dziesiec razy mniej.

Odswiezenie:
    uv run python tools/fetch_apple_schema.py
    uv run pytest tests/test_profile_schema.py
"""

from __future__ import annotations

import json
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

import yaml

BASE = "https://raw.githubusercontent.com/apple/device-management/release"
OUT = Path(__file__).resolve().parent / "apple_schema_index.json"

PROFILES = {
    "com.apple.dnsSettings.managed": f"{BASE}/mdm/profiles/com.apple.dnsSettings.managed.yaml",
    "com.apple.applicationaccess": f"{BASE}/mdm/profiles/com.apple.applicationaccess.yaml",
    "TopLevel": f"{BASE}/mdm/profiles/TopLevel.yaml",
    # kidwatch-mdm: profil zapisu do MDM i tozsamosc urzadzenia w nim.
    "com.apple.mdm": f"{BASE}/mdm/profiles/com.apple.mdm.yaml",
    "com.apple.security.pkcs12": f"{BASE}/mdm/profiles/com.apple.security.pkcs12.yaml",
}
DECLARATIONS = {
    "com.apple.configuration.network.dns-settings": (
        f"{BASE}/declarative/declarations/configurations/network.dns-settings.yaml"
    ),
    # kidwatch-mdm: deklaracje DDM wysylane przez serwer.
    "com.apple.activation.simple": f"{BASE}/declarative/declarations/activations/simple.yaml",
    "com.apple.configuration.management.status-subscriptions": (
        f"{BASE}/declarative/declarations/configurations/management.status-subscriptions.yaml"
    ),
    "com.apple.configuration.softwareupdate.enforcement.specific": (
        f"{BASE}/declarative/declarations/configurations/softwareupdate.enforcement.specific.yaml"
    ),
    "com.apple.configuration.softwareupdate.settings": (
        f"{BASE}/declarative/declarations/configurations/softwareupdate.settings.yaml"
    ),
}
#: Komendy MDM, ktore kidwatch-mdm wysyla — walidowane tak samo jak profile.
COMMANDS = {
    "DeviceInformation": f"{BASE}/mdm/commands/information.device.yaml",
    "SecurityInfo": f"{BASE}/mdm/commands/information.security.yaml",
    "ProfileList": f"{BASE}/mdm/commands/profile.list.yaml",
    "InstallProfile": f"{BASE}/mdm/commands/profile.install.yaml",
    "RemoveProfile": f"{BASE}/mdm/commands/profile.remove.yaml",
    "InstalledApplicationList": f"{BASE}/mdm/commands/application.installed.list.yaml",
    "DeclarativeManagement": f"{BASE}/mdm/commands/declarativemanagement.yaml",
    "DeviceLock": f"{BASE}/mdm/commands/device.lock.yaml",
    "RestartDevice": f"{BASE}/mdm/commands/device.restart.yaml",
}


def _distill_key(entry: dict) -> dict:
    """Wyciaga z wpisu schematu to, czym walidator faktycznie sprawdza profil."""
    supported = entry.get("supportedOS") or {}
    ios = supported.get("iOS") or {}
    macos = supported.get("macOS") or {}
    out: dict = {
        # type w schemacie ma postac '<boolean>' — obcinamy nawiasy katowe
        "type": str(entry.get("type", "")).strip("<>"),
        "presence": entry.get("presence"),
        "supervised_ios": ios.get("supervised"),
        "supervised_macos": macos.get("supervised"),
        "introduced_ios": ios.get("introduced"),
    }
    if entry.get("rangelist"):
        out["allowed"] = list(entry["rangelist"])
    subkeys = entry.get("subkeys") or []
    if subkeys:
        out["subkeys"] = {s["key"]: _distill_key(s) for s in subkeys if s.get("key")}
    return out


def _distill_document(raw: dict) -> dict:
    payload = raw.get("payload") or {}
    supported = payload.get("supportedOS") or {}
    ios = supported.get("iOS") or {}
    return {
        "title": raw.get("title"),
        "ios": {
            "introduced": ios.get("introduced"),
            "deprecated": ios.get("deprecated"),
            # Czy CALY payload wymaga nadzorowanego urzadzenia.
            "supervised": ios.get("supervised"),
            "allowmanualinstall": ios.get("allowmanualinstall"),
            "allowed_enrollments": ios.get("allowed-enrollments"),
        },
        "keys": {
            k["key"]: _distill_key(k) for k in (raw.get("payloadkeys") or []) if k.get("key")
        },
    }


def fetch(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=30) as response:  # noqa: S310
        return yaml.safe_load(response.read().decode("utf-8"))


def main() -> int:
    index = {
        "_zrodlo": "https://github.com/apple/device-management @ release",
        "_pobrano": datetime.now(UTC).strftime("%Y-%m-%d"),
        "_uwaga": (
            "Plik GENEROWANY przez tools/fetch_apple_schema.py. Nie edytuj recznie — "
            "to kopia specyfikacji Apple, a nie nasza konfiguracja."
        ),
        "profiles": {},
        "declarations": {},
        "commands": {},
    }
    for name, url in PROFILES.items():
        index["profiles"][name] = _distill_document(fetch(url))
        print(f"  {name}: {len(index['profiles'][name]['keys'])} kluczy")
    for name, url in DECLARATIONS.items():
        index["declarations"][name] = _distill_document(fetch(url))
        print(f"  {name}: {len(index['declarations'][name]['keys'])} kluczy")
    for name, url in COMMANDS.items():
        index["commands"][name] = _distill_document(fetch(url))
        print(f"  {name}: {len(index['commands'][name]['keys'])} kluczy")

    OUT.write_text(json.dumps(index, indent=1, ensure_ascii=False, sort_keys=True) + "\n", "utf-8")
    print(f"zapisano {OUT} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
