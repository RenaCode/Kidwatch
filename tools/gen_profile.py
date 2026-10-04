#!/usr/bin/env python3
"""Generator profilu DNS-over-HTTPS dla iPada.

Wszystkie nazwy kluczy sprawdzone w oficjalnym schemacie Apple
(github.com/apple/device-management, galaz `release`) 2026-09-27:

  mdm/profiles/com.apple.dnsSettings.managed.yaml
    * caly payload: supervised=false, allowmanualinstall=true, iOS 14.0+
      -> profil instaluje sie na ZWYKLYM, nienadzorowanym iPadzie
    * DNSSettings.DNSProtocol: "HTTPS" | "TLS"; ServerURL wymagany przy HTTPS
    * AllowFailover (iOS 26.0+), domyslnie false
    * ProhibitDisablement: supervised=true  <- TYLKO z nadzorem
    * nota: "When installed from an MDM, the setting only applies to managed
      Wi-Fi networks. When installed manually, this setting also applies to
      cellular networks." -> instalacja recznie daje PELNE pokrycie sieci

  mdm/profiles/TopLevel.yaml
    * PayloadRemovalDisallowed: supervised=true  <- TYLKO z nadzorem

  mdm/profiles/com.apple.applicationaccess.yaml
    * allowCloudPrivateRelay (iOS 15.0+, supervised)
    * allowVPNCreation (iOS 11.0+, supervised)
    * allowUIConfigurationProfileInstallation (iOS 6.0+, supervised)
                                              wszystkie TYLKO z nadzorem

Stad podzial na dwa tryby. Domyslny (bez --supervised) zawiera wylacznie payload
DNS, bo reszta kluczy na nienadzorowanym iPadzie jest ignorowana — wstawianie ich
dawaloby zludzenie zabezpieczenia, ktorego nie ma.
"""

from __future__ import annotations

import argparse
import json
import plistlib
import re
import sys
import uuid
from pathlib import Path

#: Stala przestrzen nazw, zeby PayloadIdentifier byl POWTARZALNY dla tej samej
#: nazwy urzadzenia. Dzieki temu ponowna instalacja aktualizuje istniejacy profil,
#: a nie dokleja drugiego obok.
NAMESPACE = uuid.UUID("6f9619ff-8b86-d011-b42d-00c04fc964ff")

DEFAULT_ORG = "Dom"
BASE_ID = "com.renacode.kidwatch"


def slug(text: str) -> str:
    """Zamienia 'iPad Kuby' na 'ipad-kuby' — nadaje sie do identyfikatora i nazwy pliku."""
    trans = str.maketrans("ąćęłńóśźżĄĆĘŁŃÓŚŹŻ", "acelnoszzACELNOSZZ")
    out = re.sub(r"[^a-z0-9]+", "-", text.translate(trans).lower())
    return out.strip("-") or "urzadzenie"


def stable_uuid(*parts: str) -> str:
    return str(uuid.uuid5(NAMESPACE, "|".join(parts))).upper()


def validate_doh_url(url: str) -> str:
    if not url.startswith("https://"):
        raise argparse.ArgumentTypeError(
            f"ServerURL musi byc adresem https (RFC 8484), dostalem: {url!r}"
        )
    return url


def build_profile(
    *,
    name: str,
    doh_url: str,
    org: str = DEFAULT_ORG,
    supervised: bool = False,
) -> dict:
    device = slug(name)

    dns_settings: dict[str, object] = {
        "DNSProtocol": "HTTPS",
        "ServerURL": doh_url,
        # Jawne false, zeby iPad nie zjechal cicho na DNS operatora, gdy nasz
        # resolver bedzie chwilowo nieosiagalny. Domyslnie i tak false, ale
        # domyslne wartosci sie zmieniaja, a cicha utrata wgladu jest najgorsza.
        "AllowFailover": False,
    }

    dns_payload: dict[str, object] = {
        "PayloadType": "com.apple.dnsSettings.managed",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.{device}.dns",
        "PayloadUUID": stable_uuid("dns", device, doh_url),
        "PayloadDisplayName": f"Szyfrowany DNS — {name}",
        "PayloadDescription": "Kieruje zapytania DNS przez DNS-over-HTTPS.",
        "PayloadOrganization": org,
        "DNSSettings": dns_settings,
    }

    payloads: list[dict] = [dns_payload]

    if supervised:
        # ProhibitDisablement jest rodzenstwem DNSSettings, NIE jego subkeyem.
        # Wsadzony do wnetrza DNSSettings jest nieznanym subkeyem, ktory iOS
        # milczaco ignoruje — profil instaluje sie bez bledu, a DNS-a nadal da
        # sie wylaczyc. Pilnuje tego tests/test_profile_schema.py.
        dns_payload["ProhibitDisablement"] = True
        payloads.append(
            {
                "PayloadType": "com.apple.applicationaccess",
                "PayloadVersion": 1,
                "PayloadIdentifier": f"{BASE_ID}.{device}.restrictions",
                "PayloadUUID": stable_uuid("restrictions", device),
                "PayloadDisplayName": f"Ograniczenia obejsc DNS — {name}",
                "PayloadDescription": (
                    "Blokuje Private Relay, tworzenie VPN i instalacje wlasnych profili."
                ),
                "PayloadOrganization": org,
                # Private Relay tuneluje ruch Safari obok naszego DNS-a.
                "allowCloudPrivateRelay": False,
                # Darmowy VPN z App Store omija DNS calkowicie.
                "allowVPNCreation": False,
                # Bez tego dziecko doinstaluje wlasny profil DNS obok naszego.
                "allowUIConfigurationProfileInstallation": False,
            }
        )

    profile: dict[str, object] = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"{BASE_ID}.{device}",
        "PayloadUUID": stable_uuid("profile", device),
        "PayloadDisplayName": f"kidwatch DNS — {name}",
        "PayloadDescription": (
            "Szyfrowany DNS dla nadzoru rodzicielskiego. "
            + (
                "Nieusuwalny (urzadzenie nadzorowane)."
                if supervised
                else "Mozliwy do usunięcia — urzadzenie nie jest nadzorowane."
            )
        ),
        "PayloadOrganization": org,
        "PayloadContent": payloads,
    }

    if supervised:
        # Na iOS ten klucz DZIALA WYLACZNIE na urzadzeniu nadzorowanym
        # (TopLevel.yaml: supervised: true). Bez nadzoru wstawianie go dawaloby
        # falszywe poczucie bezpieczenstwa.
        profile["PayloadRemovalDisallowed"] = True

    return profile


def build_declaration(*, name: str, doh_url: str, supervised: bool = False) -> dict:
    """Deklaracja DDM `com.apple.configuration.network.dns-settings` (iOS 27.0+).

    Nastepca payloadu `com.apple.dnsSettings.managed`, ktory Apple oznaczylo jako
    deprecated wlasnie w 27.0. Dostarcza sie ja serwerem MDM, nie recznie — ten
    plik jest na zapas, na moment gdy stary payload zniknie.
    """
    device = slug(name)
    payload: dict[str, object] = {
        "VisibleName": f"kidwatch DNS — {name}",
        "DNSSettings": {
            "DNSProtocol": "HTTPS",
            "ServerURL": doh_url,
            "AllowFailover": False,
        },
    }
    if supervised:
        # Jak w profilu: klucz poziomu Payload, nie subkey DNSSettings.
        payload["ProhibitDisablement"] = True
    return {
        "Type": "com.apple.configuration.network.dns-settings",
        "Identifier": f"{BASE_ID}.{device}.dns",
        "ServerToken": stable_uuid("ddm-token", device, doh_url),
        "Payload": payload,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generuje profil .mobileconfig wymuszajacy DNS-over-HTTPS na iPadzie.",
        epilog=(
            "Domyslnie profil jest przeznaczony dla ZWYKLEGO, nienadzorowanego iPada: "
            "instalujesz go recznie i obejmuje wszystkie sieci, ale dziecko moze go zdjac. "
            "Uzyj --supervised tylko gdy iPad przeszedl nadzor w Apple Configurator "
            "(co wymaga wymazania urzadzenia)."
        ),
    )
    parser.add_argument("--name", required=True, help='nazwa urzadzenia, np. "iPad Kuby"')
    parser.add_argument(
        "--doh-url",
        required=True,
        type=validate_doh_url,
        help="adres DNS-over-HTTPS, np. https://dns.nextdns.io/abc123/iPad-Kuby",
    )
    parser.add_argument("--out", required=True, help="plik wyjsciowy .mobileconfig")
    parser.add_argument("--org", default=DEFAULT_ORG, help=f"organizacja (domyslnie {DEFAULT_ORG})")
    parser.add_argument(
        "--supervised",
        action="store_true",
        help=(
            "dodaj klucze dzialajace WYLACZNIE na urzadzeniu nadzorowanym: "
            "ProhibitDisablement, PayloadRemovalDisallowed i blokady "
            "Private Relay / VPN / instalacji profili"
        ),
    )
    parser.add_argument(
        "--also-declaration",
        action="store_true",
        help="zapisz obok plik .json z deklaracja DDM (iOS 27+, na przyszlosc)",
    )
    args = parser.parse_args(argv)

    profile = build_profile(
        name=args.name, doh_url=args.doh_url, org=args.org, supervised=args.supervised
    )
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True))
    print(f"zapisano {out}")

    if args.also_declaration:
        decl = out.with_suffix(".mobileconfig.json")
        decl.write_text(
            json.dumps(
                build_declaration(
                    name=args.name, doh_url=args.doh_url, supervised=args.supervised
                ),
                indent=4,
                ensure_ascii=False,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"zapisano {decl} (deklaracja DDM, iOS 27+)")

    if args.supervised:
        print(
            "TRYB NADZOROWANY: te klucze zadzialaja tylko, jesli iPad przeszedl\n"
            "  nadzor w Apple Configurator. Na zwyklym iPadzie zostana zignorowane."
        )
    else:
        print(
            "Tryb zwykly (bez nadzoru): profil obejmie wszystkie sieci, takze\n"
            "  komorkowa, ale dziecko moze go usunac w Ustawieniach. Czujka\n"
            "  kidwatch zglosi to jako cisze urzadzenia."
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
