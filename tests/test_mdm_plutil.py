"""`plutil -lint` profili, ktore serwer MDM NAPRAWDE wysyla urzadzeniom.

tests/test_gen_profile.py lintuje profile z tools/gen_profile.py (instalowane
recznie). Serwer kidwatch-mdm buduje wlasne (src/kidwatch_mdm/profiles.py):
profil zapisu (`enrollment_profile`) i profil ograniczen
(`restrictions_profile`, wysylany komenda InstallProfile) — w wariancie
nadzorowanym (iPad) i bez nadzoru (iPhone). iOS odrzuca niepoprawny plist
dopiero na urzadzeniu, wiec sprawdzamy je tym samym narzedziem Apple.

`plutil` jest tylko na macOS: w jobie `testy` (ubuntu) testy sa pomijane,
w jobie `plutil (macOS)` biegna z KIDWATCH_WYMAGAJ_PLUTIL=1 (brak = blad).
Kanarek: celowo zepsuty plist MUSI dostac od plutil kod rozny od 0 —
inaczej cisza testow niczego by nie dowodzila.

Dane generyczne (publiczne repo): „Dziecko A”, domeny .invalid.
"""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest

from kidwatch_mdm import profiles
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import Policy
from kidwatch_mdm.service import payload_install_profile

#: Job CI na macOS ustawia 1: tam brak plutil ma byc BLEDEM, nie pominieciem.
WYMAGAJ_PLUTIL = os.environ.get("KIDWATCH_WYMAGAJ_PLUTIL") == "1"
TOPIC = "com.apple.mgmt.External.11111111-2222-4333-8444-555555555555"

POLITYKA = {
    "org": "RenaCode",
    "restrictions": {"allowDeviceNameModification": False},
    "blocked_apps": ["com.example.przegladarka"],
    "devices": {
        "ipad-a": {"name": "iPad Dziecka A",
                   "dns_url": "https://dns.nextdns.io/abc123/iPad-Dziecka-A"},
        "ipad-b": {"name": "iPad Dziecka B", "restrictions": {"allowCamera": True},
                   "blocked_apps": []},
        "iphone-a": {"name": "iPhone Dziecka A", "kind": "iphone",
                     "dns_url": "https://dns.nextdns.io/abc123/iPhone-Dziecka-A"},
    },
}

pytestmark = [
    pytest.mark.plutil,
    pytest.mark.skipif(shutil.which("plutil") is None and not WYMAGAJ_PLUTIL,
                       reason="plutil jest tylko na macOS"),
]


def _plutil(path) -> subprocess.CompletedProcess:
    assert shutil.which("plutil"), "brak plutil — ten test wymaga macOS"
    return subprocess.run(["plutil", "-lint", str(path)], capture_output=True, text=True,
                          check=False)


@pytest.fixture(scope="module")
def ca(tmp_path_factory) -> CA:
    return CA.create(tmp_path_factory.mktemp("ca"), org="Kidwatch test")


def _enrollment(ca: CA, label: str) -> bytes:
    policy = Policy.model_validate(POLITYKA)
    dev = policy.device(label)
    return profiles.enrollment_profile(
        ca=ca, public_url="https://mdm.example.invalid", topic=TOPIC, org=policy.org,
        label=label, device_name=dev.name, kind=dev.kind).data


def _restrictions(label: str) -> bytes:
    profile, _ = profiles.restrictions_profile(Policy.model_validate(POLITYKA), label)
    # Te same bajty, ktore MDMService wklada do InstallProfile (`Payload`).
    return payload_install_profile(profile)


#: (nazwa, budowa) — wszystko, co serwer wysyla: zapis i ograniczenia,
#: iPad nadzorowany (z nadpisaniami polityki i bez) oraz iPhone bez nadzoru.
PROFILE = {
    "zapis-ipad": lambda ca: _enrollment(ca, "ipad-a"),
    "zapis-iphone": lambda ca: _enrollment(ca, "iphone-a"),
    "ograniczenia-ipad": lambda ca: _restrictions("ipad-a"),
    "ograniczenia-ipad-nadpisania": lambda ca: _restrictions("ipad-b"),
    "ograniczenia-iphone": lambda ca: _restrictions("iphone-a"),
}


@pytest.mark.parametrize("nazwa", sorted(PROFILE))
def test_plutil_lint_profili_serwera_mdm(tmp_path, ca, nazwa):
    plik = tmp_path / f"{nazwa}.mobileconfig"
    plik.write_bytes(PROFILE[nazwa](ca))
    wynik = _plutil(plik)
    assert wynik.returncode == 0, wynik.stdout + wynik.stderr


def test_kanarek_zepsuty_plist_wywraca_lint(tmp_path, ca):
    """Bez tego zielone testy wyzej moglyby znaczyc tylko, ze plutil niczego
    nie sprawdza (zle wywolanie, inna sciezka)."""
    dobry = PROFILE["ograniczenia-iphone"](ca)
    zepsuty = dobry.replace(b"</dict>", b"", 1)
    assert zepsuty != dobry
    plik = tmp_path / "zepsuty.mobileconfig"
    plik.write_bytes(zepsuty)
    assert _plutil(plik).returncode != 0
