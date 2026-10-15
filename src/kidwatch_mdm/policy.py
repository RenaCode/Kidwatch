"""Polityka: czego serwer pilnuje na iPadach i iPhone'ach.

Plik YAML (ConfigMap w klastrze) opisuje ograniczenia, DNS, aktualizacje
i urzadzenia. Docelowa wersja systemu moze byc dodatkowo nadpisana z Kidwatch
przez API (store.settings["os_update"]) — wtedy wygrywa nadpisanie.

Klucze ograniczen sa walidowane wzgledem OFICJALNEGO schematu Apple przy
starcie. Literowka w nazwie klucza jest przez iOS milczaco ignorowana:
profil instaluje sie „poprawnie", a blokady nie ma. Dlatego nieznany klucz
zatrzymuje start serwera — lepiej glosno nie dzialac niz cicho nie chronic.

iPhone dziecka (`kind: iphone`) jest zwykle BEZ nadzoru — nadzor wymaga
wymazania telefonu. Dostaje wiec wylacznie to, co dziala bez nadzoru:
zadnych domyslnych blokad iPada, zadnych wspolnych nadpisan, zadnego
`blockedAppBundleIDs`; wlasne `restrictions` urzadzenia tylko z kluczy, ktore
schemat Apple dopuszcza bez nadzoru (docs/iphone.md). Zostaja inwentarz,
blokada ekranu (restart wymaga nadzoru), status DDM i wymuszenie wersji systemu.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, Field, PrivateAttr, field_validator, model_validator

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

#: Klucze `softwareupdate.settings`, ktore dzialaja tylko pod nadzorem
#: (schemat: allowed-enrollments: [supervised]). None = caly klucz, slownik =
#: podklucze. Urzadzenie bez nadzoru dostaje deklaracje bez nich — inaczej
#: moze odrzucic cala deklaracje. Zgodnosc ze schematem: test_mdm_e5_uwagi.py.
SUPERVISED_ONLY_SOFTWARE_UPDATE: dict[str, Any] = {
    "AutomaticActions": None,
    "Beta": {"ProgramEnrollment": None, "RequireProgram": None},
    "Deferrals": None,
    "RapidSecurityResponse": None,
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

#: Ekrany kreatora pomijane przy zapisie ADE (Apple: SkipKeys). Celowo NIE
#: pomijamy AppleID (dziecko loguje sie wlasnym kontem z Rodziny), Restore
#: (przywrocenie „wypranej" kopii z zapisami gier) ani ScreenTime.
DEFAULT_ADE_SKIP = ["Android", "Diagnostics", "Payment", "Privacy", "Siri"]

#: Klucze SkipKeys dla iOS/iPadOS (developer.apple.com/documentation/
#: devicemanagement/skipkeys, stan 2026-10-15). Literowke iOS przemilczy —
#: ekran sie pokaze — wiec nieznany klucz zatrzymuje start jak literowka
#: w ograniczeniach.
ADE_SKIP_KEYS = frozenset(
    {
        "AccessibilityAppearance",
        "ActionButton",
        "Android",
        "Appearance",
        "AppleID",
        "AppStore",
        "Biometric",
        "CameraButton",
        "DeviceFeaturesTour",
        "DeviceToDeviceMigration",
        "Diagnostics",
        "DisplayTone",
        "EnableLockdownMode",
        "HomeButtonSensitivity",
        "iMessageAndFaceTime",
        "Intelligence",
        "Keyboard",
        "LiquidGlass",
        "Location",
        "MessagingActivationUsingPhoneNumber",
        "Multitasking",
        "OnBoarding",
        "Passcode",
        "Payment",
        "Privacy",
        "Restore",
        "RestoreCompleted",
        "Safety",
        "SafetyAndHandling",
        "ScreenTime",
        "SIMSetup",
        "Siri",
        "SoftwareUpdate",
        "SpokenLanguage",
        "TermsOfAddress",
        "TOS",
        "UpdateCompleted",
        "WatchMigration",
        "Welcome",
        "Zoom",
    }
)

#: Rodzaje urzadzen MDM. iPhone = polityka bez kluczy „tylko pod nadzorem".
MdmKind = Literal["ipad", "iphone"]

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
    #: "iphone" = iPhone dziecka bez nadzoru (patrz docstring modulu). Brak =
    #: iPad, jak w politykach sprzed iPhone'ow. Ustaw PRZED `enroll`: rodzaj
    #: decyduje tez o profilu zapisu.
    kind: MdmKind = "ipad"
    #: Adres DNS-over-HTTPS (np. NextDNS z nazwa urzadzenia). Brak = bez DNS z MDM.
    dns_url: str | None = None
    restrictions: dict[str, Any] = Field(default_factory=dict)
    blocked_apps: list[str] | None = None
    #: Numer seryjny z Apple Business (Ustawienia > Ogolne > To urzadzenie).
    #: Wiaze zapis ADE z etykieta: iPad w kreatorze przedstawia sie numerem
    #: seryjnym, nie linkiem z zaproszenia. Brak = iPad bez ADE.
    serial: str | None = None

    @field_validator("serial")
    @classmethod
    def _serial(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().upper()
        if not re.fullmatch(r"[A-Z0-9]{8,20}", v):
            raise ValueError(f"serial: same litery i cyfry (8-20 znakow), dostalem {v!r}")
        return v

    @field_validator("kind", mode="before")
    @classmethod
    def _kind_lower(cls, v: object) -> object:
        # `kind: iPhone` w YAML-u to nie powod, zeby nie wstal serwer iPadow.
        return v.strip().lower() if isinstance(v, str) else v

    @field_validator("dns_url")
    @classmethod
    def _doh(cls, v: str | None) -> str | None:
        if v is not None and not v.startswith("https://"):
            raise ValueError(f"dns_url musi byc adresem https (RFC 8484), dostalem {v!r}")
        return v


class AdeSettings(BaseModel):
    """Profil ADE (Apple Business). Wplywa tylko na kreator konfiguracji."""

    skip_setup_items: list[str] = Field(default_factory=lambda: list(DEFAULT_ADE_SKIP))
    department: str | None = None
    support_phone_number: str | None = None
    support_email_address: str | None = None

    @field_validator("skip_setup_items")
    @classmethod
    def _skip(cls, v: list[str]) -> list[str]:
        unknown = sorted(set(v) - ADE_SKIP_KEYS)
        if unknown:
            raise ValueError(f"ade.skip_setup_items: nieznane klucze {unknown} (literowka?)")
        if "AppleID" in v or "Restore" in v:
            # Bez tych ekranow dziecko nie zaloguje sie kontem z Rodziny (Popros
            # o zakup, limity) albo nie przywroci kopii z zapisami gier.
            raise ValueError("ade.skip_setup_items: AppleID i Restore musza zostac w kreatorze")
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
    ade: AdeSettings = Field(default_factory=AdeSettings)
    #: Wpisy iPhone'ow odrzucone przy wczytaniu: {etykieta: bledy}. Ustawia
    #: load(); serwer zapisuje je jako zdarzenie (alarm w Kidwatchu).
    _rejected: dict[str, list[str]] = PrivateAttr(default_factory=dict)

    @property
    def rejected(self) -> dict[str, list[str]]:
        return self._rejected

    def device(self, label: str) -> DevicePolicy:
        return self.devices.get(label) or DevicePolicy(name=label)

    @model_validator(mode="after")
    def _unique_serials(self) -> Policy:
        seen: dict[str, str] = {}
        for label, dev in self.devices.items():
            if dev.serial and dev.serial in seen:
                raise ValueError(
                    f"serial {dev.serial} jest i w {seen[dev.serial]}, i w {label} — "
                    "zapis ADE nie wiedzialby, ktora etykiete wydac"
                )
            if dev.serial:
                seen[dev.serial] = label
        return self

    def label_for_serial(self, serial: str | None) -> str | None:
        """Etykieta iPada o tym numerze seryjnym (zapis ADE)."""
        wanted = (serial or "").strip().upper()
        if not wanted:
            return None
        return next((lb for lb, d in self.devices.items() if d.serial == wanted), None)

    def kind(self, label: str, product: str | None = None) -> MdmKind:
        """Rodzaj wg ProductName, gdy urzadzenie juz go zglosilo; inaczej wg
        polityki. „iPhone…" lapie iPhone'a zapisanego pod etykieta bez
        `kind: iphone`; „iPad…" chroni iPada przed `kind: iphone` wpisanym
        pod jego etykieta przez pomylke — po cichu stracilby blokady i DNS
        (kind_mismatch, alarm w Kidwatchu)."""
        product = product or ""
        if product.startswith("iPad"):
            return "ipad"
        if self.device(label).kind == "iphone" or product.startswith("iPhone"):
            return "iphone"
        return "ipad"

    def kind_mismatch(self, label: str, product: str | None) -> bool:
        """Polityka mowi iPhone, a urzadzenie zglasza sie jako iPad."""
        return self.device(label).kind == "iphone" and (product or "").startswith("iPad")

    def restrictions_for(self, label: str, kind: MdmKind | None = None) -> dict[str, Any]:
        dev = self.device(label)
        if (kind or dev.kind) == "iphone":
            # Tylko wlasne klucze urzadzenia, i to tylko zadeklarowanego jako
            # iPhone — tylko te walidacja sprawdzila pod katem nadzoru. Domyslne
            # i wspolne sa dla nadzorowanych iPadow.
            return dict(dev.restrictions) if dev.kind == "iphone" else {}
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
    return [error for _, error in validate_entries(policy, schema)]


def validate_entries(policy: Policy, schema: dict | None) -> list[tuple[str | None, str]]:
    """Bledy z wpisem, ktorego dotycza: (etykieta urzadzenia albo None dla
    ustawien wspolnych, tresc). Przypisanie nie z tekstu bledu — iPhone
    z etykieta `software_update` nie moze polknac bledu wspolnych ustawien."""
    entries: list[tuple[str | None, str]] = []
    labels = ["(wspolne)", *(lb for lb, d in policy.devices.items() if d.kind != "iphone")]
    for label in labels:
        errors: list[str] = []
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
        owner = None if label == "(wspolne)" else label
        entries += [(owner, e) for e in errors]
    for label, dev in policy.devices.items():
        if dev.kind == "iphone":
            entries += [(label, e) for e in _iphone_errors(label, dev, schema)]
    if schema is not None:
        su_keys = schema["declarations"]["com.apple.configuration.softwareupdate.settings"]["keys"]
        for key in policy.software_update:
            if key not in su_keys:
                entries.append((None, f"software_update: nieznany klucz {key!r}"))
    return entries


def _iphone_errors(label: str, dev: DevicePolicy, schema: dict | None) -> list[str]:
    """iPhone bez nadzoru zignoruje klucz „tylko pod nadzorem" bez slowa —
    w polityce bylby blokada, ktorej nie ma. Odrzucamy go glosno."""
    errors: list[str] = []
    if dev.blocked_apps:
        errors.append(
            f"{label}: blocked_apps (blockedAppBundleIDs) wymaga nadzoru — iPhone go zignoruje"
        )
    keys = schema["profiles"]["com.apple.applicationaccess"]["keys"] if schema else {}
    types = {"boolean": bool, "integer": int, "array": list, "string": str}
    for key, value in dev.restrictions.items():
        if key in FORBIDDEN_FALSE and value is False:
            errors.append(f"{label}: {key}=false psuje Popros o zakup / konta Rodziny")
        if key in DEFAULT_RESTRICTIONS:
            # Bez schematu znamy przynajmniej te: wszystkie wymagaja nadzoru.
            errors.append(f"{label}: {key} dziala tylko pod nadzorem — iPhone go zignoruje")
            continue
        if schema is None:
            continue
        spec = keys.get(key)
        if spec is None:
            errors.append(f"{label}: nieznany klucz ograniczen {key!r} (literowka?)")
            continue
        if spec.get("supervised_ios") is True:
            errors.append(f"{label}: {key} dziala tylko pod nadzorem — iPhone go zignoruje")
            continue
        expected = types.get(spec["type"])
        if expected and not (
            isinstance(value, expected) and not (expected is int and isinstance(value, bool))
        ):
            errors.append(f"{label}: {key} ma typ {spec['type']}, dostalem {value!r}")
    return errors


def load(path: str | os.PathLike, schema: dict | None = None) -> Policy:
    """Polityka gotowa do startu albo PolicyError.

    Zasada: zaden blad w polityce nie moze po cichu ZDJAC ochrony z iPada.

    Bledny wpis, o ktorym wiadomo, ze to iPhone (`kind: iphone` i bez
    `dns_url`), NIE zatrzymuje startu: trafia do kwarantanny (zostaje sama
    nazwa i rodzaj, bez wlasnych ograniczen — iPhone traci tez te dzialajace
    bez nadzoru) i do `policy.rejected`, a serwer zapisuje zdarzenie, z ktorego
    Kidwatch robi alarm. Brak startu odcialby od komend wszystkie iPady.

    Zatrzymuje start, jak przed E5:
      * blad we wspolnych ustawieniach albo we wpisie iPada;
      * blad we wpisie `kind: iphone` z `dns_url` — iPhone nigdy go nie ma (DNS
        idzie recznym profilem), wiec to najpewniej iPad z pomylonym `kind`,
        a kwarantanna skasowalaby mu DNS i blokady;
      * kwarantanna wpisu, pod ktorego etykieta w bazie jest zapisany iPad —
        tego load() nie wie, sprawdza MDMService przy starcie.
    Sprawdzenie na sucho: `kidwatch-mdm check-policy`.
    """
    raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    policy = Policy.model_validate(raw)
    iphones = {
        label for label, d in policy.devices.items() if d.kind == "iphone" and not d.dns_url
    }
    rejected: dict[str, list[str]] = {}
    fatal: list[str] = []
    for label, error in validate_entries(policy, schema):
        if label in iphones:
            rejected.setdefault(label, []).append(error)
        elif label is not None and policy.devices[label].kind == "iphone":
            fatal.append(
                f"{error} (wpis ma dns_url, ktorego iPhone nie uzywa — jesli to iPad, "
                f"usun `kind: iphone`; jesli iPhone, usun dns_url)"
            )
        else:
            fatal.append(error)
    if fatal:
        raise PolicyError("polityka odrzucona:\n  " + "\n  ".join(fatal))
    for label in rejected:
        policy.devices[label] = DevicePolicy(name=policy.devices[label].name, kind="iphone")
    policy._rejected = rejected
    return policy
