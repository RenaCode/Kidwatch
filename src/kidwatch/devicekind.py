"""Rodzaje urzadzen dziecka: iPad, iPhone i telefon z Androidem.

Wszystkie ida ta sama droga — zapytania DNS przez profil NextDNS z nazwa
urzadzenia — wiec silnik, sesje, noc i czujka ciszy sa wspolne. Rozni sie
tylko to, co czyta czlowiek: odmiana nazwy ("uzywa telefonu w nocy") i gdzie
na urzadzeniu szukac wylaczonego DNS.

Telefon z Androidem (zwykle pod Google Family Link) wysyla DNS przez
Prywatny DNS (DNS-over-TLS) na host `<nazwa>-<profil>.dns.nextdns.io`.
NextDNS zamienia `--` w nazwie na spacje, wiec `Telefon--Dziecka-1-abc123`
pokazuje sie w logach jako "Telefon Dziecka 1"
(renacode-infra: docs/projekty/kidwatch/telefon-android.md).
Telewizor ma osobna sciezke (sources/tv*.py) i nie jest tu rodzajem; w bazie
panelu dostaje `rodzaj = 'tv'` (RODZAJ_W_BAZIE), zeby byl przypisany do domu.

iPhone idzie droga iPada (profil NextDNS z nazwa urzadzenia, odczyt wprost
przez lockdown z LAN domu), ale zwykle jest BEZ nadzoru: ograniczenia MDM sa
ignorowane, profil DNS da sie zdjac, a telefon czesto chodzi po sieci
komorkowej. Teksty mowia to wprost (renacode-infra: docs/projekty/kidwatch/iphone.md).

Model domow (renacode-infra: docs/projekty/kidwatch/architektura-domy.md §2.4) nazywa telefon
`phone-android`.
W konfiguracji obie nazwy znacza to samo; wewnatrz i w API panelu zostaje
`phone`, dopoki front nie zna nowej nazwy. Tabela `urzadzenia` w bazie
panelu uzywa nazw z modelu domow (RODZAJ_W_BAZIE).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

DeviceKindName = Literal["ipad", "iphone", "phone"]


@dataclass(frozen=True, slots=True)
class DeviceKind:
    #: Mianownik do tekstow bez polskich znakow (pushe silnika), np. "iPad".
    noun: str
    #: Dopelniacz: "uzywa iPada w nocy", "w Ustawieniach tego telefonu".
    genitive: str
    #: Co zwykle znaczy cisza w DNS (czujka silnika, bez polskich znakow).
    dns_off: str
    #: Gdzie to sprawdzic na urzadzeniu (czujka UniFi, z polskimi znakami).
    dns_where: str
    #: Tag ntfy obok "iphone"/"warning" (tekstowy, bez emoji).
    tag: str


KINDS: dict[str, DeviceKind] = {
    "ipad": DeviceKind(
        noun="iPad",
        genitive="iPada",
        dns_off="zdjety profil DNS albo wylaczony szyfrowany DNS w Ustawieniach tego iPada",
        dns_where="Sprawdź na iPadzie: Ustawienia → Ogólne → VPN i urządzenia → profil NextDNS.",
        tag="ipad",
    ),
    "iphone": DeviceKind(
        noun="iPhone",
        genitive="iPhone'a",
        dns_off=(
            "zdjety profil DNS (iPhone bez nadzoru pozwala go usunac), wylaczony "
            "szyfrowany DNS w Ustawieniach tego iPhone'a, wlaczony tryb samolotowy "
            "albo rozladowany telefon"
        ),
        dns_where=(
            "Sprawdź na iPhonie: Ustawienia → Ogólne → VPN i urządzenia → profil NextDNS. "
            "Bez nadzoru dziecko może ten profil usunąć, a MDM tego nie zablokuje."
        ),
        tag="ios",
    ),
    "phone": DeviceKind(
        noun="telefon",
        genitive="telefonu",
        dns_off=(
            "wylaczony albo zmieniony Prywatny DNS na tym telefonie "
            "(Ustawienia -> Siec i internet -> Prywatny DNS), wlaczony tryb samolotowy "
            "albo rozladowany telefon"
        ),
        dns_where=(
            "Sprawdź na telefonie: Ustawienia → Sieć i internet → Prywatny DNS — ma być "
            "„Nazwa hosta dostawcy” z hostem profilu NextDNS, a w Ustawieniach → VPN "
            "nie może być żadnej aplikacji VPN."
        ),
        tag="android",
    ),
}


#: Nazwa z modelu domow -> nazwa uzywana w konfiguracji, silniku i API.
ALIASY: dict[str, str] = {"phone-android": "phone"}
#: Rodzaj z konfiguracji -> `urzadzenia.rodzaj` w bazie panelu (domy.py).
#: Telewizor nie jest rodzajem z `devices`, ale ma wiersz w `urzadzenia`.
RODZAJ_W_BAZIE: dict[str, str] = {
    "ipad": "ipad",
    "iphone": "iphone",
    "phone": "phone-android",
    "tv": "tv",
}


def kind_of(kind: str | None) -> DeviceKind:
    """Nieznany albo brak rodzaju = iPad (konfiguracje sprzed telefonow)."""
    kind = ALIASY.get(kind or "ipad", kind or "ipad")
    return KINDS.get(kind, KINDS["ipad"])
