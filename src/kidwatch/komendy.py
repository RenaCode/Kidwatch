"""Komendy rodzicow z WhatsAppa: ZAMKNIETA lista akcji, parser dokladnych
komend i walidacja wyniku LLM.

Wiadomosc rodzica rozpoznajemy na dwa sposoby:

  1. deterministycznie (`parsuj`) — `stan`, `pomoc`, `koniec`, `+15`, `-15`,
     `zablokuj ipad`, `odblokuj`, `cisza 2h`, `TAK 1234`, ewentualnie z nazwa
     dziecka albo urzadzenia DOKLADNIE jak w konfiguracji i dopiskiem
     `dom <numer>`. Bez LLM: tanio, powtarzalnie i dziala, gdy LLM lezy;
  2. przez LLM (komendy_llm.py), gdy tekst nie jest dokladna komenda. LLM
     dostaje tresc jako DANE i liste dzieci/urzadzen domu, a zwraca obiekt,
     ktory `z_llm` sprawdza schematem: akcja z `AKCJE`, dziecko i urzadzenie
     z podanej listy, liczby w zakresie. Cokolwiek innego = "nie zrozumialem".
     Tresc wiadomosci nigdy nie dodaje akcji: wykonawca (komendy_bot.py) zna
     tylko te z `AKCJE` i kazda wymaga potwierdzenia kodem.

Modul bez zaleznosci od bazy i sieci — testowany w calosci bez atrap.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

from . import uprawnienia as upr

# ================================================================== akcje
ZABLOKUJ = "zablokuj"
KONIEC = "koniec"
ODEJMIJ = "odejmij"
DODAJ = "dodaj"
ODBLOKUJ = "odblokuj"
CISZA = "cisza"
STAN = "stan"
POMOC = "pomoc"
#: Wynik LLM "to nie jest zadna z komend".
NIEZNANA = "nieznana"

#: JEDYNE akcje, jakie bot moze wykonac. Kolejnosc = kolejnosc w pomocy.
AKCJE = (STAN, KONIEC, ZABLOKUJ, ODEJMIJ, DODAJ, ODBLOKUJ, CISZA, POMOC)

#: Luzuja ograniczenia: dzienny limit z WhatsAppa i jawna kopia do
#: drugiego opiekuna (decyzja 2026-10-11). Kod nie zatrzyma dziecka
#: z odblokowanym telefonem rodzica — zatrzymuje je limit i jawnosc.
LUZUJACE = frozenset({DODAJ, ODBLOKUJ})
#: Bez potwierdzenia kodem: niczego nie zmieniaja.
ODCZYT = frozenset({STAN, POMOC})
#: Potrzebuja dziecka (czas gry jest per dziecko).
Z_DZIECKIEM = frozenset({KONIEC, ODEJMIJ, DODAJ, ODBLOKUJ})

#: Uprawnienie akcji W DOMU, sprawdzane obok `whatsapp.komendy` przez to
#: samo `uprawnienia.efektywne` co w panelu. `koniec` blokuje ekran tylko
#: z `mdm.komendy`; bez niego — same gry.
WYMAGA: dict[str, frozenset[str]] = {
    STAN: frozenset({upr.PODGLAD}),
    KONIEC: frozenset({upr.CZAS_GRY}),
    ZABLOKUJ: frozenset({upr.MDM_KOMENDY}),
    ODEJMIJ: frozenset({upr.CZAS_GRY}),
    DODAJ: frozenset({upr.CZAS_GRY}),
    ODBLOKUJ: frozenset({upr.CZAS_GRY}),
    CISZA: frozenset(),
    POMOC: frozenset(),
}

#: Granice parametrow (takze dla wyniku LLM).
MAX_MINUT = 180
MAX_GODZIN = 72
#: Dluzsza wiadomosc to nie komenda — do LLM idzie najwyzej tyle znakow.
MAX_TEKST = 300


@dataclass(frozen=True)
class Komenda:
    """Komenda po rozpoznaniu — juz tylko z wartosci z konfiguracji domu."""

    akcja: str
    dziecko: str | None = None
    urzadzenie: str | None = None
    minuty: int | None = None
    godziny: int | None = None


@dataclass(frozen=True)
class Surowa:
    """Wynik parsera: akcja i NIEROZPOZNANY jeszcze cel (tekst po komendzie,
    znormalizowany). Cel dopasowuje `dopasuj` do slownika konkretnego domu."""

    akcja: str
    cel: str | None = None
    minuty: int | None = None
    godziny: int | None = None
    #: "dom 2" / "dom kowalskich" z konca wiadomosci (znormalizowane).
    dom: str | None = None


@dataclass(frozen=True)
class Potwierdzenie:
    kod: str


# ============================================================ normalizacja
_ZNAKI = str.maketrans({"ł": "l", "Ł": "L"})


def norm(tekst: str) -> str:
    """Bez polskich znakow, malymi literami, pojedyncze spacje, bez
    interpunkcji na koncu: "Koniec, Dziecko Ą!" -> "koniec, dziecko a"."""
    t = unicodedata.normalize("NFKD", str(tekst).translate(_ZNAKI))
    t = "".join(c for c in t if not unicodedata.combining(c))
    t = re.sub(r"\s+", " ", t.lower()).strip()
    return t.strip(" .!?;:")


# ================================================================== parser
_DOM = re.compile(r"^(?P<reszta>.*?)\s*\bdom (?P<dom>[a-z0-9][a-z0-9 -]{0,40})$")
_TAK = re.compile(r"^(?:tak|ok|potwierdzam)[ ,:-]*(?P<kod>\d{4})$")
_MINUTY = re.compile(
    r"^(?P<znak>[+-])\s*(?P<n>\d{1,3})\s*(?:m|min|minut|minuty)?\b\s*(?P<reszta>.*)$")
_CISZA = re.compile(r"^(?:cisza|wycisz)\s+(?P<n>\d{1,2})\s*(?:h|godz|godziny|godzin|godzine)?$")
_SLOWA = {
    "stan": STAN, "status": STAN, "co robia": STAN,
    "pomoc": POMOC, "help": POMOC, "?": POMOC, "komendy": POMOC,
    "koniec": KONIEC, "stop": KONIEC,
    "zablokuj": ZABLOKUJ, "blokuj": ZABLOKUJ,
    "odblokuj": ODBLOKUJ,
}
#: Slowa przed celem, ktore niczego nie znacza ("koniec dla ...").
_WYPELNIACZE = ("dla ", "na ")
#: Rodzaj urzadzenia po `zablokuj` ("zablokuj ipad", "zablokuj ipad dziecka").
_RODZAJE = ("ipada", "ipad", "iphonea", "iphone", "tablet", "telefon", "ekran")


def parsuj(tekst: str) -> Surowa | Potwierdzenie | None:
    """Dokladna komenda albo None (=> LLM). Nie zgaduje: nic poza wzorcami."""
    t = norm(tekst)
    if not t or len(t) > MAX_TEKST:
        return None
    if m := _TAK.fullmatch(t):
        return Potwierdzenie(m["kod"])
    dom = None
    if m := _DOM.fullmatch(t):
        t, dom = m["reszta"].strip(" ,"), m["dom"].strip()
    if m := _CISZA.fullmatch(t):
        return Surowa(CISZA, godziny=int(m["n"]), dom=dom)
    if m := _MINUTY.fullmatch(t):
        akcja = DODAJ if m["znak"] == "+" else ODEJMIJ
        return Surowa(akcja, cel=_cel(m["reszta"]), minuty=int(m["n"]), dom=dom)
    for slowo, akcja in sorted(_SLOWA.items(), key=lambda kv: -len(kv[0])):
        if t == slowo or t.startswith(slowo + " "):
            return Surowa(akcja, cel=_cel(t[len(slowo):]), dom=dom)
    return None


def _cel(reszta: str) -> str | None:
    r = reszta.strip(" ,:-")
    for w in _WYPELNIACZE:
        if r.startswith(w):
            r = r[len(w):]
    return r or None


class NieZnamCelu(LookupError):
    """Cel z wiadomosci nie pasuje do zadnego dziecka ani urzadzenia domu."""


def dopasuj(cel: str | None, dzieci: Iterable[str],
            urzadzenia: Mapping[str, str | None]) -> tuple[str | None, str | None]:
    """(dziecko, urzadzenie) z celu wpisanego w komendzie. `urzadzenia`:
    nazwa -> dziecko (None = wspolne, np. telewizor). Tylko DOKLADNE nazwy
    (bez wielkosci liter i polskich znakow); odmiana ("Dziecka A") -> NieZnamCelu
    i rozpoznaje to dopiero LLM."""
    if cel is None:
        return None, None
    po_dziecku = {norm(d): d for d in dzieci}
    po_urzadzeniu = {norm(u): u for u in urzadzenia}
    kandydaci = [cel]
    for r in _RODZAJE:
        if cel == r:
            return None, None
        if cel.startswith(r + " "):
            kandydaci.append(_cel(cel[len(r):]) or "")
    for k in kandydaci:
        if k in po_urzadzeniu:
            u = po_urzadzeniu[k]
            return urzadzenia[u], u
        if k in po_dziecku:
            return po_dziecku[k], None
    raise NieZnamCelu(cel)


# ============================================================ wynik LLM
#: Schemat odpowiedzi LLM (JSON Schema, wspolny dla dostawcow).
def schemat(dzieci: list[str], urzadzenia: list[str]) -> dict:
    return {
        "type": "object",
        "properties": {
            "akcja": {"type": "string", "enum": [*AKCJE, NIEZNANA]},
            "dziecko": {"type": ["string", "null"], "enum": [*dzieci, None]},
            "urzadzenie": {"type": ["string", "null"], "enum": [*urzadzenia, None]},
            "minuty": {"type": ["integer", "null"], "minimum": 1, "maximum": MAX_MINUT},
            "godziny": {"type": ["integer", "null"], "minimum": 1, "maximum": MAX_GODZIN},
        },
        "required": ["akcja", "dziecko", "urzadzenie", "minuty", "godziny"],
        "additionalProperties": False,
    }


_POLA = frozenset({"akcja", "dziecko", "urzadzenie", "minuty", "godziny"})


def _liczba(v: object, maks: int) -> int | None:
    if v is None:
        return None
    # bool to podklasa int w Pythonie — `true` nie jest liczba minut.
    if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= maks:
        raise ValueError(v)
    return v


def z_llm(dane: object, dzieci: Iterable[str],
          urzadzenia: Mapping[str, str | None]) -> Komenda | None:
    """Wynik LLM -> Komenda albo None (nie zrozumial, poza lista, poza
    schematem). Jedyne wejscie od LLM do wykonawcy — tu konczy sie zaufanie
    do modelu: wartosc spoza listy NIE jest poprawiana ani zgadywana."""
    if not isinstance(dane, dict) or not set(dane) <= _POLA or "akcja" not in dane:
        return None
    akcja = dane.get("akcja")
    if not isinstance(akcja, str) or akcja not in AKCJE:
        return None
    dzieci = list(dzieci)
    dziecko = dane.get("dziecko")
    urzadzenie = dane.get("urzadzenie")
    if dziecko is not None and (not isinstance(dziecko, str) or dziecko not in dzieci):
        return None
    if urzadzenie is not None and (not isinstance(urzadzenie, str)
                                   or urzadzenie not in urzadzenia):
        return None
    try:
        minuty = _liczba(dane.get("minuty"), MAX_MINUT)
        godziny = _liczba(dane.get("godziny"), MAX_GODZIN)
    except ValueError:
        return None
    if urzadzenie is not None:
        wlasciciel = urzadzenia[urzadzenie]
        if dziecko is not None and wlasciciel is not None and wlasciciel != dziecko:
            return None
        dziecko = dziecko or wlasciciel
    if akcja in (DODAJ, ODEJMIJ) and minuty is None:
        return None
    if akcja == CISZA and godziny is None:
        return None
    return Komenda(akcja, dziecko, urzadzenie,
                   minuty if akcja in (DODAJ, ODEJMIJ) else None,
                   godziny if akcja == CISZA else None)


# ================================================================== teksty
def opis(k: Komenda, urzadzenia: Iterable[str] = ()) -> str:
    """Akcja w ludzkich slowach do "Zrozumialem: ...?" i do kopii."""
    kto = f" — {k.dziecko}" if k.dziecko else ""
    ekrany = ", ".join(urzadzenia)
    if k.akcja == ZABLOKUJ:
        return f"zablokować ekran: {ekrany or k.urzadzenie or k.dziecko}"
    if k.akcja == KONIEC:
        return f"zakończyć: zablokować gry{kto}" + (f" i ekran ({ekrany})" if ekrany else "")
    if k.akcja == ODEJMIJ:
        return f"skrócić dodany czas gry o {k.minuty} min{kto}"
    if k.akcja == DODAJ:
        return f"dodać {k.minuty} min czasu gry{kto}"
    if k.akcja == ODBLOKUJ:
        return f"odblokować gry{kto}"
    if k.akcja == CISZA:
        return f"wyciszyć Twoje powiadomienia Kidwatcha na {k.godziny} h"
    if k.akcja == STAN:
        return "pokazać stan" + kto
    return "pokazać pomoc"


def pomoc(dzieci: Iterable[str] = (), *, limit_minut: int = 30) -> str:
    dzieci = list(dzieci)
    przyklad = dzieci[0] if dzieci else "Dziecko"
    linie = [
        "Komendy Kidwatcha:",
        "• stan — kto co teraz robi i ile zostało",
        f"• koniec {przyklad} — blokada gier i ekranu",
        f"• zablokuj ipad {przyklad} — blokada ekranu",
        f"• -15 {przyklad} — skróć dodany czas gry",
        f"• +15 {przyklad} — dodaj czas gry"
        + (f" (najwyżej {limit_minut} min na dobę)" if limit_minut else " (wyłączone)"),
        f"• odblokuj {przyklad} — odblokuj gry",
        "• cisza 2h — wycisz moje powiadomienia",
        "Każdą zmianę potwierdzasz kodem: TAK 1234. Możesz też odpowiedzieć na "
        "powiadomienie Kidwatcha albo napisać zwykłym zdaniem.",
    ]
    if dzieci:
        linie.append("Dzieci: " + ", ".join(dzieci) + ".")
    return "\n".join(linie)


#: Odpowiedz, gdy LLM nie dziala (brak kluczy, limit, awaria obu dostawcow).
BEZ_LLM = ("Nie rozumiem teraz swobodnego tekstu. Napisz dokładną komendę, "
           "np. „koniec {dziecko}”, „+15 {dziecko}”, „stan” albo „pomoc”.")
