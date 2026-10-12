"""Model uprawnien panelu: rola -> zestaw uprawnien.

Kazda trasa panelu (panel.py, POST_TRASY i GET_TRASY) deklaruje JEDNO
uprawnienie, a serwer sprawdza je w jednym miejscu (`_wymaga`). Front
dostaje liste uprawnien konta w /api/auth/me i chowa przyciski wedlug niej,
nie wedlug nazwy roli.

Uprawnienia konta = uprawnienia roli + pojedyncze nadania - pojedyncze
odebrania (tabela `user_uprawnienia` w panel-auth.db, CLI
`user-uprawnienia <login> +tv.pauza -mdm.podglad`). Rola i zmiany pochodza
z bazy panelu, nigdy z naglowka SSO.

Modul bez zaleznosci: importuje go tez CLI (__main__.py), ktore nie
powinno ladowac argon2 ani cryptography przy kazdym poleceniu.
"""

from __future__ import annotations

ROLE_OWNER = "wlasciciel"
ROLE_VIEWER = "podglad"
ROLES = (ROLE_OWNER, ROLE_VIEWER)

#: Wlasne haslo, 2FA i zgoda na ich zmiane. Ma je kazde konto.
KONTO_WLASNE = "konto.wlasne"
#: Historia, ekrany, uzycie, powiadomienia, stan urzadzen i pauzy TV, eksport.
PODGLAD = "podglad.historia"
MDM_PODGLAD = "mdm.podglad"
MDM_KOMENDY = "mdm.komendy"
CZAS_GRY = "czas_gry.zmiana"
TV_PAUZA = "tv.pauza"
TV_APLIKACJA = "tv.aplikacja"
WHATSAPP = "whatsapp.konfiguracja"
#: Komendy rodzica z WhatsAppa w domu (komendy.py). Samo nie wystarcza:
#: kazda akcja wymaga jeszcze swojego uprawnienia (czas gry, MDM, podglad).
WHATSAPP_KOMENDY = "whatsapp.komendy"
#: Konta panelu: dodaj, usun, rola, uprawnienia i kanaly powiadomien INNYCH.
KONTA = "konta.zarzadzanie"
#: Powiadomienia techniczne (czujka, awarie, inne) per konto (odbiorcy.py).
POWIADOMIENIA_TECHNICZNE = "powiadomienia.techniczne"
#: Dzieci i urzadzenia domu (docs/architektura-domy.md §2.3).
DOM_URZADZENIA = "dom.urzadzenia"
#: Ustawienia i sekrety integracji domu (zapis i maska, nigdy odczyt wartosci).
DOM_INTEGRACJE = "dom.integracje"
#: Tworzenie i odwolywanie zaproszen do domu.
DOM_ZAPROSZENIA = "dom.zaproszenia"

#: Uprawnienie -> opis (komunikat 403, `user-list`, pomoc CLI).
OPISY: dict[str, str] = {
    KONTO_WLASNE: "własne hasło i 2FA",
    PODGLAD: "podgląd historii, ekranów i urządzeń",
    MDM_PODGLAD: "podgląd MDM (iPady, UDID-y, zdarzenia)",
    MDM_KOMENDY: "komendy MDM (blokada, restart, zapis iPada, aktualizacja)",
    CZAS_GRY: "zmiana czasu gry",
    TV_PAUZA: "wstrzymanie i wznowienie monitoringu TV",
    TV_APLIKACJA: "aplikacja Kidwatch TV (instalacja, parowanie)",
    WHATSAPP: "konfiguracja WhatsAppa i powiadomień",
    WHATSAPP_KOMENDY: "komendy z WhatsAppa (blokada, czas gry, stan)",
    KONTA: "zarządzanie kontami (dodaj, usuń, rola, uprawnienia, kanały innych)",
    POWIADOMIENIA_TECHNICZNE: "powiadomienia techniczne (czujka, awarie, inne)",
    DOM_URZADZENIA: "dzieci i urządzenia domu",
    DOM_INTEGRACJE: "integracje domu (UniFi, TV, NextDNS…) i ich klucze",
    DOM_ZAPROSZENIA: "zaproszenia do domu",
}
UPRAWNIENIA = tuple(OPISY)

#: Zakres uprawnienia (§2.3, §4.1): `konto` — konto samo o sobie, w kazdym
#: domu; `instancja` — wspolne dla instalacji (bot WhatsApp bramki); `dom` —
#: tylko w domu, ktorego dotyczy zadanie (`/api/domy/<id>/...`).
ZAKRES_KONTO = "konto"
ZAKRES_DOM = "dom"
ZAKRES_INSTANCJA = "instancja"
ZAKRESY: dict[str, str] = {
    **dict.fromkeys(UPRAWNIENIA, ZAKRES_DOM),
    KONTO_WLASNE: ZAKRES_KONTO,
    WHATSAPP: ZAKRES_INSTANCJA,
}
UPRAWNIENIA_DOMU = frozenset(u for u, z in ZAKRESY.items() if z == ZAKRES_DOM)
UPRAWNIENIA_INSTANCJI = frozenset(u for u, z in ZAKRESY.items() if z == ZAKRES_INSTANCJA)

#: Role w DOMU (docs/architektura-domy.md §2.3, tabela `czlonkostwa`).
#: `wlasciciel-domu` ma zbior roli konta `wlasciciel` (takze
#: `whatsapp.konfiguracja` — tylko dla lustra obrazu sprzed domow; w panelu
#: to uprawnienie ma zakres instancji i daje je WYLACZNIE aktywny
#: administrator instalacji, `w_domu` je odfiltrowuje), `zarzadca` jak
#: w tabeli §2.3, `podglad` = `podglad`.
ROLA_WLASCICIEL_DOMU = "wlasciciel-domu"
ROLA_ZARZADCA = "zarzadca"
ROLA_PODGLAD = ROLE_VIEWER
ROLE_DOMU = (ROLA_WLASCICIEL_DOMU, ROLA_ZARZADCA, ROLA_PODGLAD)

ROLE_UPRAWNIENIA: dict[str, frozenset[str]] = {
    ROLE_OWNER: frozenset(UPRAWNIENIA),
    ROLE_VIEWER: frozenset({KONTO_WLASNE, PODGLAD}),
}
#: Osobno od ROLE_UPRAWNIENIA: tamta idzie do panelu jako lista rol konta.
ROLE_DOMU_UPRAWNIENIA: dict[str, frozenset[str]] = {
    ROLA_WLASCICIEL_DOMU: ROLE_UPRAWNIENIA[ROLE_OWNER],
    # Komendy z WhatsAppa wydaja opiekunowie domu (decyzja 2026-10-11):
    # zarzadca dostaje je tylko pojedynczym nadaniem.
    ROLA_ZARZADCA: frozenset(UPRAWNIENIA) - {KONTA, WHATSAPP, WHATSAPP_KOMENDY, DOM_INTEGRACJE,
                                              DOM_ZAPROSZENIA},
    ROLA_PODGLAD: ROLE_UPRAWNIENIA[ROLE_VIEWER],
}

#: Nie do odebrania pojedynczo: konto bez niego nie zmieniloby hasla po
#: wycieku ani nie wylaczylo 2FA po zgubieniu telefonu.
STALE = frozenset({KONTO_WLASNE})


def efektywne(rola: str, nadane: set[str] | frozenset[str] = frozenset(),
              odebrane: set[str] | frozenset[str] = frozenset(),
              role: dict[str, frozenset[str]] = ROLE_UPRAWNIENIA) -> frozenset[str]:
    """Nieznana rola (np. reczna edycja bazy) = brak uprawnien poza STALE:
    odmowa zamiast domyslnego wlasciciela. `role` = ROLE_DOMU_UPRAWNIENIA
    dla roli w domu."""
    baza = role.get(rola, STALE)
    return frozenset((baza | set(nadane)) - (set(odebrane) - STALE)) & frozenset(UPRAWNIENIA)


def w_domu(upr: frozenset[str] | set[str]) -> frozenset[str]:
    """Czesc zbioru, ktora dziala w domu: zakres `dom` i `konto`."""
    return frozenset(u for u in upr if ZAKRESY.get(u) in (ZAKRES_DOM, ZAKRES_KONTO))


def rola_konta(rola: str) -> str:
    """Rola w domu z nazwy roli konta (`wlasciciel` -> `wlasciciel-domu`);
    rola domu przechodzi bez zmian. Stare wywolania (CLI `user-rola`,
    front sprzed domow) podaja role konta."""
    return ROLA_WLASCICIEL_DOMU if rola == ROLE_OWNER else rola


def nazwa_roli(rola_domu: str) -> str:
    """Odwrotnosc `rola_konta` dla wyswietlania i zgodnosci API sprzed domow:
    `wlasciciel-domu` -> `wlasciciel`, reszta bez zmian."""
    return ROLE_OWNER if rola_domu == ROLA_WLASCICIEL_DOMU else rola_domu


def parsuj_zmiany(zmiany: list[str]) -> dict[str, bool | None]:
    """`+tv.pauza -mdm.podglad` -> {"tv.pauza": True, "mdm.podglad": False}.

    `=tv.pauza` zdejmuje wczesniejsze nadanie albo odebranie (wraca do roli).
    Ostatnie wystapienie wygrywa. ValueError z czytelnym opisem."""
    wynik: dict[str, bool | None] = {}
    for z in zmiany:
        znak, nazwa = z[:1], z[1:]
        if znak not in ("+", "-", "="):
            raise ValueError(f"{z!r}: zacznij od '+' (nadaj), '-' (odbierz) albo '=' (jak rola)")
        if nazwa not in OPISY:
            raise ValueError(
                f"nieznane uprawnienie {nazwa!r} (dozwolone: {', '.join(UPRAWNIENIA)})"
            )
        if nazwa in STALE and znak == "-":
            raise ValueError(f"{nazwa!r} ma kazde konto — nie da sie go odebrac")
        wynik[nazwa] = {"+": True, "-": False, "=": None}[znak]
    return wynik
