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
#: Konta panelu: dodaj, usun, rola, uprawnienia i kanaly powiadomien INNYCH.
KONTA = "konta.zarzadzanie"
#: Powiadomienia techniczne (czujka, awarie, inne) per konto (odbiorcy.py).
POWIADOMIENIA_TECHNICZNE = "powiadomienia.techniczne"

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
    KONTA: "zarządzanie kontami (dodaj, usuń, rola, uprawnienia, kanały innych)",
    POWIADOMIENIA_TECHNICZNE: "powiadomienia techniczne (czujka, awarie, inne)",
}
UPRAWNIENIA = tuple(OPISY)

ROLE_UPRAWNIENIA: dict[str, frozenset[str]] = {
    ROLE_OWNER: frozenset(UPRAWNIENIA),
    ROLE_VIEWER: frozenset({KONTO_WLASNE, PODGLAD}),
}

#: Nie do odebrania pojedynczo: konto bez niego nie zmieniloby hasla po
#: wycieku ani nie wylaczylo 2FA po zgubieniu telefonu.
STALE = frozenset({KONTO_WLASNE})


def efektywne(rola: str, nadane: set[str] | frozenset[str] = frozenset(),
              odebrane: set[str] | frozenset[str] = frozenset()) -> frozenset[str]:
    """Nieznana rola (np. reczna edycja bazy) = brak uprawnien poza STALE:
    odmowa zamiast domyslnego wlasciciela."""
    baza = ROLE_UPRAWNIENIA.get(rola, STALE)
    return frozenset((baza | set(nadane)) - (set(odebrane) - STALE)) & frozenset(UPRAWNIENIA)


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
