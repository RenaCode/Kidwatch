"""Powiadomienia per konto panelu: kanaly, preferencje, routing.

DO TEJ ZMIANY odbiorcow znala tylko bramka (renacode-infra: charts/bramka):
lista numerow WhatsApp z trasami (`*`, `kidwatch`, `kidwatch:czujka`...)
w jej pliku ustawien, a mail szedl na jeden adres wlasciciela. Kidwatch
wysylal jedno zadanie i nie wiedzial, kto je dostal.

TERAZ odbiorca to konto panelu. Kazde konto ma w panel-auth.db (nigdy
w repo ani w values) swoje kanaly (numer WhatsApp, e-mail), kategorie
zdarzen, godziny ciszy i dzieci, ktorych dotycza. Outbox (notifiers/base.py)
rozdziela kazde powiadomienie na wpisy per konto (`adresaci`) i wysyla
do bramki osobne zadanie z jawnym odbiorca.

CO PER KONTO, A CO DLA DOMU (decyzja):
  - per konto: kanaly, kategorie, cisza, zakres dzieci, uprawnienia — to
    cechy osoby; dwie osoby w domu chca roznych rzeczy na rozne numery;
  - dla domu: sesja bota WhatsApp (nadawca), UniFi, MDM, telewizor, konto
    NextDNS, ntfy i Home Assistant — to jedno urzadzenie albo jedna usluga
    na dom. Rozbicie ich per osoba dubluje stan (dwa boty, dwa profile DNS
    tego samego iPada) bez zadnego zysku. ntfy i Home Assistant zostaja
    kanalami domowymi: dostaja kazde powiadomienie raz, jak dotad.

DOMY (renacode-infra: docs/projekty/kidwatch/architektura-domy.md §2.2, §4.2; od E3a). Kanaly
(numer, e-mail,
`kanal`) sa cecha OSOBY — jedno konto, jeden numer we wszystkich domach
(`user_powiadomienia`). Preferencje (kategorie, cisza, dzieci, `aktywne`)
sa per CZLONKOSTWO (`czlonkostwa_powiadomienia (dom_id, user_id)`), a tryb
per dom (`tryb:<dom_id>`). `ProfilePowiadomien(path, dom_id=...)` widzi
WYLACZNIE czlonkow swojego domu z ich rola i uprawnieniami w tym domu.
Tryb `trasy` jest dozwolony tylko w Domu 1: odbiorcow zna wtedy bramka,
wiec notka innego domu poszlaby do odbiorcow Domu 1. Preferencje i tryb
Domu 1 maja lustro w `user_powiadomienia` i kluczu `tryb` (obraz sprzed
domow czyta je stamtad); zmiana zrobiona starym obrazem (nowszy
`updated_at`, inny `tryb`) wraca przy starcie do tabel domu.

TRYB. Routing per konto wlacza sie dopiero, gdy (1) wlasciciel go wlaczyl
(`kidwatch konta-migruj --zapisz` albo panel), (2) config nie wylacza go
(`notifiers.bramka.per_konto: false`), (3) bramka deklaruje obsluge jawnego
odbiorcy (`GET /v1/stan` -> `funkcje: ["odbiorca"]`). Inaczej dziala stary
tryb tras — zachowanie sprzed zmiany, bit w bit. Starsza bramka zignorowalaby
pole `odbiorca` i wyslala KAZDE zadanie do wszystkich z trasy, czyli N razy
to samo do kazdego — dlatego bez (3) tryb kont sie nie wlacza.
"""

from __future__ import annotations

import contextlib
import copy
import json
import logging
import os
import re
import sqlite3
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from datetime import time as dtime
from pathlib import Path
from zoneinfo import ZoneInfo

from . import uprawnienia
from .bramka_admin import mask, normalize_number
from .models import Notification, NotifyKind

log = logging.getLogger(__name__)

# ================================================================ kategorie
#: Kategorie zdarzen, ktore konto wlacza i wylacza. Kolejnosc = kolejnosc w UI.
SESJE = "sesje"
ALARMY = "alarmy"
RAPORTY = "raporty"
GRA = "gra"
MDM = "mdm"
CZUJKA = "czujka"
INNE = "inne"
KATEGORIE = (SESJE, ALARMY, RAPORTY, GRA, MDM, CZUJKA, INNE)

OPISY_KATEGORII = {
    SESJE: "sesje: start, aplikacja, koniec (iPady, telewizor)",
    ALARMY: "alarmy: iPad w nocy, nowa albo usunięta aplikacja",
    RAPORTY: "raporty: dzienny i tygodniowy",
    GRA: "czas gry",
    MDM: "MDM: profil zdjęty, iPad cichy, certyfikat",
    CZUJKA: "czujka i awarie: cisza DNS, profil DNS, pauza TV, kolejka",
    INNE: "inne (nowe rodzaje bez kategorii)",
}

_RODZAJ_KATEGORIA: dict[NotifyKind, str] = {
    NotifyKind.SESSION_START: SESJE,
    NotifyKind.APP: SESJE,
    NotifyKind.SESSION_END: SESJE,
    NotifyKind.THROTTLED: SESJE,
    NotifyKind.DEVICE_LAUNCH: SESJE,
    NotifyKind.DEVICE_SCREEN: SESJE,
    NotifyKind.TV_START: SESJE,
    NotifyKind.TV_END: SESJE,
    NotifyKind.NIGHT: ALARMY,
    NotifyKind.DEVICE_INVENTORY: ALARMY,
    NotifyKind.DAILY: RAPORTY,
    NotifyKind.WEEKLY: RAPORTY,
    NotifyKind.GAME: GRA,
    NotifyKind.MDM: MDM,
    NotifyKind.WATCHDOG: CZUJKA,
    NotifyKind.DNS_PROFILE: CZUJKA,
    NotifyKind.TV_PAUSE: CZUJKA,
}

#: Kategoria -> uprawnienie, bez ktorego konto jej nie dostaje (nawet gdy
#: ma ja wlaczona — odebranie uprawnienia dziala od razu, bez edycji
#: preferencji). Podglad nie dostaje alarmow technicznych ani MDM: zdradzaja
#: UDID-y i stan infrastruktury, a ich odbiorca ma cos z nimi zrobic.
WYMAGANE: dict[str, str] = {
    SESJE: uprawnienia.PODGLAD,
    ALARMY: uprawnienia.PODGLAD,
    RAPORTY: uprawnienia.PODGLAD,
    GRA: uprawnienia.PODGLAD,
    MDM: uprawnienia.MDM_PODGLAD,
    CZUJKA: uprawnienia.POWIADOMIENIA_TECHNICZNE,
    INNE: uprawnienia.POWIADOMIENIA_TECHNICZNE,
}


def kategoria(kind: NotifyKind | str) -> str:
    """Nowy rodzaj bez wpisu trafia do INNE, czyli tylko do kont
    z uprawnieniem technicznym — jak "kidwatch:inne" w bramce."""
    try:
        return _RODZAJ_KATEGORIA.get(NotifyKind(kind), INNE)
    except ValueError:
        return INNE


def dozwolone(upr: Iterable[str]) -> frozenset[str]:
    """Kategorie, ktore konto z tymi uprawnieniami moze dostawac."""
    upr = set(upr)
    return frozenset(k for k in KATEGORIE if WYMAGANE[k] in upr)


# ================================================================== kanaly
KANALY = ("auto", "whatsapp", "email")
#: Etykieta domeny jak w bramce (charts/bramka: kanaly.EMAIL): 1-63 znaki,
#: '-' tylko w srodku. Adres, ktory przyjmie panel, a odrzuci bramka (400),
#: konczylby porzuceniem kazdego powiadomienia tego konta.
_ETYKIETA = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_EMAIL = re.compile(rf"[A-Za-z0-9._%+-]{{1,64}}@{_ETYKIETA}(?:\.{_ETYKIETA})*\.[A-Za-z]{{2,24}}",
                    re.ASCII)
MAX_EMAIL = 254


def normalize_email(raw: str) -> str | None:
    text = str(raw).strip()
    if len(text) > MAX_EMAIL or not _EMAIL.fullmatch(text):
        return None
    local, domain = text.rsplit("@", 1)
    return f"{local}@{domain.lower()}"


def mask_email(email: str) -> str:
    """"jan.k@poczta.pl" -> "j…@poczta.pl" — do logu i listy kont."""
    local, _, domain = email.partition("@")
    return f"{local[:1]}…@{domain}"


# =================================================================== cisza
_HHMM = re.compile(r"([01][0-9]|2[0-3]):([0-5][0-9])", re.ASCII)


def parse_hhmm(raw: str | None) -> dtime | None:
    if raw is None or raw == "":
        return None
    m = _HHMM.fullmatch(str(raw).strip())
    if not m:
        raise ValueError("Godzina w formacie GG:MM, np. 22:00")
    return dtime(int(m[1]), int(m[2]))


def _fmt(t: dtime | None) -> str | None:
    return None if t is None else f"{t.hour:02d}:{t.minute:02d}"


def koniec_ciszy(od: dtime, do: dtime, now_local: datetime) -> datetime | None:
    """Koniec biezacego okna ciszy (czas lokalny) albo None poza cisza.

    Okno przez polnoc (22:00-07:00) jest normalnym przypadkiem. od == do
    znaczy brak ciszy, nie cisze calodobowa — calodobowa cisza to wylaczenie
    powiadomien, do czego sluzy przelacznik `aktywne`."""
    if od == do:
        return None
    t = now_local.timetz().replace(tzinfo=None)
    day = now_local.date()
    tz = now_local.tzinfo
    if od < do:
        if od <= t < do:
            return datetime.combine(day, do, tz)
        return None
    if t >= od:
        return datetime.combine(day + timedelta(days=1), do, tz)
    if t < do:
        return datetime.combine(day, do, tz)
    return None


# ================================================================== profil
@dataclass(frozen=True)
class Profil:
    login: str
    rola: str
    uprawnienia: frozenset[str]
    whatsapp: str | None = None
    email: str | None = None
    kanal: str = "auto"
    #: None = brak zapisanych preferencji: wszystko, co dozwolone.
    kategorie: frozenset[str] | None = None
    cisza_od: dtime | None = None
    cisza_do: dtime | None = None
    #: Alarm (priorytet 5) przebija cisze — iPad w nocy to wlasnie to,
    #: co rodzic chce wiedziec o 2:00, nawet jesli sesji nie.
    cisza_alarmy: bool = True
    #: None = wszystkie dzieci.
    dzieci: frozenset[str] | None = None
    aktywne: bool = True
    #: "cisza 2h" z WhatsAppa (komendy_bot.py): do tej chwili (UTC) konto
    #: dostaje powiadomienia jak w godzinach ciszy. Cecha osoby, nie domu.
    wyciszone_do: datetime | None = None

    @property
    def ma_kanal(self) -> bool:
        if self.kanal == "whatsapp":
            return bool(self.whatsapp)
        if self.kanal == "email":
            return bool(self.email)
        return bool(self.whatsapp or self.email)

    def efektywne_kategorie(self) -> frozenset[str]:
        allowed = dozwolone(self.uprawnienia)
        chosen = allowed if self.kategorie is None else self.kategorie
        return chosen & allowed

    def adres(self) -> dict:
        """Pole `odbiorca` zadania do bramki."""
        body: dict = {"kanal": self.kanal}
        if self.whatsapp and self.kanal != "email":
            body["whatsapp"] = self.whatsapp
        if self.email and self.kanal != "whatsapp":
            body["email"] = self.email
        return body

    def publiczny(self) -> dict:
        """Dla panelu: kanaly ZAMASKOWANE. Pelny numer nie wraca do
        przegladarki nawet wlascicielowi konta — do zmiany wpisuje sie nowy."""
        return {
            "login": self.login,
            "rola": self.rola,
            "whatsapp": mask(self.whatsapp) if self.whatsapp else None,
            "email": mask_email(self.email) if self.email else None,
            "kanal": self.kanal,
            "kategorie": sorted(self.efektywne_kategorie(), key=KATEGORIE.index),
            "dozwolone": sorted(dozwolone(self.uprawnienia), key=KATEGORIE.index),
            "cisza_od": _fmt(self.cisza_od),
            "cisza_do": _fmt(self.cisza_do),
            "cisza_alarmy": self.cisza_alarmy,
            "dzieci": None if self.dzieci is None else sorted(self.dzieci),
            "aktywne": self.aktywne,
            "ma_kanal": self.ma_kanal,
        }


@dataclass(frozen=True)
class Adresat:
    login: str
    #: None = od razu; inaczej wstrzymane do konca ciszy (UTC).
    po: datetime | None = None


@dataclass
class Rozdzial:
    adresaci: list[Adresat] = field(default_factory=list)
    #: login -> powod pominiecia (do logu na poziomie DEBUG i testow).
    pominieci: dict[str, str] = field(default_factory=dict)


#: Priorytet, od ktorego powiadomienie przebija cisze (skala ntfy 1-5).
ALARM_PRIORYTET = 5


def adresaci(
    note: Notification,
    profile: Iterable[Profil],
    *,
    dziecko: Mapping[str, str],
    tz: ZoneInfo,
    now: datetime,
) -> Rozdzial:
    """Kto dostaje `note` i kiedy. Czysta funkcja — cala polityka w jednym
    miejscu, testowana bez bazy i bez sieci.

    `dziecko`: nazwa urzadzenia -> dziecko (config.devices). Powiadomienie
    bez urzadzenia albo o urzadzeniu bez dziecka (telewizor, czujka, raport
    zbiorczy) dotyczy domu i nie jest filtrowane po dzieciach.

    Cisza: alarm (priorytet 5) idzie od razu, jesli konto na to pozwala;
    informacja o sesji przepada (start sesji o 7:00 opisujacy 23:10 nic nie
    znaczy); reszta czeka do konca ciszy.
    """
    kat = kategoria(note.kind)
    child = dziecko.get(note.device or "")
    wynik = Rozdzial()
    seen: set[str] = set()
    for p in profile:
        if p.login in seen:
            continue
        seen.add(p.login)
        if not p.aktywne:
            wynik.pominieci[p.login] = "wylaczone"
            continue
        if not p.ma_kanal:
            wynik.pominieci[p.login] = "brak kanalu"
            continue
        if WYMAGANE[kat] not in p.uprawnienia:
            wynik.pominieci[p.login] = f"brak uprawnienia {WYMAGANE[kat]}"
            continue
        if kat not in p.efektywne_kategorie():
            wynik.pominieci[p.login] = f"kategoria {kat} wylaczona"
            continue
        if child is not None and p.dzieci is not None and child not in p.dzieci:
            wynik.pominieci[p.login] = "inne dziecko"
            continue
        po = None
        koniec = None
        if p.cisza_od is not None and p.cisza_do is not None:
            koniec = koniec_ciszy(p.cisza_od, p.cisza_do, now.astimezone(tz))
        if p.wyciszone_do is not None and p.wyciszone_do > now:
            koniec = p.wyciszone_do if koniec is None else max(koniec, p.wyciszone_do)
        if koniec is not None:
            if note.priority >= ALARM_PRIORYTET and p.cisza_alarmy:
                pass
            elif kat == SESJE:
                wynik.pominieci[p.login] = "cisza"
                continue
            else:
                po = koniec.astimezone(now.tzinfo)
        wynik.adresaci.append(Adresat(p.login, po))
    return wynik


def nadal_chce(p: Profil, note: Notification) -> bool:
    """Czy konto wciaz moze i chce dostac wpis, ktory juz czeka w jego
    kolejce (np. raport wstrzymany cisza). Sprawdzane tuz przed wysylka:
    odebrane uprawnienie, wylaczona kategoria albo wylaczone konto dzialaja
    od razu, takze na wpisy rozdzielone wczesniej."""
    return p.aktywne and p.ma_kanal and kategoria(note.kind) in p.efektywne_kategorie()


# ================================================================== baza
SCHEMA = """
-- Kanaly i preferencje powiadomien konta (odbiorcy.py). Brak wiersza =
-- konto bez kanalu (nic nie dostaje) z domyslnymi preferencjami.
-- Numery i adresy leza TYLKO tu (plik 0600 na wolumenie /data), nigdy
-- w repo, values ani w logu (tam zamaskowane).
CREATE TABLE IF NOT EXISTS user_powiadomienia (
    user_id      INTEGER PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    whatsapp     TEXT,
    email        TEXT,
    kanal        TEXT NOT NULL DEFAULT 'auto',
    -- JSON lista kategorii; NULL = wszystkie dozwolone uprawnieniami.
    kategorie    TEXT,
    cisza_od     TEXT,
    cisza_do     TEXT,
    cisza_alarmy INTEGER NOT NULL DEFAULT 1,
    -- JSON lista dzieci; NULL = wszystkie.
    dzieci       TEXT,
    aktywne      INTEGER NOT NULL DEFAULT 1,
    updated_at   REAL NOT NULL
);

-- Ustawienia domu dla powiadomien: tryb:<dom_id> = trasy|konta (`tryb`
-- bez domu to lustro Domu 1 dla obrazu sprzed domow).
CREATE TABLE IF NOT EXISTS powiadomienia_ustawienia (
    klucz   TEXT PRIMARY KEY,
    wartosc TEXT NOT NULL
);
"""

#: Preferencje per czlonkostwo (§2.2). Zakladane tylko obok `czlonkostwa`
#: (domy.py) — klucz obcy na nia kasuje preferencje razem z czlonkostwem.
SCHEMA_DOMU = """
CREATE TABLE IF NOT EXISTS czlonkostwa_powiadomienia (
    dom_id       INTEGER NOT NULL,
    user_id      INTEGER NOT NULL,
    kategorie    TEXT,
    cisza_od     TEXT,
    cisza_do     TEXT,
    cisza_alarmy INTEGER NOT NULL DEFAULT 1,
    dzieci       TEXT,
    aktywne      INTEGER NOT NULL DEFAULT 1,
    updated_at   REAL NOT NULL,
    PRIMARY KEY (dom_id, user_id),
    FOREIGN KEY (dom_id, user_id) REFERENCES czlonkostwa (dom_id, user_id) ON DELETE CASCADE
);
"""

#: Kolumny preferencji (wspolne dla lustra i tabeli domu).
_PREFERENCJE = ("kategorie", "cisza_od", "cisza_do", "cisza_alarmy", "dzieci", "aktywne")

TRYB_TRASY = "trasy"
TRYB_KONTA = "konta"
#: Dom operatora (domy.DOM_1) — jedyny, w ktorym wolno tryb tras.
DOM_TRAS = 1


def _jest_tabela(conn: sqlite3.Connection, nazwa: str) -> bool:
    return conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (nazwa,)
    ).fetchone() is not None


def migruj_preferencje_conn(conn: sqlite3.Connection, teraz: float) -> list[str]:
    """Preferencje i tryb Domu 1 -> tabele domu (§6 p. 5). Pierwszy raz:
    kopia `user_powiadomienia` czlonkow Domu 1 i klucza `tryb`. Kolejne
    starty: tylko zmiany zrobione obrazem sprzed domow (nowszy `updated_at`
    w lustrze, inny `tryb`). Zwraca loginy z przeniesionymi preferencjami.
    Bez tabel domow (panel jeszcze nie migrowal) — nic. Wlasna transakcja."""
    if not _jest_tabela(conn, "czlonkostwa"):
        return []
    conn.executescript(SCHEMA_DOMU)
    conn.execute("BEGIN IMMEDIATE")
    try:
        kolumny = ", ".join(_PREFERENCJE)
        rows = conn.execute(
            f"SELECT u.login, p.user_id, {', '.join('p.' + k for k in _PREFERENCJE)}, "  # noqa: S608
            "p.updated_at, cp.updated_at AS dom_at FROM user_powiadomienia p "
            "JOIN czlonkostwa c ON c.user_id = p.user_id AND c.dom_id = ? "
            "JOIN users u ON u.id = p.user_id "
            "LEFT JOIN czlonkostwa_powiadomienia cp "
            "ON cp.user_id = p.user_id AND cp.dom_id = c.dom_id "
            "WHERE cp.updated_at IS NULL OR p.updated_at > cp.updated_at",
            (DOM_TRAS,),
        ).fetchall()
        for r in rows:
            conn.execute(
                f"INSERT INTO czlonkostwa_powiadomienia (dom_id, user_id, {kolumny}, updated_at) "  # noqa: S608
                f"VALUES (?, ?, {', '.join('?' * len(_PREFERENCJE))}, ?) "
                "ON CONFLICT (dom_id, user_id) DO UPDATE SET "
                + ", ".join(f"{k} = excluded.{k}" for k in (*_PREFERENCJE, "updated_at")),
                (DOM_TRAS, r["user_id"], *(r[k] for k in _PREFERENCJE), r["updated_at"]),
            )
        ustawienia = dict(conn.execute("SELECT klucz, wartosc FROM powiadomienia_ustawienia"))
        stary = ustawienia.get("tryb")
        if stary in (TRYB_TRASY, TRYB_KONTA) and ustawienia.get(f"tryb:{DOM_TRAS}") != stary:
            conn.execute(
                "INSERT INTO powiadomienia_ustawienia (klucz, wartosc) VALUES (?, ?) "
                "ON CONFLICT (klucz) DO UPDATE SET wartosc = excluded.wartosc",
                (f"tryb:{DOM_TRAS}", stary),
            )
        conn.execute("COMMIT")
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    del teraz
    return [r["login"] for r in rows]


class ProfilePowiadomien:
    """Kanaly i preferencje kont w panel-auth.db — w JEDNYM domu (`dom_id`,
    domyslnie Dom 1). Profile to czlonkowie tego domu.

    Pisze panel (watek serwera) i CLI; czyta Outbox z petli glownej. Kazda
    operacja na wlasnym polaczeniu, jak PanelAuth i TvPauseRequests.
    """

    def __init__(self, path: str | Path, clock=time.time, *, dom_id: int = DOM_TRAS) -> None:
        self.path = str(path)
        self.clock = clock
        self.dom_id = int(dom_id)
        new = not Path(self.path).exists()
        with self._conn() as conn:
            conn.executescript(SCHEMA)
            przeniesione = migruj_preferencje_conn(conn, self.clock())
        if przeniesione:
            log.info("powiadomienia: preferencje Domu 1 z lustra: %s", ", ".join(przeniesione))
        if new:
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)

    def dla_domu(self, dom_id: int) -> ProfilePowiadomien:
        """Ten sam plik, inny dom — bez ponownej migracji."""
        kopia = copy.copy(self)
        kopia.dom_id = int(dom_id)
        return kopia

    def _domowa(self, conn: sqlite3.Connection) -> bool:
        """Baza z czlonkostwami (zawsze po PanelAuth). Bez nich — jak przed
        domami: kazde konto, rola z `users`, jeden tryb."""
        return _jest_tabela(conn, "czlonkostwa_powiadomienia")

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    # ------------------------------------------------------------- tryb
    def tryb(self) -> str:
        """Tryb domu. Dom inny niz Dom 1 jest zawsze w trybie kont (trasy
        bramki znaja tylko odbiorcow Domu 1)."""
        if self.dom_id != DOM_TRAS:
            return TRYB_KONTA
        with self._conn() as conn:
            klucze = dict(conn.execute(
                "SELECT klucz, wartosc FROM powiadomienia_ustawienia WHERE klucz IN (?, 'tryb')",
                (f"tryb:{self.dom_id}",),
            ).fetchall())
        tryb = klucze.get(f"tryb:{self.dom_id}", klucze.get("tryb"))
        return tryb if tryb in (TRYB_TRASY, TRYB_KONTA) else TRYB_TRASY

    def ustaw_tryb(self, tryb: str) -> None:
        if tryb not in (TRYB_TRASY, TRYB_KONTA):
            raise ValueError(f"tryb {tryb!r} (dozwolone: {TRYB_TRASY}, {TRYB_KONTA})")
        if self.dom_id != DOM_TRAS:
            if tryb != TRYB_KONTA:
                raise ValueError("tryb tras jest tylko w Domu 1 — inne domy wysyłają per konto")
            return
        with self._conn() as conn:
            # Klucz domu i lustro dla obrazu sprzed domow, razem.
            conn.executemany(
                "INSERT INTO powiadomienia_ustawienia (klucz, wartosc) VALUES (?, ?) "
                "ON CONFLICT (klucz) DO UPDATE SET wartosc = excluded.wartosc",
                [(f"tryb:{self.dom_id}", tryb), ("tryb", tryb)],
            )

    # ------------------------------------------------------------- odczyt
    def profile(self) -> list[Profil]:
        """Czlonkowie domu z kanalami, preferencjami W TYM DOMU i rola
        w tym domu. Baza bez tabeli `users` (panel nigdy nie startowal) =
        brak kont."""
        with self._conn() as conn:
            if not self._domowa(conn):
                return self._profile_bez_domow(conn)
            rows = conn.execute(
                "SELECT u.id, u.login, c.rola, p.whatsapp, p.email, p.kanal, "
                "cp.user_id AS pref, cp.kategorie, cp.cisza_od, cp.cisza_do, cp.cisza_alarmy, "
                "cp.dzieci, cp.aktywne FROM czlonkostwa c "
                "JOIN users u ON u.id = c.user_id "
                "LEFT JOIN user_powiadomienia p ON p.user_id = u.id "
                "LEFT JOIN czlonkostwa_powiadomienia cp "
                "ON cp.dom_id = c.dom_id AND cp.user_id = c.user_id "
                "WHERE c.dom_id = ? ORDER BY u.login",
                (self.dom_id,),
            ).fetchall()
            odst = self._odstepstwa_domu(conn)
            cisza = self._cisza(conn)
        return [self._wycisz(self._profil(r, odst.get(r["id"], (set(), set())), domu=True),
                             cisza.get(r["id"])) for r in rows]

    def _cisza(self, conn: sqlite3.Connection) -> dict[int, float]:
        """Wyciszenia z WhatsAppa (komendy_baza.py: `whatsapp_cisza`), ktore
        jeszcze trwaja. Baza bez tabeli (komendy nigdy niewlaczone) — brak."""
        if not _jest_tabela(conn, "whatsapp_cisza"):
            return {}
        return {int(r[0]): float(r[1]) for r in conn.execute(
            "SELECT user_id, do_ts FROM whatsapp_cisza WHERE do_ts > ?", (self.clock(),))}

    @staticmethod
    def _wycisz(p: Profil, do_ts: float | None) -> Profil:
        if do_ts is None:
            return p
        from dataclasses import replace  # noqa: PLC0415

        return replace(p, wyciszone_do=datetime.fromtimestamp(do_ts, UTC))

    def _profile_bez_domow(self, conn: sqlite3.Connection) -> list[Profil]:
        try:
            rows = conn.execute(
                "SELECT u.id, u.login, u.rola, p.*, p.user_id AS pref FROM users u "
                "LEFT JOIN user_powiadomienia p ON p.user_id = u.id ORDER BY u.login"
            ).fetchall()
        except sqlite3.OperationalError:
            return []
        odst = self._odstepstwa(conn)
        return [self._profil(r, odst.get(r["id"], (set(), set()))) for r in rows]

    def _odstepstwa_domu(self, conn: sqlite3.Connection) -> dict[int, tuple[set, set]]:
        wynik: dict[int, tuple[set, set]] = {}
        for r in conn.execute("SELECT user_id, uprawnienie, nadane FROM czlonkostwa_uprawnienia "
                              "WHERE dom_id = ?", (self.dom_id,)):
            nadane, odebrane = wynik.setdefault(r["user_id"], (set(), set()))
            (nadane if r["nadane"] else odebrane).add(r["uprawnienie"])
        return wynik

    def profil(self, login: str) -> Profil | None:
        """Czlonek domu albo None (takze konto z innego domu)."""
        for p in self.profile():
            if p.login == login:
                return p
        return None

    def kanaly_osoby(self, login: str) -> Profil | None:
        """Same kanaly konta (cecha osoby, wspolna dla domow) — bez roli,
        uprawnien domu i preferencji. Dla konta niezaleznie od czlonkostwa."""
        with self._conn() as conn:
            r = conn.execute(
                "SELECT u.login, p.whatsapp, p.email, p.kanal FROM users u "
                "LEFT JOIN user_powiadomienia p ON p.user_id = u.id WHERE u.login = ?",
                (login,),
            ).fetchone()
        if r is None:
            return None
        return Profil(login=r["login"], rola="", uprawnienia=uprawnienia.STALE,
                      whatsapp=r["whatsapp"] or None, email=r["email"] or None,
                      kanal=r["kanal"] if r["kanal"] in KANALY else "auto")

    @staticmethod
    def _odstepstwa(conn: sqlite3.Connection) -> dict[int, tuple[set, set]]:
        wynik: dict[int, tuple[set, set]] = {}
        try:
            rows = conn.execute("SELECT user_id, uprawnienie, nadane FROM user_uprawnienia")
        except sqlite3.OperationalError:
            return wynik
        for r in rows:
            nadane, odebrane = wynik.setdefault(r["user_id"], (set(), set()))
            (nadane if r["nadane"] else odebrane).add(r["uprawnienie"])
        return wynik

    @staticmethod
    def _profil(r: sqlite3.Row, odst: tuple[set, set], *, domu: bool = False) -> Profil:
        def lista(raw: str | None) -> frozenset[str] | None:
            if raw is None:
                return None
            try:
                val = json.loads(raw)
            except ValueError:
                return None
            return frozenset(str(v) for v in val) if isinstance(val, list) else None

        def godz(raw: str | None) -> dtime | None:
            try:
                return parse_hhmm(raw)
            except ValueError:
                return None

        if domu:
            upr = uprawnienia.efektywne(r["rola"], *odst, role=uprawnienia.ROLE_DOMU_UPRAWNIENIA)
            rola = uprawnienia.nazwa_roli(r["rola"])
        else:
            upr = uprawnienia.efektywne(r["rola"], *odst)
            rola = r["rola"]
        kanaly = {
            "whatsapp": r["whatsapp"] or None,
            "email": r["email"] or None,
            "kanal": r["kanal"] if r["kanal"] in KANALY else "auto",
        }
        if r["pref"] is None:
            return Profil(login=r["login"], rola=rola, uprawnienia=upr, **kanaly)
        return Profil(
            login=r["login"],
            rola=rola,
            uprawnienia=upr,
            **kanaly,
            kategorie=lista(r["kategorie"]),
            cisza_od=godz(r["cisza_od"]),
            cisza_do=godz(r["cisza_do"]),
            cisza_alarmy=bool(r["cisza_alarmy"]),
            dzieci=lista(r["dzieci"]),
            aktywne=bool(r["aktywne"]),
        )

    # ------------------------------------------------------------- zapis
    def _upsert(self, login: str, *, preferencje: bool = False, **pola) -> None:
        """Kanaly (osoba) albo preferencje (czlonkostwo w domu; w Domu 1
        z lustrem w `user_powiadomienia`, z tym samym `updated_at`)."""
        teraz = self.clock()
        with self._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                row = conn.execute("SELECT id FROM users WHERE login = ?", (login,)).fetchone()
                if row is None:
                    raise LookupError(login)
                domowa = preferencje and self._domowa(conn)
                if domowa and conn.execute(
                    "SELECT 1 FROM czlonkostwa WHERE dom_id = ? AND user_id = ?",
                    (self.dom_id, row["id"]),
                ).fetchone() is None:
                    raise LookupError(login)
                sets = ", ".join(f"{k} = ?" for k in pola)
                if domowa:
                    conn.execute(
                        "INSERT INTO czlonkostwa_powiadomienia (dom_id, user_id, updated_at) "
                        "VALUES (?, ?, ?) ON CONFLICT (dom_id, user_id) DO NOTHING",
                        (self.dom_id, row["id"], teraz),
                    )
                    conn.execute(
                        f"UPDATE czlonkostwa_powiadomienia SET {sets}, updated_at = ? "  # noqa: S608
                        "WHERE dom_id = ? AND user_id = ?",
                        (*pola.values(), teraz, self.dom_id, row["id"]),
                    )
                # Kanaly sa osoby; preferencje Domu 1 maja tu lustro.
                if not domowa or self.dom_id == DOM_TRAS:
                    conn.execute(
                        "INSERT INTO user_powiadomienia (user_id, updated_at) VALUES (?, ?) "
                        "ON CONFLICT (user_id) DO NOTHING", (row["id"], teraz)
                    )
                    conn.execute(
                        f"UPDATE user_powiadomienia SET {sets}, updated_at = ? "  # noqa: S608
                        "WHERE user_id = ?",
                        (*pola.values(), teraz, row["id"]),
                    )
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            conn.execute("COMMIT")

    def ustaw_kanaly(
        self, login: str, *, whatsapp: str | None, email: str | None, kanal: str = "auto"
    ) -> tuple[str | None, str | None]:
        """Zapisuje kanaly (puste = usuniety). Zwraca znormalizowane wartosci.
        ValueError z komunikatem dla czlowieka — bez samego numeru."""
        wa = None
        if whatsapp:
            wa = normalize_number(whatsapp)
            if wa is None:
                raise ValueError("Podaj numer z kierunkowym, np. 48600100200")
        em = None
        if email:
            em = normalize_email(email)
            if em is None:
                raise ValueError("Niepoprawny adres e-mail")
        if kanal not in KANALY:
            raise ValueError("Kanał: auto, whatsapp albo email")
        self._upsert(login, whatsapp=wa, email=em, kanal=kanal)
        return wa, em

    def ustaw_preferencje(
        self,
        login: str,
        *,
        kategorie: Iterable[str] | None,
        cisza_od: str | None = None,
        cisza_do: str | None = None,
        cisza_alarmy: bool = True,
        dzieci: Iterable[str] | None = None,
        aktywne: bool = True,
        znane_dzieci: Iterable[str] | None = None,
    ) -> None:
        """Kategorie spoza uprawnien konta -> ValueError: konto nie moze sobie
        wlaczyc alarmow MDM, ktorych rola nie przewiduje."""
        profil = self.profil(login)
        if profil is None:
            raise LookupError(login)
        kat_json = None
        if kategorie is not None:
            kat = list(dict.fromkeys(kategorie))
            nieznane = [k for k in kat if k not in KATEGORIE]
            if nieznane:
                raise ValueError(f"Nieznana kategoria: {nieznane[0]}")
            zakazane = [k for k in kat if k not in dozwolone(profil.uprawnienia)]
            if zakazane:
                raise ValueError(
                    f"Konto nie ma uprawnienia do kategorii „{zakazane[0]}”"
                )
            kat_json = json.dumps(kat)
        od, do = parse_hhmm(cisza_od), parse_hhmm(cisza_do)
        if (od is None) != (do is None):
            raise ValueError("Cisza: podaj obie godziny albo żadnej")
        dz_json = None
        if dzieci is not None:
            dz = list(dict.fromkeys(str(d) for d in dzieci))
            if znane_dzieci is not None:
                znane = set(znane_dzieci)
                if any(d not in znane for d in dz):
                    raise ValueError("Nieznane dziecko")
            dz_json = json.dumps(dz, ensure_ascii=False)
        self._upsert(
            login, preferencje=True, kategorie=kat_json, cisza_od=_fmt(od), cisza_do=_fmt(do),
            cisza_alarmy=int(bool(cisza_alarmy)), dzieci=dz_json, aktywne=int(bool(aktywne)),
        )


# =============================================================== migracja
#: Trasa bramki obejmujaca wszystko (charts/bramka: kanaly.WSZYSTKO).
WSZYSTKO = "*"


def trasa_bramki(kind: NotifyKind) -> str:
    """Trasa, ktora STARY tryb nadaje rodzajowi (notifiers/bramka.py)."""
    from .notifiers.bramka import kategoria as kat_bramki  # noqa: PLC0415

    k = kat_bramki(kind)
    return "kidwatch" if k is None else f"kidwatch:{k}"


def dostaje_trasa(odbiorca: Mapping, trasa: str) -> bool:
    """Semantyka bramki (kanaly.Odbiorca.dostaje): aktywny i `*` albo
    DOKLADNIE ta trasa."""
    zrodla = odbiorca.get("zrodla") or []
    return bool(odbiorca.get("aktywny", True)) and (WSZYSTKO in zrodla or trasa in zrodla)


def kategorie_z_tras(zrodla: Iterable[str]) -> frozenset[str]:
    """Kategorie Kidwatcha, ktore odbiorca bramki dostaje dzis. Kategoria
    przechodzi, gdy KAZDY jej rodzaj trafia do odbiorcy — kategorie i trasy
    nie sa 1:1 (MDM i czujka ida dzis jedna trasa "kidwatch:czujka")."""
    probe = {"zrodla": list(zrodla), "aktywny": True}
    wynik = set()
    for kat in KATEGORIE:
        rodzaje = [k for k, v in _RODZAJ_KATEGORIA.items() if v == kat]
        if kat == INNE:
            ok = dostaje_trasa(probe, "kidwatch:inne")
        else:
            ok = all(dostaje_trasa(probe, trasa_bramki(k)) for k in rodzaje)
        if ok:
            wynik.add(kat)
    return frozenset(wynik)


@dataclass(frozen=True)
class KrokMigracji:
    pozycja: int
    login: str | None
    numer: str
    etykieta: str
    aktywny: bool
    kategorie: frozenset[str]
    #: Uprawnienia, ktore konto musi dostac, zeby dalej dostawac to, co dzis.
    nadac: frozenset[str] = frozenset()


def plan_migracji(
    odbiorcy_bramki: list[Mapping],
    profile: list[Profil],
    przypisania: Mapping[int, str],
) -> list[KrokMigracji]:
    """Odbiorcy bramki (GET /v1/whatsapp, `odbiorcy`) -> kanaly kont.

    `przypisania`: pozycja (od 1) -> login. Bez jawnego przypisania jedyny
    odbiorca z `*` trafia do jedynego wlasciciela — to numer przeniesiony
    z czasow jednego odbiorcy (migracja tras bramki z 2026-10-05). Reszta
    bez przypisania: login None — CLI pokazuje ja i nie wlacza trybu kont.
    """
    loginy = {p.login: p for p in profile}
    for poz, login in przypisania.items():
        if login not in loginy:
            raise ValueError(f"pozycja {poz}: nie ma konta {login!r}")
    if len(set(przypisania.values())) != len(przypisania):
        raise ValueError("jedno konto przypisane do dwoch numerow")
    auto: dict[int, str] = {}
    wlasciciele = [p.login for p in profile if p.rola == uprawnienia.ROLE_OWNER]
    z_gwiazdka = [i for i, o in enumerate(odbiorcy_bramki, 1)
                  if WSZYSTKO in (o.get("zrodla") or [])]
    if (len(wlasciciele) == 1 and len(z_gwiazdka) == 1
            and z_gwiazdka[0] not in przypisania
            and wlasciciele[0] not in przypisania.values()):
        auto[z_gwiazdka[0]] = wlasciciele[0]
    kroki = []
    for i, o in enumerate(odbiorcy_bramki, 1):
        login = przypisania.get(i) or auto.get(i)
        kat = kategorie_z_tras(o.get("zrodla") or [])
        nadac: frozenset[str] = frozenset()
        if login is not None:
            p = loginy[login]
            nadac = frozenset(WYMAGANE[k] for k in kat) - p.uprawnienia
        kroki.append(KrokMigracji(
            pozycja=i, login=login, numer=str(o.get("numer", "")),
            etykieta=str(o.get("etykieta", "")), aktywny=bool(o.get("aktywny", True)),
            kategorie=kat, nadac=nadac,
        ))
    return kroki


def zastosuj_migracje(konta: ProfilePowiadomien, kroki: list[KrokMigracji], auth) -> None:
    """Zapisuje kanaly i kategorie przypisanych kont; `auth` (PanelAuth)
    nadaje brakujace uprawnienia. Nie wlacza trybu kont — to osobny krok.
    E-mail konta zostaje: bramka go nie zna, a ponowna migracja (nowy numer
    w bramce) nie moze po cichu skasowac zapasowego kanalu."""
    for k in kroki:
        if k.login is None:
            continue
        if k.nadac:
            auth.set_permissions(k.login, dict.fromkeys(k.nadac, True))
        przed = konta.profil(k.login)
        konta.ustaw_kanaly(k.login, whatsapp=k.numer, email=przed.email if przed else None,
                           kanal="auto")
        konta.ustaw_preferencje(
            k.login, kategorie=sorted(k.kategorie, key=KATEGORIE.index), aktywne=k.aktywny,
        )


def profile_po_migracji(kroki: list[KrokMigracji], profile: list[Profil]) -> list[Profil]:
    """Profile kont tak, jak wygladalyby po `zastosuj_migracje` — do
    porownania przed zapisem (CLI) i w tescie rownowaznosci."""
    from dataclasses import replace  # noqa: PLC0415

    by_login = {p.login: p for p in profile}
    for k in kroki:
        if k.login is None:
            continue
        p = by_login[k.login]
        by_login[k.login] = replace(
            p, uprawnienia=p.uprawnienia | k.nadac, whatsapp=k.numer or None,
            kanal="auto", kategorie=k.kategorie, cisza_od=None, cisza_do=None,
            dzieci=None, aktywne=k.aktywny,
        )
    return list(by_login.values())


def porownanie(
    odbiorcy_bramki: list[Mapping], profile: list[Profil], now: datetime
) -> list[tuple[NotifyKind, frozenset[str], frozenset[str]]]:
    """Dla kazdego rodzaju: numery WhatsApp w trybie tras (bramka) i w trybie
    kont (te profile). Rownosc w kazdym wierszu = migracja niczego nie
    zmienia. Bez ciszy i filtra dzieci - tych tryb tras nie znal."""
    by_login = {p.login: p for p in profile}
    wynik = []
    for kind in NotifyKind:
        przed = frozenset(str(o.get("numer", "")) for o in odbiorcy_bramki
                          if dostaje_trasa(o, trasa_bramki(kind)))
        note = Notification(kind=kind, title="", text="", dedup_key="", ts=now)
        rozdzial = adresaci(note, profile, dziecko={}, tz=ZoneInfo("UTC"), now=now)
        po = frozenset(by_login[a.login].whatsapp or "" for a in rozdzial.adresaci)
        wynik.append((kind, przed, po))
    return wynik
