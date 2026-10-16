"""Panel: integracje domu (NextDNS, UniFi, TV, MDM, ntfy, Home Assistant...).

Trasy /api/domy/<id>/integracje* (panel.py). Decyzja wlasciciela
2026-10-12: sekrety i ustawienia integracji wpisuje przez panel
ADMINISTRATOR INSTALACJI — uprawnienie `dom.integracje` w domu nie
wystarcza, potrzebna jest aktywna rola administratora (panel_domy.
admin_aktywny: flaga + grupa `admins` albo TOTP). Tu sa walidacja,
potwierdzenia i bezpieczniki, testowane bez serwera HTTP (jak panel_konta).

ZASADY BEZPIECZENSTWA (renacode-infra: docs/projekty/kidwatch/architektura-domy.md §3.1, §3.6)
  - Sekrety tylko do zapisu: odpowiedz niesie nazwy pol i maski
    (`sejf.maska`), nigdy wartosci. Pusty albo pominiety sekret = bez
    zmian; usuniecie to osobna akcja (`/integracje/usun-sekret`).
  - Kazdy zapis wymaga potwierdzenia haslem albo kodem 2FA (`auth.reauth`),
    jak zmiana kanalow i czlonkow domu.
  - Kazdy odczyt i zapis zostawia wiersz w `audyt` (kto, dom, typ, nazwy
    zmienionych pol — bez wartosci). Blad zapisu dziennika przy odczycie
    = 503: wgladu bez sladu nie ma.
  - Komunikaty bledow (walidacja, straznik sieci, sejf) nie zawieraja
    wartosci sekretow z definicji; dodatkowo kazdy komunikat i wpis w logu
    przechodzi przez `bez_sekretow` z wartosciami z tego zadania.
  - Dom w trybie `yaml` (config.yaml) — odmowa 409: tam prawda jest plik,
    zapis w bazie niczego by nie zmienil.
  - Zmiana, po ktorej dzialajacy dom przestalby startowac (np. wylaczone
    jedyne zrodlo DNS, usuniety klucz API), jest wycofywana w transakcji
    (`RejestrDomow.zapisz_integracje(sprawdz_dom=...)`).

Przeladowanie (§5.1): zapis podbija `domy.wersja`, nadzorca
(`domy.Nadzorca`) w ciagu ~10 s restartuje TYLKO ten dom. Stan nadzorcy
(`domy.StanyDomow`) trafia do odpowiedzi — ekran mowi wprost, czy dom juz
dziala na nowej wersji, czy nowa konfiguracja nie wystartowala, czy (dom bez
przeladowania) zmiana zadziala dopiero po restarcie Kidwatcha.
"""

from __future__ import annotations

import logging
import types
import typing
from collections.abc import Callable
from datetime import UTC, datetime

from pydantic_core import PydanticUndefined

from . import domy as dm
from .konfiguracja_domu import MODELE_INTEGRACJI, blad_startu_conn
from .panel_auth import AuthError, PanelAuth, Session
from .sejf import BrakKek, Sejf, SejfError

log = logging.getLogger(__name__)

NAZWY = {
    "nextdns": "NextDNS (źródło DNS)",
    "adguard": "AdGuard Home (źródło DNS)",
    "unifi": "UniFi (kontroler sieci)",
    "tv": "Telewizor",
    "mdm": "Serwer MDM (iPady)",
    "ntfy": "ntfy (powiadomienia push)",
    "homeassistant": "Home Assistant",
}
OPISY_SEKRETOW = {
    ("nextdns", "api_key"): "klucz API",
    ("adguard", "password"): "hasło",
    ("unifi", "api_key"): "klucz API",
    ("tv", "sony_psk"): "klucz PSK Sony",
    ("tv", "adb_key"): "klucz prywatny ADB (PEM)",
    ("tv", "adb_key_pub"): "klucz publiczny ADB",
    ("tv", "app_token"): "token aplikacji Kidwatch TV (ustawia parowanie)",
    ("mdm", "token"): "token API serwera MDM",
    ("ntfy", "topic"): "temat (nazwa tematu jest hasłem)",
    ("ntfy", "token"): "token dostępu",
    ("homeassistant", "webhook_id"): "identyfikator webhooka",
}
#: Zrodla DNS — dom ma wlaczone dokladnie jedno.
ZRODLA_DNS = ("nextdns", "adguard")
#: Pola modelu, ktorych nie ma w formularzu: `enabled` to przelacznik
#: integracji, katalog klucza ADB ustawia srodowisko domu (pamiec poda).
POMIJANE = frozenset({"enabled", "adb_key_dir"})
#: Pola wielolinijkowe (PEM) — w formularzu pole tekstowe, nie haslo.
WIELOLINIJKOWE = frozenset({("tv", "adb_key"), ("tv", "adb_key_pub")})
#: Najdluzszy sekret (klucz PEM RSA 4096 ma ~3,3 kB).
MAX_SEKRET = 8192
MAX_POL = 40
#: Wskazowka przy odmowie straznika sieci (§3.6).
WSKAZOWKA_SIECI = (
    "Adres musi należeć do sieci tego domu. Sieci (CIDR) i hosty API dopuszcza "
    "administrator z CLI: kidwatch dom-sieci <dom> --dodaj <CIDR> albo --host <nazwa>."
)
NIE_DLA_YAML = (
    "Ten dom ma konfigurację z config.yaml (tryb yaml) — integracje zmienia się tam. "
    "Ekran integracji działa tylko dla domów z konfiguracją w bazie (kidwatch dom-importuj)."
)
BEZ_PRZELADOWANIA = (
    "Kidwatch nie przeładowuje tego domu automatycznie — zmiana zadziała po restarcie "
    "Kidwatcha."
)


def bez_sekretow(tekst: str, wartosci: typing.Iterable[str]) -> str:
    """Ostatnia zapora: wartosci sekretow z TEGO zadania wyciete z komunikatu.
    Krotkie (< 4 znaki) zostaja — wycinanie ich psuloby zwykle slowa."""
    for w in sorted({w for w in wartosci if isinstance(w, str) and len(w) >= 4},
                    key=len, reverse=True):
        tekst = tekst.replace(w, "***")
    return tekst


def _rodzaj(adnotacja) -> str:
    pochodzenie = typing.get_origin(adnotacja)
    if pochodzenie in (typing.Union, types.UnionType):
        reszta = [a for a in typing.get_args(adnotacja) if a is not type(None)]
        return _rodzaj(reszta[0]) if len(reszta) == 1 else "tekst"
    if pochodzenie is list:
        return "lista"
    if pochodzenie is dict:
        return "slownik"
    return {bool: "bool", int: "int", float: "float"}.get(adnotacja, "tekst")


def pola_ustawien(typ: str) -> list[dict]:
    """Formularz integracji z modelu konfiguracji: nazwa, rodzaj (bool, int,
    float, tekst, lista, slownik), wartosc domyslna, czy wymagane. Bez pol
    sekretow — te maja osobna sekcje."""
    model = MODELE_INTEGRACJI[typ]
    out = []
    for nazwa, pole in model.model_fields.items():
        if nazwa in POMIJANE or nazwa in dm.POLA_SEKRETOW[typ]:
            continue
        if pole.default_factory is not None:
            domyslna = pole.default_factory()
        elif pole.default is PydanticUndefined:
            domyslna = None
        else:
            domyslna = pole.default
        out.append({"pole": nazwa, "rodzaj": _rodzaj(pole.annotation),
                    "domyslna": domyslna, "wymagane": pole.is_required()})
    return out


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, UTC).isoformat() if ts else None


class PanelIntegracje:
    def __init__(self, auth: PanelAuth, sejf: Callable[[], Sejf], *,
                 stany: dm.StanyDomow | None = None,
                 resolver: Callable[[str, int], list[str]] | None = None) -> None:
        self.auth = auth
        self.rejestr = dm.RejestrDomow(auth.path)
        self._sejf = sejf
        self.stany = stany
        self.resolver = resolver

    # ------------------------------------------------------------ wspolne
    def _dostep(self, session: Session, ctx) -> dm.Dom:
        """Aktywny administrator instalacji i dom z konfiguracja w bazie."""
        if not ctx.admin:
            log.warning("panel: %r (bez roli administratora) do integracji domu %d",
                        session.login, ctx.dom_id)
            raise AuthError(403, "Integracje domu wpisuje tylko administrator instalacji.")
        dom = self.rejestr.dom(ctx.dom_id)
        if dom is None:
            raise AuthError(404, "Nie ma takiego domu")
        if dom.zrodlo_konfiguracji != dm.ZRODLO_BAZA:
            raise AuthError(409, NIE_DLA_YAML)
        return dom

    def _sejf_lub_503(self) -> Sejf:
        try:
            return self._sejf()
        except BrakKek as exc:
            raise AuthError(503, "Brak klucza KIDWATCH_KEK — sekretów domu nie da się "
                                 "odczytać ani zapisać.") from exc
        except SejfError as exc:
            raise AuthError(503, f"Klucz sejfu niepoprawny: {exc}") from exc

    def _audyt(self, dom_id: int, login: str, akcja: str, opis: str) -> None:
        try:
            self.rejestr.zapisz_audyt(dom_id, login, akcja, opis)
        except Exception as exc:
            log.exception("panel: nie zapisano audytu integracji")
            raise AuthError(503, "Nie udało się zapisać wpisu w dzienniku domu") from exc

    def przeladowanie(self, dom: dm.Dom) -> dict:
        stan = self.stany.get(dom.id) if self.stany is not None else None
        if stan is None:
            return {"automatyczne": False, "wersja": dom.wersja, "komunikat": BEZ_PRZELADOWANIA}
        return {
            "automatyczne": True,
            "wersja": dom.wersja,
            "wersja_dzialajaca": stan.wersja,
            "nieudana": stan.nieudana,
            "blad": stan.blad,
            "aktualna": stan.wersja == dom.wersja,
        }

    def _blad_startu(self, dom_id: int, sejf: Sejf) -> str | None:
        with self.rejestr._conn() as conn:
            return blad_startu_conn(conn, dom_id, sejf)

    def _wiersz(self, typ: str, integracja: dm.Integracja | None,
                maski: dict[str, str]) -> dict:
        return {
            "typ": typ,
            "nazwa": NAZWY[typ],
            "skonfigurowana": integracja is not None,
            "wlaczona": bool(integracja and integracja.wlaczona),
            "ustawienia": dict(integracja.ustawienia) if integracja else {},
            "pola": pola_ustawien(typ),
            "sekrety": [{
                "pole": p,
                "opis": OPISY_SEKRETOW.get((typ, p), p),
                "ustawiony": p in maski,
                "maska": maski.get(p),
                "wielolinijkowy": (typ, p) in WIELOLINIJKOWE,
            } for p in dm.POLA_SEKRETOW[typ]],
            "uwaga": ("Włączenie tego źródła DNS wyłącza drugie (NextDNS/AdGuard) w tym "
                      "samym zapisie — dom ma dokładnie jedno." if typ in ZRODLA_DNS else None),
            "zmienione_przez": integracja.zmienione_przez if integracja else None,
            "zmienione_at": _iso(integracja.zmienione_at) if integracja else None,
        }

    # ------------------------------------------------------------- odczyt
    def stan(self, session: Session, ctx) -> dict:
        """Samo przeladowanie i start domu — do odswiezania ekranu po zapisie.
        Bez ustawien i masek, wiec bez wpisu `integracje.odczyt` (dziennik
        nie puchnie od sondowania); dostep jak przy liscie."""
        dom = self._dostep(session, ctx)
        sejf = self._sejf_lub_503()
        return {
            "dom": {"id": dom.id, "nazwa": dom.nazwa, "wersja": dom.wersja},
            "start": self._blad_startu(dom.id, sejf),
            "przeladowanie": self.przeladowanie(dom),
        }

    def lista(self, session: Session, ctx) -> dict:
        dom = self._dostep(session, ctx)
        sejf = self._sejf_lub_503()
        self._audyt(dom.id, session.login, "integracje.odczyt",
                    "odczyt ustawień integracji (sekrety jako maski)")
        try:
            maski = self.rejestr.maski(dom.id, sejf)
        except SejfError as exc:
            raise AuthError(503, f"Sekretów domu nie da się odszyfrować: {exc}") from exc
        integracje = {i.typ: i for i in self.rejestr.integracje(dom.id)}
        return {
            "dom": {"id": dom.id, "nazwa": dom.nazwa, "wersja": dom.wersja},
            "sieci": list(dom.dozwolone_sieci),
            "hosty": list(dom.dozwolone_hosty),
            "start": self._blad_startu(dom.id, sejf),
            "przeladowanie": self.przeladowanie(dom),
            "integracje": [self._wiersz(t, integracje.get(t), maski.get(t, {}))
                           for t in dm.TYPY_INTEGRACJI],
        }

    # -------------------------------------------------------------- zapis
    @staticmethod
    def _typ(data: dict) -> str:
        typ = data.get("typ")
        if typ not in dm.TYPY_INTEGRACJI:
            raise AuthError(400, "Nieznany typ integracji")
        return typ

    @staticmethod
    def _sekrety(typ: str, data: dict) -> dict[str, str]:
        """Pole -> nowa wartosc; puste i pominiete = bez zmian."""
        raw = data.get("sekrety") or {}
        if not isinstance(raw, dict):
            raise AuthError(400, "Niepoprawne pole 'sekrety'")
        out = {}
        for pole, wartosc in raw.items():
            if pole not in dm.POLA_SEKRETOW[typ]:
                raise AuthError(400, f"Integracja {typ} nie ma sekretu {pole!r:.40}")
            if wartosc is None:
                continue
            if not isinstance(wartosc, str) or len(wartosc) > MAX_SEKRET:
                raise AuthError(400, f"Niepoprawna wartość sekretu {pole}")
            if wartosc.strip():
                out[pole] = wartosc.strip() + ("\n" if (typ, pole) in WIELOLINIJKOWE else "")
        return out

    @staticmethod
    def _ustawienia(data: dict) -> dict | None:
        raw = data.get("ustawienia")
        if raw is None:
            return None
        if not isinstance(raw, dict) or len(raw) > MAX_POL or not all(
                isinstance(k, str) and len(k) <= 64 for k in raw):
            raise AuthError(400, "Niepoprawne pole 'ustawienia'")
        return raw

    def _potwierdz(self, session: Session, data: dict) -> None:
        """Haslo albo kod 2FA przed kazda zmiana. Zle potwierdzenie to 403,
        nie 401 z `auth.reauth`: sesja jest wazna, a front na 401 wraca do
        ekranu logowania i administrator stracilby wpisany formularz."""
        confirm = data.get("confirm", "")
        if not isinstance(confirm, str) or len(confirm) > 512:
            raise AuthError(400, "Niepoprawne pole 'confirm'")
        try:
            self.auth.reauth(session, confirm)
        except AuthError as exc:
            raise AuthError(403 if exc.status == 401 else exc.status, exc.message) from exc

    @staticmethod
    def _wersja(data: dict) -> int | None:
        w = data.get("wersja")
        if w is None:
            return None
        if not isinstance(w, int) or isinstance(w, bool):
            raise AuthError(400, "Niepoprawne pole 'wersja'")
        return w

    def _zapisz(self, session: Session, ctx, typ: str, *, sejf: Sejf,
                wlaczona: bool | None, ustawienia: dict | None,
                sekrety: dict[str, str | None], tajne: list[str],
                wersja: int | None = None) -> dict:
        # Zrodlo DNS jest dokladnie jedno: wlaczenie jednego wylacza drugie
        # w tej samej transakcji (przelaczenie NextDNS <-> AdGuard z panelu).
        wylacz = [t for t in ZRODLA_DNS if t != typ] if typ in ZRODLA_DNS and wlaczona else []
        try:
            self.rejestr.zapisz_integracje(
                ctx.dom_id, typ, sejf=sejf, wlaczona=wlaczona, ustawienia=ustawienia,
                sekrety=sekrety or None, kto=session.login, resolver=self.resolver,
                sprawdz_dom=lambda conn: blad_startu_conn(conn, ctx.dom_id, sejf),
                wylacz=wylacz, oczekiwana_wersja=wersja)
        except dm.ZmianaWersji as exc:
            raise AuthError(409, "Konfiguracja domu zmieniła się od wczytania ekranu (inny "
                                 "zapis albo CLI) — odśwież i wpisz zmianę ponownie.") from exc
        except (ValueError, SejfError) as exc:
            komunikat = bez_sekretow(str(exc), tajne)
            log.warning("panel: %s — integracja %s domu %d odrzucona: %s",
                        session.login, typ, ctx.dom_id, komunikat)
            self._audyt(ctx.dom_id, session.login, "integracja.odmowa",
                        f"integracja {typ}: zapis odrzucony (walidacja)")
            siec = "poza siecią domu" in komunikat or "spoza listy dozwolonych" in komunikat
            raise AuthError(400, komunikat + (f" — {WSKAZOWKA_SIECI}" if siec else "")) from exc
        log.warning("panel: %s zapisal integracje %s domu %d (sekrety: %s)", session.login,
                    typ, ctx.dom_id, ", ".join(sorted(sekrety)) or "bez zmian")
        try:
            dom = self.rejestr.dom(ctx.dom_id)
            assert dom is not None
            maski = self.rejestr.maski(dom.id, sejf)
            zmienione = [self._wiersz(t, self.rejestr.integracja(dom.id, t), maski.get(t, {}))
                         for t in [typ, *wylacz]]
            return {
                "ok": True,
                "integracja": zmienione[0],
                "zmienione": zmienione,
                "dom": {"id": dom.id, "nazwa": dom.nazwa, "wersja": dom.wersja},
                "start": self._blad_startu(dom.id, sejf),
                "przeladowanie": self.przeladowanie(dom),
            }
        except Exception as exc:
            # Zapis JEST w bazie — odpowiedz bledem udawalaby, ze nic sie nie
            # stalo, i zachecala do powtorki. Sukces z ostrzezeniem.
            log.error("panel: integracja %s domu %d zapisana, ale odczyt stanu nieudany: %s",
                      typ, ctx.dom_id, type(exc).__name__)
            return {"ok": True, "ostrzezenie": "Zapisano, ale nie udało się odczytać stanu "
                                               "domu po zapisie — odśwież ekran."}

    def zapisz(self, session: Session, data: dict, ctx) -> dict:
        """{typ, wlaczona?, ustawienia?, sekrety?: {pole: wartosc}, wersja?, confirm}.
        `wersja` — `domy.wersja` z ekranu; inna w chwili zapisu = 409."""
        self._dostep(session, ctx)
        typ = self._typ(data)
        sekrety = self._sekrety(typ, data)
        tajne = [w.strip() for w in sekrety.values()]
        try:
            wlaczona = data.get("wlaczona")
            if wlaczona is not None and not isinstance(wlaczona, bool):
                raise AuthError(400, "Niepoprawne pole 'wlaczona'")
            ustawienia = self._ustawienia(data)
            wersja = self._wersja(data)
            sejf = self._sejf_lub_503()
            self._potwierdz(session, data)
            return self._zapisz(session, ctx, typ, sejf=sejf, wlaczona=wlaczona,
                                ustawienia=ustawienia, sekrety=dict(sekrety), tajne=tajne,
                                wersja=wersja)
        except AuthError as exc:
            exc.message = bez_sekretow(exc.message, tajne)
            raise

    def usun_sekret(self, session: Session, data: dict, ctx) -> dict:
        """{typ, pole, wersja?, confirm} — jawne usuniecie jednego sekretu."""
        self._dostep(session, ctx)
        typ = self._typ(data)
        pole = data.get("pole")
        if pole not in dm.POLA_SEKRETOW[typ]:
            raise AuthError(400, f"Integracja {typ} nie ma takiego sekretu")
        wersja = self._wersja(data)
        sejf = self._sejf_lub_503()
        self._potwierdz(session, data)
        return self._zapisz(session, ctx, typ, sejf=sejf, wlaczona=None, ustawienia=None,
                            sekrety={pole: None}, tajne=[], wersja=wersja)
