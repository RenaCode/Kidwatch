"""Panel: wlasny profil powiadomien i zarzadzanie czlonkami domu.

Logika tras /api/konto/kanaly (kazde konto, o SOBIE, kanaly osoby),
/api/domy/<id>/konto/* (wlasne preferencje W DOMU) i /api/domy/<id>/konta/*
(uprawnienie `konta.zarzadzanie` w tym domu — czlonkowie TEGO domu, §2.3).
panel.py tylko dopina je do tablicy tras i podaje kontekst domu (`WDomu`);
tu sa walidacja, potwierdzenia i bezpieczniki, testowane bez serwera HTTP.

DOMY: lista, role, odstepstwa i preferencje dotycza wylacznie czlonkow domu
z kontekstu. Konto z innego domu dla tych tras nie istnieje (404). Kanaly
(numer, e-mail) sa cecha osoby, wspolna dla wszystkich jej domow, wiec
zarzadca zmieni je tylko kontu, ktorego WSZYSTKIE domy sam zarzadza —
zarzadca Domu 2 nie przekieruje powiadomien czlonka Domu 1. „Usun” wypisuje
z domu; konto znika dopiero, gdy nie zostal mu zaden dom.

ZASADY BEZPIECZENSTWA
  - /api/konto/* dziala WYLACZNIE na koncie z sesji — login z ciala zadania
    nie istnieje, wiec nie da sie nim zmienic cudzego kanalu.
  - Zmiana kanalu (numer, e-mail) wymaga potwierdzenia haslem albo kodem 2FA
    (`auth.reauth`) — przejeta sesja nie przekieruje powiadomien o dzieciach
    na obcy numer. Kategorie, cisza i dzieci tylko sesji + CSRF: ich zmiana
    niczego nikomu nie wysyla.
  - Kazda zmiana w /api/domy/<id>/konta/* (cudze konto) wymaga potwierdzenia
    wykonujacego. Nie da sie usunac siebie ani zostawic domu bez konta
    z prawem do zarzadzania kontami (sprawdzane przed potwierdzeniem
    i drugi raz w transakcji — domy.OstatniZarzadzajacy).
  - Pelne numery i adresy nie wracaja do przegladarki (Profil.publiczny).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from . import domy as dm
from . import odbiorcy as o
from . import uprawnienia as u
from .bramka_admin import mask
from .panel_auth import AuthError, PanelAuth, Session, UnknownUser, UserExists, generate_password
from .panel_sso import login_ok

log = logging.getLogger(__name__)

MAX_LOGIN = 64


def _str(data: dict, key: str, limit: int = 512, *, required: bool = False) -> str:
    value = data.get(key, "")
    if value is None:
        value = ""
    if not isinstance(value, str) or len(value) > limit:
        raise AuthError(400, f"Niepoprawne pole {key!r}")
    if required and not value.strip():
        raise AuthError(400, f"Brak pola {key!r}")
    return value


def _bool(data: dict, key: str, default: bool) -> bool:
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise AuthError(400, f"Niepoprawne pole {key!r}")
    return value


def _lista(data: dict, key: str) -> list[str] | None:
    value = data.get(key)
    if value is None:
        return None
    if not isinstance(value, list) or len(value) > 50 or not all(
            isinstance(v, str) and len(v) <= 64 for v in value):
        raise AuthError(400, f"Niepoprawne pole {key!r}")
    return value


@dataclass(frozen=True)
class WDomu:
    """Kontekst domu trasy (panel_domy.KontekstDomu w wersji dla kont)."""

    dom_id: int
    #: Uprawnienia sesji w tym domu.
    uprawnienia: frozenset[str]
    dzieci: list[str] = field(default_factory=list)
    #: Aktywny administrator instalacji.
    admin: bool = False
    #: Administrator bez czlonkostwa w tym domu.
    administracja: bool = False


def _ma(d: WDomu, upr: str, login: str) -> None:
    if upr not in d.uprawnienia:
        log.warning("panel: %r bez uprawnienia %s w domu %d", login, upr, d.dom_id)
        raise AuthError(403, f"To konto nie ma uprawnienia: {u.OPISY.get(upr, upr)}.")


def _opis_kanalow(p: o.Profil | None) -> str:
    if p is None:
        return "-"
    return ", ".join(x for x in (
        p.whatsapp and f"WhatsApp {mask(p.whatsapp)}",
        p.email and f"e-mail {o.mask_email(p.email)}",
    ) if x) or "brak"


def edytowalne(dom_id: int) -> list[str]:
    """Uprawnienia, ktore w domu maja sens: zakres `dom` i `konto`. Zakresu
    instancji (bot WhatsApp) nie nadaje rola w zadnym domu — ma go tylko
    administrator instalacji. `dom_id` zostaje dla czytelnosci wolajacych."""
    del dom_id
    return [k for k in u.UPRAWNIENIA if u.ZAKRESY[k] != u.ZAKRES_INSTANCJA]


class PanelKonta:
    def __init__(self, auth: PanelAuth, konta: o.ProfilePowiadomien) -> None:
        self.auth = auth
        self.konta = konta
        self.rejestr = dm.RejestrDomow(auth.path)

    # ------------------------------------------------------------ wspolne
    def _w(self, d: WDomu) -> o.ProfilePowiadomien:
        return self.konta.dla_domu(d.dom_id)

    def _katalog(self, d: WDomu) -> dict:
        return {
            "kategorie": [{"id": k, "opis": o.OPISY_KATEGORII[k], "wymaga": o.WYMAGANE[k]}
                          for k in o.KATEGORIE],
            "kanaly": list(o.KANALY),
            "dzieci": sorted(set(d.dzieci)),
            "tryb": self._w(d).tryb(),
            "tryb_trasy": d.dom_id == o.DOM_TRAS,
        }

    def _profil(self, d: WDomu, login: str) -> o.Profil:
        """Czlonek domu; konto spoza domu = 404 (nie zdradza, ze istnieje)."""
        p = self._w(d).profil(login)
        if p is None:
            raise AuthError(404, "Nie ma takiego konta")
        return p

    def _zapisz_preferencje(self, d: WDomu, login: str, data: dict) -> None:
        try:
            self._w(d).ustaw_preferencje(
                login,
                kategorie=_lista(data, "kategorie"),
                cisza_od=_str(data, "cisza_od", 5) or None,
                cisza_do=_str(data, "cisza_do", 5) or None,
                cisza_alarmy=_bool(data, "cisza_alarmy", True),
                dzieci=_lista(data, "dzieci"),
                aktywne=_bool(data, "aktywne", True),
                znane_dzieci=d.dzieci,
            )
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        except LookupError as exc:
            raise AuthError(404, "Nie ma takiego konta") from exc

    def _kanaly_osoby(self, login: str) -> o.Profil:
        p = self.konta.kanaly_osoby(login)
        if p is None:
            raise AuthError(404, "Nie ma takiego konta")
        return p

    def _zapisz_kanaly(self, kto: Session, login: str, data: dict) -> None:
        """Pole nieobecne = bez zmiany (przegladarka zna tylko maske, wiec
        nie odesle starego numeru), pusty napis = usun kanal."""
        przed = self._kanaly_osoby(login)
        whatsapp = _str(data, "whatsapp", 64) if "whatsapp" in data else przed.whatsapp or ""
        email = _str(data, "email", o.MAX_EMAIL) if "email" in data else przed.email or ""
        kanal = _str(data, "kanal", 16) or przed.kanal
        # Walidacja PRZED potwierdzeniem: literowka w numerze nie ma zjadac
        # proby hasla (licza sie do blokady konta).
        if whatsapp and o.normalize_number(whatsapp) is None:
            raise AuthError(400, "Podaj numer z kierunkowym, np. 48600100200")
        if email and o.normalize_email(email) is None:
            raise AuthError(400, "Niepoprawny adres e-mail")
        if kanal not in o.KANALY:
            raise AuthError(400, "Kanał: auto, whatsapp albo email")
        self.auth.reauth(kto, _str(data, "confirm", 512))
        try:
            self.konta.ustaw_kanaly(login, whatsapp=whatsapp or None, email=email or None,
                                    kanal=kanal)
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        except LookupError as exc:
            raise AuthError(404, "Nie ma takiego konta") from exc
        log.warning("panel: %s zmienil kanaly powiadomien konta %r: %s -> %s",
                    kto.login, login, _opis_kanalow(przed),
                    _opis_kanalow(self.konta.kanaly_osoby(login)))

    def _publiczny(self, d: WDomu, session: Session) -> dict:
        """Wlasny profil w domu. Administrator bez czlonkostwa nie ma
        preferencji w domu (nie dostaje jego powiadomien) — tylko kanaly."""
        p = self._w(d).profil(session.login)
        if p is None:
            return {**self._kanaly_osoby(session.login).publiczny(), "czlonek": False}
        return {**p.publiczny(), "czlonek": True}

    # ------------------------------------------------------ /api/konto/*
    def moje(self, session: Session, d: WDomu) -> dict:
        return {"profil": self._publiczny(d, session), **self._katalog(d)}

    def moje_preferencje(self, session: Session, data: dict, d: WDomu) -> dict:
        if d.administracja:
            raise AuthError(409, "Nie jesteś członkiem tego domu — jego powiadomienia "
                                 "dostają tylko członkowie.")
        self._zapisz_preferencje(d, session.login, data)
        return self.moje(session, d)

    def moje_kanaly(self, session: Session, data: dict, d: WDomu | None = None) -> dict:
        """Kanaly osoby (zakres konta). `d` — dom, z ktorego ekranu przyszlo
        zadanie (odpowiedz jak `moje`); bez domu — same kanaly."""
        self._zapisz_kanaly(session, session.login, data)
        if d is None:
            return {"profil": self._kanaly_osoby(session.login).publiczny()}
        return self.moje(session, d)

    # ------------------------------------------------------ /api/konta/*
    def lista(self, session: Session, d: WDomu) -> dict:
        _ma(d, u.KONTA, session.login)
        konta = []
        edyt = edytowalne(d.dom_id)
        dane = {r["login"]: r for r in self.auth.list_users()}
        czlonkowie = {c.login: c for c in self.rejestr.czlonkowie(d.dom_id)}
        for p in self._w(d).profile():
            c = czlonkowie[p.login]
            row = dane.get(p.login, {})
            konta.append({
                "login": p.login,
                "rola": c.rola,
                "uprawnienia": sorted(p.uprawnienia & frozenset(edyt)),
                "odstepstwa": sorted([f"+{n}" for n in c.nadane] + [f"-{n}" for n in c.odebrane],
                                     key=lambda x: x[1:]),
                "totp": bool(row.get("totp")),
                "last_login_at": row.get("last_login_at"),
                "ja": p.login == session.login,
                "powiadomienia": p.publiczny(),
            })
        return {
            "konta": konta,
            "role": list(u.ROLE_DOMU),
            "uprawnienia": [{"id": k, "opis": u.OPISY[k], "stale": k in u.STALE} for k in edyt],
            "role_uprawnienia": {r: sorted(v & frozenset(edyt))
                                 for r, v in u.ROLE_DOMU_UPRAWNIENIA.items()},
            **self._katalog(d),
        }

    def _cel(self, session: Session, data: dict, d: WDomu) -> str:
        _ma(d, u.KONTA, session.login)
        login = _str(data, "login", MAX_LOGIN, required=True).strip()
        self._profil(d, login)
        return login

    def _zostaje_zarzadca(self, d: WDomu, *, bez: str | None = None, login: str | None = None,
                          rola: str | None = None,
                          odst: tuple[set, set] | None = None) -> None:
        """Po zmianie musi zostac w domu konto z `konta.zarzadzanie` — inaczej
        dom zostaje bez nikogo, kto doda konto albo zmieni kanal (zostaje
        CLI). `login` z `rola`/`odst` to stan konta PO zmianie. Wstepnie,
        przed potwierdzeniem haslem; ostatecznie pilnuje transakcja."""
        for p in self._w(d).profile():
            if p.login == bez:
                continue
            if p.login == login:
                if odst is None:
                    upr = u.efektywne(u.rola_konta(rola or p.rola),
                                      role=u.ROLE_DOMU_UPRAWNIENIA)
                else:
                    upr = u.efektywne(u.rola_konta(rola or p.rola), *odst,
                                      role=u.ROLE_DOMU_UPRAWNIENIA)
            else:
                upr = p.uprawnienia
            if u.KONTA in upr:
                return
        raise AuthError(409, "Musi zostać co najmniej jedno konto z zarządzaniem kontami.")

    def dodaj(self, session: Session, data: dict, d: WDomu) -> dict:
        _ma(d, u.KONTA, session.login)
        login = _str(data, "login", MAX_LOGIN, required=True).strip()
        rola = _str(data, "rola", 32) or u.ROLE_VIEWER
        if not login_ok(login):
            raise AuthError(400, "Login: małe litery a-z, cyfry, '.', '_', '-' (jak w SSO)")
        if rola not in (*u.ROLES, *u.ROLE_DOMU):
            raise AuthError(400, "Nieznana rola")
        self.auth.reauth(session, _str(data, "confirm", 512))
        haslo = generate_password()
        try:
            self.auth.add_user(login, haslo, rola, dom_id=d.dom_id)
        except UserExists as exc:
            raise AuthError(409, "Takie konto już istnieje") from exc
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        log.warning("panel: %s zalozyl konto %r (dom %d, rola %s)", session.login, login,
                    d.dom_id, rola)
        # Haslo wraca RAZ; w bazie jest tylko hash.
        return {"ok": True, "login": login, "haslo": haslo}

    def usun(self, session: Session, data: dict, d: WDomu) -> dict:
        """Wypisuje konto z domu. Konto bez zadnego domu (i nie
        administracyjne) znika calkiem — w jednym domu to dawne „usun konto”."""
        login = self._cel(session, data, d)
        if login == session.login:
            raise AuthError(409, "Nie usuniesz własnego konta z panelu (CLI: user-del).")
        self._zostaje_zarzadca(d, bez=login)
        self.auth.reauth(session, _str(data, "confirm", 512))
        # Przed wypisaniem: czy mogl widziec sekrety integracji (E4 — sugestia
        # rotacji klucza domu, bo mogl zrobic zrzut, zanim stracil dostep).
        c = self.rejestr.czlonkostwo(self.auth.user_id(login), d.dom_id)
        integracje = c is not None and u.DOM_INTEGRACJE in c.uprawnienia
        try:
            self.auth.remove_membership(login, d.dom_id)
        except UnknownUser as exc:
            raise AuthError(404, "Nie ma takiego konta") from exc
        except dm.OstatniZarzadzajacy as exc:
            raise AuthError(409, "Musi zostać co najmniej jedno konto z zarządzaniem "
                                 "kontami.") from exc
        u_row = next((r for r in self.auth.list_users() if r["login"] == login), None)
        usuniete = bool(u_row) and not u_row["domy"] and not u_row["admin_instancji"]
        if usuniete:
            self.auth.delete_user(login)
        log.warning("panel: %s wypisal konto %r z domu %d%s", session.login, login, d.dom_id,
                    " i je usunal (bez domow)" if usuniete else "")
        sugestia = (f"Konto miało dostęp do integracji domu — rozważ nowy klucz domu: "
                    f"kidwatch dom-klucz-rotuj {d.dom_id}" if integracje else None)
        try:
            self.rejestr.zapisz_audyt(
                d.dom_id, session.login, "konta.usun",
                f"{login} wypisany z domu (sesje zamknięte, preferencje usunięte)"
                + ("; konto usunięte" if usuniete else "")
                + ("; sugestia: dom-klucz-rotuj" if integracje else ""))
        except Exception:
            # Zmiana juz zapisana; brak wpisu nie cofa wypisania (jest w logu).
            log.exception("panel: nie zapisano wpisu dziennika o wypisaniu %r", login)
        return {"ok": True, "konto_usuniete": usuniete, "sugestia": sugestia}

    def rola(self, session: Session, data: dict, d: WDomu) -> dict:
        login = self._cel(session, data, d)
        rola = _str(data, "rola", 32)
        if rola not in (*u.ROLES, *u.ROLE_DOMU):
            raise AuthError(400, "Nieznana rola")
        # set_role kasuje odstepstwa — po zmianie liczy sie sama rola.
        self._zostaje_zarzadca(d, login=login, rola=rola)
        self.auth.reauth(session, _str(data, "confirm", 512))
        try:
            n = self.auth.set_role(login, rola, dom_id=d.dom_id)
        except dm.OstatniZarzadzajacy as exc:
            raise AuthError(409, str(exc)) from exc
        log.warning("panel: %s zmienil role %r w domu %d na %s", session.login, login,
                    d.dom_id, rola)
        return {"ok": True, "closed_sessions": n}

    def uprawnienia(self, session: Session, data: dict, d: WDomu) -> dict:
        login = self._cel(session, data, d)
        raw = data.get("zmiany")
        edyt = edytowalne(d.dom_id)
        if not isinstance(raw, dict) or not raw or len(raw) > len(u.OPISY):
            raise AuthError(400, "Niepoprawne pole 'zmiany'")
        zmiany: dict[str, bool | None] = {}
        for k, v in raw.items():
            if k not in edyt or not (v is None or isinstance(v, bool)):
                raise AuthError(400, f"Niepoprawna zmiana uprawnienia {k!r}")
            if k in u.STALE and v is False:
                raise AuthError(400, f"Uprawnienia {k!r} nie da się odebrać")
            zmiany[k] = v
        c = self.rejestr.czlonkostwo(self.auth.user_id(login), d.dom_id)
        if c is None:
            raise AuthError(404, "Nie ma takiego konta")
        # Odstepstwa po zmianie, do sprawdzenia "zostaje zarzadca".
        nadane, odebrane = set(c.nadane), set(c.odebrane)
        for k, v in zmiany.items():
            nadane.discard(k)
            odebrane.discard(k)
            if v is True:
                nadane.add(k)
            elif v is False:
                odebrane.add(k)
        self._zostaje_zarzadca(d, login=login, rola=c.rola, odst=(nadane, odebrane))
        self.auth.reauth(session, _str(data, "confirm", 512))
        try:
            n = self.auth.set_permissions(login, zmiany, dom_id=d.dom_id)
        except dm.OstatniZarzadzajacy as exc:
            raise AuthError(409, str(exc)) from exc
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        log.warning("panel: %s zmienil uprawnienia %r w domu %d: %s", session.login, login,
                    d.dom_id, ", ".join(f"{'+' if v else '-' if v is False else '='}{k}"
                                        for k, v in zmiany.items()))
        return {"ok": True, "closed_sessions": n}

    def preferencje(self, session: Session, data: dict, d: WDomu) -> dict:
        login = self._cel(session, data, d)
        self.auth.reauth(session, _str(data, "confirm", 512))
        self._zapisz_preferencje(d, login, data)
        log.warning("panel: %s zmienil preferencje powiadomien %r w domu %d",
                    session.login, login, d.dom_id)
        return {"ok": True, "powiadomienia": self._profil(d, login).publiczny()}

    def kanaly(self, session: Session, data: dict, d: WDomu) -> dict:
        login = self._cel(session, data, d)
        # Kanaly sa osoby, wspolne dla jej domow: tylko gdy wykonujacy
        # zarzadza kazdym z nich (albo jest aktywnym administratorem).
        if not d.admin and login != session.login:
            for c in self.rejestr.czlonkostwa(self.auth.user_id(login)):
                if c.dom_id != d.dom_id and u.KONTA not in self.rejestr.uprawnienia(
                        session.user_id, c.dom_id):
                    raise AuthError(403, "To konto należy też do innego domu — jego kanały "
                                         "zmieni ono samo albo administrator.")
        self._zapisz_kanaly(session, login, data)
        return {"ok": True, "powiadomienia": self._profil(d, login).publiczny()}

    def tryb(self, session: Session, data: dict, d: WDomu) -> dict:
        _ma(d, u.KONTA, session.login)
        tryb = _str(data, "tryb", 16)
        if tryb not in (o.TRYB_TRASY, o.TRYB_KONTA):
            raise AuthError(400, "Tryb: trasy albo konta")
        if tryb == o.TRYB_TRASY and d.dom_id != o.DOM_TRAS:
            raise AuthError(400, "Tryb tras jest tylko w Domu 1 — ten dom wysyła per konto.")
        if tryb == o.TRYB_KONTA and not any(
                p.ma_kanal and p.aktywne and u.KONTA in p.uprawnienia
                for p in self._w(d).profile()):
            # Wlasciciel bez kanalu w trybie kont = alarmy techniczne do nikogo.
            raise AuthError(409, "Najpierw ustaw kanał (WhatsApp albo e-mail) "
                                 "na koncie zarządzającym.")
        self.auth.reauth(session, _str(data, "confirm", 512))
        try:
            self._w(d).ustaw_tryb(tryb)
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        log.warning("panel: %s przelaczyl powiadomienia domu %d na tryb %s", session.login,
                    d.dom_id, tryb)
        return {"ok": True, "tryb": tryb}

    # ---------------------------------------------------------- dziennik
    def dziennik(self, session: Session, d: WDomu) -> dict:
        """Dom -> Dziennik (§2.3): kto co zrobil w domu, w tym kazde wejscie
        administratora instalacji. Bez wartosci sekretow (nie trafiaja do
        `audyt`)."""
        _ma(d, u.KONTA, session.login)
        return {"wpisy": [
            {**w, "ts": datetime.fromtimestamp(w["ts"], UTC).isoformat()}
            for w in self.rejestr.audyt(d.dom_id)
        ]}
