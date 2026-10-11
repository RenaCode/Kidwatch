"""Panel: wlasny profil powiadomien i zarzadzanie kontami.

Logika tras /api/konto/* (kazde konto, o SOBIE) i /api/konta/* (uprawnienie
`konta.zarzadzanie`). panel.py tylko dopina je do tablicy tras; tu sa
walidacja, potwierdzenia i bezpieczniki, testowane bez serwera HTTP.

ZASADY BEZPIECZENSTWA
  - /api/konto/* dziala WYLACZNIE na koncie z sesji — login z ciala zadania
    nie istnieje, wiec nie da sie nim zmienic cudzego kanalu.
  - Zmiana kanalu (numer, e-mail) wymaga potwierdzenia haslem albo kodem 2FA
    (`auth.reauth`) — przejeta sesja nie przekieruje powiadomien o dzieciach
    na obcy numer. Kategorie, cisza i dzieci tylko sesji + CSRF: ich zmiana
    niczego nikomu nie wysyla.
  - Kazda zmiana w /api/konta/* (cudze konto) wymaga potwierdzenia
    wykonujacego. Nie da sie usunac siebie ani zostawic domu bez konta
    z prawem do zarzadzania kontami.
  - Pelne numery i adresy nie wracaja do przegladarki (Profil.publiczny).
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

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


def _ma(session: Session, upr: str) -> None:
    if upr not in session.uprawnienia:
        log.warning("panel: %r bez uprawnienia %s", session.login, upr)
        raise AuthError(403, f"To konto nie ma uprawnienia: {u.OPISY.get(upr, upr)}.")


def _opis_kanalow(p: o.Profil | None) -> str:
    if p is None:
        return "-"
    return ", ".join(x for x in (
        p.whatsapp and f"WhatsApp {mask(p.whatsapp)}",
        p.email and f"e-mail {o.mask_email(p.email)}",
    ) if x) or "brak"


class PanelKonta:
    def __init__(self, auth: PanelAuth, konta: o.ProfilePowiadomien,
                 dzieci: Iterable[str]) -> None:
        self.auth = auth
        self.konta = konta
        self.dzieci = sorted(set(dzieci))

    # ------------------------------------------------------------ wspolne
    def _katalog(self) -> dict:
        return {
            "kategorie": [{"id": k, "opis": o.OPISY_KATEGORII[k], "wymaga": o.WYMAGANE[k]}
                          for k in o.KATEGORIE],
            "kanaly": list(o.KANALY),
            "dzieci": self.dzieci,
            "tryb": self.konta.tryb(),
        }

    def _profil(self, login: str) -> o.Profil:
        p = self.konta.profil(login)
        if p is None:
            raise AuthError(404, "Nie ma takiego konta")
        return p

    def _zapisz_preferencje(self, login: str, data: dict) -> None:
        try:
            self.konta.ustaw_preferencje(
                login,
                kategorie=_lista(data, "kategorie"),
                cisza_od=_str(data, "cisza_od", 5) or None,
                cisza_do=_str(data, "cisza_do", 5) or None,
                cisza_alarmy=_bool(data, "cisza_alarmy", True),
                dzieci=_lista(data, "dzieci"),
                aktywne=_bool(data, "aktywne", True),
                znane_dzieci=self.dzieci,
            )
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        except LookupError as exc:
            raise AuthError(404, "Nie ma takiego konta") from exc

    def _zapisz_kanaly(self, kto: Session, login: str, data: dict) -> None:
        """Pole nieobecne = bez zmiany (przegladarka zna tylko maske, wiec
        nie odesle starego numeru), pusty napis = usun kanal."""
        przed = self._profil(login)
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
                    _opis_kanalow(self.konta.profil(login)))

    # ------------------------------------------------------ /api/konto/*
    def moje(self, session: Session) -> dict:
        return {"profil": self._profil(session.login).publiczny(), **self._katalog()}

    def moje_preferencje(self, session: Session, data: dict) -> dict:
        self._zapisz_preferencje(session.login, data)
        return self.moje(session)

    def moje_kanaly(self, session: Session, data: dict) -> dict:
        self._zapisz_kanaly(session, session.login, data)
        return self.moje(session)

    # ------------------------------------------------------ /api/konta/*
    def lista(self, session: Session) -> dict:
        _ma(session, u.KONTA)
        profile = {p.login: p for p in self.konta.profile()}
        konta = []
        for row in self.auth.list_users():
            p = profile.get(row["login"])
            konta.append({
                "login": row["login"],
                "rola": row["rola"],
                "uprawnienia": row.get("uprawnienia", sorted(p.uprawnienia) if p else []),
                "odstepstwa": row.get("odstepstwa", []),
                "totp": bool(row["totp"]),
                "last_login_at": row["last_login_at"],
                "ja": row["login"] == session.login,
                "powiadomienia": p.publiczny() if p else None,
            })
        return {
            "konta": konta,
            "role": list(u.ROLES),
            "uprawnienia": [{"id": k, "opis": v, "stale": k in u.STALE}
                            for k, v in u.OPISY.items()],
            "role_uprawnienia": {r: sorted(v) for r, v in u.ROLE_UPRAWNIENIA.items()},
            **self._katalog(),
        }

    def _cel(self, session: Session, data: dict) -> str:
        _ma(session, u.KONTA)
        login = _str(data, "login", MAX_LOGIN, required=True).strip()
        self._profil(login)
        return login

    def _zostaje_zarzadca(self, *, bez: str | None = None, login: str | None = None,
                          rola: str | None = None,
                          odst: tuple[set, set] = (set(), set())) -> None:
        """Po zmianie musi zostac konto z `konta.zarzadzanie` — inaczej dom
        zostaje bez nikogo, kto doda konto albo zmieni kanal (zostaje CLI).
        `login` z `rola`/`odst` to stan konta PO zmianie."""
        for p in self.konta.profile():
            if p.login == bez:
                continue
            upr = u.efektywne(rola or p.rola, *odst) if p.login == login else p.uprawnienia
            if u.KONTA in upr:
                return
        raise AuthError(409, "Musi zostać co najmniej jedno konto z zarządzaniem kontami.")

    def dodaj(self, session: Session, data: dict) -> dict:
        _ma(session, u.KONTA)
        login = _str(data, "login", MAX_LOGIN, required=True).strip()
        rola = _str(data, "rola", 32) or u.ROLE_VIEWER
        if not login_ok(login):
            raise AuthError(400, "Login: małe litery a-z, cyfry, '.', '_', '-' (jak w SSO)")
        if rola not in u.ROLES:
            raise AuthError(400, "Nieznana rola")
        self.auth.reauth(session, _str(data, "confirm", 512))
        haslo = generate_password()
        try:
            self.auth.add_user(login, haslo, rola)
        except UserExists as exc:
            raise AuthError(409, "Takie konto już istnieje") from exc
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        log.warning("panel: %s zalozyl konto %r (rola %s)", session.login, login, rola)
        # Haslo wraca RAZ; w bazie jest tylko hash.
        return {"ok": True, "login": login, "haslo": haslo}

    def usun(self, session: Session, data: dict) -> dict:
        login = self._cel(session, data)
        if login == session.login:
            raise AuthError(409, "Nie usuniesz własnego konta z panelu (CLI: user-del).")
        self._zostaje_zarzadca(bez=login)
        self.auth.reauth(session, _str(data, "confirm", 512))
        try:
            self.auth.delete_user(login)
        except UnknownUser as exc:
            raise AuthError(404, "Nie ma takiego konta") from exc
        log.warning("panel: %s usunal konto %r", session.login, login)
        return {"ok": True}

    def rola(self, session: Session, data: dict) -> dict:
        login = self._cel(session, data)
        rola = _str(data, "rola", 32)
        if rola not in u.ROLES:
            raise AuthError(400, "Nieznana rola")
        # set_role kasuje odstepstwa — po zmianie liczy sie sama rola.
        self._zostaje_zarzadca(login=login, rola=rola)
        self.auth.reauth(session, _str(data, "confirm", 512))
        n = self.auth.set_role(login, rola)
        log.warning("panel: %s zmienil role %r na %s", session.login, login, rola)
        return {"ok": True, "closed_sessions": n}

    def uprawnienia(self, session: Session, data: dict) -> dict:
        login = self._cel(session, data)
        raw = data.get("zmiany")
        if not isinstance(raw, dict) or not raw or len(raw) > len(u.OPISY):
            raise AuthError(400, "Niepoprawne pole 'zmiany'")
        zmiany: dict[str, bool | None] = {}
        for k, v in raw.items():
            if k not in u.OPISY or not (v is None or isinstance(v, bool)):
                raise AuthError(400, f"Niepoprawna zmiana uprawnienia {k!r}")
            if k in u.STALE and v is False:
                raise AuthError(400, f"Uprawnienia {k!r} nie da się odebrać")
            zmiany[k] = v
        p = self._profil(login)
        # Odstepstwa po zmianie, do sprawdzenia "zostaje zarzadca".
        nadane = set(p.uprawnienia - u.efektywne(p.rola))
        odebrane = set(u.efektywne(p.rola) - p.uprawnienia)
        for k, v in zmiany.items():
            nadane.discard(k)
            odebrane.discard(k)
            if v is True:
                nadane.add(k)
            elif v is False:
                odebrane.add(k)
        self._zostaje_zarzadca(login=login, odst=(nadane, odebrane))
        self.auth.reauth(session, _str(data, "confirm", 512))
        try:
            n = self.auth.set_permissions(login, zmiany)
        except ValueError as exc:
            raise AuthError(400, str(exc)) from exc
        log.warning("panel: %s zmienil uprawnienia %r: %s", session.login, login,
                    ", ".join(f"{'+' if v else '-' if v is False else '='}{k}"
                              for k, v in zmiany.items()))
        return {"ok": True, "closed_sessions": n}

    def preferencje(self, session: Session, data: dict) -> dict:
        login = self._cel(session, data)
        self.auth.reauth(session, _str(data, "confirm", 512))
        self._zapisz_preferencje(login, data)
        log.warning("panel: %s zmienil preferencje powiadomien %r", session.login, login)
        return {"ok": True, "powiadomienia": self._profil(login).publiczny()}

    def kanaly(self, session: Session, data: dict) -> dict:
        login = self._cel(session, data)
        self._zapisz_kanaly(session, login, data)
        return {"ok": True, "powiadomienia": self._profil(login).publiczny()}

    def tryb(self, session: Session, data: dict) -> dict:
        _ma(session, u.KONTA)
        tryb = _str(data, "tryb", 16)
        if tryb not in (o.TRYB_TRASY, o.TRYB_KONTA):
            raise AuthError(400, "Tryb: trasy albo konta")
        if tryb == o.TRYB_KONTA and not any(
                p.ma_kanal and p.aktywne and u.KONTA in p.uprawnienia
                for p in self.konta.profile()):
            # Wlasciciel bez kanalu w trybie kont = alarmy techniczne do nikogo.
            raise AuthError(409, "Najpierw ustaw kanał (WhatsApp albo e-mail) "
                                 "na koncie zarządzającym.")
        self.auth.reauth(session, _str(data, "confirm", 512))
        self.konta.ustaw_tryb(tryb)
        log.warning("panel: %s przelaczyl powiadomienia na tryb %s", session.login, tryb)
        return {"ok": True, "tryb": tryb}

