"""SSO: rozpoznanie uzytkownika po naglowkach od Authelii (Traefik forwardAuth).

Kontrakt: renacode-infra docs/sso-tozsamosc.md. W skrocie:

  - Traefik usuwa `Remote-*` podane przez klienta i dokleja naglowki od
    Authelii dopiero po jej 2FA i sprawdzeniu grupy hosta. Panelowi wolno im
    ufac WYLACZNIE przy `SSO_NAGLOWKI=1`, a te zmienna ustawia ten sam
    przelacznik chartu (`sso.enabled`), ktory dopina middleware'y. Bez flagi
    naglowki sa ignorowane w calosci — panel bez SSO stoi za routerem, ktory
    `Remote-User` od klienta przepuszcza.
  - `Remote-User` == `users.login` w panel-auth.db. Kont nie zakladamy w locie:
    konto bez dopasowania to 403 z czytelnym komunikatem.
  - Sesja z naglowka nie pyta o haslo ani o wlasny TOTP panelu — 2FA wymusila
    juz Authelia. Dlatego sesja `sso` jest wazna TYLKO z naglowkiem tego
    samego uzytkownika: bez niego (port-forward, wylaczona flaga) nic nie
    otwiera. Lokalne haslo i TOTP zostaja jako droga awaryjna
    (`kubectl port-forward`, gdy Authelia lezy).
  - Wylogowanie konczy tez sesje Authelii: portal `/logout?rd=<adres panelu>`.

`Remote-Groups` NIE nadaje uprawnien w panelu (rola konta, `wlasciciel` albo
`podglad`, pochodzi z panel-auth.db, panel_auth.ROLES). Sluzy tylko jako
bezpiecznik: sesja powstaje, gdy uzytkownik nalezy do jednej z grup, ktore
Authelia wpuszcza na ten host. Gdyby regula w Authelii zostala kiedys
poluzowana, panel nie otworzy sie dla calej reszty uzytkownikow SSO.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from email.message import Message
from urllib.parse import quote

from .panel_auth import AuthError

FLAG_ENV = "SSO_NAGLOWKI"
#: Adres panelu, na ktory portal wraca po wylogowaniu (chart: https://<host>/).
RETURN_ENV = "SSO_ADRES"
PORTAL_ENV = "SSO_PORTAL"
GROUPS_ENV = "SSO_GRUPY"

DEFAULT_PORTAL = "https://auth.renacode.com"
#: Grupy Authelii z dostepem do panelu (decyzja wlasciciela 11.10): konto
#: codzienne wlasciciela i rodzina. `admins` (konto administracyjne) do
#: Kidwatcha NIE wchodzi. Chart: `sso.grupy` -> SSO_GRUPY.
DEFAULT_GROUPS = ("wlasciciel", "rodzina")

USER_HEADER = "Remote-User"
GROUPS_HEADER = "Remote-Groups"

_LOGIN = re.compile(r"[a-z0-9._-]{1,64}")


def login_ok(login: str) -> bool:
    """Czy konto panelu o tym loginie da sie dopasowac do `Remote-User`."""
    return bool(_LOGIN.fullmatch(login))


class SsoError(AuthError):
    """Odmowa z kodem HTTP. Panel odsyla przy niej adres wylogowania z portalu:
    z nieznanym kontem trzeba moc zalogowac sie w Authelii jako ktos inny."""


@dataclass(frozen=True)
class SsoIdentity:
    login: str
    groups: tuple[str, ...]


@dataclass(frozen=True)
class SsoConfig:
    portal: str = DEFAULT_PORTAL
    return_url: str = ""
    groups: tuple[str, ...] = DEFAULT_GROUPS

    @property
    def logout_url(self) -> str:
        url = f"{self.portal.rstrip('/')}/logout"
        return f"{url}?rd={quote(self.return_url, safe='')}" if self.return_url else url

    def identity(self, headers: Message) -> SsoIdentity | None:
        """Tozsamosc z naglowkow albo None, gdy `Remote-User` nie przyszedl
        (droga awaryjna przez port-forward — zwykle logowanie).

        Czyta WYLACZNIE `Remote-User` i `Remote-Groups`; warianty
        z podkreslnikiem ani `X-Remote-User` nie sa tozsamoscia."""
        users = headers.get_all(USER_HEADER) or []
        if not users:
            return None
        if len(users) > 1:
            raise SsoError(400, "Nagłówek Remote-User wystąpił więcej niż raz")
        login = users[0].strip()
        if not login_ok(login):
            raise SsoError(400, "Niepoprawny nagłówek Remote-User")
        groups = tuple(
            g.strip() for raw in headers.get_all(GROUPS_HEADER) or [] for g in raw.split(",")
            if g.strip()
        )
        if not set(groups) & set(self.groups):
            raise SsoError(
                403, f"Użytkownik „{login}” nie należy do grupy z dostępem do Kidwatcha "
                f"({', '.join(self.groups)}) — poproś administratora."
            )
        return SsoIdentity(login=login, groups=groups)


def config_from_env() -> SsoConfig | None:
    """SsoConfig przy `SSO_NAGLOWKI=1`, inaczej None (naglowki ignorowane)."""
    if os.environ.get(FLAG_ENV, "").strip() != "1":
        return None
    groups = tuple(
        g.strip() for g in os.environ.get(GROUPS_ENV, "").split(",") if g.strip()
    ) or DEFAULT_GROUPS
    return SsoConfig(
        portal=os.environ.get(PORTAL_ENV, "").strip() or DEFAULT_PORTAL,
        return_url=os.environ.get(RETURN_ENV, "").strip(),
        groups=groups,
    )
