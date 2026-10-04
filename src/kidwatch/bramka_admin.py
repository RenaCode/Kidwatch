"""Zarzadzanie kanalami bramki (WhatsApp) z panelu — po stronie serwera.

Przegladarka nigdy nie zna kluczy bramki: panel przyjmuje zadanie z sesja
i CSRF (/api/profile/*), a dopiero ten modul wola bramke kluczem
ADMINISTRACYJNYM (BRAMKA_KLUCZ_ADMIN, patrz BramkaConfig.admin_key). Klucz
wysylkowy dostaje na tych sciezkach 403.
Bramka jest w klastrze (Service ClusterIP), wiec z zewnatrz i tak nie jest
osiagalna — klucz chroni ja przed innymi podami.

Synchroniczny httpx, bo wola go watek ThreadingHTTPServer panelu, nie petla
asyncio. Krotki timeout: QR odswiezany co 20 s nie moze trzymac watku dluzej.
"""

from __future__ import annotations

import re

import httpx

from .config import BramkaConfig

TIMEOUT_SECONDS = 10.0
# Wiadomosc probna: w bramce status WAHA (3 s) + sendText do wszystkich
# aktywnych naraz (15 s) i ewentualnie mail - 10 s ucinalo odpowiedz, choc
# wiadomosc dochodzila.
TEST_TIMEOUT_SECONDS = 35.0
_NUMBER = re.compile(r"[0-9]{10,15}", re.ASCII)
#: Co wolno wpisac w numer: cyfry ASCII, + na poczatku i separatory. Litery
#: ("wew. 12") albo cyfry z innych alfabetow odrzucamy, zamiast po cichu
#: sklejac z nich numer, na ktory WhatsApp niczego nie dostarczy.
_NUMBER_INPUT = re.compile(r"\+?[0-9 ().-]+", re.ASCII)
#: Te same granice co w bramce (kanaly.MAX_ODBIORCOW / MAX_ETYKIETA) - panel
#: odrzuca wczesniej, z komunikatem po polsku, ale decyduje bramka.
MAX_RECIPIENTS = 5
MAX_LABEL = 40


class BramkaError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def normalize_number(raw: str) -> str | None:
    """"+48 600 100 200" / "0048 600-100-200" -> "48600100200"; None, gdy to
    nie numer z kierunkowym albo zawiera cos poza cyframi i separatorami."""
    text = str(raw).strip()
    if not _NUMBER_INPUT.fullmatch(text):
        return None
    digits = re.sub(r"[^0-9]", "", text)
    # "0048 600..." to ten sam numer co "+48 600..." - prefiks miedzynarodowy.
    if not text.startswith("+") and digits.startswith("00"):
        digits = digits[2:]
    return digits if _NUMBER.fullmatch(digits) else None


def mask(number: str) -> str:
    """Numer do logu: tylko 3 ostatnie cyfry."""
    return f"...{number[-3:]}"


def normalize_recipients(raw: object) -> list[dict]:
    """Lista z przegladarki [{number, label, active}] -> lista dla bramki
    [{numer, etykieta, aktywny}]. ValueError z komunikatem dla czlowieka -
    pozycja na liscie, nigdy sam numer."""
    if not isinstance(raw, list):
        raise ValueError("Lista odbiorców ma zły format")
    if len(raw) > MAX_RECIPIENTS:
        raise ValueError(f"Najwyżej {MAX_RECIPIENTS} odbiorców")
    result: list[dict] = []
    for i, item in enumerate(raw, 1):
        if not isinstance(item, dict):
            raise ValueError(f"Odbiorca {i}: zły format")
        number = normalize_number(item.get("number", "")) if isinstance(
            item.get("number"), str) else None
        if number is None:
            raise ValueError(f"Odbiorca {i}: podaj numer z kierunkowym, np. 48600100200")
        label = item.get("label", "")
        if not isinstance(label, str):
            raise ValueError(f"Odbiorca {i}: zła etykieta")
        label = " ".join("".join(c if c.isprintable() else " " for c in label).split())
        if len(label) > MAX_LABEL:
            raise ValueError(f"Odbiorca {i}: etykieta najwyżej {MAX_LABEL} znaków")
        active = item.get("active", True)
        if not isinstance(active, bool):
            raise ValueError(f"Odbiorca {i}: zła wartość „aktywny”")
        if any(r["numer"] == number for r in result):
            raise ValueError(f"Odbiorca {i}: ten numer jest już na liście")
        result.append({"numer": number, "etykieta": label, "aktywny": active})
    return result


class BramkaAdmin:
    def __init__(
        self, cfg: BramkaConfig, key: str, transport: httpx.BaseTransport | None = None
    ) -> None:
        self.cfg = cfg
        self._key = key
        self._transport = transport

    def _call(
        self, method: str, path: str, body: dict | None = None,
        timeout: float = TIMEOUT_SECONDS,
    ) -> dict:
        try:
            with httpx.Client(
                base_url=self.cfg.url.rstrip("/"),
                timeout=timeout,
                transport=self._transport,
            ) as client:
                response = client.request(
                    method, path, headers={"X-Api-Key": self._key},
                    json=body if method != "GET" else None,
                )
        except httpx.HTTPError as exc:
            raise BramkaError(502, f"bramka nieosiagalna: {exc}") from exc
        try:
            data = response.json()
        except ValueError:
            data = {}
        if not isinstance(data, dict):
            data = {}
        if response.status_code >= 400:
            # 502 z /v1/test to "zaden kanal nie przyjal" — tresc mowi dlaczego.
            msg = data.get("blad") or "; ".join(
                f"{k}: {v}" for k, v in (data.get("bledy") or {}).items()
            ) or f"HTTP {response.status_code}"
            raise BramkaError(response.status_code, str(msg))
        return data

    def status(self) -> dict:
        return self._call("GET", "/v1/whatsapp")

    def start(self) -> dict:
        return self._call("POST", "/v1/whatsapp/start", {})

    def qr(self) -> dict:
        return self._call("GET", "/v1/whatsapp/qr")

    def set_recipient(self, number: str) -> dict:
        """Stare API bramki: lista z jednym aktywnym numerem."""
        return self._call("POST", "/v1/whatsapp/odbiorca", {"numer": number})

    def set_recipients(self, recipients: list[dict]) -> dict:
        """Cala lista [{numer, etykieta, aktywny}] (normalize_recipients)."""
        return self._call("POST", "/v1/whatsapp/odbiorcy", {"odbiorcy": recipients})

    def logout(self) -> dict:
        return self._call("POST", "/v1/whatsapp/wyloguj", {})

    def test(self, channel: str = "auto") -> dict:
        return self._call("POST", "/v1/test", {"kanal": channel, "zrodlo": self.cfg.zrodlo},
                          timeout=TEST_TIMEOUT_SECONDS)
