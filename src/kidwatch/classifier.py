"""Klasyfikacja domen: szum / aplikacja / nieznane.

Strategia dopasowania to **najdluzszy wygrywa**, a nie "pierwszy w pliku". Dzieki
temu kolejnosc wpisow w app_map.yaml nie ma znaczenia i `music.apple.com` w apps
bije `apple.com` w noise. Przy dokladnie tej samej dlugosci wzorca pierwszenstwo
ma szum, bo lepiej przeoczyc aplikacje niz budzic sesje przy spiacym iPadzie.
"""

from __future__ import annotations

import logging
import time as _time
from pathlib import Path

import yaml

from .models import Classification, Kind

log = logging.getLogger(__name__)

NOISE = Classification(Kind.NOISE)
AMBIGUOUS = Classification(Kind.AMBIGUOUS)
UNKNOWN = Classification(Kind.UNKNOWN)

#: Etykieta dla ruchu, ktory nie jest szumem, ale nie pasuje do zadnej aplikacji.
UNKNOWN_LABEL = "Przegladarka / inne"


def normalize_domain(domain: str) -> str:
    return domain.strip().rstrip(".").lower()


#: Sufiksy dwuczlonowe, przy ktorych "dwie ostatnie etykiety" daja zly wynik
#: (wp.com.pl zwinalby sie do "com.pl"). Nie jest to pelna Public Suffix List —
#: tylko to, co realnie wystepuje w logach polskiego gospodarstwa.
TWO_LEVEL_SUFFIXES = frozenset(
    {
        "com.pl", "net.pl", "org.pl", "gov.pl", "edu.pl", "info.pl", "waw.pl",
        "co.uk", "org.uk", "ac.uk", "com.au", "co.jp", "com.br", "com.cn",
        "com.tr", "co.in", "com.mx", "com.hk", "com.tw",
    }
)


def registrable(domain: str) -> str:
    """Zwija poddomeny do domeny, ktora czlowiek rozpoznaje.

    'rr1---sn-abc.googlevideo.com' -> 'googlevideo.com'
    Sluzy do pokazywania domen w powiadomieniach i raportach, nie do decyzji —
    klasyfikacja dziala na pelnej nazwie.
    """
    parts = normalize_domain(domain).split(".")
    if len(parts) <= 2:
        return ".".join(parts)
    if ".".join(parts[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _suffixes(domain: str) -> list[str]:
    """['a.b.youtube.com', 'b.youtube.com', 'youtube.com', 'com'] — od najdluzszego."""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


class Classifier:
    """Trzyma mape domen i przeladowuje ja, gdy plik zmieni mtime."""

    def __init__(self, path: str | Path, reload_check_seconds: float = 5.0) -> None:
        self._path = Path(path)
        self._reload_check_seconds = reload_check_seconds
        self._mtime: float | None = None
        self._last_check: float = 0.0
        self._exact: dict[str, Classification] = {}
        self._suffix: dict[str, Classification] = {}
        self.reload()

    # ------------------------------------------------------------------ ladowanie
    def reload(self) -> None:
        raw = yaml.safe_load(self._path.read_text(encoding="utf-8")) or {}
        exact: dict[str, Classification] = {}
        suffix: dict[str, Classification] = {}

        def add(pattern: str, verdict: Classification) -> None:
            pattern = pattern.strip().lower()
            if not pattern:
                return
            if pattern.startswith("="):
                target, key = exact, pattern[1:].strip().rstrip(".")
            else:
                target = suffix
                key = pattern.removeprefix("*.").strip().rstrip(".")
            if not key:
                return
            existing = target.get(key)
            # Kolizja na identycznym wzorcu: wygrywa kategoria ostrozniejsza,
            # czyli ta, ktora NIE otworzy sesji. Lepiej przeoczyc aplikacje niz
            # budzic pushem spiacy iPad (patrz docstring modulu).
            if existing is not None and existing.kind in (Kind.NOISE, Kind.AMBIGUOUS):
                log.warning(
                    "wzorzec %r wystepuje w %s i w %s — zostaje %s",
                    key,
                    existing.kind.value,
                    verdict.kind.value if verdict.app is None else f"apps/{verdict.app}",
                    existing.kind.value,
                )
                return
            target[key] = verdict

        for pattern in raw.get("noise") or []:
            add(str(pattern), NOISE)
        for pattern in raw.get("shared") or []:
            add(str(pattern), AMBIGUOUS)
        for app_name, patterns in (raw.get("apps") or {}).items():
            verdict = Classification(Kind.APP, str(app_name))
            for pattern in patterns or []:
                add(str(pattern), verdict)

        self._exact, self._suffix = exact, suffix
        self._mtime = self._path.stat().st_mtime
        self._last_check = _time.monotonic()
        log.info(
            "app_map przeladowany: %d wzorcow dokladnych, %d sufiksowych",
            len(exact),
            len(suffix),
        )

    def _maybe_reload(self) -> None:
        now = _time.monotonic()
        if now - self._last_check < self._reload_check_seconds:
            return
        self._last_check = now
        try:
            mtime = self._path.stat().st_mtime
        except OSError as exc:
            log.warning(
                "nie moge sprawdzic mtime %s: %s — zostaje przy starej mapie", self._path, exc
            )
            return
        if mtime == self._mtime:
            return
        try:
            self.reload()
        except Exception:
            # Zly YAML nie moze zabic serwisu — zostajemy przy poprzedniej mapie
            # i probujemy ponownie przy nastepnej zmianie pliku.
            log.exception("app_map %s jest niepoprawny — zostaje stara mapa", self._path)
            self._mtime = mtime

    # ------------------------------------------------------------- klasyfikacja
    def classify(self, domain: str) -> Classification:
        self._maybe_reload()
        d = normalize_domain(domain)
        if not d:
            return UNKNOWN
        hit = self._exact.get(d)
        if hit is not None:
            return hit
        for suffix in _suffixes(d):
            hit = self._suffix.get(suffix)
            if hit is not None:
                return hit
        return UNKNOWN

    def label(self, domain: str) -> str | None:
        """Nazwa aplikacji do pokazania czlowiekowi.

        None dla szumu i dla ruchu wspoldzielonego — ani jedno, ani drugie nie
        pozwala nazwac aplikacji.
        """
        verdict = self.classify(domain)
        if verdict.kind in (Kind.NOISE, Kind.AMBIGUOUS):
            return None
        if verdict.kind is Kind.APP and verdict.app:
            return verdict.app
        return UNKNOWN_LABEL
