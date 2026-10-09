"""Regresja 2026-10-09: obudzony, NIEUZYWANY iPad nie moze dac pushy.

iPad lezal; podlaczenie kablem do Maca, odczyt przez USB i zapis do MDM
obudzily go. App Store i iCloud (przez CDN-y Akamai i Cloudflare) poszly jako
„nieznane" i otworzyly sesje „aktywny — edgekey.net, cloudflare.com", a
odswiezenie Netflixa w tle (trzy zapytania w jednej sekundzie) dostalo push
aplikacji. Plik z danymi to PRAWDZIWA sekwencja z NextDNS (same godziny UTC
i domeny), a test idzie na PRAWDZIWEJ mapie domen z repo.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from conftest import make_config
from kidwatch.classifier import Classifier
from kidwatch.engine import Engine
from kidwatch.models import DnsEvent, Kind, NotifyKind
from kidwatch.store import Store

ROOT = Path(__file__).resolve().parents[1]
SEKWENCJA = ROOT / "tests" / "fixtures" / "ipad_wybudzenie_2026-10-09.txt"


def zdarzenia() -> list[DnsEvent]:
    out = []
    for line in SEKWENCJA.read_text(encoding="utf-8").splitlines():
        hhmmss, domain = line.split()
        h, m, s = map(int, hhmmss.split(":"))
        ts = datetime(2026, 10, 9, h, m, s, tzinfo=UTC)
        out.append(DnsEvent(ts=ts, device_id="ipad-kuby", domain=domain))
    return out


def silnik(mapa: Path) -> Engine:
    # Progi PRODUKCYJNE (charts/kidwatch/files/config.yaml) — make_config
    # w testach potwierdza sesje od razu (confirm_moments=1).
    cfg = make_config(engine={"confirm_minutes": 5, "confirm_moments": 3})
    return Engine(cfg, Store(":memory:"), Classifier(mapa))


def test_obudzony_lezacy_ipad_nie_daje_pushy():
    eng = silnik(ROOT / "app_map.yaml")
    notes = []
    for event in zdarzenia():
        notes += eng.handle(event)
    rodzaje = {n.kind for n in notes}
    assert NotifyKind.SESSION_START not in rodzaje, [n.title for n in notes]
    assert NotifyKind.APP not in rodzaje, [n.title for n in notes]


def test_systemowe_domeny_z_wybudzenia_sa_szumem():
    c = Classifier(ROOT / "app_map.yaml")
    for domain in (
        "sf-api-token-service.itunes.apple.com.edgekey.net",
        "uts-api.itunes.apple.com.edgesuite.net",
        "apple-relay.cloudflare.com",
        "dap.pat-issuer.cloudflare.com",
        "cp10.cloudflare.com",
        "mdm.renacode.com",
    ):
        assert c.classify(domain).kind is Kind.NOISE, domain


def test_waskie_wpisy_nie_wyciszaja_calego_cdn():
    """edgekey.net i cloudflare.com hostuja tez gry i strony — nie do szumu."""
    c = Classifier(ROOT / "app_map.yaml")
    for domain in ("www.example.com.edgekey.net", "gra.cloudflare.com"):
        assert c.classify(domain).kind is not Kind.NOISE, domain
