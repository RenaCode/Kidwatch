"""Telefon z Androidem (Family Link) jako urzadzenie dziecka z DNS.

Telefon idzie ta sama droga co iPad: Prywatny DNS -> profil NextDNS z nazwa
urzadzenia. Te testy pilnuja tego, co rozne: tlo Androida nie moze budzic
sesji (prawdziwa app_map.yaml, domyslne progi potwierdzania), teksty mowia
"telefon", a podpowiedzi czujek wskazuja Prywatny DNS, nie profil iOS.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from conftest import local, make_config
from kidwatch.classifier import Classifier
from kidwatch.config import Config, DeviceConfig, QuietHours
from kidwatch.engine import Engine
from kidwatch.models import DnsEvent, Kind, NotifyKind
from kidwatch.sources.unifi import UnifiWatcher
from kidwatch.store import Store, to_iso

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = Path(__file__).parent / "fixtures" / "telefon_android.jsonl"
MOON = "\U0001F319"
PHONE = "Telefon Kuby"


def phone_config(**extra) -> Config:
    """Prawdziwe progi silnika (bez confirm_moments=1 z make_config) i prawdziwa
    mapa domen — to one decyduja, czy tlo Androida otwiera sesje."""
    from datetime import time  # noqa: PLC0415

    from kidwatch.config import (  # noqa: PLC0415
        EngineConfig,
        NextDnsConfig,
        NotifiersConfig,
        NtfyConfig,
        SourceConfig,
        StoreConfig,
    )

    return Config(
        source=SourceConfig(kind="nextdns", nextdns=NextDnsConfig(profile_id="test")),
        devices=[
            DeviceConfig(display_name="iPad Kuby", child="Kuba", source_ids=["ipad-kuby"]),
            DeviceConfig(display_name=PHONE, child="Kuba", kind="phone",
                         source_ids=["Telefon Kuby"]),
        ],
        engine=EngineConfig(quiet_hours=QuietHours(start=time(21, 30), end=time(7, 0))),
        notifiers=NotifiersConfig(ntfy=NtfyConfig(topic="test-topic")),
        store=StoreConfig(path=":memory:"),
        app_map_path=str(ROOT / "app_map.yaml"),
        **extra,
    )


def replay() -> list:
    cfg = phone_config()
    engine = Engine(cfg, Store(":memory:"), Classifier(cfg.app_map_path))
    rows = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    out = []
    for row in rows:
        ts = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        out += engine.handle(DnsEvent(ts=ts, device_id=row["device"], domain=row["domain"]))
        out += engine.tick(ts)
    last = datetime.fromisoformat(rows[-1]["ts"].replace("Z", "+00:00"))
    out += engine.tick(last + timedelta(minutes=11))
    # Czujka ciszy (iPad z konfiguracji nie ma tu ruchu) ma wlasne testy nizej.
    return [n for n in out if n.kind not in (NotifyKind.DAILY, NotifyKind.WATCHDOG)]


# ================================================================ konfiguracja
def test_telefon_w_konfiguracji_i_w_panelu():
    cfg = phone_config()
    assert [(w.name, w.kind) for w in cfg.watched] == [("iPad Kuby", "ipad"), (PHONE, "phone")]
    # Nazwa z NextDNS ("Telefon--Kuby" -> "Telefon Kuby") dopasowana bez wielkosci liter.
    assert cfg.device_for("TELEFON KUBY").kind == "phone"


def test_domyslny_rodzaj_to_ipad():
    assert DeviceConfig(display_name="x", child="y", source_ids=["x"]).kind == "ipad"


@pytest.mark.parametrize("field", [
    {"udid": "00008101-AAAA", "host": "192.168.0.81"},
    {"known_apps": {"com.example": "Gra"}},
])
def test_telefon_nie_ma_odczytu_wprost(field):
    with pytest.raises(ValidationError, match="kind=phone nie ma odczytu wprost"):
        DeviceConfig(display_name=PHONE, child="Kuba", kind="phone", source_ids=["t"], **field)


def test_nieznany_rodzaj_odrzucony():
    with pytest.raises(ValidationError):
        DeviceConfig(display_name="x", child="y", kind="android-tv", source_ids=["x"])


def test_telefon_i_ipad_dziecka_na_jednym_profilu():
    """Czas gry jest ustawieniem profilu NextDNS — telefon na innym profilu
    niz iPad tego samego dziecka zostalby poza blokada."""
    from kidwatch.config import NextDnsConfig, SourceConfig  # noqa: PLC0415

    with pytest.raises(ValidationError, match="roznych profilach"):
        Config(
            source=SourceConfig(kind="nextdns", nextdns=NextDnsConfig(profile_id="glowny")),
            devices=[
                DeviceConfig(display_name="iPad Kuby", child="Kuba", source_ids=["a"],
                             nextdns_profile="abc123"),
                DeviceConfig(display_name=PHONE, child="Kuba", kind="phone", source_ids=["b"]),
            ],
        )


# ============================================================ mapa domen
@pytest.mark.parametrize("domain", [
    "mtalk.google.com", "alt3-mtalk.google.com", "connectivitycheck.gstatic.com",
    "connectivitycheck.android.com", "time.android.com", "android.clients.google.com",
    "redirector.gvt1.com", "dms.samsungdm.com", "vas.samsungapps.com",
    "api.miui.com", "metrics.data.hicloud.com",
])
def test_tlo_androida_to_szum(domain):
    assert Classifier(ROOT / "app_map.yaml").classify(domain).kind is Kind.NOISE


def test_szum_androida_nie_przykrywa_aplikacji():
    """Dluzszy wpis wygrywa: android.com w szumie nie moze zjesc YouTube ani
    zaplecza Google ze `shared`."""
    c = Classifier(ROOT / "app_map.yaml")
    assert c.classify("youtubei.googleapis.com").app == "YouTube"
    assert c.classify("play.googleapis.com").kind is Kind.AMBIGUOUS
    assert c.classify("www.google.com").kind is Kind.AMBIGUOUS


# ===================================================== doba telefonu (fixture)
def test_doba_telefonu_tlo_nie_budzi_sesji():
    notes = replay()
    tz = local(2026, 10, 10, 0, 0).tzinfo
    hours = [n.ts.astimezone(tz).hour for n in notes]
    # Ani jednego pusha z samego tla od polnocy do startu YouTube o 15:00.
    assert all(h >= 15 for h in hours), [(n.title, n.ts) for n in notes]
    assert not any("WhatsApp" in (n.app or "") for n in notes)


def test_doba_telefonu_sesja_i_alarm_nocny():
    notes = replay()
    tz = local(2026, 10, 10, 0, 0).tzinfo
    starts = [n for n in notes if n.kind is NotifyKind.SESSION_START]
    assert len(starts) == 1
    assert starts[0].title == f"{PHONE} aktywny"
    assert starts[0].app == "YouTube"
    assert starts[0].ts.astimezone(tz).strftime("%H:%M") == "15:01"
    assert "android" in starts[0].tags and "ipad" not in starts[0].tags

    nights = [n for n in notes if n.kind is NotifyKind.NIGHT]
    assert nights, "TikTok o 22:40 musi dac alarm nocny"
    assert nights[0].title == f"{MOON} Kuba uzywa telefonu w nocy"
    assert nights[0].device == PHONE
    assert "TikTok" in nights[0].text
    assert nights[0].tags == ("warning", "android")

    ends = [n for n in notes if n.kind is NotifyKind.SESSION_END]
    assert len(ends) == 2


# ================================================================== czujki
def test_cisza_telefonu_wskazuje_prywatny_dns(classifier):
    cfg = make_config()
    cfg.devices.append(DeviceConfig(display_name=PHONE, child="Kuba", kind="phone",
                                    source_ids=["telefon kuby"]))
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 10, 10, 10, 0)
    eng.handle(DnsEvent(ts=t, device_id="telefon kuby", domain="www.youtube.com"))
    eng.handle(DnsEvent(ts=t, device_id="ipad-kuby", domain="gsp-ssl.ls.apple.com"))
    later = t + timedelta(minutes=181)
    eng.handle(DnsEvent(ts=later, device_id="ipad-kuby", domain="gsp-ssl.ls.apple.com"))
    alerts = [n for n in eng.tick(later) if n.kind is NotifyKind.WATCHDOG]
    assert [n.title for n in alerts] == [f"{PHONE} nie zglasza sie do DNS"]
    assert "Prywatny DNS" in alerts[0].text
    assert "iPada" not in alerts[0].text


def test_cisza_ipada_bez_zmian(classifier):
    """Regresja: tekst czujki iPada zostaje dokladnie taki jak przed telefonami."""
    eng = Engine(make_config(), Store(":memory:"), classifier)
    t = local(2026, 10, 10, 10, 0)
    eng.handle(DnsEvent(ts=t, device_id="ipad-kuby", domain="gsp-ssl.ls.apple.com"))
    later = t + timedelta(minutes=181)
    eng.handle(DnsEvent(ts=later, device_id="ipad-zosi", domain="gsp-ssl.ls.apple.com"))
    alerts = [n for n in eng.tick(later) if n.kind is NotifyKind.WATCHDOG]
    assert alerts[0].text.endswith(
        "Najczestsza przyczyna: zdjety profil DNS albo wylaczony szyfrowany DNS "
        "w Ustawieniach tego iPada."
    )


class _NoClient:
    async def stations(self):  # pragma: no cover - observe() dostaje stacje wprost
        return []


def test_unifi_telefon_bez_dns_wskazuje_prywatny_dns():
    store = Store(":memory:")
    mac = "02:00:00:00:00:03"
    w = UnifiWatcher(_NoClient(), [(PHONE, mac, None)], store, window_minutes=15,
                     alarm_mb=20, kinds={PHONE: "phone"})
    t0 = local(2026, 10, 10, 16, 0)
    # Strumien DNS zyje (inne urzadzenie), telefon milczy, a w Wi-Fi przesyla.
    store.set_meta("alive:__all__", to_iso(t0 + timedelta(minutes=20)))
    out = []
    for minute in range(0, 21):
        sta = {"mac": mac, "ip": "192.168.0.83", "essid": "dom",
               "rx_bytes": minute * 3_000_000, "tx_bytes": 0}
        out += w.observe([sta], t0 + timedelta(minutes=minute))
    alerts = [n for n in out if n.kind is NotifyKind.DNS_PROFILE]
    assert alerts, "telefon w Wi-Fi z ruchem i bez DNS musi dac alarm"
    assert "Prywatny DNS" in alerts[0].text
    assert "iPadzie" not in alerts[0].text


# =================================================================== panel
def test_panel_pokazuje_telefon_obok_ipada(tmp_path):
    from kidwatch.panel import PanelQueries  # noqa: PLC0415

    cfg = make_config()
    cfg.devices.append(DeviceConfig(display_name=PHONE, child="Kuba", kind="phone",
                                    source_ids=["telefon kuby"]))
    cfg.store.path = str(tmp_path / "k.db")
    store = Store(cfg.store.path)
    sid = store.open_session(PHONE, "Kuba", local(2026, 10, 10, 15, 0))
    store.record_app_minute(sid, "YouTube", local(2026, 10, 10, 15, 0))
    store.close_session(sid, local(2026, 10, 10, 15, 20))
    q = PanelQueries(cfg, cfg.store.path)
    meta = {d["name"]: d["kind"] for d in q.meta()["devices"]}
    assert meta == {"iPad Kuby": "ipad", "iPad Zosi": "ipad", PHONE: "phone"}
    with q.connect() as conn:
        karty = {d["name"]: d for d in q.devices(conn, {"child": "Kuba"})}
        dzien = q.day(conn, {"day": "2026-10-10", "child": "Kuba"})
    assert karty[PHONE]["kind"] == "phone"
    assert karty[PHONE]["reads_device"] is False
    assert PHONE in [d["name"] for d in dzien["devices"]]
    store.close()
