"""iPhone dziecka jako urzadzenie z DNS (etap E5, docs/iphone.md).

iPhone idzie droga iPada: profil NextDNS z nazwa urzadzenia, odczyt wprost
przez lockdown z LAN domu. Rozni sie tym, co czyta czlowiek — a ze iPhone
dziecka jest zwykle bez nadzoru, teksty czujek musza mowic, ze profil DNS
da sie zdjac. Testy po stronie serwera MDM: test_mdm_iphone.py.
"""

from __future__ import annotations

import typing
from datetime import timedelta

import pytest
from pydantic import ValidationError

from conftest import local, make_config
from kidwatch.config import DeviceConfig
from kidwatch.devicekind import ALIASY, KINDS, RODZAJ_W_BAZIE, DeviceKindName, kind_of
from kidwatch.engine import Engine
from kidwatch.models import DnsEvent, NotifyKind
from kidwatch.sources.unifi import UnifiWatcher
from kidwatch.store import Store, to_iso

MOON = "\U0001F319"
IPHONE = "iPhone Kuby"


def _z_iphonem():
    cfg = make_config()
    cfg.devices.append(DeviceConfig(display_name=IPHONE, child="Kuba", kind="iphone",
                                    source_ids=["iphone-kuby"]))
    return cfg


# ======================================================= spojnosc rodzajow
def test_trzy_mapowania_rodzajow_sa_spojne():
    """Rodzaj dodany do jednego mapowania, a zapomniany w drugim, wychodzi
    dopiero w produkcji: konfiguracja go przyjmie, a zapis do `urzadzenia`
    (domy.py) albo teksty pushy nie beda go znac."""
    assert set(typing.get_args(DeviceKindName)) == set(KINDS)
    # Telewizor nie jest rodzajem z `devices`, ale ma wiersz w `urzadzenia`.
    assert set(RODZAJ_W_BAZIE) == set(KINDS) | {"tv"}
    assert RODZAJ_W_BAZIE["iphone"] == "iphone"
    assert RODZAJ_W_BAZIE["phone"] == "phone-android"
    # Kazda nazwa z bazy jest w komentarzu schematu tabeli (domy.py).
    from kidwatch import domy  # noqa: PLC0415

    linia = next(x for x in domy.SCHEMAT.splitlines() if "rodzaj" in x and "TEXT" in x)
    for rodzaj in RODZAJ_W_BAZIE.values():
        assert f"'{rodzaj}'" in linia
    # Alias telefonu nie przykrywa iPhone'a.
    assert "iphone" not in ALIASY


def test_rodzaje_ipada_i_telefonu_bez_zmian():
    """Regresja: dodanie iPhone'a nie zmienia tekstow iPada ani telefonu."""
    assert kind_of(None) is KINDS["ipad"]
    assert kind_of("nieznany") is KINDS["ipad"]
    assert kind_of("phone-android") is KINDS["phone"]
    assert KINDS["ipad"].genitive == "iPada" and KINDS["ipad"].tag == "ipad"
    assert KINDS["phone"].tag == "android"


def test_iphone_ma_wlasne_teksty():
    k = kind_of("iphone")
    assert k is KINDS["iphone"]
    assert (k.noun, k.genitive) == ("iPhone", "iPhone'a")
    # Uczciwie: bez nadzoru profil DNS da sie zdjac.
    assert "bez nadzoru" in k.dns_off and "bez nadzoru" in k.dns_where.lower()
    assert "iPada" not in k.dns_off and "iPadzie" not in k.dns_where
    # Tag tekstowy, nie emoji ntfy i nie to samo co "iphone" stojace obok.
    assert k.tag not in ("iphone", "ipad", "android")


# ============================================================ konfiguracja
def test_iphone_w_konfiguracji_z_odczytem_wprost_jak_ipad():
    dev = DeviceConfig(display_name=IPHONE, child="Kuba", kind="iphone", source_ids=["i"],
                       udid="00008110-000A00000000000B", host="192.0.2.31",
                       known_apps={"com.example.gra": "Gra"})
    assert dev.kind == "iphone" and dev.reads_device


def test_iphone_walidatory_jak_ipad():
    with pytest.raises(ValidationError, match="musza byc podane RAZEM"):
        DeviceConfig(display_name=IPHONE, child="Kuba", kind="iphone", source_ids=["i"],
                     udid="00008110-000A00000000000B")
    with pytest.raises(ValidationError, match="adres IPv6"):
        DeviceConfig(display_name=IPHONE, child="Kuba", kind="iphone", source_ids=["i"],
                     udid="00008110-000A00000000000B", host="2001:db8::31")


def test_iphone_w_panelu():
    cfg = _z_iphonem()
    assert (IPHONE, "iphone") in [(w.name, w.kind) for w in cfg.watched]
    assert cfg.device_for("IPHONE-KUBY").kind == "iphone"


# ================================================================== pushe
def test_sesja_i_noc_iphone_a(classifier):
    eng = Engine(_z_iphonem(), Store(":memory:"), classifier)
    out = []
    t = local(2026, 10, 10, 15, 0)
    for minute in range(0, 4):
        out += eng.handle(DnsEvent(ts=t + timedelta(minutes=minute), device_id="iphone-kuby",
                                   domain="www.youtube.com"))
    starts = [n for n in out if n.kind is NotifyKind.SESSION_START]
    assert [n.device for n in starts] == [IPHONE]
    assert starts[0].tags == ("iphone", "ios")

    eng2 = Engine(_z_iphonem(), Store(":memory:"), classifier)
    night = local(2026, 10, 10, 22, 40)
    notes = []
    for minute in range(0, 4):
        notes += eng2.handle(DnsEvent(ts=night + timedelta(minutes=minute),
                                      device_id="iphone-kuby", domain="www.youtube.com"))
    nights = [n for n in notes if n.kind is NotifyKind.NIGHT]
    assert nights and nights[0].title == f"{MOON} Kuba uzywa iPhone'a w nocy"
    assert nights[0].tags == ("warning", "ios")


def test_cisza_iphone_a_mowi_ze_profil_da_sie_zdjac(classifier):
    eng = Engine(_z_iphonem(), Store(":memory:"), classifier)
    t = local(2026, 10, 10, 10, 0)
    eng.handle(DnsEvent(ts=t, device_id="iphone-kuby", domain="www.youtube.com"))
    eng.handle(DnsEvent(ts=t, device_id="ipad-kuby", domain="gsp-ssl.ls.apple.com"))
    later = t + timedelta(minutes=181)
    eng.handle(DnsEvent(ts=later, device_id="ipad-kuby", domain="gsp-ssl.ls.apple.com"))
    alerts = [n for n in eng.tick(later) if n.kind is NotifyKind.WATCHDOG]
    assert [n.title for n in alerts] == [f"{IPHONE} nie zglasza sie do DNS"]
    assert "iPhone bez nadzoru pozwala go usunac" in alerts[0].text
    assert "iPada" not in alerts[0].text


class _NoClient:
    async def stations(self):  # pragma: no cover - observe() dostaje stacje wprost
        return []


def test_unifi_iphone_bez_dns():
    store = Store(":memory:")
    mac = "02:00:00:00:00:05"
    w = UnifiWatcher(_NoClient(), [(IPHONE, mac, None)], store, window_minutes=15,
                     alarm_mb=20, kinds={IPHONE: "iphone"})
    t0 = local(2026, 10, 10, 16, 0)
    store.set_meta("alive:__all__", to_iso(t0 + timedelta(minutes=20)))
    out = []
    for minute in range(0, 21):
        sta = {"mac": mac, "ip": "192.0.2.35", "essid": "dom",
               "rx_bytes": minute * 3_000_000, "tx_bytes": 0}
        out += w.observe([sta], t0 + timedelta(minutes=minute))
    alerts = [n for n in out if n.kind is NotifyKind.DNS_PROFILE]
    assert alerts
    assert "Sprawdź na iPhonie" in alerts[0].text and "MDM tego nie zablokuje" in alerts[0].text

