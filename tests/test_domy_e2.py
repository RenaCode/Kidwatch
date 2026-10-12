"""Etap E2 domow (docs/architektura-domy.md §3, §6 p. 4, §7 E2): integracje
per dom, sekrety w bazie (KEK/DEK, AAD), dom-importuj, straznik sieci.

Dane wylacznie generyczne (tests/test_repo_prywatnosc.py): „Dziecko 1”,
adresy z RFC 5737, nazwy *.example.invalid. Sekrety losowane w tescie jako
KANARKI — kazdy test, ktory cos wypisuje albo loguje, szuka ich w calym
wyjsciu. Zaden test nie laczy sie z siecia (fixture `bez_sieci`)."""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import secrets
import sqlite3
import stat
import subprocess
import sys
import tarfile
from datetime import UTC, datetime, timedelta
from io import BytesIO
from pathlib import Path

import pytest
import yaml

import kidwatch.__main__ as cli
from kidwatch import domy, konfiguracja_domu
from kidwatch.classifier import Classifier
from kidwatch.config import Config, HomeConfig, MissingSecretError
from kidwatch.domy import DOM_1, RejestrDomow, SekretyDomu
from kidwatch.konfiguracja_domu import (
    importuj,
    sekrety_z_yaml,
    zbuduj_dom,
)
from kidwatch.models import Notification, NotifyKind
from kidwatch.notifiers.homeassistant import HomeAssistantNotifier
from kidwatch.panel_auth import PanelAuth
from kidwatch.scheduler import source_loop
from kidwatch.sejf import Sejf, SejfError
from kidwatch.sources.nextdns import ConnectGate
from kidwatch.store import Store
from kidwatch.straznik import OdmowaSieci, StraznikTransport

pytestmark = pytest.mark.usefixtures("bez_sieci")

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).parent / "fixtures"
APP_MAP = ROOT / "app_map.yaml"
DAY = FIXTURES / "day.jsonl"
SNAPSHOT = FIXTURES / "day.expected.txt"
HASLO = "haslo-testowe-123"
#: Obraz na produkcji przed E2 (E1, #47) — test wycofania uruchamia JEGO kod.
STARY_OBRAZ = "2723214507c06c0ab3c97d9ede5b947b4ca0907e"
ODCISK = "ab" * 32
PUBLICZNY = "9.9.9.9"

#: Sekret -> zmienna srodowiskowa, z ktorej Dom 1 bierze go w trybie yaml.
ENV = {
    "nextdns.api_key": "NEXTDNS_API_KEY", "ntfy.topic": "NTFY_TOPIC",
    "ntfy.token": "NTFY_TOKEN", "homeassistant.webhook_id": "HA_WEBHOOK_ID",
    "tv.sony_psk": "TV_SONY_PSK", "unifi.api_key": "UNIFI_API_KEY",
    "mdm.token": "MDM_ADMIN_TOKEN",
}


def _klucz_adb() -> str:
    """Prawdziwy (losowy) klucz RSA — AdbTcpShell musi go przyjac."""
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415

    klucz = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return klucz.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption()).decode().strip()


def _kanarki() -> dict[str, str]:
    """Losowe wartosci sekretow, latwe do wyszukania w wyjsciu."""
    out = {k: f"KANAREK-{k.replace('.', '-')}-{secrets.token_hex(10)}" for k in ENV}
    out["tv.adb_key"] = _klucz_adb()
    out["tv.adb_key_pub"] = "KANAREK-ADBPUB-" + secrets.token_hex(12) + " kidwatch@example.invalid"
    out["tv.app_token"] = "KANAREK-TOKEN-TV-" + secrets.token_hex(12)
    return out


def _wartosci_kanarkow(kanarki: dict[str, str]) -> list[str]:
    """Fragmenty do szukania: calosc i rdzen (klucz PEM jest wielolinijkowy)."""
    out = []
    for v in kanarki.values():
        out.append(v)
        out += [czesc for czesc in v.split() if "KANAREK" in czesc]
        # Linie tresci klucza PEM (bez naglowkow) — kazda jest losowa.
        out += [linia for linia in v.splitlines()
                if len(linia) >= 32 and not linia.startswith("-----")]
    return out


def _bez_kanarkow(tekst: str, kanarki: dict[str, str]) -> None:
    for v in _wartosci_kanarkow(kanarki):
        assert v not in tekst, "sekret-kanarek w wyjsciu"


def _pelna(tmp_path: Path) -> dict:
    return {
        "timezone": "Europe/Lisbon",
        "app_map_path": str(APP_MAP),
        "source": {"kind": "nextdns", "nextdns": {"profile_id": "abc123"}},
        "devices": [
            {"display_name": "iPad Dziecka 1", "child": "Dziecko 1", "source_ids": ["iPad-1"],
             "udid": "00000000-0000000000000001", "host": "192.0.2.10",
             "unifi_mac": "02:00:00:00:00:01", "nextdns_profile": "def456",
             "known_apps": {"com.example.gra": "Gra"}},
            {"display_name": "iPad Dziecka 1 b", "child": "Dziecko 1", "source_ids": ["iPad-1b"],
             "nextdns_profile": "def456"},
            {"display_name": "Telefon Dziecka 2", "child": "Dziecko 2", "source_ids": ["Tel-2"],
             "kind": "phone-android", "unifi_ip": "192.0.2.12"},
        ],
        "engine": {"idle_minutes": 7, "quiet_hours": {"start": "21:00", "end": "07:00"},
                   "night": {"reminder_minutes": 20}},
        "watchdog": {"device_silence_minutes": 99},
        "notifiers": {
            "ntfy": {"enabled": True, "default_priority": 4},
            "homeassistant": {"enabled": True, "base_url": "http://192.0.2.30:8123"},
        },
        "device_read": {"enabled": True, "pair_record_dir": str(tmp_path / "rekordy"),
                        "poll_seconds": 45, "process_aliases": {"Gra9": "com.example.gra"}},
        "store": {"path": str(tmp_path / "kidwatch.db"), "retention_days": 14,
                  "notifications_retention_days": 100, "rollup_retention_days": 7},
        "panel": {"enabled": False},
        "tv": {"enabled": True, "name": "TV wspolny", "host": "192.0.2.20",
               "adb_key_dir": str(tmp_path / "adb"), "apps": {"com.example.tv": "Kanal"}},
        "unifi": {"enabled": True, "url": "https://192.0.2.1", "cert_sha256": ODCISK,
                  "window_minutes": 20},
        "game_time": {"enabled": True, "services": ["youtube"], "categories": ["gaming"],
                      "block_schedule": {"start": "20:00", "end": "07:00"}},
        "mdm": {"enabled": True, "url": "http://mdm.example.invalid:8081",
                "silent_alert_hours": 12},
    }


def _zapisz_konfig(tmp_path: Path, data: dict) -> Path:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return p


@pytest.fixture(autouse=True)
def _aplikacja_tv_bez_przecieku(monkeypatch):
    """build_tv_app ustawia globalne tv_app.AKTYWNA (do E3b) — po tescie
    wraca poprzednia wartosc, zeby testy panelu nie widzialy naszej."""
    from kidwatch.sources import tv_app  # noqa: PLC0415

    monkeypatch.setattr(tv_app, "AKTYWNA", tv_app.AKTYWNA)


@pytest.fixture
def kek(monkeypatch, tmp_path):
    klucz = secrets.token_bytes(32)
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(klucz).decode())
    monkeypatch.delenv("KIDWATCH_KEK_POPRZEDNI", raising=False)
    monkeypatch.setenv("KIDWATCH_KATALOG_SEKRETOW", str(tmp_path / "run"))
    return klucz


@pytest.fixture
def dom1(tmp_path, monkeypatch):
    """Dom 1 z pelna konfiguracja w config.yaml, sekrety-kanarki w env
    i w plikach (klucz ADB, token aplikacji TV) — jak na produkcji."""
    kanarki = _kanarki()
    for klucz, env in ENV.items():
        monkeypatch.setenv(env, kanarki[klucz])
    monkeypatch.delenv("ADGUARD_PASSWORD", raising=False)
    (tmp_path / "adb").mkdir()
    (tmp_path / "adb" / "adbkey").write_text(kanarki["tv.adb_key"])
    (tmp_path / "adb" / "adbkey.pub").write_text(kanarki["tv.adb_key_pub"])
    (tmp_path / "tv-app").mkdir()
    (tmp_path / "tv-app" / "token").write_text(kanarki["tv.app_token"])
    cfg_path = _zapisz_konfig(tmp_path, _pelna(tmp_path))
    cfg = Config.load(cfg_path)
    inst, home = cfg.split()
    # Dom 1 zalozony przez PanelAuth (np. user-add przed pierwszym run):
    # strefa domyslna, nie z config.yaml (przeglad E1, Z3).
    PanelAuth(inst.panel_auth_path).add_user("konto-a", HASLO, "wlasciciel")
    return {"cfg_path": cfg_path, "cfg": cfg, "inst": inst, "home": home, "kanarki": kanarki,
            "rejestr": RejestrDomow(inst.panel_auth_path)}


def _importuj(d, sejf, *, zapisz=True):
    katalog = domy.katalog_domu(DOM_1, d["inst"].store.path)
    sekrety = sekrety_z_yaml(d["home"], katalog)
    return importuj(d["rejestr"], DOM_1, d["home"], sekrety, sejf=sejf, zapisz=zapisz,
                    kto="test", plik_tokenu_tv=katalog / "tv-app" / "token")


def _wyczysc_env():
    for env in ENV.values():
        os.environ.pop(env, None)


def _zrzut(path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return list(conn.iterdump())
    finally:
        conn.close()


def _sql(path, sql: str, args: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(path, isolation_level=None)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# ============================================================ dom-importuj
def test_podglad_importu_nie_zmienia_bazy(dom1, kek):
    path = dom1["inst"].panel_auth_path
    przed = _zrzut(path)
    raport = _importuj(dom1, Sejf(kek), zapisz=False)
    assert raport.roznice == [] and not raport.zapisano
    assert _zrzut(path) == przed
    assert raport.integracje["nextdns"][0] is True
    assert set(raport.integracje["tv"][1]) == {"sony_psk", "adb_key", "adb_key_pub", "app_token"}
    _bez_kanarkow(repr(raport), dom1["kanarki"])


def test_import_zapisuje_i_baza_daje_ten_sam_home(dom1, kek, tmp_path):
    rejestr: RejestrDomow = dom1["rejestr"]
    assert rejestr.dom(DOM_1).strefa == "Europe/Warsaw"  # z PanelAuth, nie z config.yaml
    raport = _importuj(dom1, Sejf(kek))
    assert raport.zapisano and raport.roznice == []
    dom = rejestr.dom(DOM_1)
    assert dom.zrodlo_konfiguracji == "baza" and dom.strefa == "Europe/Lisbon"
    # Sieci z adresow wpisanych dzis w config.yaml, po jednym hoscie (§3.6).
    assert set(dom.dozwolone_sieci) == {"192.0.2.20/32", "192.0.2.1/32", "192.0.2.30/32",
                                        "192.0.2.10/32"}
    assert dom.ma_dek and dom.kek_id == Sejf(kek).kek_id
    # Na dysku tylko szyfrogramy.
    surowe = Path(dom1["inst"].panel_auth_path).read_bytes()
    for v in _wartosci_kanarkow(dom1["kanarki"]):
        assert v.encode() not in surowe

    _wyczysc_env()  # od teraz NIC nie moze przyjsc ze srodowiska
    home = zbuduj_dom(rejestr, DOM_1, Sejf(kek))
    assert konfiguracja_domu.porownaj(dom1["home"], home) == []
    k = dom1["kanarki"]
    assert home.source.nextdns.api_key() == k["nextdns.api_key"]
    assert home.notifiers.ntfy.topic == k["ntfy.topic"]
    assert home.notifiers.ntfy.token() == k["ntfy.token"]
    assert home.notifiers.homeassistant.webhook_id() == k["homeassistant.webhook_id"]
    assert home.tv.sony_psk() == k["tv.sony_psk"]
    assert home.unifi.api_key() == k["unifi.api_key"]
    assert home.mdm.token() == k["mdm.token"]
    # Pliki z sekretow: w katalogu domu w pamieci poda, 0600 / 0700.
    kat = tmp_path / "run" / "domy" / "1"
    assert Path(home.tv.adb_key_dir) == kat / "adb"
    assert (kat / "adb" / "adbkey").read_text().strip() == k["tv.adb_key"]
    assert (kat / "tv-app" / "token").read_text().strip() == k["tv.app_token"]
    for plik in ("adb/adbkey", "adb/adbkey.pub", "tv-app/token"):
        assert stat.S_IMODE((kat / plik).stat().st_mode) == 0o600
    assert stat.S_IMODE(kat.stat().st_mode) == 0o700
    _bez_kanarkow(repr(home.sekrety), k)
    assert home.straznik is not None
    # Wszystkie wpisy audytu bez wartosci.
    opisy = " ".join(r[0] for r in _sql(dom1["inst"].panel_auth_path, "SELECT opis FROM audyt"))
    _bez_kanarkow(opisy, k)


def test_import_wykrywa_roznice_i_nic_nie_zapisuje(dom1, kek, monkeypatch):
    path = dom1["inst"].panel_auth_path
    przed = _zrzut(path)
    prawdziwy = konfiguracja_domu.home_z_danych

    def zgubiony_telefon(dane, sekrety, **kw):
        dane.urzadzenia = [u for u in dane.urzadzenia if u["rodzaj"] != "phone-android"]
        return prawdziwy(dane, sekrety, **kw)

    monkeypatch.setattr(konfiguracja_domu, "home_z_danych", zgubiony_telefon)
    raport = _importuj(dom1, Sejf(kek))
    assert not raport.zapisano and any("devices" in r for r in raport.roznice)
    assert _zrzut(path) == przed
    assert dom1["rejestr"].dom(DOM_1).zrodlo_konfiguracji == "yaml"


def test_import_wykrywa_zgubiony_sekret(dom1, kek, monkeypatch):
    from kidwatch import sejf as sejf_mod  # noqa: PLC0415

    oryginal = sejf_mod.zaszyfruj_sekrety

    def gubi_psk(dek, dom_id, typ, sekrety):
        return oryginal(dek, dom_id, typ, {k: v for k, v in sekrety.items() if k != "sony_psk"})

    monkeypatch.setattr(sejf_mod, "zaszyfruj_sekrety", gubi_psk)
    raport = _importuj(dom1, Sejf(kek))
    assert not raport.zapisano
    assert "sekret tv.sony_psk: brak w bazie" in raport.roznice


def test_konfiguracja_z_bazy_nie_siega_do_srodowiska(dom1, kek, monkeypatch):
    _importuj(dom1, Sejf(kek))
    for env in ENV.values():
        monkeypatch.setenv(env, "INNA-WARTOSC-Z-ENV")
    home = zbuduj_dom(dom1["rejestr"], DOM_1, Sejf(kek))
    assert home.source.nextdns.api_key() == dom1["kanarki"]["nextdns.api_key"]
    assert home.notifiers.ntfy.topic == dom1["kanarki"]["ntfy.topic"]
    assert home.mdm.token() == dom1["kanarki"]["mdm.token"]


def test_dom_2_bez_sekretow_nie_dostaje_sekretow_domu_1(tmp_path, kek, monkeypatch):
    """Brak sekretu w domu z baza = blad tego domu, NIGDY wartosc z env
    (env to sekrety Domu 1)."""
    monkeypatch.setenv("NTFY_TOPIC", "TEMAT-DOMU-1-" + secrets.token_hex(6))
    monkeypatch.setenv("NEXTDNS_API_KEY", "KLUCZ-DOMU-1-" + secrets.token_hex(6))
    rejestr = RejestrDomow(tmp_path / "panel-auth.db")
    rejestr.migruj()
    dom2 = rejestr.dodaj_dom("Dom 2")
    sejf = Sejf(kek)
    _dziecko_z_urzadzeniem(rejestr, dom2, "phone-android")
    resolver = {"api.nextdns.io": [PUBLICZNY], "ntfy.sh": [PUBLICZNY]}.get
    rejestr.zapisz_integracje(dom2, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": "abc999"},
                              resolver=lambda h, p: resolver(h) or [])
    home = zbuduj_dom(rejestr, dom2, sejf, materializuj=False)
    with pytest.raises(MissingSecretError, match="Dom 2: brak sekretu nextdns.api_key") as exc:
        home.source.nextdns.api_key()
    assert "KLUCZ-DOMU-1" not in str(exc.value)
    rejestr.zapisz_integracje(dom2, "ntfy", sejf=sejf, wlaczona=True, ustawienia={},
                              resolver=lambda h, p: resolver(h) or [])
    with pytest.raises(ValueError, match="topic") as exc:
        zbuduj_dom(rejestr, dom2, sejf, materializuj=False)
    assert "TEMAT-DOMU-1" not in str(exc.value)
    # Domyslny katalog klucza ADB (/adb = Sekret Domu 1) nigdy dla innego domu.
    rejestr.zapisz_integracje(dom2, "ntfy", sejf=sejf, wlaczona=False)
    home = zbuduj_dom(rejestr, dom2, sejf, materializuj=False, katalog=tmp_path / "run")
    assert home.tv.adb_key_dir == str(tmp_path / "run" / "domy" / str(dom2) / "adb")


def _dziecko_z_urzadzeniem(rejestr: RejestrDomow, dom_id: int, rodzaj: str = "ipad",
                           **kolumny) -> None:
    with rejestr._conn() as conn, domy._transakcja(conn):
        cur = conn.execute("INSERT INTO dzieci (dom_id, nazwa) VALUES (?, 'Dziecko A')",
                           (dom_id,))
        nazwy = ", ".join(["dom_id", "dziecko_id", "rodzaj", "nazwa", "source_ids", *kolumny])
        conn.execute(f"INSERT INTO urzadzenia ({nazwy}) VALUES "
                     f"({', '.join('?' * (5 + len(kolumny)))})",
                     (dom_id, cur.lastrowid, rodzaj, "Urzadzenie A", '["urz-a"]',
                      *kolumny.values()))


# ================================================================ AAD
def test_aad_blob_innego_domu_i_typu_sie_nie_odszyfrowuje(dom1, kek):
    """§4.4 p. 6: szyfrogram Domu 1 wklejony do wiersza Domu 2 (albo innego
    typu) = blad, nie cicha podmiana klucza."""
    sejf = Sejf(kek)
    _importuj(dom1, sejf)
    rejestr: RejestrDomow = dom1["rejestr"]
    path = dom1["inst"].panel_auth_path
    dom2 = rejestr.dodaj_dom("Dom 2")
    rejestr.zapisz_integracje(dom2, "nextdns", sejf=sejf, wlaczona=False,
                              ustawienia={"profile_id": "abc999"},
                              sekrety={"api_key": "klucz-domu-2-" + secrets.token_hex(8)})
    assert rejestr.sprawdz(sejf) == []

    # 1. Blob nextdns Domu 1 w wierszu nextdns Domu 2.
    _sql(path, "UPDATE integracje SET sekrety = (SELECT sekrety FROM integracje WHERE dom_id = 1 "
               "AND typ = 'nextdns') WHERE dom_id = ? AND typ = 'nextdns'", (dom2,))
    with pytest.raises(SejfError, match="nextdns domu 2") as exc:
        rejestr.sekrety_domu(dom2, sejf)
    _bez_kanarkow(str(exc.value), dom1["kanarki"])
    assert [(d, t) for d, t, _ in rejestr.sprawdz(sejf)] == [(dom2, "nextdns")]

    # 2. Blob unifi Domu 1 w wierszu nextdns Domu 1 (zamiana typow).
    _sql(path, "UPDATE integracje SET sekrety = (SELECT sekrety FROM integracje WHERE dom_id = 1 "
               "AND typ = 'unifi') WHERE dom_id = 1 AND typ = 'nextdns'")
    with pytest.raises(SejfError, match="nextdns domu 1"):
        rejestr.sekrety_domu(DOM_1, sejf)

    # 3. DEK Domu 1 skopiowany do Domu 2.
    _sql(path, "UPDATE domy SET dek_zaszyfrowany = (SELECT dek_zaszyfrowany FROM domy "
               "WHERE id = 1) WHERE id = ?", (dom2,))
    with pytest.raises(SejfError, match="DEK domu 2"):
        rejestr.sekrety_domu(dom2, sejf)


# ============================================================= rotacja
def test_rotacja_kek_przepakowuje_tylko_dek(dom1, kek):
    stary = Sejf(kek)
    _importuj(dom1, stary)
    rejestr: RejestrDomow = dom1["rejestr"]
    path = dom1["inst"].panel_auth_path
    bloby = _sql(path, "SELECT typ, sekrety FROM integracje ORDER BY typ")
    nowy_klucz = secrets.token_bytes(32)
    sejf = Sejf.z_srodowiska({"KIDWATCH_KEK": base64.b64encode(nowy_klucz).decode(),
                              "KIDWATCH_KEK_POPRZEDNI": base64.b64encode(kek).decode()})
    assert rejestr.rotuj_kek(sejf) == [DOM_1]
    assert rejestr.rotuj_kek(sejf) == []  # idempotentna
    assert _sql(path, "SELECT typ, sekrety FROM integracje ORDER BY typ") == bloby
    assert rejestr.dom(DOM_1).kek_id == Sejf(nowy_klucz).kek_id
    # Po usunieciu KEK_POPRZEDNI: nowy klucz wystarcza, stary juz nie.
    assert rejestr.sprawdz(Sejf(nowy_klucz)) == []
    assert [t for _, t, _ in rejestr.sprawdz(stary)] == [None]
    assert rejestr.sekrety_domu(DOM_1, Sejf(nowy_klucz)).get("nextdns", "api_key") == \
        dom1["kanarki"]["nextdns.api_key"]


def test_rotacja_dek_domu(dom1, kek):
    sejf = Sejf(kek)
    _importuj(dom1, sejf)
    rejestr: RejestrDomow = dom1["rejestr"]
    path = dom1["inst"].panel_auth_path
    przed = dict(_sql(path, "SELECT typ, sekrety FROM integracje WHERE sekrety IS NOT NULL"))
    dek_przed = _sql(path, "SELECT dek_zaszyfrowany FROM domy WHERE id = 1")
    wersja = rejestr.dom(DOM_1).wersja
    typy = rejestr.rotuj_dek(DOM_1, sejf, kto="test")
    assert set(typy) == set(przed)
    po = dict(_sql(path, "SELECT typ, sekrety FROM integracje WHERE sekrety IS NOT NULL"))
    assert all(po[t] != przed[t] for t in przed)
    assert _sql(path, "SELECT dek_zaszyfrowany FROM domy WHERE id = 1") != dek_przed
    assert rejestr.dom(DOM_1).wersja == wersja + 1
    assert rejestr.sekrety_domu(DOM_1, sejf).get("tv", "app_token") == \
        dom1["kanarki"]["tv.app_token"]


# ===================================================== zapis z panelu (SSRF)
def _dom2(tmp_path, kek):
    rejestr = RejestrDomow(tmp_path / "panel-auth.db")
    rejestr.migruj()
    return rejestr, rejestr.dodaj_dom("Dom 2"), Sejf(kek)


def test_zapis_integracji_sprawdza_adresy_przy_zapisie(tmp_path, kek):
    """§4.4 p. 7: adres spoza dozwolone_sieci domu = odmowa przy zapisie."""
    rejestr, dom2, sejf = _dom2(tmp_path, kek)
    dns = {"udm.example.invalid": ["192.0.2.1"], "ha.example.invalid": ["10.0.0.5"],
           "api.nextdns.io": [PUBLICZNY], "obce.example.invalid": [PUBLICZNY]}

    def resolver(host, port):
        if host not in dns:
            raise OSError("NXDOMAIN")
        return dns[host]

    def zapisz(typ, ustawienia, **kw):
        kw.setdefault("wlaczona", True)
        return rejestr.zapisz_integracje(dom2, typ, sejf=sejf, ustawienia=ustawienia,
                                         resolver=resolver, **kw)

    unifi = {"url": "https://192.0.2.1", "cert_sha256": ODCISK}
    for typ, ustawienia, blad in [
        ("unifi", unifi, "poza siecią"),
        ("unifi", {**unifi, "url": "https://udm.example.invalid"}, "poza siecią"),
        ("unifi", {"url": "https://192.0.2.1"}, "cert_sha256"),
        ("unifi", {**unifi, "url": "http://192.0.2.1"}, "schematy"),
        ("tv", {"host": "192.0.2.20"}, "poza siecią"),
        ("tv", {"host": "fe80::1"}, "poza siecią"),
        ("homeassistant", {"base_url": "http://ha.example.invalid:8123"}, "poza siecią"),
        ("homeassistant", {"base_url": "http://169.254.169.254"}, "poza siecią"),
        ("homeassistant", {"base_url": "http://kidwatch-mdm-admin:8081"}, "nie rozwiązuje"),
        ("adguard", {"base_url": "http://[::ffff:10.0.0.1]", "username": "u"}, "poza siecią"),
        ("nextdns", {"profile_id": "abc", "base_url": "https://obce.example.invalid"},
         "spoza listy"),
        ("ntfy", {"server": "http://ntfy.sh"}, "schematy"),
        ("ntfy", {"topic": "jawny"}, "sekrety"),
        ("nextdns", {"profile_id": "abc", "api_key": "x"}, "sekrety"),
    ]:
        with pytest.raises(ValueError, match=blad):
            zapisz(typ, ustawienia)
    assert rejestr.integracje(dom2) == []
    # Wylaczona integracja z adresem z LAN mozna zapisac, wlaczyc juz nie.
    zapisz("unifi", unifi, wlaczona=False)
    with pytest.raises(ValueError, match="poza siecią"):
        rejestr.zapisz_integracje(dom2, "unifi", sejf=sejf, wlaczona=True, resolver=resolver)
    # Administrator instancji dopisuje siec (CLI dom-sieci) — teraz wolno.
    rejestr.ustaw_sieci(dom2, sieci=["192.0.2.1/32"])
    integracja = zapisz("unifi", {**unifi, "url": "https://udm.example.invalid"},
                        sekrety={"api_key": "klucz-" + secrets.token_hex(8)})
    assert integracja.wlaczona and integracja.sekrety_pola == ("api_key",)
    assert "api_key" not in json.dumps(integracja.ustawienia)


def test_polaczenie_sprawdzane_takze_po_zapisie(tmp_path, kek):
    """DNS rebinding: nazwa przy zapisie publiczna, przy polaczeniu z LAN."""
    rejestr, dom2, sejf = _dom2(tmp_path, kek)
    odpowiedzi = {"udm.example.invalid": [PUBLICZNY]}
    resolver = lambda host, port: odpowiedzi[host]  # noqa: E731
    rejestr.zapisz_integracje(dom2, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": "abc999"},
                              sekrety={"api_key": "k-" + secrets.token_hex(8)},
                              resolver=lambda h, p: [PUBLICZNY])
    rejestr.zapisz_integracje(dom2, "unifi", sejf=sejf, wlaczona=True,
                              ustawienia={"url": "https://udm.example.invalid",
                                          "cert_sha256": ODCISK},
                              sekrety={"api_key": "k-" + secrets.token_hex(8)},
                              resolver=resolver)
    _dziecko_z_urzadzeniem(rejestr, dom2, unifi_mac="02:00:00:00:00:0a")
    odpowiedzi["udm.example.invalid"] = ["10.0.0.1"]
    home = zbuduj_dom(rejestr, dom2, sejf, resolver=resolver, materializuj=False)
    watcher = cli.build_unifi_watcher(home, Store(":memory:"))
    from kidwatch.sources.unifi import UnifiError  # noqa: PLC0415

    with pytest.raises(UnifiError, match="OdmowaSieci"):
        asyncio.run(watcher.client.stations())


def test_dom_sieci_tylko_scisle_cidr(tmp_path, kek, capsys):
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    assert cli.main(["--config", str(cfg_path), "dom-sieci", "1", "--dodaj", "192.0.2.0/24",
                     "--host", "API.example.invalid"]) == 0
    assert cli.main(["--config", str(cfg_path), "dom-sieci", "1", "--dodaj",
                     "192.0.2.5/24"]) == 2
    dom = RejestrDomow(tmp_path / "panel-auth.db").dom(DOM_1)
    assert dom.dozwolone_sieci == ("192.0.2.0/24",)
    assert dom.dozwolone_hosty == ("api.example.invalid",)
    assert cli.main(["--config", str(cfg_path), "dom-sieci", "1", "--usun", "192.0.2.0/24",
                     "--bez-hosta", "api.example.invalid"]) == 0
    dom = RejestrDomow(tmp_path / "panel-auth.db").dom(DOM_1)
    assert dom.dozwolone_sieci == () and dom.dozwolone_hosty == ()
    akcje = _sql(tmp_path / "panel-auth.db", "SELECT akcja FROM audyt WHERE akcja = 'dom.sieci'")
    assert len(akcje) == 2


# ================================================= srodowisko domu z bazy
def test_srodowisko_domu_z_bazy_laczy_sie_przez_straznika(dom1, kek, tmp_path):
    """Kazda droga do adresu wpisanego recznie idzie przez straznika domu
    (UniFi, ADB, Sony, aplikacja TV, HA, ntfy, NextDNS, czas gry), a Dom 1
    z config.yaml — jak przed domami (bez straznika)."""
    _importuj(dom1, Sejf(kek))
    home = zbuduj_dom(dom1["rejestr"], DOM_1, Sejf(kek))

    def zbadaj(home: HomeConfig):
        rt = cli.build_home_runtime(DOM_1, dom1["inst"], home, Classifier(str(APP_MAP)))
        [hybryda] = [f.__self__ for f in rt.sprzatanie
                     if type(getattr(f, "__self__", None)).__name__ == "HybridProbe"]
        transporty = {
            "nextdns": [s._client._transport for s in rt.source.sources],
            "ntfy": [n._client._transport for n in rt.outbox.notifiers if n.name == "ntfy"],
            "ha": [n._client._transport for n in rt.outbox.notifiers
                   if n.name == "homeassistant"],
        }
        transporty["sony"] = [hybryda.sony.http._transport]
        transporty["tv-app"] = [hybryda.aplikacja.http._transport]
        straznicy = {"adb": hybryda.adb.shell.straznik,
                     "unifi-tv": hybryda.licznik.client.straznik}
        return rt, transporty, straznicy, hybryda

    rt, transporty, straznicy, hybryda = zbadaj(home)
    for nazwa, lista in transporty.items():
        assert lista and all(isinstance(t, StraznikTransport) for t in lista), nazwa
        assert all(t.straznik is home.straznik for t in lista), nazwa
    assert all(s is home.straznik for s in straznicy.values())
    assert hybryda.aplikacja.po_sparowaniu is not None
    assert hybryda.aplikacja.katalog == tmp_path / "run" / "domy" / "1" / "tv-app"
    asyncio.run(_zamknij(rt))

    # Tryb yaml: nic z tego (zero zmian zachowania).
    rt, transporty, straznicy, hybryda = zbadaj(dom1["home"])
    for nazwa, lista in transporty.items():
        assert not any(isinstance(t, StraznikTransport) for t in lista), nazwa
    assert all(s is None for s in straznicy.values())
    assert hybryda.aplikacja.po_sparowaniu is None
    assert hybryda.aplikacja.katalog == tmp_path / "tv-app"
    asyncio.run(_zamknij(rt))


async def _zamknij(rt):
    for fn in rt.sprzatanie:
        await fn()
    await rt.outbox.aclose()
    await rt.source.aclose()
    rt.store.close()


def test_parowanie_tv_zapisuje_token_w_bazie(dom1, kek):
    _importuj(dom1, Sejf(kek))
    home = zbuduj_dom(dom1["rejestr"], DOM_1, Sejf(kek))
    nowy = "NOWY-TOKEN-" + secrets.token_hex(8)
    home.sekrety.zapisz("tv", "app_token", nowy)
    assert dom1["rejestr"].sekrety_domu(DOM_1, Sejf(kek)).get("tv", "app_token") == nowy
    # Pozostale sekrety integracji tv nietkniete.
    assert dom1["rejestr"].sekrety_domu(DOM_1, Sejf(kek)).get("tv", "sony_psk") == \
        dom1["kanarki"]["tv.sony_psk"]


def test_odczyt_ipada_w_domu_z_baza_tylko_po_sprawdzonym_ip(dom1, kek, monkeypatch, caplog):
    _importuj(dom1, Sejf(kek))
    home = zbuduj_dom(dom1["rejestr"], DOM_1, Sejf(kek))
    from kidwatch.sources import device as device_mod  # noqa: PLC0415

    proby = []

    def over_tcp(target, records, timeout):
        proby.append(target.host)
        raise device_mod.DeviceUnavailable("atrapa")

    monkeypatch.setattr(device_mod.DeviceProbe, "over_tcp", staticmethod(over_tcp))
    cli.build_watchers(home, Store(":memory:"), Path("/rekordy"))
    assert proby == ["192.0.2.10"]  # w dozwolone_sieci z importu
    dom1["rejestr"].ustaw_sieci(DOM_1, sieci=[])
    home = zbuduj_dom(dom1["rejestr"], DOM_1, Sejf(kek))
    cli.build_watchers(home, Store(":memory:"), Path("/rekordy"))
    assert proby == ["192.0.2.10"]
    assert "poza siecią domu" in caplog.text


# ===================================================================== run
def _prosta(tmp_path: Path) -> dict:
    data = yaml.safe_load((FIXTURES / "config.yaml").read_text(encoding="utf-8"))
    data["store"]["path"] = str(tmp_path / "kidwatch.db")
    data["app_map_path"] = str(APP_MAP)
    return data


class Puste:
    name = "atrapa"

    async def events(self):
        return
        yield  # pragma: no cover

    async def aclose(self):
        pass


@pytest.mark.parametrize("kek_env", [None, "", "zly-klucz-nie-base64"])
def test_brak_kek_nie_blokuje_domu_1_z_yaml(tmp_path, monkeypatch, kek_env):
    monkeypatch.setattr(cli, "build_source", lambda cfg, store: Puste())
    monkeypatch.setenv("KIDWATCH_HEARTBEAT", str(tmp_path / "hb"))
    if kek_env is None:
        monkeypatch.delenv("KIDWATCH_KEK", raising=False)
    else:
        monkeypatch.setenv("KIDWATCH_KEK", kek_env)
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    # Koniec atrapy zrodla = koniec zadania = kod 1 (jak w E1): proces ruszyl.
    assert cli.main(["--config", str(cfg_path), "run"]) == 1


def test_run_dom_1_z_bazy_i_bez_kek(tmp_path, monkeypatch, kek, caplog, capsys):
    kanarek = "KANAREK-NEXTDNS-" + secrets.token_hex(10)
    monkeypatch.setenv("NEXTDNS_API_KEY", kanarek)
    monkeypatch.setenv("KIDWATCH_HEARTBEAT", str(tmp_path / "hb"))
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    assert cli.main(["--config", str(cfg_path), "dom-importuj", "1", "--zapisz"]) == 0
    monkeypatch.delenv("NEXTDNS_API_KEY")
    widziane = {}

    def zrodlo(cfg, store):
        widziane["klucz"] = cfg.source.nextdns.api_key()
        widziane["straznik"] = cfg.straznik
        return Puste()

    monkeypatch.setattr(cli, "build_source", zrodlo)
    caplog.set_level(logging.DEBUG)
    assert cli.main(["--config", str(cfg_path), "run"]) == 1
    assert widziane["klucz"] == kanarek and widziane["straznik"] is not None
    assert "Dom 1: konfiguracja z bazy" in caplog.text

    # Bez KEK dom w trybie `baza` nie startuje — kod 2, czytelny blad.
    monkeypatch.delenv("KIDWATCH_KEK")
    widziane.clear()
    assert cli.main(["--config", str(cfg_path), "run"]) == 2
    assert widziane == {}
    assert "brak KIDWATCH_KEK" in caplog.text and "dom-zrodlo 1 yaml" in caplog.text
    _bez_kanarkow(caplog.text + capsys.readouterr().out, {"k": kanarek})

    # Powrot do config.yaml bez KEK: dziala jak przed E2.
    assert cli.main(["--config", str(cfg_path), "dom-zrodlo", "1", "yaml"]) == 0
    monkeypatch.setenv("NEXTDNS_API_KEY", kanarek)
    assert cli.main(["--config", str(cfg_path), "run"]) == 1
    assert widziane["straznik"] is None


async def test_dzien_przez_dom_1_z_bazy_daje_te_same_powiadomienia(tmp_path, monkeypatch, kek):
    """§6 p. 8 dla E2: replay dnia przez HomeRuntime(Dom 1) z konfiguracja
    z BAZY daje ten sam wynik (day.expected.txt) co sciezka z config.yaml."""
    from test_domy import Kolektor, ZrodloZPliku  # noqa: PLC0415

    monkeypatch.setenv("NEXTDNS_API_KEY", "k-" + secrets.token_hex(8))
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    cfg = Config.load(cfg_path)
    inst, home_yaml = cfg.split()
    rejestr = RejestrDomow(inst.panel_auth_path)
    rejestr.migruj(strefa=home_yaml.timezone)
    raport = importuj(rejestr, DOM_1, home_yaml, sekrety_z_yaml(home_yaml, tmp_path),
                      sejf=Sejf(kek), zapisz=True)
    assert raport.zapisano
    monkeypatch.delenv("NEXTDNS_API_KEY")
    home = zbuduj_dom(rejestr, DOM_1, Sejf(kek))

    kolektor, zrodlo = Kolektor(), ZrodloZPliku(DAY)
    monkeypatch.setattr(cli, "build_source", lambda cfg, store: zrodlo)
    monkeypatch.setattr(cli, "build_notifiers", lambda cfg, bramka: [kolektor])
    rt = cli.build_home_runtime(DOM_1, inst, home, Classifier(inst.app_map_path))
    await source_loop(rt.source, rt.engine, rt.outbox, rt.store)
    last = datetime.fromisoformat(zrodlo.rows[-1]["ts"].replace("Z", "+00:00"))
    await rt.outbox.send_all(rt.engine.tick(last + timedelta(minutes=home.engine.idle_minutes
                                                             + 1)))
    while await rt.outbox.flush():
        pass
    wydruk = "".join(cli.render(n) + "\n" for n in kolektor.notes)
    snapshot = SNAPSHOT.read_text(encoding="utf-8")
    assert kolektor.notes and snapshot.startswith(wydruk)
    assert snapshot[len(wydruk):].startswith(
        f"\n--- {len(zrodlo.rows)} zdarzen -> {len(kolektor.notes)} powiadomien ---")
    await rt.outbox.aclose()
    rt.store.close()


# ================================================================= kanarek
def test_sekrety_kanarki_nie_trafiaja_do_logow_ani_wyjscia(dom1, kek, tmp_path, monkeypatch,
                                                           caplog, capsys):
    """Sekret-kanarek (§4.4 p. 6) szukany w CALYM wyjsciu CLI, logach
    i komunikatach bledow: import, sprawdzenie, rotacje, przelaczenia,
    odmowa straznika na polaczeniu z webhookiem HA w adresie."""
    caplog.set_level(logging.DEBUG)
    k = dom1["kanarki"]
    cfg = ["--config", str(dom1["cfg_path"])]
    assert cli.main([*cfg, "dom-importuj", "1", "--podglad"]) == 0
    assert cli.main([*cfg, "dom-importuj", "1", "--zapisz"]) == 0
    assert cli.main([*cfg, "domy", "--sprawdz"]) == 0
    assert cli.main([*cfg, "dom-zrodlo", "1", "baza"]) == 0
    assert cli.main([*cfg, "dom-klucz-rotuj", "1"]) == 0
    monkeypatch.setenv("KIDWATCH_KEK_POPRZEDNI", os.environ["KIDWATCH_KEK"])
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(secrets.token_bytes(32)).decode())
    assert cli.main([*cfg, "klucze-rotuj"]) == 0
    monkeypatch.delenv("KIDWATCH_KEK_POPRZEDNI")
    assert cli.main([*cfg, "domy", "--sprawdz"]) == 0
    assert cli.main([*cfg, "dom-sieci", "1", "--wyczysc"]) == 0
    # Zly klucz: lista bledow bez wartosci; zly format klucza: SEJF bez wartosci.
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(secrets.token_bytes(32)).decode())
    assert cli.main([*cfg, "domy", "--sprawdz"]) == 1
    monkeypatch.setenv("KIDWATCH_KEK", "zly")
    assert cli.main([*cfg, "domy", "--sprawdz"]) == 2
    assert cli.main([*cfg, "run"]) == 2
    out = capsys.readouterr()
    assert "SEJF" in out.err and "BLAD: Dom 1 DEK" in out.out

    wyjscie = out.out + out.err + caplog.text
    _bez_kanarkow(wyjscie, k)
    assert "…" in out.out or "znakow" in out.out  # maski w podgladzie


async def test_odmowa_straznika_w_logu_bez_sekretu(dom1, kek, caplog):
    caplog.set_level(logging.DEBUG)
    _importuj(dom1, Sejf(kek))
    dom1["rejestr"].ustaw_sieci(DOM_1, sieci=[])  # HA 192.0.2.30 juz niedozwolony
    home = zbuduj_dom(dom1["rejestr"], DOM_1, Sejf(kek))
    ha = home.notifiers.homeassistant

    async def bez_czekania(_):
        return None

    notifier = HomeAssistantNotifier(ha, webhook_id=ha.webhook_id(),
                                     transport=home.straznik.transport(), sleep=bez_czekania)
    note = Notification(kind=NotifyKind.APP, title="t", text="x", dedup_key="k",
                        ts=datetime(2026, 10, 1, tzinfo=UTC))
    assert await notifier.send(note) is False
    await notifier.aclose()
    assert "poza siecią domu" in caplog.text
    _bez_kanarkow(caplog.text, dom1["kanarki"])


# ============================================================ drobne
def test_sekrety_domu_repr_bez_wartosci():
    kanarek = "KANAREK-" + secrets.token_hex(8)
    s = SekretyDomu(3, {"nextdns": {"api_key": kanarek}})
    assert kanarek not in repr(s) and kanarek not in str(s) and "api_key" in repr(s)
    with pytest.raises(RuntimeError):
        s.zapisz("nextdns", "api_key", "x")


def test_bramka_nextdns_wspolna_dla_klucza():
    a = ConnectGate.dla_klucza("klucz-a-" + secrets.token_hex(4), 5.0)
    b = ConnectGate.dla_klucza("klucz-b-" + secrets.token_hex(4), 5.0)
    assert a is not b
    klucz = "klucz-c-" + secrets.token_hex(4)
    c1, c2 = ConnectGate.dla_klucza(klucz, 5.0), ConnectGate.dla_klucza(klucz, 8.0)
    assert c1 is c2 and c1.spacing == 8.0


def test_migracja_bazy_z_e1_dodaje_kolumne_hostow(tmp_path):
    path = tmp_path / "panel-auth.db"
    schemat_e1 = "\n".join(line for line in domy.SCHEMAT.splitlines()
                           if "dozwolone_hosty" not in line and "Hosty API" not in line
                           and "Jak dozwolone_sieci" not in line)
    conn = sqlite3.connect(path)
    conn.executescript(schemat_e1)
    conn.close()
    raport = RejestrDomow(path).migruj()
    assert "domy.dozwolone_hosty" in raport.kolumny
    assert not RejestrDomow(path).migruj().zmiany
    assert RejestrDomow(path).dom(DOM_1).dozwolone_hosty == ()


def test_dom_zrodlo_cli(tmp_path, kek, capsys):
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    assert cli.main(["--config", str(cfg_path), "dom-zrodlo", "1", "baza"]) == 2  # bez importu
    rejestr = RejestrDomow(tmp_path / "panel-auth.db")
    assert rejestr.dom(DOM_1).zrodlo_konfiguracji == "yaml"
    dom2 = rejestr.dodaj_dom("Dom 2")
    assert cli.main(["--config", str(cfg_path), "dom-zrodlo", str(dom2), "yaml"]) == 2
    assert cli.main(["--config", str(cfg_path), "dom-importuj", "2", "--podglad"]) == 2


def test_odtworzenie_z_kopii_i_kek(dom1, kek, tmp_path, monkeypatch, capsys):
    """§3.3: kopia panel-auth.db + KEK -> `domy --baza <kopia> --sprawdz`
    odszyfrowuje wszystko, bez config.yaml; bez KEK albo z innym — nie."""
    import shutil  # noqa: PLC0415

    _importuj(dom1, Sejf(kek))
    kopia = tmp_path / "kopia" / "panel-auth.db"
    kopia.parent.mkdir()
    shutil.copy(dom1["inst"].panel_auth_path, kopia)
    argv = ["--config", str(tmp_path / "nie-ma.yaml"), "domy", "--baza", str(kopia), "--sprawdz"]
    assert cli.main(argv) == 0
    assert "wszystko sie odszyfrowuje" in capsys.readouterr().out
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(secrets.token_bytes(32)).decode())
    assert cli.main(argv) == 1
    monkeypatch.delenv("KIDWATCH_KEK")
    assert cli.main(argv) == 2
    _bez_kanarkow(capsys.readouterr().out, dom1["kanarki"])


# ============================================================ wycofanie
def _kod_starego_obrazu(tmp_path: Path) -> Path:
    """`git archive` z commitu obrazu sprzed E2 — PRAWDZIWY stary kod, nie
    przepisany SQL. W CI (fetch-depth: 0) commit musi byc dostepny."""
    jest = subprocess.run(["git", "cat-file", "-e", f"{STARY_OBRAZ}^{{commit}}"], cwd=ROOT,
                          capture_output=True)
    if jest.returncode != 0:
        if os.environ.get("CI"):
            pytest.fail(f"brak commitu {STARY_OBRAZ} — checkout w CI musi miec fetch-depth: 0")
        pytest.skip(f"brak commitu {STARY_OBRAZ} w lokalnym repo")
    archiwum = subprocess.run(["git", "archive", "--format=tar", STARY_OBRAZ, "src"], cwd=ROOT,
                              capture_output=True, check=True).stdout
    cel = tmp_path / "stary"
    with tarfile.open(fileobj=BytesIO(archiwum)) as tar:
        tar.extractall(cel, filter="data")
    return cel / "src"


STARY_SKRYPT = r"""
import json, sqlite3, sys
import kidwatch, kidwatch.domy as d
from kidwatch.panel_auth import PanelAuth
from kidwatch.tvpause import TvPauseRequests
from kidwatch.gametime import GameRequests
assert kidwatch.__file__.startswith(sys.argv[2]), kidwatch.__file__
assert not hasattr(d, "SekretyDomu")  # na pewno kod sprzed E2
path = sys.argv[1]
r = d.RejestrDomow(path)
raport = r.migruj(strefa="Europe/Warsaw")
auth = PanelAuth(path)
auth.add_user("konto-stare", "haslo-testowe-123", "podglad")
auth.set_role("konto-stare", "wlasciciel")
TvPauseRequests(path).submit("pause", None, "konto-stare")
GameRequests(path).submit("Dziecko 1", "allow", None, "konto-stare")
dom = r.dom(1)
print(json.dumps({
    "zmiany": raport.zmiany,
    "dom": [dom.id, dom.nazwa, dom.zrodlo_konfiguracji, dom.wersja],
    "czlonkowie": sorted(c.login for c in r.czlonkowie(1)),
    "integralnosc": sqlite3.connect(path).execute("PRAGMA integrity_check").fetchone()[0],
    "fk": sqlite3.connect(path).execute("PRAGMA foreign_key_check").fetchall(),
}))
"""


def test_stary_obraz_dziala_na_bazie_po_e2_a_nowy_dalej_odszyfrowuje(dom1, kek, tmp_path):
    """Wycofanie obrazu (§6 p. 7): kod sha-2723214 na bazie po imporcie E2
    (integracje, DEK, nowa kolumna, Dom 1 w trybie `baza`) — migracja,
    konta, kolejki i `domy` dzialaja; potem nowy obraz odszyfrowuje wszystko.
    Stary obraz zignoruje `zrodlo_konfiguracji` i wroci do config.yaml —
    to jest wlasnie plan cofniecia."""
    sejf = Sejf(kek)
    _importuj(dom1, sejf)
    stary_src = _kod_starego_obrazu(tmp_path)
    path = dom1["inst"].panel_auth_path
    env = {**os.environ, "PYTHONPATH": str(stary_src), "PYTHONDONTWRITEBYTECODE": "1"}
    wynik = subprocess.run([sys.executable, "-c", STARY_SKRYPT, path, str(stary_src)],
                           env=env, capture_output=True, text=True, timeout=120)
    assert wynik.returncode == 0, wynik.stderr
    stan = json.loads(wynik.stdout.strip().splitlines()[-1])
    assert stan["dom"][:3] == [1, "Dom 1", "baza"]
    assert stan["czlonkowie"] == ["konto-a", "konto-stare"]
    assert stan["integralnosc"] == "ok" and stan["fk"] == []
    # Stary CLI `domy` na tej bazie.
    stary_cli = subprocess.run([sys.executable, "-m", "kidwatch", "--config",
                                str(dom1["cfg_path"]), "domy"], env=env, capture_output=True,
                               text=True, timeout=120)
    assert stary_cli.returncode == 0, stary_cli.stderr
    assert "1. Dom 1" in stary_cli.stdout
    _bez_kanarkow(stary_cli.stdout + stary_cli.stderr, dom1["kanarki"])
    # Powrot nowego obrazu: migracja bez zmian schematu, sekrety caly czas te same.
    raport = RejestrDomow(path).migruj()
    assert not raport.kolumny
    assert RejestrDomow(path).sprawdz(sejf) == []
    assert {c.login for c in RejestrDomow(path).czlonkowie(DOM_1)} == {"konto-a", "konto-stare"}
    home = zbuduj_dom(RejestrDomow(path), DOM_1, sejf, materializuj=False)
    assert konfiguracja_domu.porownaj(dom1["home"], home) == []


def test_odmowa_sieci_to_oserror():
    """Petle traktuja OSError jak „nie odpowiada” — odmowa nie zabija petli."""
    assert issubclass(OdmowaSieci, OSError)
