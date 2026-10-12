"""Etap E1 domow (docs/architektura-domy.md): model, migracja do Domu 1,
podzial konfiguracji, srodowisko domu — bez zmiany zachowania.

Dane wylacznie generyczne: publiczne repo (tests/test_repo_prywatnosc.py).
"""

from __future__ import annotations

import asyncio
import dataclasses
import inspect
import json
import os
import sqlite3
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

import kidwatch.__main__ as cli
from kidwatch import domy, uprawnienia
from kidwatch.classifier import Classifier
from kidwatch.config import Config, DeviceConfig, HomeConfig, InstanceConfig
from kidwatch.devicekind import KINDS, kind_of
from kidwatch.domy import (
    DOM_1,
    HomeRuntime,
    Nadzorca,
    RejestrDomow,
    katalog_domu,
    sciezka_bazy_domu,
)
from kidwatch.gametime import GameRequests
from kidwatch.models import DnsEvent, Notification, NotifyKind
from kidwatch.notifiers.base import Dispatcher, Outbox
from kidwatch.panel_auth import PanelAuth
from kidwatch.scheduler import source_loop
from kidwatch.store import Store, note_to_json
from kidwatch.tvpause import TvPauseRequests

FIXTURES = Path(__file__).parent / "fixtures"
PRZED_DOMAMI = FIXTURES / "panel_auth_przed_domami.sql"
DAY = FIXTURES / "day.jsonl"
SNAPSHOT = FIXTURES / "day.expected.txt"
APP_MAP = Path(__file__).parent.parent / "app_map.yaml"

# Haslo spelniajace polityke, generyczne (PanelAuth wymaga 12 znakow).
HASLO = "haslo-testowe-123"

PELNA_KONFIGURACJA = {
    "timezone": "Europe/Warsaw",
    "app_map_path": str(APP_MAP),
    "source": {"kind": "nextdns", "nextdns": {"profile_id": "abc123"}},
    "devices": [
        {"display_name": "iPad Dziecka 1", "child": "Dziecko 1", "source_ids": ["iPad-1"],
         "udid": "00000000-0000000000000001", "host": "192.0.2.10",
         "unifi_mac": "02:00:00:00:00:01", "nextdns_profile": "def456"},
        {"display_name": "Telefon Dziecka 2", "child": "Dziecko 2", "source_ids": ["Tel-2"],
         "kind": "phone-android"},
    ],
    "engine": {"idle_minutes": 7, "quiet_hours": {"start": "21:00", "end": "07:00"}},
    "watchdog": {"device_silence_minutes": 99},
    "notifiers": {
        "ntfy": {"enabled": True, "topic": "temat-testowy"},
        "homeassistant": {"enabled": True, "base_url": "http://ha.example.invalid"},
        "bramka": {"enabled": True, "url": "http://bramka.example.invalid", "per_konto": True},
    },
    "device_read": {"enabled": True, "pair_record_dir": "/rekordy", "poll_seconds": 45},
    "store": {"path": "/dane/kidwatch.db", "retention_days": 14,
              "notifications_retention_days": 100, "rollup_retention_days": 7},
    "panel": {"enabled": True, "host": "0.0.0.0", "port": 8080},
    "tv": {"enabled": True, "name": "TV wspolny", "host": "192.0.2.20"},
    "unifi": {"enabled": True, "url": "https://192.0.2.1", "window_minutes": 20},
    "game_time": {"enabled": True, "services": ["youtube"], "categories": ["gaming"]},
    "mdm": {"enabled": True, "url": "http://mdm.example.invalid:8081", "silent_alert_hours": 12},
}


def _config(tmp_path, data=None) -> Config:
    p = tmp_path / "config.yaml"
    p.write_text(yaml.safe_dump(data or PELNA_KONFIGURACJA, allow_unicode=True),
                 encoding="utf-8")
    return Config.load(p)


def _baza_przed_domami(tmp_path) -> Path:
    path = tmp_path / "panel-auth.db"
    conn = sqlite3.connect(path)
    conn.executescript(PRZED_DOMAMI.read_text(encoding="utf-8"))
    conn.close()
    return path


def _zrzut(path: Path) -> list[str]:
    conn = sqlite3.connect(path)
    try:
        return list(conn.iterdump())
    finally:
        conn.close()


def _sql(path: Path, sql: str, args: tuple = ()) -> list[tuple]:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


# ============================================================ konfiguracja
def test_home_config_z_yaml_to_dzisiejszy_config_pole_w_pole(tmp_path):
    cfg = _config(tmp_path)
    inst, home = cfg.split()

    assert isinstance(cfg, HomeConfig)
    assert type(home) is HomeConfig and isinstance(inst, InstanceConfig)
    # Kazde pole domu ma te sama wartosc co w Config (bez podpol instancji).
    assert home.model_dump() == cfg.model_dump(
        include=set(HomeConfig.model_fields), exclude=domy_instancji()
    )
    assert set(HomeConfig.model_fields) | {"panel", "app_map_path"} == set(Config.model_fields)
    # Czesc instancji: dokladnie to, co w Config.
    assert inst.store == cfg.store and inst.panel == cfg.panel
    assert inst.notifiers.bramka == cfg.notifiers.bramka
    assert inst.mdm.url == cfg.mdm.url
    assert inst.device_read.records_path == cfg.device_read.records_path
    assert inst.app_map_path == cfg.app_map_path
    assert inst.panel_auth_path == cfg.panel_auth_path
    # Pola instancji nie przeciekaja do domu.
    for obj, pole in ((home, "panel"), (home, "app_map_path"), (home.store, "path"),
                      (home.notifiers, "bramka"), (home.mdm, "url"),
                      (home.device_read, "pair_record_dir")):
        assert not hasattr(obj, pole), pole
    # Wyprowadzenia uzywane przez silnik i petle.
    assert home.watched == cfg.watched
    assert home.nextdns_profiles == cfg.nextdns_profiles
    assert home.child_profiles() == cfg.child_profiles()
    assert home.tz == cfg.tz
    assert home.device_for("ipad-1") == cfg.device_for("ipad-1")
    assert home.mdm.token() == cfg.mdm.token()


def domy_instancji() -> dict:
    from kidwatch.config import _TYLKO_INSTANCJA  # noqa: PLC0415

    return _TYLKO_INSTANCJA


def test_split_nie_wspoldzieli_obiektow(tmp_path):
    cfg = _config(tmp_path)
    inst, home = cfg.split()
    inst.store.retention_days = 1
    home.engine.idle_minutes = 1
    assert cfg.store.retention_days == 14
    assert cfg.engine.idle_minutes == 7


def test_walidatory_dzialaja_per_dom(tmp_path):
    """HomeConfig odrzuca to samo, co odrzucal Config — tym samym tekstem."""
    data = json.loads(json.dumps(PELNA_KONFIGURACJA))
    data["devices"][1]["source_ids"] = ["iPad-1"]
    with pytest.raises(ValidationError, match="przypisany do dwoch urzadzen") as stary:
        Config.model_validate(data)
    dom = {k: v for k, v in data.items() if k in HomeConfig.model_fields}
    dom["store"] = {"retention_days": 14}
    dom["notifiers"] = {"ntfy": data["notifiers"]["ntfy"]}
    dom["device_read"] = {"enabled": True}
    dom["mdm"] = {"enabled": True}
    with pytest.raises(ValidationError, match="przypisany do dwoch urzadzen") as nowy:
        HomeConfig.model_validate(dom)
    assert stary.value.errors()[0]["msg"] == nowy.value.errors()[0]["msg"]


def test_phone_android_to_alias_phone():
    dev = DeviceConfig(display_name="Telefon", child="Dziecko 1", source_ids=["t"],
                       kind="phone-android")
    assert dev.kind == "phone"
    assert kind_of("phone-android") is KINDS["phone"]
    with pytest.raises(ValidationError, match="kind=phone nie ma odczytu wprost"):
        DeviceConfig(display_name="Telefon", child="Dziecko 1", source_ids=["t"],
                     kind="phone-android", udid="u", host="192.0.2.5")


def test_sciezki_domow():
    assert sciezka_bazy_domu(DOM_1, "/data/kidwatch.db") == Path("/data/kidwatch.db")
    assert sciezka_bazy_domu(2, "/data/kidwatch.db") == Path("/data/domy/2/kidwatch.db")
    assert katalog_domu(DOM_1, "/data/kidwatch.db") == Path("/data")
    assert katalog_domu(2, "/data/kidwatch.db") == Path("/data/domy/2")


# ================================================================ migracja
def test_migracja_zaklada_dom_1_z_czlonkami(tmp_path):
    path = _baza_przed_domami(tmp_path)
    przed = {t: _sql(path, f"SELECT * FROM {t} ORDER BY 1") for t in
             ("users", "user_uprawnienia", "sessions", "user_powiadomienia",
              "powiadomienia_ustawienia")}

    raport = RejestrDomow(path).migruj(strefa="Europe/Warsaw")

    assert raport.dom_1_zalozony
    assert raport.uzgodnione == ("konto-a", "konto-b", "konto-c")
    assert raport.kolumny == ("users.admin_instancji",)
    rejestr = RejestrDomow(path)
    [dom] = rejestr.domy()
    assert (dom.id, dom.nazwa, dom.zrodlo_konfiguracji, dom.wersja, dom.zawieszony) == (
        1, "Dom 1", "yaml", 1, False)
    czl = {c.login: c for c in rejestr.czlonkowie(DOM_1)}
    assert {k: c.rola for k, c in czl.items()} == {
        "konto-a": "wlasciciel-domu", "konto-b": "podglad", "konto-c": "wlasciciel-domu"}
    assert czl["konto-b"].nadane == {"tv.pauza"} and not czl["konto-b"].odebrane
    assert czl["konto-c"].odebrane == {"mdm.komendy"} and not czl["konto-c"].nadane
    # Nikt nie dostaje administratora instalacji przy migracji.
    assert _sql(path, "SELECT DISTINCT admin_instancji FROM users") == [(0,)]
    # Dotychczasowe dane nietkniete (kolumna admin_instancji doszla na koncu).
    po = {t: _sql(path, f"SELECT * FROM {t} ORDER BY 1") for t in przed}
    assert [r[:-1] for r in po["users"]] == przed["users"]
    assert {t: v for t, v in po.items() if t != "users"} == {
        t: v for t, v in przed.items() if t != "users"}
    assert _sql(path, "SELECT akcja, login FROM audyt ORDER BY id") == [
        ("migracja.dom1", None), ("migracja.czlonkostwo", "konto-a"),
        ("migracja.czlonkostwo", "konto-b"), ("migracja.czlonkostwo", "konto-c")]


def test_uprawnienia_w_domu_1_takie_jak_dotad(tmp_path):
    path = _baza_przed_domami(tmp_path)
    auth = PanelAuth(path)  # konstruktor tez migruje
    rejestr = RejestrDomow(path)
    dotad = {u["login"]: frozenset(u["uprawnienia"]) for u in auth.list_users()}
    ids = dict(_sql(path, "SELECT login, id FROM users"))
    for login, uid in ids.items():
        assert rejestr.uprawnienia(uid, DOM_1) == dotad[login], login
        assert rejestr.uprawnienia(uid, 2) == frozenset()
    assert rejestr.czlonkostwo(ids["konto-a"], 2) is None
    assert [c.dom_id for c in rejestr.czlonkostwa(ids["konto-b"])] == [DOM_1]


def _start(path: Path):
    """Wszystko, co przy starcie poda dotyka panel-auth.db."""
    raport = RejestrDomow(path).migruj(strefa="Europe/Warsaw")
    PanelAuth(path)
    GameRequests(path)
    TvPauseRequests(path)
    return raport


def test_baza_panelu_zalozona_przez_migracje_tylko_dla_wlasciciela(tmp_path):
    """`run` i `domy` migruja, zanim PanelAuth czy kolejki zobacza plik. Plik
    z hashami hasel nie moze dostac praw z umask (0644), jak przed domami."""
    path = tmp_path / "panel-auth.db"
    RejestrDomow(path).migruj()
    PanelAuth(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_migracja_idempotentna(tmp_path):
    path = _baza_przed_domami(tmp_path)
    assert _start(path).zmiany
    zrzut = _zrzut(path)

    assert not _start(path).zmiany
    assert _zrzut(path) == zrzut


def test_kolejki_po_migracji_naleza_do_domu_1(tmp_path):
    path = _baza_przed_domami(tmp_path)
    RejestrDomow(path).migruj()
    gry = GameRequests(path)
    [czeka] = gry.pending()
    assert (czeka["child"], czeka["action"], czeka["dom_id"]) == ("Dziecko 2", "bonus", 1)
    assert gry.latest("Dziecko 1")["ok"] is True
    obce = GameRequests(path, dom_id=2)
    assert obce.pending() == [] and obce.latest("Dziecko 2") is None
    obce.finish(czeka["id"], False, "nie moje")  # cudzy dom nie odhacza
    assert [r["id"] for r in gry.pending()] == [czeka["id"]]

    tv = TvPauseRequests(path)
    assert [r["action"] for r in tv.pending()] == ["pause"]
    assert TvPauseRequests(path, dom_id=2).pending() == []
    assert TvPauseRequests(path, dom_id=2).latest() is None
    nowe = TvPauseRequests(path, dom_id=2).submit("resume", None, "konto-a")
    assert [r["id"] for r in tv.pending()] != [nowe]


# =============================================================== wycofanie
#: Zapytania obrazu sprzed domow (main 13c3a8e), przepisane doslownie.
STARY_LIST_USERS = (
    "SELECT u.login, u.rola, u.failed_logins, u.locked_until, u.created_at, "
    "u.last_login_at, u.totp_confirmed_at IS NOT NULL AS totp, "
    "(SELECT COUNT(*) FROM backup_codes b WHERE b.user_id = u.id "
    " AND b.used_at IS NULL) AS backup_codes_left "
    "FROM users u ORDER BY u.login"
)


def _stary_note_from_json(text: str) -> Notification:
    """store.note_from_json z obrazu sprzed domow."""
    from kidwatch.store import from_iso  # noqa: PLC0415

    d = json.loads(text)
    return Notification(
        kind=NotifyKind(d["kind"]), title=d["title"], text=d["text"],
        dedup_key=d["dedup_key"], ts=from_iso(d["ts"]), device=d.get("device"),
        app=d.get("app"), priority=int(d.get("priority", 3)), tags=tuple(d.get("tags") or ()),
        data=d.get("data"),
    )


def test_stary_obraz_dziala_na_nowej_bazie_a_nowy_przejmuje_jego_zmiany(tmp_path):
    path = _baza_przed_domami(tmp_path)
    auth = PanelAuth(path)
    auth.add_user("konto-d", HASLO, "podglad")
    GameRequests(path).submit("Dziecko 1", "allow", None, "konto-a")

    # --- stary obraz: jego SQL na nowej bazie (wszystkie polaczenia z FK, jak PanelAuth)
    stary = sqlite3.connect(path, isolation_level=None)
    stary.execute("PRAGMA foreign_keys = ON")
    from kidwatch.panel_auth import SCHEMA  # noqa: PLC0415 — schemat sprzed domow (bez zmian)

    stary.executescript(SCHEMA)
    assert [r[0] for r in stary.execute(STARY_LIST_USERS)] == [
        "konto-a", "konto-b", "konto-c", "konto-d"]
    stary.execute("INSERT INTO users (login, password_hash, created_at, rola) "
                  "VALUES (?, ?, ?, ?)", ("konto-e", "atrapa", 1759001000, "podglad"))
    uid_b = stary.execute("SELECT id FROM users WHERE login = 'konto-b'").fetchone()[0]
    stary.execute("UPDATE users SET rola = ? WHERE id = ?", ("wlasciciel", uid_b))
    stary.execute("DELETE FROM user_uprawnienia WHERE user_id = ?", (uid_b,))
    stary.execute("DELETE FROM users WHERE login = ?", ("konto-c",))
    stary.execute("INSERT INTO game_requests (child, action, minutes, login, created_at) "
                  "VALUES (?, ?, ?, ?, ?)", ("Dziecko 2", "block", None, "konto-a", 1759001100))
    stary_pending = stary.execute(
        "SELECT child, action FROM game_requests WHERE done_at IS NULL ORDER BY id").fetchall()
    stary.execute("INSERT INTO tv_pause_requests (action, until, login, created_at) "
                  "VALUES (?, ?, ?, ?)", ("resume", None, "konto-a", 1759001200))
    stary.close()
    # Stary obraz widzi kolejke tak, jak ja zostawil nowy (jeden dom).
    assert stary_pending == [("Dziecko 2", "bonus"), ("Dziecko 1", "allow"),
                             ("Dziecko 2", "block")]

    # --- powrot nowego obrazu: start uzgadnia czlonkostwa z `users`
    raport = RejestrDomow(path).migruj()
    assert set(raport.uzgodnione) == {"konto-b", "konto-e"}
    czl = {c.login: c for c in RejestrDomow(path).czlonkowie(DOM_1)}
    assert set(czl) == {"konto-a", "konto-b", "konto-d", "konto-e"}  # konto-c usuniete
    assert czl["konto-b"].rola == "wlasciciel-domu" and not czl["konto-b"].nadane
    assert czl["konto-e"].rola == "podglad"
    assert [r["action"] for r in GameRequests(path).pending()] == ["bonus", "allow", "block"]
    assert [r["action"] for r in TvPauseRequests(path).pending()] == ["pause", "resume"]
    assert not RejestrDomow(path).migruj().zmiany


def test_stary_obraz_czyta_kolejke_powiadomien_z_domem(tmp_path):
    note = Notification(kind=NotifyKind.SESSION_START, title="t", text="x", dedup_key="k",
                        ts=datetime(2026, 10, 1, tzinfo=UTC), device="iPad Dziecka 1",
                        tags=("a",), data={"s": 1}, dom_id=1)
    tekst = note_to_json(note)
    assert json.loads(tekst)["dom_id"] == 1
    assert _stary_note_from_json(tekst) == Notification(
        kind=note.kind, title="t", text="x", dedup_key="k", ts=note.ts,
        device="iPad Dziecka 1", tags=("a",), data={"s": 1})
    # Bez domu JSON jest bajt w bajt taki jak przed domami.
    bez = note_to_json(Notification(kind=NotifyKind.APP, title="t", text="x", dedup_key="k",
                                    ts=note.ts))
    assert "dom_id" not in json.loads(bez)


# ============================================================ lustro rol
def test_zmiany_kont_trafiaja_do_czlonkostwa_domu_1(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    rejestr = RejestrDomow(path)
    auth.add_user("konto-x", HASLO, "podglad")
    uid = _sql(path, "SELECT id FROM users WHERE login = 'konto-x'")[0][0]
    assert rejestr.czlonkostwo(uid, DOM_1).rola == "podglad"

    auth.set_permissions("konto-x", {"tv.pauza": True})
    assert rejestr.czlonkostwo(uid, DOM_1).nadane == {"tv.pauza"}
    auth.set_role("konto-x", "wlasciciel")
    c = rejestr.czlonkostwo(uid, DOM_1)
    assert (c.rola, c.nadane, c.odebrane) == ("wlasciciel-domu", frozenset(), frozenset())
    auth.set_permissions("konto-x", {"mdm.podglad": False})
    assert rejestr.czlonkostwo(uid, DOM_1).odebrane == {"mdm.podglad"}
    dotad = next(u for u in auth.list_users() if u["login"] == "konto-x")["uprawnienia"]
    assert rejestr.uprawnienia(uid, DOM_1) == frozenset(dotad)

    auth.delete_user("konto-x")
    assert rejestr.czlonkowie(DOM_1) == []
    assert _sql(path, "SELECT COUNT(*) FROM czlonkostwa_uprawnienia") == [(0,)]


def test_zarzadca_w_domu_1_ma_lustro_w_users(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("konto-z", HASLO, "podglad")
    uid = _sql(path, "SELECT id FROM users WHERE login = 'konto-z'")[0][0]
    rejestr = RejestrDomow(path)

    rejestr.ustaw_czlonkostwo(DOM_1, uid, "zarzadca", odebrane=frozenset({"tv.aplikacja"}))

    c = rejestr.czlonkostwo(uid, DOM_1)
    oczekiwane = uprawnienia.ROLE_DOMU_UPRAWNIENIA["zarzadca"] - {"tv.aplikacja"}
    assert c.uprawnienia == oczekiwane
    u = next(u for u in auth.list_users() if u["login"] == "konto-z")
    assert u["rola"] == "podglad"  # stary obraz zna tylko wlasciciel/podglad
    assert frozenset(u["uprawnienia"]) == oczekiwane  # ...i liczy te same uprawnienia
    # Start nie spycha zarzadcy do podgladu, mimo ze w users jest `podglad`.
    assert not rejestr.migruj().zmiany
    assert rejestr.czlonkostwo(uid, DOM_1).rola == "zarzadca"
    # Ale zmiana roli w starym obrazie wraca do czlonkostwa.
    _sql(path, "UPDATE users SET rola = 'wlasciciel' WHERE id = ?", (uid,))
    _sql(path, "DELETE FROM user_uprawnienia WHERE user_id = ?", (uid,))
    assert rejestr.migruj().uzgodnione == ("konto-z",)
    assert rejestr.czlonkostwo(uid, DOM_1).rola == "wlasciciel-domu"


def test_ustaw_czlonkostwo_odrzuca_bledy(tmp_path):
    path = tmp_path / "panel-auth.db"
    PanelAuth(path).add_user("konto-y", HASLO)
    uid = _sql(path, "SELECT id FROM users")[0][0]
    rejestr = RejestrDomow(path)
    with pytest.raises(ValueError, match="nieznana rola"):
        rejestr.ustaw_czlonkostwo(DOM_1, uid, "wlasciciel")
    with pytest.raises(ValueError, match="niedozwolone"):
        rejestr.ustaw_czlonkostwo(DOM_1, uid, "podglad", odebrane=frozenset({"konto.wlasne"}))
    with pytest.raises(ValueError, match="niedozwolone"):
        rejestr.ustaw_czlonkostwo(DOM_1, uid, "podglad", nadane=frozenset({"nie.ma"}))
    with pytest.raises(LookupError):
        rejestr.ustaw_czlonkostwo(7, uid, "podglad")
    assert rejestr.czlonkostwo(uid, DOM_1).rola == "wlasciciel-domu"


def test_konto_administracyjne_nie_dostaje_domu(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("konto-admin", HASLO)
    uid = _sql(path, "SELECT id FROM users")[0][0]
    _sql(path, "DELETE FROM czlonkostwa WHERE user_id = ?", (uid,))
    _sql(path, "UPDATE users SET admin_instancji = 1 WHERE id = ?", (uid,))

    assert not RejestrDomow(path).migruj().zmiany
    assert RejestrDomow(path).konta_bez_domu() == ["konto-admin"]
    assert RejestrDomow(path).uprawnienia(uid, DOM_1) == frozenset()


# ================================================================ kontrakt
#: Interfejs domy.py zamrozony w E1 dla E2/E3a/E5 (opis w docstringu modulu).
KONTRAKT = {
    "sciezka_bazy_domu": "(dom_id: 'int', baza_domu_1: 'str | Path') -> 'Path'",
    "katalog_domu": "(dom_id: 'int', baza_domu_1: 'str | Path') -> 'Path'",
    "RejestrDomow.__init__": "(self, path: 'str | Path') -> 'None'",
    "RejestrDomow.migruj": "(self, *, strefa: 'str | None' = None) -> 'RaportMigracji'",
    "RejestrDomow.domy": "(self) -> 'list[Dom]'",
    "RejestrDomow.dom": "(self, dom_id: 'int') -> 'Dom | None'",
    "RejestrDomow.czlonkowie": "(self, dom_id: 'int') -> 'list[Czlonkostwo]'",
    "RejestrDomow.czlonkostwa": "(self, user_id: 'int') -> 'list[Czlonkostwo]'",
    "RejestrDomow.czlonkostwo": "(self, user_id: 'int', dom_id: 'int') -> 'Czlonkostwo | None'",
    "RejestrDomow.uprawnienia": "(self, user_id: 'int', dom_id: 'int') -> 'frozenset[str]'",
    "RejestrDomow.konta_bez_domu": "(self) -> 'list[str]'",
    "RejestrDomow.ustaw_czlonkostwo": (
        "(self, dom_id: 'int', user_id: 'int', rola: 'str', "
        "nadane: 'frozenset[str]' = frozenset(), odebrane: 'frozenset[str]' = frozenset()) "
        "-> 'None'"),
    "ustaw_czlonkostwo_conn": (
        "(conn: 'sqlite3.Connection', dom_id: 'int', user_id: 'int', rola: 'str', "
        "nadane: 'frozenset[str]' = frozenset(), odebrane: 'frozenset[str]' = frozenset(), "
        "teraz: 'float | None' = None) -> 'None'"),
    "uzgodnij_konto_conn": (
        "(conn: 'sqlite3.Connection', user_id: 'int', teraz: 'float | None' = None) "
        "-> 'bool'"),
    "migruj_conn": (
        "(conn: 'sqlite3.Connection', *, strefa: 'str | None' = None, "
        "teraz: 'float | None' = None) -> 'RaportMigracji'"),
    "HomeRuntime.dodaj_petle": (
        "(self, nazwa: 'str', fabryka: 'Callable[[], Coroutine[Any, Any, Any]]') -> 'None'"),
    "HomeRuntime.dodaj_sprzatanie": "(self, fn: 'Callable[[], Awaitable[None]]') -> 'None'",
    "HomeRuntime.start": "(self) -> 'list[asyncio.Task]'",
    "HomeRuntime.zamknij": "(self, flush_seconds: 'float') -> 'None'",
    "Nadzorca.__init__": "(self, domy: 'Sequence[HomeRuntime]') -> 'None'",
    "Nadzorca.run": "(self, stop: 'asyncio.Event') -> 'int'",
    "Nadzorca.zamknij": "(self, flush_seconds: 'float') -> 'None'",
}


def _parametry(sygnatura: str) -> tuple[list[str], str]:
    """'(a: 'int', b: 'str' = 1) -> 'X'' -> (['a: 'int'', "b: 'str' = 1"], "'X'")."""
    srodek, _, zwrot = sygnatura.rpartition(" -> ")
    return [p.strip() for p in _podziel(srodek[1:-1])], zwrot


def _podziel(tekst: str) -> list[str]:
    """Przecinki na najwyzszym poziomie (typy maja nawiasy i przecinki)."""
    out, glebokosc, biezacy = [], 0, ""
    for znak in tekst:
        if znak in "([{":
            glebokosc += 1
        elif znak in ")]}":
            glebokosc -= 1
        if znak == "," and glebokosc == 0:
            out.append(biezacy)
            biezacy = ""
        else:
            biezacy += znak
    if biezacy.strip():
        out.append(biezacy)
    return out


#: Pola dataclass z E1: (nazwa, typ). Kolejnosc i typy nie moga sie zmienic.
POLA_E1 = {
    "Dom": [("id", "int"), ("nazwa", "str"), ("strefa", "str"),
            ("zrodlo_konfiguracji", "str"), ("wersja", "int"), ("zawieszony", "bool")],
    "Czlonkostwo": [("dom_id", "int"), ("user_id", "int"), ("login", "str"), ("rola", "str"),
                    ("nadane", "frozenset[str]"), ("odebrane", "frozenset[str]")],
    "HomeRuntime": [("dom_id", "int"), ("home", "HomeConfig"), ("store", "Store"),
                    ("engine", "Engine"), ("outbox", "Outbox"), ("source", "Any"),
                    ("petle", "list[tuple[str, Callable[[], Coroutine[Any, Any, Any]]]]"),
                    ("sprzatanie", "list[Callable[[], Awaitable[None]]]")],
}


def test_interfejs_domy_zamrozony():
    """Kontrakt E1 dla rownoleglych etapow: nic z niego nie ZNIKA i nie
    zmienia typu. Rozszerzenia addytywne (E2: nowe pola z wartosciami
    domyslnymi, nowe parametry z domyslnymi na koncu) sa dozwolone."""
    for nazwa, sygnatura in KONTRAKT.items():
        obj = domy
        for czesc in nazwa.split("."):
            obj = getattr(obj, czesc)
        stare, stary_zwrot = _parametry(sygnatura)
        nowe, nowy_zwrot = _parametry(str(inspect.signature(obj)))
        assert nowy_zwrot == stary_zwrot, nazwa
        assert nowe[:len(stare)] == stare, nazwa
        for dodany in nowe[len(stare):]:
            assert "=" in dodany or dodany.startswith("**"), (nazwa, dodany)
    assert (domy.DOM_1, domy.NAZWA_DOMU_1, domy.ZRODLO_YAML, domy.ZRODLO_BAZA) == (
        1, "Dom 1", "yaml", "baza")
    for klasa, pola in POLA_E1.items():
        fields = getattr(domy, klasa).__dataclass_fields__
        assert [(n, str(fields[n].type)) for n in list(fields)[:len(pola)]] == pola, klasa
        for n in list(fields)[len(pola):]:
            f = fields[n]
            assert f.default is not dataclasses.MISSING or \
                f.default_factory is not dataclasses.MISSING, (klasa, n)
    assert uprawnienia.ROLE_DOMU == ("wlasciciel-domu", "zarzadca", "podglad")


def test_test_zamrozenia_lapie_usuniecie_i_zmiane_typu(monkeypatch):
    """Kanarek: test kontraktu musi pasc, gdy pole zniknie albo zmieni typ."""
    import dataclasses as dc  # noqa: PLC0415

    @dc.dataclass(frozen=True)
    class ZlyDom:
        id: int
        nazwa: str
        strefa: str
        zrodlo_konfiguracji: str
        wersja: str  # zmieniony typ
        zawieszony: bool

    monkeypatch.setattr(domy, "Dom", ZlyDom)
    with pytest.raises(AssertionError):
        test_interfejs_domy_zamrozony()


# ========================================================= kolejka domu
async def test_kolejka_domu_stempluje_dom_i_odrzuca_cudze(tmp_path):
    ts = datetime(2026, 10, 1, tzinfo=UTC)

    def notka(klucz, dom=None):
        return Notification(kind=NotifyKind.APP, title=klucz, text="x", dedup_key=klucz,
                            ts=ts, dom_id=dom)

    with Store(tmp_path / "k.db") as store:
        outbox = Outbox(Dispatcher([]), store, dom_id=1)
        await outbox.send_all([notka("a"), notka("b", 1), notka("c", 2)])
        assert [(i.note.dedup_key, i.note.dom_id) for i in store.outbox_pending()] == [
            ("a", 1), ("b", 1)]
    with Store(tmp_path / "k2.db") as store:
        await Outbox(Dispatcher([]), store).send_all([notka("a")])
        assert store.outbox_pending()[0].note.dom_id is None


# =================================================== zachowanie end-to-end
class Kolektor:
    name = "kolektor"

    def __init__(self) -> None:
        self.notes: list[Notification] = []

    async def send(self, note):
        self.notes.append(note)
        return True

    async def aclose(self):
        return None


class ZrodloZPliku:
    name = "nextdns"

    def __init__(self, path: Path) -> None:
        self.rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
                     if line]
        self.closed = False

    async def events(self):
        for row in self.rows:
            ts = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
            yield DnsEvent(ts=ts, device_id=row["device"], domain=row["domain"])

    async def aclose(self):
        self.closed = True


def _konfiguracja_dnia(tmp_path) -> Path:
    data = yaml.safe_load((FIXTURES / "config.yaml").read_text(encoding="utf-8"))
    data["store"]["path"] = str(tmp_path / "kidwatch.db")
    data["app_map_path"] = str(APP_MAP)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return cfg_path


async def test_dzien_przez_srodowisko_domu_1_daje_te_same_powiadomienia(tmp_path, monkeypatch):
    """§6 p. 8: replay dnia daje ten sam wynik na sciezce jednodomowej
    (`kidwatch replay`, snapshot) i przez HomeRuntime(Dom 1): HomeConfig
    z split(), baza domu, kolejka z dom_id, petla zrodla, wysylka."""
    kolektor = Kolektor()
    zrodlo = ZrodloZPliku(DAY)
    monkeypatch.setattr(cli, "build_source", lambda cfg, store: zrodlo)
    monkeypatch.setattr(cli, "build_notifiers", lambda cfg, bramka: [kolektor])
    cfg = Config.load(_konfiguracja_dnia(tmp_path))
    inst, home = cfg.split()

    rt = cli.build_home_runtime(DOM_1, inst, home, Classifier(inst.app_map_path))
    assert type(rt.engine.cfg) is HomeConfig
    assert Path(rt.store.path) == tmp_path / "kidwatch.db"
    assert [n for n, _ in rt.petle] == ["source", "tick", "outbox"]

    await source_loop(rt.source, rt.engine, rt.outbox, rt.store)
    last = datetime.fromisoformat(zrodlo.rows[-1]["ts"].replace("Z", "+00:00"))
    await rt.outbox.send_all(rt.engine.tick(last + timedelta(minutes=home.engine.idle_minutes
                                                             + 1)))
    while await rt.outbox.flush():
        pass

    wydruk = "".join(cli.render(n) + "\n" for n in kolektor.notes)
    snapshot = SNAPSHOT.read_text(encoding="utf-8")
    assert snapshot.startswith(wydruk) and snapshot[len(wydruk):].startswith(
        f"\n--- {len(zrodlo.rows)} zdarzen -> {len(kolektor.notes)} powiadomien ---")
    assert {n.dom_id for n in kolektor.notes} == {1}
    # Ta sama tresc co silnik na starym Config, pole w pole (poza domem).
    stary_cfg = Config.load(tmp_path / "config.yaml")
    stary = []
    with Store(":memory:") as store:
        from kidwatch.engine import Engine  # noqa: PLC0415

        engine = Engine(stary_cfg, store, Classifier(stary_cfg.app_map_path))
        for ev in [e async for e in ZrodloZPliku(DAY).events()]:
            stary += engine.handle(ev)
        stary += engine.tick(last + timedelta(minutes=stary_cfg.engine.idle_minutes + 1))
    pola = ("kind", "title", "text", "dedup_key", "ts", "device", "app", "priority", "tags",
            "data")
    assert [tuple(getattr(n, p) for p in pola) for n in kolektor.notes] == [
        tuple(getattr(n, p) for p in pola) for n in stary]
    await rt.outbox.aclose()
    rt.store.close()


def test_run_zaklada_dom_1_przy_starcie(tmp_path, monkeypatch):
    """`run` przez nadzorce: Dom 1 w panel-auth.db (0600), koniec zadania = kod 1."""

    class Puste:
        name = "atrapa"

        async def events(self):
            return
            yield  # pragma: no cover

        async def aclose(self):
            pass

    monkeypatch.setattr(cli, "build_source", lambda cfg, store: Puste())
    monkeypatch.setenv("KIDWATCH_HEARTBEAT", str(tmp_path / "hb"))
    cfg_path = _konfiguracja_dnia(tmp_path)
    stara = os.umask(0o022)
    try:
        assert cli.main(["--config", str(cfg_path), "run"]) == 1
    finally:
        os.umask(stara)
    assert stat.S_IMODE((tmp_path / "panel-auth.db").stat().st_mode) == 0o600
    [dom] = RejestrDomow(tmp_path / "panel-auth.db").domy()
    assert (dom.id, dom.zrodlo_konfiguracji) == (1, "yaml")
    assert (tmp_path / "kidwatch.db").exists()  # baza Domu 1 = dotychczasowa


@pytest.mark.parametrize("pierwszy", ["migruj", "domy"])
def test_rejestr_zaklada_panel_auth_z_prawami_0600(tmp_path, pierwszy):
    """Swieza instalacja: `run` (migruj) i CLI `domy` zakladaja panel-auth.db
    jako pierwsze, wiec PanelAuth/TvPauseRequests widza istniejacy plik i nie
    robia chmod — prawa musi ustawic rejestr (hashe hasel, TOTP, sesje)."""
    path = tmp_path / "panel-auth.db"
    stara = os.umask(0o022)
    try:
        getattr(RejestrDomow(path), pierwszy)()
        TvPauseRequests(path)
        PanelAuth(path)
    finally:
        os.umask(stara)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_rejestr_nie_zmienia_praw_istniejacej_bazy(tmp_path):
    path = tmp_path / "panel-auth.db"
    path.touch(mode=0o640)
    path.chmod(0o640)
    RejestrDomow(path).migruj()
    assert stat.S_IMODE(path.stat().st_mode) == 0o640


async def test_nadzorca_stop_i_zamkniecie(tmp_path):
    zdarzenia: list[str] = []

    class Kolejka:
        async def flush(self):
            zdarzenia.append("flush")

        async def aclose(self):
            zdarzenia.append("outbox.aclose")

    class Zrodlo:
        async def aclose(self):
            zdarzenia.append("source.aclose")

    async def sonda():
        zdarzenia.append("sonda.aclose")

    store = Store(tmp_path / "k.db")
    rt = HomeRuntime(DOM_1, None, store, None, Kolejka(), Zrodlo())  # type: ignore[arg-type]
    rt.dodaj_petle("wieczna", lambda: asyncio.sleep(3600))
    rt.dodaj_sprzatanie(sonda)
    stop = asyncio.Event()
    nadzorca = Nadzorca([rt])
    zadanie = asyncio.create_task(nadzorca.run(stop))
    await asyncio.sleep(0)
    stop.set()
    assert await zadanie == 0
    await nadzorca.zamknij(1.0)
    assert zdarzenia == ["sonda.aclose", "flush", "outbox.aclose", "source.aclose"]
    with pytest.raises(sqlite3.ProgrammingError):
        store.conn.execute("SELECT 1")

    rt2 = HomeRuntime(DOM_1, None, Store(":memory:"), None, Kolejka(), Zrodlo())  # type: ignore
    rt2.dodaj_petle("konczy", lambda: asyncio.sleep(0))
    assert await Nadzorca([rt2]).run(asyncio.Event()) == 1


def test_cli_domy_pokazuje_dom_1_z_czlonkami(tmp_path, capsys):
    cfg_path = _konfiguracja_dnia(tmp_path)
    PanelAuth(tmp_path / "panel-auth.db").add_user("konto-a", HASLO, "podglad")
    assert cli.main(["--config", str(cfg_path), "domy"]) == 0
    out = capsys.readouterr().out
    assert "1. Dom 1 — konfiguracja: config.yaml, strefa: Europe/Warsaw" in out
    assert "konto-a" in out and "podglad" in out
