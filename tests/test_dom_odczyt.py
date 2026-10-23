# ruff: noqa: F811 — fixtury dom1/kek importowane z test_domy_e2
"""`kidwatch dom-odczyt` — odczyt procesow iPadow (lockdown) dla domu
z konfiguracja w bazie. Dom 1 w trybie `baza` trzyma `device_read`
w `domy.ustawienia`, a jedyna droga, zeby go wlaczyc, byl ponowny
`dom-importuj 1` z config.yaml.

Jak test_domy_e2.py: dane generyczne (RFC 5737), sekrety losowane, bez sieci."""

from __future__ import annotations

import json
import plistlib
import sqlite3

import pytest

import kidwatch.__main__ as cli
from kidwatch.config import Config
from kidwatch.domy import DOM_1, RejestrDomow
from kidwatch.konfiguracja_domu import zbuduj_dom
from kidwatch.sejf import Sejf
from kidwatch.store import Store
from test_domy_e2 import (  # noqa: F401 — fixtury
    _aplikacja_tv_bez_przecieku,
    _bez_kanarkow,
    _pelna,
    _zapisz_konfig,
    _zrzut,
    dom1,
    kek,
)

pytestmark = pytest.mark.usefixtures("bez_sieci")

#: iPad z `udid` i `host` w _pelna (test_domy_e2).
UDID = "00000000-0000000000000001"
HOST = "192.0.2.10"


def _cfg(d) -> list[str]:
    return ["--config", str(d["cfg_path"])]


def _db(d):
    return d["inst"].panel_auth_path


def _wiersz(d) -> dict:
    conn = sqlite3.connect(_db(d))
    conn.row_factory = sqlite3.Row
    try:
        return dict(conn.execute("SELECT * FROM domy WHERE id = ?", (DOM_1,)).fetchone())
    finally:
        conn.close()


def _audyt(d) -> list[tuple]:
    conn = sqlite3.connect(_db(d))
    try:
        return conn.execute("SELECT login, opis FROM audyt WHERE akcja = 'dom.odczyt' "
                            "ORDER BY id").fetchall()
    finally:
        conn.close()


def _przygotuj(d, tmp_path, zmien=None, *, importuj=True) -> dict:
    """Dom 1 jak na produkcji: zaimportowany do bazy z WYLACZONYM odczytem,
    wiec adres iPada nie trafil do `dozwolone_sieci`."""
    dane = _pelna(tmp_path)
    dane["device_read"]["enabled"] = False
    if zmien:
        zmien(dane)
    d["cfg_path"] = _zapisz_konfig(tmp_path, dane)
    d["inst"], d["home"] = Config.load(d["cfg_path"]).split()
    if importuj:
        assert cli.main([*_cfg(d), "dom-importuj", "1", "--zapisz"]) == 0
    return d


@pytest.fixture
def dom(dom1, kek, tmp_path, capsys):
    d = _przygotuj(dom1, tmp_path)
    assert d["rejestr"].dom(DOM_1).zrodlo_konfiguracji == "baza"
    assert f"{HOST}/32" not in d["rejestr"].dom(DOM_1).dozwolone_sieci
    capsys.readouterr()
    d["kek"] = kek
    return d


def test_podglad_stanu_bez_pelnego_udid(dom, tmp_path, capsys):
    zrzut = _zrzut(_db(dom))
    assert cli.main([*_cfg(dom), "dom-odczyt", "1"]) == 0
    assert _zrzut(_db(dom)) == zrzut
    capsys.readouterr()
    assert cli.main([*_cfg(dom), "dom-odczyt", "1"]) == 0
    out = capsys.readouterr().out
    assert "odczyt iPadow wylaczony" in out
    assert "poll_seconds: 45" in out and "unreachable_alert_hours: 24" in out
    assert UDID not in out and UDID[:-4] not in out
    assert "…0001" in out and f"host {HOST}" in out
    assert f"NIE (kidwatch dom-sieci 1 --dodaj {HOST}/32)" in out
    assert "rekord parowania: BRAK" in out and "BRAK KATALOGU" in out
    # Rekord: sam fakt istnienia pliku, tresci nie czytamy (smiec przechodzi).
    (tmp_path / "rekordy").mkdir()
    (tmp_path / "rekordy" / f"{UDID}.plist").write_bytes(b"nie-plist")
    assert cli.main([*_cfg(dom), "dom-sieci", "1", "--dodaj", f"{HOST}/32"]) == 0
    capsys.readouterr()
    assert cli.main([*_cfg(dom), "dom-odczyt", "1"]) == 0
    out = capsys.readouterr().out
    assert "siec: dopuszczony" in out and "rekord parowania: jest" in out
    assert "BRAK KATALOGU" not in out and UDID not in out
    # Podglad niczego nie zapisuje.
    assert _audyt(dom) == []


def test_wlacz_i_wylacz(dom, tmp_path, capsys, monkeypatch):
    przed = _wiersz(dom)
    # Podpowiedz z odmowy to dzialajace polecenie.
    assert cli.main([*_cfg(dom), "dom-sieci", "1", "--dodaj", f"{HOST}/32"]) == 0
    po_sieci = _wiersz(dom)
    assert cli.main([*_cfg(dom), "dom-odczyt", "1", "--wlacz", "--co", "30",
                     "--alarm-po", "12"]) == 0
    out = capsys.readouterr()
    assert "ZAPISANO. Zadziala w ciagu ok. 10 s" in out.out and "WLACZONY" in out.out
    po = _wiersz(dom)
    assert po["wersja"] == po_sieci["wersja"] + 1
    ust_przed, ust_po = json.loads(przed["ustawienia"]), json.loads(po["ustawienia"])
    dr_przed, dr_po = ust_przed.pop("device_read"), ust_po.pop("device_read")
    assert ust_po == ust_przed  # reszta ustawien nietknieta
    assert dr_po == {**dr_przed, "enabled": True, "poll_seconds": 30.0,
                     "unreachable_alert_hours": 12.0}
    assert dr_po["process_aliases"] == {"Gra9": "com.example.gra"}
    for kol in ("strefa", "dozwolone_sieci", "dozwolone_hosty", "zrodlo_konfiguracji",
                "dek_zaszyfrowany"):
        assert po[kol] == po_sieci[kol], kol
    audyt = _audyt(dom)
    assert len(audyt) == 1 and audyt[0][0] == "cli"
    assert "enabled False -> True" in audyt[0][1] and "poll_seconds 45.0 -> 30.0" in audyt[0][1]
    assert UDID not in audyt[0][1] and "0001" not in audyt[0][1]

    # Sciezka runtime w trybie `baza`: dom z bazy + rekordy parowania z katalogu
    # INSTANCJI (config.yaml, montowany Sekret) -> obserwator iPada.
    home = zbuduj_dom(dom["rejestr"], DOM_1, Sejf(dom["kek"]), materializuj=False)
    assert home.device_read.enabled and home.device_read.poll_seconds == 30
    rekordy = dom["inst"].device_read.records_path
    assert cli.build_watchers(home, Store(":memory:"), rekordy) == []  # brak rekordu
    rekordy.mkdir(parents=True)
    (rekordy / f"{UDID}.plist").write_bytes(plistlib.dumps({"HostID": "test"}))
    watchers = cli.build_watchers(home, Store(":memory:"), rekordy)
    assert [w.device_name for w in watchers] == ["iPad Dziecka 1"]

    # Bez zmian = bez zapisu i bez podbicia wersji.
    assert cli.main([*_cfg(dom), "dom-odczyt", "1", "--wlacz"]) == 0
    assert "Bez zmian" in capsys.readouterr().out
    assert _wiersz(dom)["wersja"] == po["wersja"]

    assert cli.main([*_cfg(dom), "dom-odczyt", "1", "--wylacz"]) == 0
    wyl = _wiersz(dom)
    assert wyl["wersja"] == po["wersja"] + 1
    dr = json.loads(wyl["ustawienia"])["device_read"]
    assert dr == {**dr_po, "enabled": False}
    assert len(_audyt(dom)) == 2 and "enabled True -> False" in _audyt(dom)[1][1]
    out = capsys.readouterr()
    _bez_kanarkow(out.out + out.err, dom["kanarki"])


def test_odmowa_bez_dopuszczonego_hosta(dom, capsys):
    zrzut = _zrzut(_db(dom))
    assert cli.main([*_cfg(dom), "dom-odczyt", "1", "--wlacz"]) == 2
    err = capsys.readouterr().err
    assert "ODMOWA (nic nie zapisano)" in err
    assert f"kidwatch dom-sieci 1 --dodaj {HOST}/32" in err
    assert UDID not in err
    assert _zrzut(_db(dom)) == zrzut


def test_odmowa_zlej_wartosci(dom, capsys):
    """--co ponizej minimum modelu (ge=5) — ten sam walidator co start."""
    assert cli.main([*_cfg(dom), "dom-sieci", "1", "--dodaj", f"{HOST}/32"]) == 0
    zrzut = _zrzut(_db(dom))
    assert cli.main([*_cfg(dom), "dom-odczyt", "1", "--co", "1"]) == 2
    assert "poll_seconds" in capsys.readouterr().err
    assert _zrzut(_db(dom)) == zrzut


def test_odmowa_bez_urzadzen_z_udid_i_host(dom1, kek, tmp_path, capsys):
    def bez_udid(dane):
        for dev in dane["devices"]:
            dev.pop("udid", None)
            dev.pop("host", None)

    d = _przygotuj(dom1, tmp_path, bez_udid)
    capsys.readouterr()
    zrzut = _zrzut(_db(d))
    assert cli.main([*_cfg(d), "dom-odczyt", "1", "--wlacz"]) == 2
    assert "zadne urzadzenie nie ma 'udid' i 'host'" in capsys.readouterr().err
    assert _zrzut(_db(d)) == zrzut


def test_dom_yaml_odmowa(dom1, kek, tmp_path, capsys):
    d = _przygotuj(dom1, tmp_path, importuj=False)
    assert cli.main([*_cfg(d), "domy"]) == 0  # zaklada Dom 1 (tryb yaml)
    assert RejestrDomow(_db(d)).dom(DOM_1).zrodlo_konfiguracji == "yaml"
    capsys.readouterr()
    zrzut = _zrzut(_db(d))
    assert cli.main([*_cfg(d), "dom-odczyt", "1", "--wlacz"]) == 2
    assert "tryb yaml" in capsys.readouterr().err
    assert _zrzut(_db(d)) == zrzut


def test_nieistniejacy_dom(dom, capsys):
    zrzut = _zrzut(_db(dom))
    assert cli.main([*_cfg(dom), "dom-odczyt", "99", "--wlacz"]) == 2
    assert "nie ma domu 99" in capsys.readouterr().err
    assert cli.main([*_cfg(dom), "dom-odczyt", "99"]) == 2
    assert _zrzut(_db(dom)) == zrzut


def test_dom_bez_zrodla_dns_tez_walidowany(dom, tmp_path, capsys):
    """Dom po `dom-dodaj` bez integracji juz „nie startuje” (brak zrodla DNS),
    wiec porownanie bledu startu przed/po niczego by nie zlapalo — model domu
    jest sprawdzany zawsze."""
    assert cli.main([*_cfg(dom), "dom-dodaj", "Dom testowy"]) == 0
    dom2 = max(x.id for x in dom["rejestr"].domy())
    plik = tmp_path / "dom.yaml"
    plik.write_text(json.dumps({"devices": [{"display_name": "Tablet B", "child": "Dziecko B",
                                             "source_ids": ["tablet-b"]}]}), encoding="utf-8")
    assert cli.main([*_cfg(dom), "dom-importuj", str(dom2), "--plik", str(plik),
                     "--zapisz"]) == 0
    capsys.readouterr()
    zrzut = _zrzut(_db(dom))
    assert cli.main([*_cfg(dom), "dom-odczyt", str(dom2), "--wlacz"]) == 2
    assert "zadne urzadzenie nie ma 'udid' i 'host'" in capsys.readouterr().err
    assert _zrzut(_db(dom)) == zrzut
