# ruff: noqa: F811 — fixtura kek importowana z test_domy_e2
"""Struktura kolejnego domu z pliku: `dom-importuj N --plik` (przygotowanie
E6, renacode-infra: docs/projekty/kidwatch/architektura-domy.md §7).

Dom ≠ 1 nie ma config.yaml, a integracje wpisuje sie w panelu — bez tego
importu nie bylo jak wpisac mu dzieci i urzadzen. Import zastepuje dzieci,
urzadzenia i ustawienia, a integracji, sekretow i sieci domu nie rusza.
Dane generyczne, sekrety losowane (kanarki), bez sieci."""

from __future__ import annotations

import secrets
import sqlite3
from pathlib import Path

import pytest
import yaml

import kidwatch.__main__ as cli
from kidwatch.domy import DOM_1, RejestrDomow
from kidwatch.konfiguracja_domu import importuj_strukture, zbuduj_dom
from kidwatch.sejf import Sejf
from test_domy_e2 import PUBLICZNY, ROOT, _prosta, _zapisz_konfig, kek  # noqa: F401

pytestmark = pytest.mark.usefixtures("bez_sieci")

TELEFON = {"display_name": "Telefon Dziecka A", "child": "Dziecko A", "kind": "phone",
           "source_ids": ["Telefon Dziecka A"]}
TABLET = {"display_name": "Tablet Dziecka B", "child": "Dziecko B",
          "source_ids": ["Tablet-B"]}


def _resolver(host: str, port: int) -> list[str]:
    return [PUBLICZNY]


@pytest.fixture
def dom2(tmp_path, monkeypatch, kek):
    """Instalacja z Domem 1 z config.yaml i pustym Domem 2 z `dom-dodaj`."""
    monkeypatch.setenv("NEXTDNS_API_KEY", "k-" + secrets.token_hex(8))
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    assert cli.main(["--config", str(cfg_path), "dom-dodaj", "Dom testowy"]) == 0
    rejestr = RejestrDomow(tmp_path / "panel-auth.db")
    dom_id = max(d.id for d in rejestr.domy())
    assert dom_id != DOM_1
    return {"cfg_path": cfg_path, "rejestr": rejestr, "dom_id": dom_id,
            "sejf": Sejf(kek), "db": tmp_path / "panel-auth.db"}


def _plik(tmp_path: Path, dane: dict) -> Path:
    p = tmp_path / "dom.yaml"
    p.write_text(yaml.safe_dump(dane, allow_unicode=True), encoding="utf-8")
    return p


def _wiersze(db: Path, dom_id: int) -> dict[str, list]:
    conn = sqlite3.connect(db)
    try:
        return {t: conn.execute(f"SELECT * FROM {t} WHERE dom_id = ? ORDER BY 1",  # noqa: S608
                                (dom_id,)).fetchall()
                for t in ("dzieci", "urzadzenia", "integracje")}
    finally:
        conn.close()


def _nextdns(d, *, klucz: str) -> None:
    d["rejestr"].zapisz_integracje(
        d["dom_id"], "nextdns", sejf=d["sejf"], wlaczona=True,
        ustawienia={"profile_id": "fed987"}, sekrety={"api_key": klucz}, kto="test",
        resolver=_resolver)


def _cli(d, plik: Path, *tryb: str) -> int:
    return cli.main(["--config", str(d["cfg_path"]), "dom-importuj", str(d["dom_id"]),
                     "--plik", str(plik), *tryb])


# ================================================================== zapis
def test_podglad_nic_nie_zapisuje_a_zapis_wpisuje_strukture(dom2, tmp_path):
    plik = _plik(tmp_path, {"timezone": "Europe/Lisbon", "devices": [TELEFON, TABLET],
                            "watchdog": {"device_silence_minutes": 240}})
    przed = _wiersze(dom2["db"], dom2["dom_id"])
    assert _cli(dom2, plik, "--podglad") == 0
    assert _wiersze(dom2["db"], dom2["dom_id"]) == przed

    assert _cli(dom2, plik, "--zapisz") == 0
    dane = dom2["rejestr"].dane_domu(dom2["dom_id"])
    assert dane.dzieci == ["Dziecko A", "Dziecko B"]
    assert [(u["nazwa"], u["dziecko"]) for u in dane.urzadzenia] == [
        ("Telefon Dziecka A", "Dziecko A"), ("Tablet Dziecka B", "Dziecko B")]
    assert dane.dom.strefa == "Europe/Lisbon"
    assert dane.dom.ustawienia["watchdog"]["device_silence_minutes"] == 240
    assert dane.integracje == []


def test_dom_1_nietkniety(dom2, tmp_path):
    assert cli.main(["--config", str(dom2["cfg_path"]), "dom-importuj", "1", "--zapisz"]) == 0
    przed = _wiersze(dom2["db"], DOM_1)
    wersja = dom2["rejestr"].dom(DOM_1).wersja
    assert _cli(dom2, _plik(tmp_path, {"devices": [TELEFON]}), "--zapisz") == 0
    assert _wiersze(dom2["db"], DOM_1) == przed
    assert dom2["rejestr"].dom(DOM_1).wersja == wersja


def test_integracje_i_sekrety_z_panelu_zostaja(dom2, tmp_path, capsys):
    """Kolejny import (np. drugie dziecko) nie kasuje klucza NextDNS
    wpisanego w panelu, a klucz nie pojawia sie w wyjsciu."""
    klucz = "KANAREK-" + secrets.token_hex(12)
    _nextdns(dom2, klucz=klucz)
    assert _cli(dom2, _plik(tmp_path, {"devices": [TELEFON]}), "--zapisz") == 0
    integ_przed = _wiersze(dom2["db"], dom2["dom_id"])["integracje"]
    wersja = dom2["rejestr"].dom(dom2["dom_id"]).wersja

    assert _cli(dom2, _plik(tmp_path, {"devices": [TELEFON, TABLET]}), "--zapisz") == 0
    assert _wiersze(dom2["db"], dom2["dom_id"])["integracje"] == integ_przed
    assert dom2["rejestr"].dom(dom2["dom_id"]).wersja > wersja  # nadzorca przeladuje dom
    home = zbuduj_dom(dom2["rejestr"], dom2["dom_id"], dom2["sejf"], resolver=_resolver,
                      materializuj=False)
    assert [d.display_name for d in home.devices] == ["Telefon Dziecka A", "Tablet Dziecka B"]
    assert home.source.nextdns.api_key() == klucz
    assert klucz not in capsys.readouterr().out


def test_sieci_domu_zostaja_puste(dom2, tmp_path):
    """Import struktury Domu 1 dopisuje hosty urzadzen do dozwolonych sieci;
    dom ≠ 1 nie — adres w jego LAN dopuszcza tylko `dom-sieci` (§8 p. 4)."""
    zly = {**TABLET, "udid": "00000000-0000000000000002", "host": "192.0.2.50"}
    plik = _plik(tmp_path, {"devices": [zly], "device_read": {"enabled": True}})
    assert _cli(dom2, plik, "--zapisz") == 0
    dom = dom2["rejestr"].dom(dom2["dom_id"])
    assert not dom.dozwolone_sieci and not dom.dozwolone_hosty


# =============================================================== odmowy
@pytest.mark.parametrize("sekcja", ["source", "notifiers", "tv", "unifi", "mdm"])
def test_sekcja_integracji_odrzucona(dom2, tmp_path, capsys, sekcja):
    przed = _wiersze(dom2["db"], dom2["dom_id"])
    plik = _plik(tmp_path, {"devices": [TELEFON], sekcja: {}})
    assert _cli(dom2, plik, "--zapisz") == 1
    assert "Integracje" in capsys.readouterr().err
    assert _wiersze(dom2["db"], dom2["dom_id"]) == przed


@pytest.mark.parametrize("dane", [
    {"devices": []},
    {"devices": [{**TELEFON, "kind": "pralka"}]},
    {"devices": [TELEFON, {**TABLET, "source_ids": ["Telefon Dziecka A"]}]},
    {"devices": [TELEFON], "timezone": "Europa/Nigdzie"},
    {"devices": [TELEFON], "nieznane_pole": 1},
])
def test_niepoprawny_plik_odrzucony_bez_zmian(dom2, tmp_path, dane):
    przed = _wiersze(dom2["db"], dom2["dom_id"])
    assert _cli(dom2, _plik(tmp_path, dane), "--zapisz") == 1
    assert _wiersze(dom2["db"], dom2["dom_id"]) == przed


def test_dom_1_z_plikiem_i_inny_dom_bez_pliku(dom2, tmp_path):
    plik = _plik(tmp_path, {"devices": [TELEFON]})
    assert cli.main(["--config", str(dom2["cfg_path"]), "dom-importuj", "1",
                     "--plik", str(plik), "--zapisz"]) == 2
    assert cli.main(["--config", str(dom2["cfg_path"]), "dom-importuj",
                     str(dom2["dom_id"]), "--zapisz"]) == 2
    with pytest.raises(ValueError, match="Dom 1"):
        importuj_strukture(dom2["rejestr"], DOM_1, {"devices": [TELEFON]},
                           sejf=dom2["sejf"], zapisz=True)


def test_nieistniejacy_dom(dom2, tmp_path):
    plik = _plik(tmp_path, {"devices": [TELEFON]})
    assert cli.main(["--config", str(dom2["cfg_path"]), "dom-importuj", "999",
                     "--plik", str(plik), "--zapisz"]) == 1


def test_walidacja_z_biezacym_zrodlem_domu(dom2, tmp_path):
    """Przy zrodle AdGuard profil NextDNS urzadzenia to blad — walidacja
    bierze zrodlo, ktore dom naprawde ma, nie atrape."""
    dom2["rejestr"].zapisz_integracje(
        dom2["dom_id"], "adguard", sejf=dom2["sejf"], wlaczona=True,
        ustawienia={"base_url": "https://adguard.example.invalid", "username": "u"},
        kto="test", resolver=_resolver)
    plik = _plik(tmp_path, {"devices": [{**TELEFON, "nextdns_profile": "abc123"}]})
    assert _cli(dom2, plik, "--zapisz") == 1
    assert _cli(dom2, _plik(tmp_path, {"devices": [TELEFON]}), "--zapisz") == 0


# ================================================================== wzor
def test_wzor_dom_example_przechodzi(dom2):
    """Wzor w repo nie moze zgnic: musi przejsc walidacje i porownanie."""
    assert _cli(dom2, ROOT / "dom.example.yaml", "--podglad") == 0
