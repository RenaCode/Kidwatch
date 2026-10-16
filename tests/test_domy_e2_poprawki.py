# ruff: noqa: F811 — fixtury dom1/kek importowane z test_domy_e2
"""Poprawki E2 po przegladzie PR #49: wyjscie z CrashLoopa bez
`kubectl exec` (P1), test odtworzenia, ktory nie potwierdza niczego, gdy
nie ma czego sprawdzic (P2), potwierdzenie kopii KEK przed usunieciem
klucza poprzedniego (R1/R2), token aplikacji TV przy ponownym imporcie
(I1), strażnik: IPv4 w ::/96 i SIIT (S1), kolejny sprawdzony adres (S2),
SNI przy literale IP (S3).

Jak test_domy_e2.py: dane generyczne, sekrety losowane, bez sieci."""

from __future__ import annotations

import base64
import ipaddress
import logging
import os
import secrets
import sqlite3
import time
from pathlib import Path

import httpx
import pytest

import kidwatch.__main__ as cli
from conftest import plik_dokumentacji
from kidwatch.domy import DOM_1, RejestrDomow
from kidwatch.sejf import Sejf
from kidwatch.sources import unifi as unifi_mod
from kidwatch.straznik import Straznik
from test_domy_e2 import (  # noqa: F401 — fixtury
    ROOT,
    Puste,
    _aplikacja_tv_bez_przecieku,
    _bez_kanarkow,
    _importuj,
    _prosta,
    _zapisz_konfig,
    dom1,
    kek,
)

pytestmark = pytest.mark.usefixtures("bez_sieci", "run_zatrzymany_po_awarii")

PUBLICZNY = "9.9.9.9"
PUBLICZNY_2 = "149.112.112.112"


def _dom_1_w_bazie(tmp_path, monkeypatch) -> Path:
    monkeypatch.setenv("NEXTDNS_API_KEY", "k-" + secrets.token_hex(8))
    monkeypatch.setenv("KIDWATCH_HEARTBEAT", str(tmp_path / "hb"))
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    assert cli.main(["--config", str(cfg_path), "dom-importuj", "1", "--zapisz"]) == 0
    monkeypatch.setattr(cli, "build_source", lambda cfg, store: Puste())
    return cfg_path


# ======================================================== P1: bez exec
def test_wymuszenie_yaml_z_sekretu_wyprowadza_z_crashloopa(tmp_path, monkeypatch, kek,
                                                             caplog):
    """Dom 1 w `baza`, KEK zniknal (np. odtworzony kidwatch-secrets): bez
    exec jedyne wyjscie to klucz w Sekrecie. Baza nie jest zmieniana."""
    cfg_path = _dom_1_w_bazie(tmp_path, monkeypatch)
    monkeypatch.delenv("KIDWATCH_KEK")
    caplog.set_level(logging.INFO)
    assert cli.main(["--config", str(cfg_path), "run"]) == 2  # CrashLoop

    monkeypatch.setenv("KIDWATCH_DOM_1_ZRODLO", "yaml")
    # Wystartowal: atrapa zrodla sie konczy, nadzorca planuje restart domu (E3b).
    assert cli.main(["--config", str(cfg_path), "run"]) == 0
    ostrzezenia = [r for r in caplog.records if r.levelno == logging.WARNING
                   and "KIDWATCH_DOM_1_ZRODLO" in r.getMessage()]
    assert ostrzezenia and "config.yaml" in ostrzezenia[0].getMessage()
    dom = RejestrDomow(tmp_path / "panel-auth.db").dom(DOM_1)
    assert dom.zrodlo_konfiguracji == "baza"  # wymuszenie nie przepisuje bazy


@pytest.mark.parametrize("wartosc", ["baza", "YAML ", "cokolwiek"])
def test_wymuszenie_tylko_dokladnie_yaml(tmp_path, monkeypatch, kek, caplog, wartosc):
    cfg_path = _dom_1_w_bazie(tmp_path, monkeypatch)
    monkeypatch.delenv("KIDWATCH_KEK")
    monkeypatch.setenv("KIDWATCH_DOM_1_ZRODLO", wartosc)
    oczekiwany = 0 if wartosc.strip().lower() == "yaml" else 2
    assert cli.main(["--config", str(cfg_path), "run"]) == oczekiwany
    if oczekiwany == 2:
        assert "KIDWATCH_DOM_1_ZRODLO" in caplog.text  # nieznana wartosc nie przechodzi cicho


def test_chart_ma_opcjonalny_klucz_wymuszenia():
    tekst = (ROOT / "charts/kidwatch/templates/deployment.yaml").read_text()
    blok = tekst[tekst.index("name: KIDWATCH_DOM_1_ZRODLO"):][:300]
    assert "key: KIDWATCH_DOM_1_ZRODLO" in blok and "optional: true" in blok


def test_chart_odtworzenia_sekretu_zna_kek():
    assert "KIDWATCH_KEK" in (ROOT / "charts/kidwatch/values.yaml").read_text()


def test_dokumentacja_odtworzenia_sekretu_zna_kek():
    assert "KIDWATCH_KEK" in plik_dokumentacji("uruchomienie-od-zera.md").read_text()
    runbook = plik_dokumentacji("sejf-domow.md").read_text()
    assert "KIDWATCH_DOM_1_ZRODLO" in runbook


# ==================================================== P2: nic do sprawdzenia
def test_sprawdz_bez_kluczy_domow_nie_potwierdza_niczego(tmp_path, monkeypatch, capsys):
    from kidwatch.panel_auth import PanelAuth  # noqa: PLC0415

    baza = tmp_path / "kopia.db"
    PanelAuth(baza).add_user("konto-a", "haslo-testowe-123", "wlasciciel")  # konto, bez DEK
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(secrets.token_bytes(32)).decode())
    rc = cli.main(["--config", str(tmp_path / "nie-ma.yaml"), "domy", "--baza", str(baza),
                   "--sprawdz"])
    out = capsys.readouterr().out
    assert rc != 0
    assert "wszystko sie odszyfrowuje" not in out
    assert "nic nie potwierdzono" in out


def test_sprawdz_wypisuje_liczby(dom1, kek, capsys):
    _importuj(dom1, Sejf(kek))
    assert cli.main(["--config", str(dom1["cfg_path"]), "domy", "--sprawdz"]) == 0
    out = capsys.readouterr().out
    n_integracji = len([i for i in dom1["rejestr"].integracje(DOM_1) if i.sekrety_pola])
    assert f"kluczy domow: 1, integracji: {n_integracji}" in out


# ================================================ R1/R2: potwierdzenie kopii KEK
def _potwierdz(cfg_path, monkeypatch, klucz: bytes | str, *extra) -> int:
    import io  # noqa: PLC0415

    tekst = klucz if isinstance(klucz, str) else base64.b64encode(klucz).decode()
    monkeypatch.setattr("sys.stdin", io.StringIO(tekst + "\n"))
    return cli.main(["--config", str(cfg_path), "klucze-potwierdz", *extra])


def test_potwierdzenie_kopii_kek_przerywa_bez_dowodu(dom1, kek, monkeypatch, capsys, caplog):
    cfg = dom1["cfg_path"]
    # Baza bez kluczy domow: nie ma czym potwierdzic — odmowa.
    assert _potwierdz(cfg, monkeypatch, kek) == 1
    _importuj(dom1, Sejf(kek))
    # Klucz spoza menedzera (inny) — odmowa.
    assert _potwierdz(cfg, monkeypatch, secrets.token_bytes(32)) == 1
    assert _potwierdz(cfg, monkeypatch, "to-nie-klucz") == 2
    # Wlasciwy klucz — potwierdzone, wpis w audycie.
    assert _potwierdz(cfg, monkeypatch, kek) == 0
    out = capsys.readouterr().out
    assert "NIE usuwaj" in out and "POTWIERDZONO" in out

    # W trakcie rotacji: klucz z menedzera musi byc NOWYM biezacym, a DEK-i
    # juz na nim — inaczej usuniecie poprzedniego zabije start poda.
    nowy = secrets.token_bytes(32)
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(nowy).decode())
    monkeypatch.setenv("KIDWATCH_KEK_POPRZEDNI", base64.b64encode(kek).decode())
    assert _potwierdz(cfg, monkeypatch, nowy) == 1  # przed klucze-rotuj
    assert "klucze-rotuj" in capsys.readouterr().out
    assert cli.main(["--config", str(cfg), "klucze-rotuj"]) == 0
    assert _potwierdz(cfg, monkeypatch, kek) == 1  # stary klucz po rotacji
    assert _potwierdz(cfg, monkeypatch, nowy) == 0
    out = capsys.readouterr().out
    assert "kopie bazy sprzed" in out  # stary klucz trzymac dla starszych kopii
    _bez_kanarkow(out + caplog.text, {"k": base64.b64encode(nowy).decode(),
                                      "s": base64.b64encode(kek).decode()})
    conn = sqlite3.connect(dom1["inst"].panel_auth_path)
    try:
        akcje = conn.execute("SELECT akcja FROM audyt WHERE akcja = 'klucze.potwierdzenie'")
        assert len(akcje.fetchall()) == 2
    finally:
        conn.close()


def test_runbook_rotacji_najpierw_test_potem_usuwanie():
    tekst = plik_dokumentacji("sejf-domow.md").read_text()
    rotacja = tekst[tekst.index("## 7. Rotacja KEK"):tekst.index("## 8.")]
    assert rotacja.index("klucze-potwierdz") < rotacja.index("remove")
    assert "kopie" in rotacja and "sprzed rotacji" in rotacja


# ================================================== I1: token aplikacji TV
def _token_w_bazie(dom1, kek) -> str | None:
    return dom1["rejestr"].sekrety_domu(DOM_1, Sejf(kek)).get("tv", "app_token")


def test_ponowny_import_nie_cofa_nowszego_tokenu_tv(dom1, kek, tmp_path):
    _importuj(dom1, Sejf(kek))
    plik = tmp_path / "tv-app" / "token"
    stary = plik.read_text().strip()
    # Parowanie w trybie `baza`: nowy token tylko w bazie, plik na /data stary.
    os.utime(plik, (time.time() - 3600, time.time() - 3600))
    nowy = "TOKEN-NOWY-" + secrets.token_hex(8)
    dom1["rejestr"].sekrety_domu(DOM_1, Sejf(kek)).zapisz("tv", "app_token", nowy)
    raport = _importuj(dom1, Sejf(kek))
    assert raport.zapisano, raport.roznice
    assert _token_w_bazie(dom1, kek) == nowy != stary
    assert any("token aplikacji TV" in o for o in raport.ostrzezenia)

    # Bez pliku (np. nowy PVC) token z bazy tez zostaje.
    plik.unlink()
    assert _importuj(dom1, Sejf(kek)).zapisano
    assert _token_w_bazie(dom1, kek) == nowy


def test_ponowny_import_bierze_nowszy_plik_tokenu(dom1, kek, tmp_path):
    """Odwrotnie: po powrocie do yaml sparowano TV (plik nowszy niz baza)."""
    _importuj(dom1, Sejf(kek))
    plik = tmp_path / "tv-app" / "token"
    nowy = "TOKEN-Z-YAML-" + secrets.token_hex(8)
    plik.write_text(nowy)
    os.utime(plik, (time.time() + 60, time.time() + 60))
    assert _importuj(dom1, Sejf(kek)).zapisano
    assert _token_w_bazie(dom1, kek) == nowy


# ============================================================ straznik
@pytest.mark.parametrize("adres", ["::7f00:1", "::a00:1", "::c0a8:1", "::ffff:0:7f00:1",
                                   "::ffff:0:a00:1"])
def test_ipv4_w_ipv6_kompatybilnym_i_siit_odrzucany(adres):
    assert not Straznik(2).dozwolony(ipaddress.ip_address(adres))


async def test_transport_probuje_kolejnych_sprawdzonych_adresow():
    proby = []

    def odpowiedz(request):
        proby.append(request.url.host)
        if request.url.host == PUBLICZNY:
            raise httpx.ConnectError("atrapa: nie odpowiada", request=request)
        return httpx.Response(200)

    resolver = lambda h, p: [PUBLICZNY, PUBLICZNY_2]  # noqa: E731
    straznik = Straznik(2, resolver=resolver)
    async with httpx.AsyncClient(transport=straznik.transport(httpx.MockTransport(odpowiedz))) \
            as c:
        r = await c.get("https://api.example.invalid/")
    assert r.status_code == 200 and proby == [PUBLICZNY, PUBLICZNY_2]

    # Wszystkie padaja — blad polaczenia, kazdy adres sprobowany raz.
    proby.clear()

    def zawsze_pada(request):
        proby.append(request.url.host)
        raise httpx.ConnectTimeout("atrapa", request=request)

    async with httpx.AsyncClient(transport=straznik.transport(httpx.MockTransport(zawsze_pada))) \
            as c:
        with pytest.raises(httpx.ConnectTimeout):
            await c.get("https://api.example.invalid/")
    assert proby == [PUBLICZNY, PUBLICZNY_2]


async def test_literal_ip_nie_dziedziczy_sni():
    widziane = []

    def odpowiedz(request):
        widziane.append(request.extensions.get("sni_hostname"))
        return httpx.Response(200)

    straznik = Straznik(2)
    async with httpx.AsyncClient(transport=straznik.transport(httpx.MockTransport(odpowiedz))) \
            as c:
        await c.get(f"https://{PUBLICZNY}/", extensions={"sni_hostname": "stara.example.invalid"})
    assert widziane == [None]


def test_unifi_probuje_kolejnego_adresu(monkeypatch):
    proby = []

    class Polaczenie:
        def __init__(self, host, port, timeout, context):
            self.host = host

        def connect(self):
            proby.append(self.host)
            raise ConnectionRefusedError("atrapa")

        def close(self):
            pass

    monkeypatch.setattr(unifi_mod.http.client, "HTTPSConnection", Polaczenie)
    straznik = Straznik(1, ["192.0.2.1/32", "192.0.2.2/32"],
                        resolver=lambda h, p: ["192.0.2.1", "192.0.2.2"])
    with pytest.raises(ConnectionRefusedError):
        unifi_mod.fetch_pinned("https://udm.example.invalid", "/x", "k", "0" * 64, 1, straznik)
    assert proby == ["192.0.2.1", "192.0.2.2"]


async def test_adb_probuje_kolejnego_adresu(tmp_path, monkeypatch):
    import adb_shell.adb_device_async as adb_async  # noqa: PLC0415

    from kidwatch.sources import tv as tv_mod  # noqa: PLC0415
    from test_domy_e2 import _klucz_adb  # noqa: PLC0415

    (tmp_path / "adbkey").write_text(_klucz_adb())
    proby = []

    class Urzadzenie:
        available = False

        def __init__(self, host, port, default_transport_timeout_s):
            self.host = host

        async def connect(self, **kw):
            proby.append(self.host)
            raise ConnectionRefusedError("atrapa")

        async def close(self):
            pass

    monkeypatch.setattr(adb_async, "AdbDeviceTcpAsync", Urzadzenie)
    shell = tv_mod.AdbTcpShell("tv.example.invalid", 5555, tmp_path, 1, straznik=Straznik(
        1, ["192.0.2.20/31"], resolver=lambda h, p: ["192.0.2.20", "192.0.2.21"]))
    with pytest.raises(tv_mod.TvUnavailable):
        await shell.shell("true")
    assert proby == ["192.0.2.20", "192.0.2.21"]


def test_test_wycofania_uzywa_pelnego_sha():
    import test_domy_e2  # noqa: PLC0415

    assert len(test_domy_e2.STARY_OBRAZ) == 40

