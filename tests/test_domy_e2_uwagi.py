# ruff: noqa: F811 — fixtury dom1/kek importowane z test_domy_e2
"""Uwagi z przegladu PR #50 (przeglad-e2-poprawki.md, U1–U10).

Jak test_domy_e2.py: dane generyczne, sekrety losowane, bez sieci."""

from __future__ import annotations

import base64
import io
import os
import secrets
import sqlite3
import time

import pytest

import kidwatch.__main__ as cli
from kidwatch.domy import DOM_1
from kidwatch.sejf import Sejf
from test_domy_e2 import (  # noqa: F401 — fixtury
    ROOT,
    _aplikacja_tv_bez_przecieku,
    _importuj,
    _klucz_adb,
    dom1,
    kek,
)

pytestmark = pytest.mark.usefixtures("bez_sieci")


def _token_w_bazie(dom1, kek) -> str | None:
    return dom1["rejestr"].sekrety_domu(DOM_1, Sejf(kek)).get("tv", "app_token")


# ======================================================================= U1
def test_token_tv_porownywany_z_czasem_zmiany_tokenu_nie_integracji(dom1, kek, tmp_path):
    """Import (token A), parowanie w yaml (plik B nowszy niz A), potem zmiana
    INNEGO pola integracji tv w bazie. Ponowny import: wygrywa B — nowszy niz
    ostatnia zmiana TOKENU, choc starszy niz ostatnia zmiana integracji."""
    _importuj(dom1, Sejf(kek))
    plik = tmp_path / "tv-app" / "token"
    b = "TOKEN-B-" + secrets.token_hex(8)
    plik.write_text(b)
    teraz = time.time()
    os.utime(plik, (teraz + 50, teraz + 50))
    dom1["rejestr"].sekrety_domu(DOM_1, Sejf(kek)).zapisz("tv", "sony_psk", "psk-" +
                                                          secrets.token_hex(4))
    conn = sqlite3.connect(dom1["inst"].panel_auth_path)
    with conn:  # zmiana sony_psk „pozniej” niz parowanie B
        conn.execute("UPDATE integracje SET zmienione_at = ? WHERE typ = 'tv'", (teraz + 100,))
        conn.execute("UPDATE audyt SET ts = ? WHERE id = (SELECT MAX(id) FROM audyt)",
                     (teraz + 100,))
    conn.close()
    raport = _importuj(dom1, Sejf(kek))
    assert raport.zapisano, raport.roznice
    assert _token_w_bazie(dom1, kek) == b
    assert not any("token aplikacji TV" in o for o in raport.ostrzezenia)


def test_ostrzezenie_o_tokenie_mowi_prawde(dom1, kek, tmp_path):
    _importuj(dom1, Sejf(kek))
    plik = tmp_path / "tv-app" / "token"
    os.utime(plik, (time.time() - 3600, time.time() - 3600))
    dom1["rejestr"].sekrety_domu(DOM_1, Sejf(kek)).zapisz("tv", "app_token", "NOWY-" +
                                                          secrets.token_hex(6))
    raport = _importuj(dom1, Sejf(kek))
    [ostrz] = [o for o in raport.ostrzezenia if "token aplikacji TV" in o]
    assert "starszy niz ostatnia zmiana tokenu w bazie" in ostrz


# ======================================================================= U2
async def test_adb_kolejny_adres_przy_timeoucie_adb_shell_i_zamyka(tmp_path, monkeypatch):
    import adb_shell.adb_device_async as adb_async  # noqa: PLC0415
    from adb_shell import exceptions as adb_exc  # noqa: PLC0415

    from kidwatch.sources import tv as tv_mod  # noqa: PLC0415
    from kidwatch.straznik import Straznik  # noqa: PLC0415

    (tmp_path / "adbkey").write_text(_klucz_adb())
    proby, zamkniete = [], []

    class Urzadzenie:
        available = False

        def __init__(self, host, port, default_transport_timeout_s):
            self.host = host

        async def connect(self, **kw):
            proby.append(self.host)
            raise adb_exc.TcpTimeoutException("atrapa: timeout")

        async def close(self):
            zamkniete.append(self.host)

    monkeypatch.setattr(adb_async, "AdbDeviceTcpAsync", Urzadzenie)
    shell = tv_mod.AdbTcpShell("tv.example.invalid", 5555, tmp_path, 1, straznik=Straznik(
        1, ["192.0.2.20/31"], resolver=lambda h, p: ["192.0.2.20", "192.0.2.21"]))
    with pytest.raises(tv_mod.TvUnavailable):
        await shell.shell("true")
    assert proby == ["192.0.2.20", "192.0.2.21"]
    assert zamkniete == ["192.0.2.20", "192.0.2.21"]


# ======================================================================= U3
def test_runbook_usuniecie_poprzedniego_tylko_po_potwierdzeniu():
    tekst = (ROOT / "docs/sejf-domow.md").read_text()
    rotacja = tekst[tekst.index("## 7. Rotacja KEK"):tekst.index("## 8.")]
    linie = [linia for linia in rotacja.splitlines() if "KIDWATCH_KEK_POPRZEDNI" in linia
             and "remove" in linia]
    assert linie, "brak polecenia usuniecia"
    # Usuniecie w JEDNYM poleceniu z warunkiem: kp && kubectl ... remove.
    blok = rotacja[rotacja.index("kp &&"):]
    assert blok.index("KIDWATCH_KEK_POPRZEDNI") < blok.index("```")


def test_kp_zwraca_kod_klucze_potwierdz(tmp_path):
    """`kp && remove` dziala tylko, gdy funkcja kp zwraca kod polecenia, a nie
    kod koncowego `unset` (zawsze 0). Uruchamiamy definicje z runbooka w zsh
    z atrapa kubectl konczaca sie kodem 1."""
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    zsh = shutil.which("zsh")
    if zsh is None:
        if os.environ.get("CI"):
            pytest.fail("brak zsh — workflow CI musi go instalowac (apt-get install zsh)")
        pytest.skip("brak zsh")
    tekst = (ROOT / "docs/sejf-domow.md").read_text()
    definicja = tekst[tekst.index("kp() {"):]
    definicja = definicja[:definicja.index("}\n") + 1]
    atrapa = tmp_path / "kubectl"
    atrapa.write_text("#!/bin/sh\ncat >/dev/null\nexit 1\n")
    atrapa.chmod(0o755)
    skrypt = definicja + "\nkp && echo USUNIETO; echo KOD=$?\n"
    wynik = subprocess.run([zsh, "-f", "-c", skrypt], input="klucz\n", text=True,
                           capture_output=True, timeout=30,
                           env={"PATH": f"{tmp_path}:/usr/bin:/bin"})
    assert "USUNIETO" not in wynik.stdout and "KOD=1" in wynik.stdout, wynik


# ======================================================================= U4
def test_domy_pokazuje_wymuszenie(dom1, kek, monkeypatch, capsys):
    _importuj(dom1, Sejf(kek))
    monkeypatch.setenv("KIDWATCH_DOM_1_ZRODLO", "yaml")
    assert cli.main(["--config", str(dom1["cfg_path"]), "domy"]) == 0
    out = capsys.readouterr().out
    assert "WYMUSZONE config.yaml przez KIDWATCH_DOM_1_ZRODLO" in out


# ======================================================================= U5
def test_runbook_ostrzega_ze_starsze_obrazy_ignoruja_wymuszenie():
    tekst = (ROOT / "docs/sejf-domow.md").read_text()
    cofniecie = tekst[tekst.index("## 4. Cofnięcie"):tekst.index("## 5.")]
    assert "sha-c38b19c" in cofniecie and "ignoruje" in cofniecie


# ======================================================================= U6
@pytest.mark.parametrize("polecenie", ["domy", "klucze-potwierdz"])
def test_baza_nieistniejaca_czytelny_blad(tmp_path, monkeypatch, capsys, polecenie):
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(secrets.token_bytes(32)).decode())
    monkeypatch.setattr("sys.stdin", io.StringIO(os.environ["KIDWATCH_KEK"] + "\n"))
    sciezka = tmp_path / "nie-ma.db"
    argv = ["--config", str(tmp_path / "x.yaml"), polecenie, "--baza", str(sciezka)]
    if polecenie == "domy":
        argv.append("--sprawdz")
    assert cli.main(argv) == 2
    assert "nie ma pliku bazy" in capsys.readouterr().err
    assert not sciezka.exists()


# ======================================================================= U7
def test_odmowa_rozroznia_dek_od_uszkodzonej_integracji(dom1, kek, monkeypatch, capsys):
    _importuj(dom1, Sejf(kek))
    conn = sqlite3.connect(dom1["inst"].panel_auth_path)
    with conn:  # jeden bajt szyfrogramu zmieniony — tag GCM sie nie zgadza
        [blob] = conn.execute("SELECT sekrety FROM integracje WHERE typ = 'unifi'").fetchone()
        zepsuty = bytes(blob[:-1]) + bytes([blob[-1] ^ 1])
        conn.execute("UPDATE integracje SET sekrety = ? WHERE typ = 'unifi'", (zepsuty,))
    conn.close()
    monkeypatch.setattr("sys.stdin", io.StringIO(base64.b64encode(kek).decode() + "\n"))
    assert cli.main(["--config", str(dom1["cfg_path"]), "klucze-potwierdz"]) == 1
    out = capsys.readouterr().out
    assert "integracji nie odszyfrowuje sie" in out and "unifi" in out
    assert "klucze-rotuj" not in out  # klucz domu otwarty — to nie sprawa rotacji


# ======================================================================= U8
def test_testy_e2_nie_polegaja_na_pustej_liscie_bledow():
    tekst = (ROOT / "tests/test_domy_e2.py").read_text()
    assert ".sprawdz(sejf) == []" not in tekst and ".sprawdz(Sejf(" not in tekst


# ================================================================= U9, U10
def test_kp_bez_globalnej_zmiennej_z_kluczem():
    """N3: `local K` — po Ctrl-C klucz nie zostaje w powloce."""
    tekst = (ROOT / "docs/sejf-domow.md").read_text()
    definicja = tekst[tekst.index("kp() {"):]
    assert definicja.startswith("kp() { local K rc;")


def test_schowek_czyszczony_przed_kp():
    """N1: klucz wrzucony do schowka trzeba usunac przed `kp`, inaczej `kp`
    potwierdza schowek, a nie wpis w menedzerze hasel."""
    tekst = (ROOT / "docs/sejf-domow.md").read_text()
    for start, kp in (("## 2. Klucz KEK", "## 3."), ("## 7. Rotacja KEK", "kp &&")):
        sekcja = tekst[tekst.index(start):]
        wrzut = sekcja.index("| pbcopy")
        assert wrzut < sekcja.index("pbcopy </dev/null") < sekcja.index(kp), start


def test_runbook_powloka_i_schowek():
    tekst = (ROOT / "docs/sejf-domow.md").read_text()
    assert "zsh" in tekst
    assert 'printf \'%s\\n\' "$NOWY"' not in tekst and 'printf \'%s\\n\' "$KEK"' not in tekst
    assert "pbcopy" in tekst
