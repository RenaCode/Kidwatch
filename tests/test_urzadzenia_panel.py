# ruff: noqa: F811 — fikstury importowane z test_integracje_panel i test_domy_e2
"""Ekran „Dzieci i urzadzenia” domu (uprawnienie `dom.urzadzenia`).

Wlasciciel domu i zarzadca sami zmieniaja dzieci i urzadzenia swojego domu,
administrator instalacji — w kazdym. Testy pilnuja:
  * dostepu: wlasciciel-domu i zarzadca tak, podglad 403, obcy dom 404,
    administrator bez czlonkostwa z wpisem `admin.*`, dom `yaml` 409;
  * pol administratora (UDID, adres, MAC, lista aplikacji): rola domu ich
    nie widzi, nie wysle i nie zgubi — takze po zmianie nazwy urzadzenia
    (dopasowanie po id wiersza); Dom 1 na produkcyjnym ksztalcie danych;
  * walidacji tymi samymi walidatorami co config.yaml: blad = baza bez
    zmian; 409 przy nieaktualnej wersji; ostatnie urzadzenie dzialajacego
    domu zostaje, swiezy dom mozna czyscic;
  * integracji, sekretow, telewizora i ustawien domu — nietkniete; sekret-
    kanarek nie w odpowiedzi, logu, audycie.

Dane generyczne: „Dziecko A”, adresy RFC 5737, UDID-y z samych zer.
"""

from __future__ import annotations

import logging
import sqlite3

import pytest

from kidwatch import domy as dm
from kidwatch import straznik
from kidwatch import uprawnienia as u
from kidwatch.gametime import GameRequests
from kidwatch.komendy import Komenda
from kidwatch.komendy_baza import BazaKomend, Konto
from kidwatch.konfiguracja_domu import porownaj, zbuduj_dom
from kidwatch.odbiorcy import ProfilePowiadomien
from kidwatch.panel_auth import AuthError, PanelAuth
from kidwatch.panel_domy import KontekstDomu
from kidwatch.panel_urzadzenia import DZIECKO_USUNIETE, OSTATNIE, PanelUrzadzenia
from kidwatch.sejf import Sejf
from test_domy_e2 import _dziecko_z_urzadzeniem, _importuj, dom1, kek  # noqa: F401
from test_integracje_panel import (  # noqa: F401 — fikstura inst
    DOM_1,
    DOM_B,
    HASLO,
    SIEC_DOMU,
    Slady,
    _rozwiaz,
    admin,
    inst,
    sso,
)
from test_panel_sso import call

pytestmark = pytest.mark.usefixtures("bez_sieci")

URL = f"/api/domy/{DOM_B}/urzadzenia"


def _zrzut(path) -> list[str]:
    """Konfiguracja domow: domy, dzieci, urzadzenia, integracje (bez kont —
    licznik nieudanych potwierdzen to nie zmiana domu)."""
    conn = sqlite3.connect(path)
    try:
        return [w for w in conn.iterdump() if w.startswith(tuple(
            f'INSERT INTO "{t}"' for t in ("domy", "dzieci", "urzadzenia", "integracje")))]
    finally:
        conn.close()


def _audyt(path, akcja: str | None = None) -> list[tuple]:
    conn = sqlite3.connect(path)
    try:
        sql, args = "SELECT login, akcja, opis FROM audyt", ()
        if akcja:
            sql, args = sql + " WHERE akcja = ?", (akcja,)
        return conn.execute(sql + " ORDER BY id", args).fetchall()
    finally:
        conn.close()


def _cialo(ekran: dict, *, admin_: bool = False, **zmiany) -> dict:
    """Odpowiedz GET -> cialo zapisu bez zmian. Rola domu: bez pol
    administratora (techniczne i profil NextDNS); administrator: z nimi."""
    def urz(x: dict) -> dict:
        out = {k: x[k] for k in ("id", "nazwa", "dziecko", "rodzaj", "source_ids")}
        if admin_:
            out |= {"nextdns_profile": x["nextdns_profile"], **x["techniczne"]}
        return out

    return {
        "wersja": ekran["dom"]["wersja"],
        "dzieci": [{"id": d["id"], "nazwa": d["nazwa"]} for d in ekran["dzieci"]],
        "urzadzenia": [urz(x) for x in ekran["urzadzenia"]],
        **zmiany,
    }


def _zapisz(srv, h, body, confirm=HASLO):
    return call(srv, "POST", f"{URL}/zapisz", {**body, "confirm": confirm}, headers=h)


@pytest.fixture
def b(inst):
    """Dom B z inst: dziala (NextDNS z kluczem-kanarkiem, jedno urzadzenie);
    dodatkowe konto `zarzadca-b`."""
    inst.auth.add_user("zarzadca-b", HASLO, u.ROLA_ZARZADCA, dom_id=DOM_B)
    return inst


# ============================================================== dostep
@pytest.mark.parametrize(("login", "grupy", "status"), [
    ("wlasciciel-b", "wlasciciel", 200),
    ("zarzadca-b", "wlasciciel", 200),
    ("podglad-b", "wlasciciel", 403),
    ("obcy", "wlasciciel", 404),          # cudzy dom wyglada jak brak domu
    ("admin", "wlasciciel", 404),         # flaga bez grupy `admins` nic nie otwiera
])
def test_dostep_wedlug_roli_w_domu(b, login, grupy, status):
    h = sso(b, login, grupy)
    wersja = b.rejestr.dom(DOM_B).wersja
    st, _, ekran = call(b, "GET", URL, headers=h)
    assert st == status, ekran
    wlasny = admin(b) if status != 200 else h
    _, _, pelny = call(b, "GET", URL, headers=wlasny)
    cialo = _cialo(pelny, urzadzenia=[{**_cialo(pelny)["urzadzenia"][0], "nazwa": "Nowa"}])
    st, _, body = _zapisz(b, h, cialo)
    assert st == status, body
    nazwy = [x["nazwa"] for x in b.rejestr.dane_domu(DOM_B).urzadzenia]
    if status == 200:
        assert nazwy == ["Nowa"] and b.rejestr.dom(DOM_B).wersja > wersja
        assert "techniczne" not in repr(ekran)
        wpis = _audyt(b.cfg.panel_auth_path, "dom.urzadzenia.zapis")
        assert wpis and wpis[-1][0] == login and "zmienione 1" in wpis[-1][2]
    else:
        assert nazwy == ["Urzadzenie A"]


def test_administrator_bez_czlonkostwa_z_wpisem_w_audycie(b):
    h = admin(b)
    st, _, ekran = call(b, "GET", URL, headers=h)
    assert st == 200 and ekran["administrator"] is True
    assert "techniczne" in ekran["urzadzenia"][0]
    st, _, body = _zapisz(b, h, _cialo(ekran, admin_=True))
    assert st == 200, body
    akcje = [a for _, a, _ in _audyt(b.cfg.panel_auth_path) if a.startswith("admin.")]
    assert "admin.wglad" in akcje and "admin.urzadzenia.zapisz" in akcje
    assert ("admin", "dom.urzadzenia.zapis") in [(lg, a) for lg, a, _ in
                                                  _audyt(b.cfg.panel_auth_path)]


def test_dom_yaml_odmowa_409(b):
    h = admin(b)
    wersja = b.rejestr.dom(DOM_1).wersja
    st, _, body = call(b, "GET", f"/api/domy/{DOM_1}/urzadzenia", headers=h)
    assert st == 409 and "config.yaml" in body["error"], body
    st, _, body = call(b, "POST", f"/api/domy/{DOM_1}/urzadzenia/zapisz",
                       {"wersja": wersja, "dzieci": [], "urzadzenia": [], "confirm": HASLO},
                       headers=h)
    assert st == 409 and "config.yaml" in body["error"], body
    assert b.rejestr.dom(DOM_1).wersja == wersja


def test_zle_potwierdzenie_i_brak_wersji(b):
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, _ = _zapisz(b, h, _cialo(ekran), confirm="zle-haslo")
    assert st == 403
    bez_wersji = _cialo(ekran)
    del bez_wersji["wersja"]
    st, _, body = _zapisz(b, h, bez_wersji)
    assert st == 400 and "wersja" in body["error"]
    assert _zrzut(b.cfg.panel_auth_path) == przed


# ======================================================== wspolbieznosc
def test_nieaktualna_wersja_409_i_baza_bez_zmian(b):
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    # Ktos inny zmienil dom (np. integracje) — wersja poszla w gore.
    b.rejestr.ustaw_sieci(DOM_B, sieci=[SIEC_DOMU, "198.51.100.0/28"])
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, body = _zapisz(b, h, _cialo(ekran, dzieci=[{"id": None, "nazwa": "Dziecko A"}]))
    assert st == 409 and "odśwież" in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed


# ============================================================ walidacja
@pytest.mark.parametrize(("zmiana", "fragment"), [
    ({"rodzaj": "tv"}, "rodzaj"),
    ({"source_ids": []}, "NextDNS"),
    ({"dziecko": "Ktos Inny"}, "nie jest na liście"),
])
def test_zla_walidacja_400_i_baza_bez_zmian(b, zmiana, fragment):
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran)
    cialo["urzadzenia"][0].update(zmiana)
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, body = _zapisz(b, h, cialo)
    assert st == 400 and fragment in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed


def test_dwa_profile_u_jednego_dziecka_odrzucone_walidatorem_configu(b):
    """Walidator HomeConfig (_profiles_need_nextdns), nie wlasny: dziecko
    z urzadzeniami na dwoch profilach NextDNS."""
    h = admin(b)
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran, admin_=True)
    cialo["urzadzenia"].append({"id": None, "nazwa": "iPad A", "dziecko": "Dziecko A",
                                "rodzaj": "ipad", "source_ids": ["ipad-a"],
                                "nextdns_profile": "inny123"})
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, body = _zapisz(b, h, cialo)
    assert st == 400 and "profilach NextDNS" in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed


def test_dodanie_dziecka_i_urzadzenia_zamiana_nazw(b):
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran)
    cialo["dzieci"].append({"id": None, "nazwa": "Dziecko B"})
    cialo["urzadzenia"].append({"id": None, "nazwa": "Telefon B", "dziecko": "Dziecko B",
                                "rodzaj": "phone", "source_ids": ["Telefon B"]})
    st, _, po = _zapisz(b, h, cialo)
    assert st == 200, po
    assert [d["nazwa"] for d in po["dzieci"]] == ["Dziecko A", "Dziecko B"]
    nowy = next(x for x in po["urzadzenia"] if x["nazwa"] == "Telefon B")
    assert nowy["rodzaj"] == "phone-android" and nowy["source_ids"] == ["telefon b"]
    # Zamiana nazw dwoch urzadzen (UNIQUE w domu) i dzieci w jednym zapisie.
    cialo = _cialo(po)
    a, bb = cialo["urzadzenia"]
    a["nazwa"], bb["nazwa"] = bb["nazwa"], a["nazwa"]
    da, db = cialo["dzieci"]
    da["nazwa"], db["nazwa"] = db["nazwa"], da["nazwa"]
    a["dziecko"], bb["dziecko"] = da["nazwa"], db["nazwa"]
    st, _, po2 = _zapisz(b, h, cialo)
    assert st == 200, po2
    assert {x["id"]: x["nazwa"] for x in po2["urzadzenia"]} == {a["id"]: "Telefon B",
                                                                bb["id"]: "Urzadzenie A"}
    assert po2["przeladowanie"]["automatyczne"] is True


# ===================================================== ostatnie urzadzenie
def test_ostatnie_urzadzenie_dzialajacego_domu_zostaje(b):
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    assert ekran["start"] is None  # dom B wystartowalby
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, body = _zapisz(b, h, _cialo(ekran, dzieci=[], urzadzenia=[]))
    assert st == 400 and body["error"] == OSTATNIE, body
    assert _zrzut(b.cfg.panel_auth_path) == przed


def test_swiezy_dom_bez_nextdns_mozna_uzupelniac_i_czyscic(b):
    """Dom po `dom-dodaj` bez zrodla DNS „czeka na konfiguracje” (#84):
    urzadzenia mozna dodac przed kluczem NextDNS i usunac do zera."""
    dom_c = b.rejestr.dodaj_dom("Dom C")
    b.auth.add_user("wlasciciel-c", HASLO, u.ROLA_WLASCICIEL_DOMU, dom_id=dom_c)
    h = sso(b, "wlasciciel-c")
    url = f"/api/domy/{dom_c}/urzadzenia"
    st, _, ekran = call(b, "GET", url, headers=h)
    assert st == 200 and ekran["urzadzenia"] == [] and ekran["start"], ekran
    cialo = {"wersja": ekran["dom"]["wersja"], "dzieci": [{"nazwa": "Dziecko C"}],
             "urzadzenia": [{"nazwa": "Telefon C", "dziecko": "Dziecko C",
                             "rodzaj": "phone-android", "source_ids": ["Telefon C"]}]}
    st, _, po = call(b, "POST", f"{url}/zapisz", {**cialo, "confirm": HASLO}, headers=h)
    assert st == 200, po
    assert [x["nazwa"] for x in po["urzadzenia"]] == ["Telefon C"]
    st, _, po = call(b, "POST", f"{url}/zapisz", {"wersja": po["dom"]["wersja"], "dzieci": [],
                                                  "urzadzenia": [], "confirm": HASLO},
                     headers=h)
    assert st == 200, po
    assert b.rejestr.dane_domu(dom_c).urzadzenia == [] and b.rejestr.dane_domu(dom_c).dzieci == []


def test_swiezy_dom_tez_walidowany_modelem_configu(b):
    """Dom bez zrodla DNS i tak nie startuje, wiec sprawdzenie startu nic tu
    nie zlapie — zly profil odrzuca walidacja modelem (atrapa zrodla)."""
    dom_c = b.rejestr.dodaj_dom("Dom C")
    h = admin(b)
    url = f"/api/domy/{dom_c}/urzadzenia"
    _, _, ekran = call(b, "GET", url, headers=h)
    przed = _zrzut(b.cfg.panel_auth_path)
    cialo = {"wersja": ekran["dom"]["wersja"], "dzieci": [{"nazwa": "Dziecko C"}],
             "urzadzenia": [{"nazwa": "Telefon C", "dziecko": "Dziecko C",
                             "rodzaj": "phone-android", "source_ids": ["Telefon C"],
                             "nextdns_profile": "ZLY PROFIL"}]}
    st, _, body = call(b, "POST", f"{url}/zapisz", {**cialo, "confirm": HASLO}, headers=h)
    assert st == 400 and "„Telefon C”" in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed


# =================================================== pola administratora
def test_rola_domu_nie_wysle_pol_technicznych(b):
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran)
    cialo["urzadzenia"][0]["host"] = "192.0.2.9"
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, body = _zapisz(b, h, cialo)
    assert st == 403 and "administrator" in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed


def test_dns_adresu_przed_transakcja(b, monkeypatch):
    """Nazwa w `host` rozwiazywana PRZED BEGIN IMMEDIATE: resolver probuje
    zalozyc blokade zapisu bazy panelu — w transakcji zapisu by nie zdolal."""
    wywolania = []

    def resolver(host: str, port: int) -> list[str]:
        conn = sqlite3.connect(b.cfg.panel_auth_path, timeout=0, isolation_level=None)
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("ROLLBACK")
        finally:
            conn.close()
        wywolania.append(host)
        return ["192.0.2.9"]

    monkeypatch.setattr(straznik, "rozwiaz_systemowo", resolver)
    h = admin(b)
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran, admin_=True)
    cialo["urzadzenia"].append({"id": None, "nazwa": "iPad A", "dziecko": "Dziecko A",
                                "rodzaj": "ipad", "source_ids": ["ipad-a"],
                                "udid": "00000000-00000000000000A1",
                                "host": "ipad-a.example.invalid"})
    st, _, po = _zapisz(b, h, cialo)
    assert st == 200, po
    assert wywolania == ["ipad-a.example.invalid"]


def test_administrator_adres_przez_straznika_sieci(b):
    h = admin(b)
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran)
    cialo["urzadzenia"].append({"id": None, "nazwa": "iPad A", "dziecko": "Dziecko A",
                                "rodzaj": "ipad", "source_ids": ["ipad-a"],
                                "udid": "00000000-00000000000000A1", "host": "192.0.2.200"})
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, body = _zapisz(b, h, cialo)
    assert st == 400 and "poza siecią domu" in body["error"] and "dom-sieci" in body["error"]
    assert _zrzut(b.cfg.panel_auth_path) == przed
    cialo["urzadzenia"][-1]["host"] = "192.0.2.9"   # w SIEC_DOMU
    st, _, po = _zapisz(b, h, cialo)
    assert st == 200, po
    ipad = next(x for x in po["urzadzenia"] if x["nazwa"] == "iPad A")
    assert ipad["techniczne"]["host"] == "192.0.2.9" and ipad["chronione"]
    # Wlasciciel domu: flagi bez wartosci, usunac nie moze, zmienic nazwe moze.
    hw = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=hw)
    assert "192.0.2.9" not in repr(ekran) and "00A1" not in repr(ekran)
    wpis = next(x for x in ekran["urzadzenia"] if x["nazwa"] == "iPad A")
    assert wpis["administrator"]["udid"] and wpis["administrator"]["host"]
    bez_ipada = _cialo(ekran)
    bez_ipada["urzadzenia"] = [x for x in bez_ipada["urzadzenia"] if x["nazwa"] != "iPad A"]
    st, _, body = _zapisz(b, hw, bez_ipada)
    assert st == 400 and "administrator instalacji" in body["error"], body
    zmiana = _cialo(ekran)
    next(x for x in zmiana["urzadzenia"] if x["nazwa"] == "iPad A")["nazwa"] = "iPad A2"
    st, _, po = _zapisz(b, hw, zmiana)
    assert st == 200, po
    wiersz = next(x for x in b.rejestr.dane_domu(DOM_B).urzadzenia if x["nazwa"] == "iPad A2")
    assert wiersz["udid"] == "00000000-00000000000000A1" and wiersz["host"] == "192.0.2.9"
    for _, _, opis in _audyt(b.cfg.panel_auth_path):
        assert "192.0.2.9" not in opis and "00A1" not in opis, opis


# ============================================================ sekrety
def test_integracje_i_sekrety_nietkniete_kanarek_nigdzie(b, caplog):
    caplog.set_level(logging.DEBUG)
    s = Slady(b, caplog)
    h = sso(b, "wlasciciel-b")
    integracje = b.rejestr.integracje(DOM_B)
    sekrety = b.rejestr.sekrety_domu(DOM_B, b.sejf).pola()
    _, _, ekran = s.zapisz(call(b, "GET", URL, headers=h))
    cialo = _cialo(ekran)
    cialo["urzadzenia"][0]["source_ids"] = ["urz-a", "urz-a2"]
    st, _, po = s.zapisz(_zapisz(b, h, cialo))
    assert st == 200, po
    zly = _cialo(po)                                   # aktualna wersja: sciezka 400
    zly["urzadzenia"][0]["dziecko"] = "Ktos Inny"
    st, _, body = s.zapisz(_zapisz(b, h, zly))
    assert st == 400, body
    _, _, ekran_admina = call(b, "GET", URL, headers=admin(b))
    zly = _cialo(ekran_admina, admin_=True)            # administrator: walidator modelu
    zly["urzadzenia"][0]["nextdns_profile"] = "ZLY PROFIL"
    st, _, body = s.zapisz(_zapisz(b, admin(b), zly))
    assert st == 400 and "nextdns_profile" in body["error"], body
    s.zapisz(call(b, "GET", URL, headers=admin(b)))
    assert [(i.typ, i.wlaczona, i.ustawienia, i.sekrety_pola)
            for i in b.rejestr.integracje(DOM_B)] == [
        (i.typ, i.wlaczona, i.ustawienia, i.sekrety_pola) for i in integracje]
    assert b.rejestr.sekrety_domu(DOM_B, b.sejf).pola() == sekrety
    assert b.rejestr.sekrety_domu(DOM_B, b.sejf).get("nextdns", "api_key") == \
        b.kanarki["nextdns"]
    assert s.przecieki(*b.kanarki.values()) == []


# ===================================================== Dom 1 (produkcja)
def _ctx(dom_id: int, *, admin_: bool = False) -> KontekstDomu:
    return KontekstDomu(dom_id, "Dom", u.ROLE_DOMU_UPRAWNIENIA[u.ROLA_WLASCICIEL_DOMU],
                        administracja=False, admin=admin_)


def test_dom1_wlasciciel_nie_zmienia_ipadow(dom1, kek, caplog):
    """Dom 1 w trybie `baza` na ksztalcie produkcji (UDID, host, known_apps,
    UniFi, telewizor, ntfy, HA, MDM): wlasciciel zmienia nazwe iPada i jego
    nazwe w NextDNS. UDID, adres, MAC, lista aplikacji, telewizor,
    integracje, sekrety i ustawienia domu — bez zmian; HomeConfig rozni sie
    tylko nazwa i source_ids."""
    caplog.set_level(logging.DEBUG)
    sejf = Sejf(kek)
    assert _importuj(dom1, sejf).zapisano
    rejestr: dm.RejestrDomow = dom1["rejestr"]
    auth = PanelAuth(dom1["inst"].panel_auth_path)
    session = auth.login("konto-a", HASLO).session
    p = PanelUrzadzenia(auth, lambda: sejf, resolver=_rozwiaz)
    przed_home = zbuduj_dom(rejestr, DOM_1, sejf, materializuj=False)
    przed = rejestr.dane_domu(DOM_1)
    przed_sekrety = rejestr.sekrety_domu(DOM_1, sejf)

    ekran = p.lista(session, _ctx(DOM_1))
    tekst = repr(ekran)
    for wartosc in ("00000000-0000000000000001", "192.0.2.10", "02:00:00:00:00:01",
                    "192.0.2.12", "com.example.gra"):
        assert wartosc not in tekst, wartosc
    assert [x["nazwa"] for x in ekran["urzadzenia"]] == [
        "iPad Dziecka 1", "iPad Dziecka 1 b", "Telefon Dziecka 2"]   # bez telewizora
    ipad = ekran["urzadzenia"][0]
    assert ipad["administrator"] == {"udid": True, "host": True, "unifi_mac": True,
                                     "unifi_ip": False, "mdm": False, "known_apps": True,
                                     "nextdns_profile": True}
    assert ekran["profil_nextdns"] == "abc123"
    # Administrator widzi wartosci.
    assert p.lista(session, _ctx(DOM_1, admin_=True))["urzadzenia"][0]["techniczne"][
        "udid"] == "00000000-0000000000000001"

    cialo = _cialo(ekran)
    cialo["urzadzenia"][0]["nazwa"] = "iPad Dziecka 1 nowy"
    cialo["urzadzenia"][0]["source_ids"] = ["iPad-1", "iPad-1-nowy"]
    wynik = p.zapisz(session, {**cialo, "confirm": HASLO}, _ctx(DOM_1))
    assert wynik["ok"] and wynik["dom"]["wersja"] == ekran["dom"]["wersja"] + 1

    po = rejestr.dane_domu(DOM_1)
    stary, nowy = przed.urzadzenia[0], po.urzadzenia[0]
    assert nowy["nazwa"] == "iPad Dziecka 1 nowy"
    for pole in ("udid", "host", "unifi_mac", "unifi_ip", "mdm", "ustawienia",
                 "nextdns_profile", "rodzaj", "dziecko"):
        assert nowy[pole] == stary[pole], pole
    assert po.urzadzenia[1:] == przed.urzadzenia[1:]           # reszta i telewizor
    assert [(i.typ, i.wlaczona, i.ustawienia, i.sekrety_pola) for i in po.integracje] == [
        (i.typ, i.wlaczona, i.ustawienia, i.sekrety_pola) for i in przed.integracje]
    assert (po.dom.ustawienia, po.dom.strefa, po.dom.dozwolone_sieci) == (
        przed.dom.ustawienia, przed.dom.strefa, przed.dom.dozwolone_sieci)
    assert rejestr.sekrety_domu(DOM_1, sejf).pola() == przed_sekrety.pola()
    po_home = zbuduj_dom(rejestr, DOM_1, sejf, materializuj=False)
    assert porownaj(przed_home, po_home) == [
        "devices[0].display_name: rozne", "devices[0].source_ids: rozne"]
    assert po_home.devices[0].udid == przed_home.devices[0].udid
    assert po_home.devices[0].known_apps == {"com.example.gra": "Gra"}
    # Audyt: nazwy pol, bez UDID-u i adresow; kanarki nigdzie.
    opis = _audyt(dom1["inst"].panel_auth_path, "dom.urzadzenia.zapis")[-1][2]
    assert "pola: nazwa, source_ids" in opis
    for wartosc in ("00000000-0000000000000001", "192.0.2.10", "02:00:00:00:00:01"):
        assert wartosc not in opis
    tekst = repr(wynik) + caplog.text
    for k in dom1["kanarki"].values():
        assert k not in tekst


def test_dom1_wlasciciel_nie_usunie_ipada_z_udid(dom1, kek):
    sejf = Sejf(kek)
    assert _importuj(dom1, sejf).zapisano
    auth = PanelAuth(dom1["inst"].panel_auth_path)
    session = auth.login("konto-a", HASLO).session
    p = PanelUrzadzenia(auth, lambda: sejf)
    ekran = p.lista(session, _ctx(DOM_1))
    cialo = _cialo(ekran)
    cialo["urzadzenia"] = cialo["urzadzenia"][1:]
    przed = _zrzut(dom1["inst"].panel_auth_path)
    with pytest.raises(AuthError) as exc:
        p.zapisz(session, {**cialo, "confirm": HASLO}, _ctx(DOM_1))
    assert exc.value.status == 400 and "administrator instalacji" in exc.value.message
    # Zmiana rodzaju iPada z UDID na telefon — walidator configu (lockdown).
    cialo = _cialo(ekran)
    cialo["urzadzenia"][0]["rodzaj"] = "phone-android"
    with pytest.raises(AuthError) as exc:
        p.zapisz(session, {**cialo, "confirm": HASLO}, _ctx(DOM_1))
    assert exc.value.status == 400 and "udid" in exc.value.message
    assert "00000000-0000000000000001" not in exc.value.message
    assert _zrzut(dom1["inst"].panel_auth_path) == przed


# ===================================================== profil NextDNS (#86)
def test_profil_nextdns_ustawia_tylko_administrator(b):
    """Obcy profil czytalby kluczem API domu cudze logi, a czas gry blokowalby
    w nim gry: rola domu (takze zarzadca) profilu nie ustawia — 403 z wpisem
    w audycie. Widzi go tylko do odczytu; nowe urzadzenie dziecka dziedziczy
    profil jego pozostalych urzadzen."""
    h = sso(b, "zarzadca-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran)
    cialo["urzadzenia"][0]["nextdns_profile"] = "obcy123"
    przed = _zrzut(b.cfg.panel_auth_path)
    st, _, body = _zapisz(b, h, cialo)
    assert st == 403 and "administrator" in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed
    odmowa = _audyt(b.cfg.panel_auth_path, "dom.urzadzenia.odmowa")
    assert odmowa and odmowa[-1][0] == "zarzadca-b" and "nextdns_profile" in odmowa[-1][2]
    assert "obcy123" not in odmowa[-1][2]
    # Administrator ustawia profil dziecka.
    ha = admin(b)
    _, _, ekran_a = call(b, "GET", URL, headers=ha)
    cialo = _cialo(ekran_a, admin_=True)
    cialo["urzadzenia"][0]["nextdns_profile"] = "dziecko1"
    st, _, body = _zapisz(b, ha, cialo)
    assert st == 200, body
    # Rola domu: widzi profil, dodaje urzadzenie temu dziecku — profil dziedziczony,
    # zmienia nazwe — profil zostaje.
    _, _, ekran = call(b, "GET", URL, headers=h)
    assert ekran["urzadzenia"][0]["nextdns_profile"] == "dziecko1"
    cialo = _cialo(ekran)
    cialo["urzadzenia"][0]["nazwa"] = "Telefon A"
    cialo["urzadzenia"].append({"id": None, "nazwa": "iPad A", "dziecko": "Dziecko A",
                                "rodzaj": "ipad", "source_ids": ["ipad-a"]})
    st, _, po = _zapisz(b, h, cialo)
    assert st == 200, po
    assert {x["nazwa"]: x["nextdns_profile"] for x in po["urzadzenia"]} == {
        "Telefon A": "dziecko1", "iPad A": "dziecko1"}


# ============================================ filtr wartosci technicznych
def test_blad_startu_i_przeladowania_bez_wartosci_technicznych_dla_roli_domu(b, caplog):
    """Blad startu (walidator powtarza adres urzadzenia) i blad przeladowania
    (adres UniFi, UDID) — rola domu dostaje je bez wartosci, administrator
    z wartosciami. Log tez bez nich."""
    caplog.set_level(logging.DEBUG)
    ipv6 = "2001:db8::7"
    udid = "00000000-00000000000000B2"
    with sqlite3.connect(b.cfg.panel_auth_path) as conn:
        dz = conn.execute("SELECT id FROM dzieci WHERE dom_id = ?", (DOM_B,)).fetchone()[0]
        conn.execute("INSERT INTO urzadzenia (dom_id, dziecko_id, rodzaj, nazwa, source_ids, "
                     "udid, host) VALUES (?, ?, 'ipad', 'iPad X', ?, ?, ?)",
                     (DOM_B, dz, '["ipad-x"]', udid, ipv6))
    wersja = b.rejestr.dom(DOM_B).wersja
    b.stany.ustaw(DOM_B, dm.StanDomu(wersja - 1, nieudana=wersja,
                                     blad=f"unifi: https://192.0.2.5 i {udid} nie odpowiada"))
    _, _, rola = call(b, "GET", URL, headers=sso(b, "wlasciciel-b"))
    _, _, adm = call(b, "GET", URL, headers=admin(b))
    assert rola["start"] and "IPv6" in rola["start"], rola["start"]
    for tekst in (rola["start"], rola["przeladowanie"]["blad"], repr(rola)):
        assert ipv6 not in tekst and udid not in tekst and "192.0.2.5" not in tekst, tekst
    assert ipv6 in adm["start"]
    assert udid in adm["przeladowanie"]["blad"] and "192.0.2.5" in adm["przeladowanie"]["blad"]
    # Odmowa zapisu administratora (ten sam blad walidacji): w odpowiedzi
    # dla niego wartosc jest, w logu — nie.
    st, _, body = _zapisz(b, admin(b), _cialo(adm, admin_=True))
    assert st == 400 and ipv6 in body["error"], body
    assert ipv6 not in caplog.text and udid not in caplog.text


# ========================================================== obce wiersze
def test_id_dziecka_i_urzadzenia_z_innego_domu_400(b):
    dom_c = b.rejestr.dodaj_dom("Dom C")
    _dziecko_z_urzadzeniem(b.rejestr, dom_c, "phone-android")
    obce = b.rejestr.dane_domu(dom_c)
    with sqlite3.connect(b.cfg.panel_auth_path) as conn:
        id_dziecka = conn.execute("SELECT id FROM dzieci WHERE dom_id = ?", (dom_c,)).fetchone()[0]
        id_urz = conn.execute("SELECT id FROM urzadzenia WHERE dom_id = ?", (dom_c,)).fetchone()[0]
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    przed = _zrzut(b.cfg.panel_auth_path)
    cialo = _cialo(ekran)
    cialo["urzadzenia"].append({"id": id_urz, "nazwa": "Przejete", "dziecko": "Dziecko A",
                                "rodzaj": "phone-android", "source_ids": ["x"]})
    st, _, body = _zapisz(b, h, cialo)
    assert st == 400 and "Nieznane urządzenie" in body["error"], body
    cialo = _cialo(ekran)
    cialo["dzieci"] = [{"id": id_dziecka, "nazwa": "Dziecko A"}]
    st, _, body = _zapisz(b, h, cialo)
    assert st == 400 and "Nieznane dziecko" in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed
    assert b.rejestr.dane_domu(dom_c).urzadzenia == obce.urzadzenia


# ================================================ imiona dzieci poza `dzieci`
def _dwoje_dzieci(b) -> dict:
    """Dom B z Dzieckiem A i Dzieckiem B; zakresy powiadomien: wlasciciel-b
    tylko A, zarzadca-b A i B; otwarte i zamkniete zadanie czasu gry dla A;
    oczekujacy kod komendy z WhatsAppa dla A."""
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran)
    cialo["dzieci"].append({"id": None, "nazwa": "Dziecko B"})
    cialo["urzadzenia"].append({"id": None, "nazwa": "Telefon B", "dziecko": "Dziecko B",
                                "rodzaj": "phone-android", "source_ids": ["telefon b"]})
    st, _, ekran = _zapisz(b, h, cialo)
    assert st == 200, ekran
    pref = ProfilePowiadomien(b.cfg.panel_auth_path, dom_id=DOM_B)
    pref.ustaw_preferencje("wlasciciel-b", kategorie=None, dzieci=["Dziecko A"])
    pref.ustaw_preferencje("zarzadca-b", kategorie=None, dzieci=["Dziecko A", "Dziecko B"])
    gry = GameRequests(b.cfg.panel_auth_path, dom_id=DOM_B)
    zamkniete = gry.submit("Dziecko A", "block", None, "wlasciciel-b")
    with sqlite3.connect(b.cfg.panel_auth_path) as conn:
        conn.execute("UPDATE game_requests SET done_at = 1, ok = 1 WHERE id = ?", (zamkniete,))
    otwarte = gry.submit("Dziecko A", "block", None, "wlasciciel-b")
    BazaKomend(b.cfg.panel_auth_path).nowy_kod(
        "numer-testowy-1", Konto(b.auth.user_id("wlasciciel-b"), "wlasciciel-b"), DOM_B,
        Komenda("blokada", dziecko="Dziecko A"), llm=False, wiadomosc_id=None, waznosc=600)
    return {"h": h, "ekran": ekran, "zamkniete": zamkniete, "otwarte": otwarte}


def _stan_imion(b) -> dict:
    with sqlite3.connect(b.cfg.panel_auth_path) as conn:
        return {
            "zakresy": dict(conn.execute(
                "SELECT u.login, cp.dzieci FROM czlonkostwa_powiadomienia cp JOIN users u "
                "ON u.id = cp.user_id WHERE cp.dom_id = ?", (DOM_B,)).fetchall()),
            "gry": {r[0]: r[1:] for r in conn.execute(
                "SELECT id, child, done_at IS NULL, error FROM game_requests")},
            "kody": [r[0] for r in conn.execute("SELECT komenda FROM whatsapp_komendy_kody")],
        }


def test_zmiana_imienia_dziecka_przemapowuje_zakresy_zadania_i_kody(b):
    d = _dwoje_dzieci(b)
    cialo = _cialo(d["ekran"])
    a = next(x for x in cialo["dzieci"] if x["nazwa"] == "Dziecko A")
    a["nazwa"] = "Dziecko A2"
    for x in cialo["urzadzenia"]:
        if x["dziecko"] == "Dziecko A":
            x["dziecko"] = "Dziecko A2"
    st, _, body = _zapisz(b, d["h"], cialo)
    assert st == 200, body
    stan = _stan_imion(b)
    assert stan["zakresy"] == {"wlasciciel-b": '["Dziecko A2"]',
                               "zarzadca-b": '["Dziecko A2", "Dziecko B"]'}
    assert stan["gry"][d["otwarte"]] == ("Dziecko A2", 1, None)
    assert stan["gry"][d["zamkniete"]][0] == "Dziecko A"        # historia bez zmian
    assert '"dziecko": "Dziecko A2"' in stan["kody"][0]
    assert "zakresy powiadomien 2" in _audyt(b.cfg.panel_auth_path,
                                             "dom.urzadzenia.zapis")[-1][2]


def test_usuniecie_dziecka_jedynego_w_zakresie_400_inaczej_zdjete(b):
    d = _dwoje_dzieci(b)
    bez_a = _cialo(d["ekran"])
    bez_a["dzieci"] = [x for x in bez_a["dzieci"] if x["nazwa"] != "Dziecko A"]
    bez_a["urzadzenia"] = [x for x in bez_a["urzadzenia"] if x["dziecko"] != "Dziecko A"]
    przed, przed_imion = _zrzut(b.cfg.panel_auth_path), _stan_imion(b)
    st, _, body = _zapisz(b, d["h"], bez_a)
    assert st == 400 and "wlasciciel-b" in body["error"] and "zakres" in body["error"], body
    assert _zrzut(b.cfg.panel_auth_path) == przed and _stan_imion(b) == przed_imion
    # Wlasciciel zmienia swoj zakres — teraz usuniecie przechodzi.
    ProfilePowiadomien(b.cfg.panel_auth_path, dom_id=DOM_B).ustaw_preferencje(
        "wlasciciel-b", kategorie=None, dzieci=["Dziecko B"])
    st, _, body = _zapisz(b, d["h"], bez_a)
    assert st == 200, body
    stan = _stan_imion(b)
    assert stan["zakresy"] == {"wlasciciel-b": '["Dziecko B"]', "zarzadca-b": '["Dziecko B"]'}
    assert stan["gry"][d["otwarte"]] == ("Dziecko A", 0, DZIECKO_USUNIETE)
    assert stan["kody"] == []


def test_dom1_zmiana_imienia_takze_w_lustrze_preferencji(dom1, kek):
    """Dom 1: preferencje maja lustro w `user_powiadomienia` (odbiorcy._upsert)."""
    sejf = Sejf(kek)
    assert _importuj(dom1, sejf).zapisano
    path = dom1["inst"].panel_auth_path
    auth = PanelAuth(path)
    ProfilePowiadomien(path, dom_id=DOM_1).ustaw_preferencje(
        "konto-a", kategorie=None, dzieci=["Dziecko 1"])
    session = auth.login("konto-a", HASLO).session
    p = PanelUrzadzenia(auth, lambda: sejf)
    cialo = _cialo(p.lista(session, _ctx(DOM_1)))
    next(x for x in cialo["dzieci"] if x["nazwa"] == "Dziecko 1")["nazwa"] = "Dziecko 1 nowe"
    for x in cialo["urzadzenia"]:
        if x["dziecko"] == "Dziecko 1":
            x["dziecko"] = "Dziecko 1 nowe"
    p.zapisz(session, {**cialo, "confirm": HASLO}, _ctx(DOM_1))
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT dzieci FROM czlonkostwa_powiadomienia WHERE dom_id = 1"
                            ).fetchone()[0] == '["Dziecko 1 nowe"]'
        assert conn.execute("SELECT dzieci FROM user_powiadomienia").fetchone()[0] == \
            '["Dziecko 1 nowe"]'
