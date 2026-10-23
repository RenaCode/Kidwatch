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
from kidwatch import uprawnienia as u
from kidwatch.konfiguracja_domu import porownaj, zbuduj_dom
from kidwatch.panel_auth import AuthError, PanelAuth
from kidwatch.panel_domy import KontekstDomu
from kidwatch.panel_urzadzenia import OSTATNIE, PanelUrzadzenia
from kidwatch.sejf import Sejf
from test_domy_e2 import _importuj, dom1, kek  # noqa: F401 — fikstury
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


def _cialo(ekran: dict, **zmiany) -> dict:
    """Odpowiedz GET -> cialo zapisu bez zmian (rola domu: bez pol technicznych)."""
    return {
        "wersja": ekran["dom"]["wersja"],
        "dzieci": [{"id": d["id"], "nazwa": d["nazwa"]} for d in ekran["dzieci"]],
        "urzadzenia": [{k: x[k] for k in ("id", "nazwa", "dziecko", "rodzaj", "source_ids",
                                          "nextdns_profile")} for x in ekran["urzadzenia"]],
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
    st, _, body = _zapisz(b, h, _cialo(ekran))
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
    ({"nextdns_profile": "ZLY PROFIL"}, "nextdns_profile"),
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
    h = sso(b, "wlasciciel-b")
    _, _, ekran = call(b, "GET", URL, headers=h)
    cialo = _cialo(ekran)
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
    s.zapisz(_zapisz(b, h, cialo))
    zly = _cialo(ekran)
    zly["urzadzenia"][0]["nextdns_profile"] = "ZLY"
    s.zapisz(_zapisz(b, h, zly))                       # 400 (wersja juz inna -> 409)
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
                                     "unifi_ip": False, "mdm": False, "known_apps": True}
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
