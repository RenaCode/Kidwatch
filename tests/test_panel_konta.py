"""Panel: wlasny profil powiadomien (/api/konto/*) i zarzadzanie kontami
(/api/konta/*, uprawnienie konta.zarzadzanie).

Bezpieczenstwo: nikt nie zmieni kanalow cudzego konta bez uprawnienia,
zmiana kanalu wymaga hasla albo kodu 2FA, pelny numer nie wraca do
przegladarki, dom nie zostaje bez konta zarzadzajacego.
"""

from __future__ import annotations

import json

import pytest

from conftest import make_config, panel_login
from kidwatch import odbiorcy as o
from kidwatch import uprawnienia as u
from kidwatch.config import PanelConfig, StoreConfig
from kidwatch.panel import start_panel
from kidwatch.panel_auth import PanelAuth
from kidwatch.store import Store
from test_panel_sso import call

HASLO = "dlugie-haslo-testowe"
NR = "48500100201"
NR2 = "48500100202"
#: Dziecko z make_config (conftest).
DZIECKO = "Zosia"


@pytest.fixture
def srv(tmp_path):
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path)))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    auth = PanelAuth(cfg.panel_auth_path)
    auth.add_user("rodzic1", HASLO)
    auth.add_user("rodzic2", HASLO, u.ROLE_VIEWER)
    server = start_panel(cfg)
    server.konta = o.ProfilePowiadomien(cfg.panel_auth_path)
    server.auth = auth
    yield server
    server.shutdown()


def h(srv, login, haslo=HASLO):
    c = panel_login(srv.server_address[1], login, haslo)
    j = dict(x.split("=", 1) for x in c.split("; "))
    return {"Cookie": c, "X-CSRF-Token": j["kidwatch_csrf"]}


# ========================================================= wlasny profil
def test_wlasny_profil_kanaly_z_potwierdzeniem_i_zamaskowane(srv):
    hh = h(srv, "rodzic2")
    status, _, body = call(srv, "GET", "/api/konto/powiadomienia", headers=hh)
    assert status == 200 and body["profil"]["login"] == "rodzic2"
    assert body["profil"]["dozwolone"] == [o.SESJE, o.ALARMY, o.RAPORTY, o.GRA]
    assert [k["id"] for k in body["kategorie"]] == list(o.KATEGORIE)

    st, _, b = call(srv, "POST", "/api/konto/kanaly", {"whatsapp": NR}, hh)
    assert st == 401  # bez potwierdzenia
    st, _, b = call(srv, "POST", "/api/konto/kanaly", {"whatsapp": NR, "confirm": "zle"}, hh)
    assert st == 401
    assert srv.konta.profil("rodzic2").whatsapp is None
    st, _, b = call(srv, "POST", "/api/konto/kanaly",
                    {"whatsapp": "+48 500 100 201", "email": "ja@poczta.pl",
                     "confirm": HASLO}, hh)
    assert st == 200, b
    assert NR not in json.dumps(b) and "ja@poczta.pl" not in json.dumps(b)
    assert b["profil"]["whatsapp"] == "...201" and b["profil"]["ma_kanal"] is True
    p = srv.konta.profil("rodzic2")
    assert (p.whatsapp, p.email) == (NR, "ja@poczta.pl")


def test_login_w_ciele_nie_zmienia_cudzego_konta(srv):
    st, _, _ = call(srv, "POST", "/api/konto/kanaly",
                    {"login": "rodzic1", "whatsapp": NR2, "confirm": HASLO}, h(srv, "rodzic2"))
    assert st == 200
    assert srv.konta.profil("rodzic1").whatsapp is None
    assert srv.konta.profil("rodzic2").whatsapp == NR2


def test_zly_numer_odrzucony_przed_haslem(srv):
    """Literowka w numerze nie zjada proby hasla (blokada konta po 5)."""
    hh = h(srv, "rodzic2")
    for _ in range(6):
        st, _, b = call(srv, "POST", "/api/konto/kanaly",
                        {"whatsapp": "123", "confirm": "zle-haslo"}, hh)
        assert st == 400, b
    assert call(srv, "POST", "/api/konto/kanaly", {"whatsapp": NR, "confirm": HASLO},
                hh)[0] == 200


def test_podglad_nie_wlaczy_sobie_mdm_ani_czujki(srv):
    hh = h(srv, "rodzic2")
    st, _, b = call(srv, "POST", "/api/konto/powiadomienia",
                    {"kategorie": [o.SESJE, o.MDM]}, hh)
    assert st == 400 and "uprawnienia" in b["error"]
    st, _, b = call(srv, "POST", "/api/konto/powiadomienia",
                    {"kategorie": [o.SESJE], "cisza_od": "22:00", "cisza_do": "07:00",
                     "dzieci": [DZIECKO]}, hh)
    assert st == 200, b
    assert b["profil"]["kategorie"] == [o.SESJE] and b["profil"]["cisza_od"] == "22:00"
    st, _, b = call(srv, "POST", "/api/konto/powiadomienia", {"dzieci": ["Obce"]}, hh)
    assert st == 400


# ===================================================== zarzadzanie kontami
KONTA_POST = ["/api/konta/dodaj", "/api/konta/usun", "/api/konta/rola",
              "/api/konta/uprawnienia", "/api/konta/powiadomienia", "/api/konta/kanaly",
              "/api/konta/tryb"]


@pytest.mark.parametrize("path", KONTA_POST)
def test_podglad_nie_zarzadza_kontami(srv, path):
    body = {"login": "rodzic1", "whatsapp": NR2, "rola": "podglad", "tryb": "konta",
            "zmiany": {"mdm.podglad": True}, "confirm": HASLO}
    st, _, b = call(srv, "POST", path, body, h(srv, "rodzic2"))
    assert st == 403, (path, b)
    assert srv.konta.profil("rodzic1").whatsapp is None
    assert srv.konta.profil("rodzic1").rola == u.ROLE_OWNER


def test_podglad_nie_widzi_listy_kont(srv):
    assert call(srv, "GET", "/api/konta", headers=h(srv, "rodzic2"))[0] == 403


def test_wlasciciel_zarzadza_kontem_innym(srv):
    hh = h(srv, "rodzic1")
    st, _, b = call(srv, "POST", "/api/konta/dodaj",
                    {"login": "domownik", "rola": "podglad", "confirm": HASLO}, hh)
    assert st == 200 and len(b["haslo"]) >= 12
    h(srv, "domownik", b["haslo"])  # nowe konto loguje sie podanym haslem
    st, _, b = call(srv, "POST", "/api/konta/dodaj",
                    {"login": "Duze Litery", "confirm": HASLO}, hh)
    assert st == 400

    # Kanal cudzego konta: tylko z potwierdzeniem wykonujacego.
    assert call(srv, "POST", "/api/konta/kanaly", {"login": "domownik", "whatsapp": NR2},
                hh)[0] == 401
    st, _, b = call(srv, "POST", "/api/konta/kanaly",
                    {"login": "domownik", "whatsapp": NR2, "confirm": HASLO}, hh)
    assert st == 200 and b["powiadomienia"]["whatsapp"] == "...202"

    st, _, b = call(srv, "POST", "/api/konta/uprawnienia",
                    {"login": "domownik", "zmiany": {"mdm.podglad": True}, "confirm": HASLO},
                    hh)
    assert st == 200, b
    st, _, b = call(srv, "POST", "/api/konta/powiadomienia",
                    {"login": "domownik", "kategorie": [o.SESJE, o.MDM], "confirm": HASLO}, hh)
    assert st == 200 and b["powiadomienia"]["kategorie"] == [o.SESJE, o.MDM]

    st, _, lista = call(srv, "GET", "/api/konta", headers=hh)
    assert st == 200
    by = {k["login"]: k for k in lista["konta"]}
    assert by["domownik"]["odstepstwa"] == ["+mdm.podglad"]
    assert by["rodzic1"]["ja"] is True
    assert NR2 not in json.dumps(lista)

    assert call(srv, "POST", "/api/konta/rola",
                {"login": "domownik", "rola": "wlasciciel", "confirm": HASLO}, hh)[0] == 200
    assert srv.konta.profil("domownik").rola == u.ROLE_OWNER
    assert call(srv, "POST", "/api/konta/usun",
                {"login": "domownik", "confirm": HASLO}, hh)[0] == 200
    assert srv.konta.profil("domownik") is None


def test_dom_nie_zostaje_bez_zarzadcy(srv):
    hh = h(srv, "rodzic1")
    st, _, b = call(srv, "POST", "/api/konta/usun", {"login": "rodzic1", "confirm": HASLO}, hh)
    assert st == 409
    st, _, b = call(srv, "POST", "/api/konta/rola",
                    {"login": "rodzic1", "rola": "podglad", "confirm": HASLO}, hh)
    assert st == 409, b
    st, _, b = call(srv, "POST", "/api/konta/uprawnienia",
                    {"login": "rodzic1", "zmiany": {u.KONTA: False}, "confirm": HASLO}, hh)
    assert st == 409, b
    assert srv.konta.profil("rodzic1").rola == u.ROLE_OWNER


def test_tryb_kont_dopiero_z_kanalem_zarzadcy(srv):
    hh = h(srv, "rodzic1")
    st, _, b = call(srv, "POST", "/api/konta/tryb", {"tryb": "konta", "confirm": HASLO}, hh)
    assert st == 409 and srv.konta.tryb() == o.TRYB_TRASY
    call(srv, "POST", "/api/konto/kanaly", {"email": "ja@poczta.pl", "confirm": HASLO}, hh)
    st, _, b = call(srv, "POST", "/api/konta/tryb", {"tryb": "konta", "confirm": HASLO}, hh)
    assert st == 200 and srv.konta.tryb() == o.TRYB_KONTA
    assert call(srv, "POST", "/api/konta/tryb", {"tryb": "trasy", "confirm": HASLO},
                hh)[0] == 200
    assert srv.konta.tryb() == o.TRYB_TRASY


def test_zmiana_jednego_kanalu_nie_kasuje_drugiego(srv):
    hh = h(srv, "rodzic2")
    call(srv, "POST", "/api/konto/kanaly", {"whatsapp": NR, "confirm": HASLO}, hh)
    call(srv, "POST", "/api/konto/kanaly", {"email": "ja@poczta.pl", "confirm": HASLO}, hh)
    p = srv.konta.profil("rodzic2")
    assert (p.whatsapp, p.email) == (NR, "ja@poczta.pl")
    call(srv, "POST", "/api/konto/kanaly", {"whatsapp": "", "confirm": HASLO}, hh)
    p = srv.konta.profil("rodzic2")
    assert (p.whatsapp, p.email) == (None, "ja@poczta.pl")
