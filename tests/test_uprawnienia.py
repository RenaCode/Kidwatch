"""Model uprawnien panelu (uprawnienia.py) i kompletnosc routera.

Kazda trasa panelu ma w panel.POST_TRASY albo panel.GET_TRASY jedno
uprawnienie. Testy ponizej biora liste tras Z ROUTERA, wiec nowa trasa bez
decyzji o uprawnieniu wywraca test, a nowa trasa z uprawnieniem, ktorego nie
ma `podglad`, automatycznie dostaje sprawdzenie 403.
"""

from __future__ import annotations

import inspect
import io
import re
from pathlib import Path

import pytest

from conftest import make_config, panel_login
from kidwatch import panel, panel_auth, uprawnienia
from kidwatch.__main__ import main
from kidwatch.config import PanelConfig, StoreConfig
from kidwatch.panel import GET_TRASY, POST_TRASY, PUBLICZNA, get_uprawnienie, start_panel, trasa
from kidwatch.panel_auth import PanelAuth
from kidwatch.panel_domy import PREFIKS_DOMU
from kidwatch.store import Store
from kidwatch.uprawnienia import ROLE_UPRAWNIENIA, ROLE_VIEWER, UPRAWNIENIA
from test_panel_auth import CONFIG
from test_panel_sso import call

HASLO = "dlugie-haslo-testowe"
UDID = "00008030-000A1B2C3D4E5F6A"
WEB = Path(__file__).resolve().parents[1] / "web" / "src"

#: Jedyne trasy bez sesji. Kazda nowa PUBLICZNA wymaga swiadomego dopisania.
PUBLICZNE_POST = {"/api/auth/login", "/api/auth/mfa", "/api/auth/logout"}
PUBLICZNE_GET = {"/api/health"}
PODGLAD = ROLE_UPRAWNIENIA[ROLE_VIEWER]


def _get_path(klucz: str) -> str:
    """Stara sciezka (alias Domu 1, jedyny dom konta) — tak wola front sprzed
    domow i tak dzialaja testy ponizej. Sciezki z domem: test_domy_panel.py."""
    klucz = klucz.replace(PREFIKS_DOMU, "/api")
    return klucz + UDID if klucz.endswith("/") else klucz


def _zakres_zgodny(path: str, uprawnienie: str, zakres: str) -> None:
    """Trasa domu lezy pod prefiksem domu i odwrotnie; uprawnienie domu nie
    wisi na trasie bez domu, a instancji — na trasie domu."""
    assert zakres in (uprawnienia.ZAKRES_KONTO, uprawnienia.ZAKRES_DOM,
                      uprawnienia.ZAKRES_INSTANCJA), (path, zakres)
    assert path.startswith(PREFIKS_DOMU + "/") == (zakres == uprawnienia.ZAKRES_DOM), path
    if uprawnienie != PUBLICZNA:
        if uprawnienia.ZAKRESY[uprawnienie] == uprawnienia.ZAKRES_DOM:
            assert zakres == uprawnienia.ZAKRES_DOM, path
        if uprawnienia.ZAKRESY[uprawnienie] == uprawnienia.ZAKRES_INSTANCJA:
            assert zakres == uprawnienia.ZAKRES_INSTANCJA, path


# ===================================================================== router
@pytest.mark.parametrize("path", sorted(POST_TRASY))
def test_kazda_trasa_POST_ma_uprawnienie_zakres_i_handler(path):
    uprawnienie, metoda, zakres = POST_TRASY[path]
    assert uprawnienie in UPRAWNIENIA or (uprawnienie == PUBLICZNA and path in PUBLICZNE_POST), (
        f"{path}: trasa bez decyzji o uprawnieniu ({uprawnienie!r})"
    )
    _zakres_zgodny(path, uprawnienie, zakres)
    handler = panel.make_handler(None, Path("."), None)
    assert callable(getattr(handler, metoda, None)), f"{path}: brak metody {metoda}"


@pytest.mark.parametrize("path", sorted(GET_TRASY))
def test_kazda_trasa_GET_ma_uprawnienie_i_zakres(path):
    uprawnienie, zakres = GET_TRASY[path]
    assert uprawnienie in UPRAWNIENIA or (uprawnienie == PUBLICZNA and path in PUBLICZNE_GET)
    _zakres_zgodny(path, uprawnienie, zakres)


def test_router_nie_ma_tras_poza_tabelami():
    """do_POST nie zna zadnej sciezki na sztywno, _api nie obsluguje sciezki
    spoza GET_TRASY, a PUT/PATCH/DELETE nie istnieja (dostalyby 501 od
    http.server). Dopisanie trasy obok tabeli wywraca ten test."""
    zrodlo = inspect.getsource(panel.make_handler)
    post = zrodlo[zrodlo.index("def do_POST"):zrodlo.index("def _authed")]
    assert not re.findall(r'"/api/', post), "do_POST ma trase poza POST_TRASY"
    api = zrodlo[zrodlo.index("def _api"):zrodlo.index("def _export")]
    for p in set(re.findall(r'"(/api/[^"]*)"', api)):
        assert get_uprawnienie(p) is not None, f"GET {p} bez wpisu w GET_TRASY"
    domu = zrodlo[zrodlo.index("def _api_domu"):zrodlo.index("def _export")]
    for p in set(re.findall(r'"(/[a-z][^"]*)"', domu)) - {"/api"}:
        if p.endswith("/"):  # prefiks rozdzielajacy handlery, nie trasa
            assert any(k.startswith(PREFIKS_DOMU + p) for k in GET_TRASY), p
        else:
            assert PREFIKS_DOMU + p in GET_TRASY, f"GET domu {p} bez wpisu w GET_TRASY"
    metody = set(re.findall(r"def (do_[A-Z]+)\(", zrodlo))
    assert metody == {"do_GET", "do_HEAD", "do_POST"}, metody
    # Zadna metoda nie sprawdza juz roli po swojemu — tylko _wymaga().
    assert "ROLE_OWNER" not in inspect.getsource(panel)
    assert zrodlo.count("not in uprawnienia") == 1
    assert "session.uprawnienia" not in zrodlo


def test_prefiks_GET_tylko_z_dalsza_sciezka():
    assert get_uprawnienie(f"/api/mdm/devices/{UDID}") == uprawnienia.MDM_PODGLAD
    assert get_uprawnienie(f"/api/domy/2/mdm/devices/{UDID}") == uprawnienia.MDM_PODGLAD
    assert get_uprawnienie("/api/mdm/devices/") is None
    assert get_uprawnienie("/api/nieznana") is None


def test_trasa_rozpoznaje_dom_alias_i_odrzuca_reszte():
    t = trasa("GET", "/api/domy/12/day")
    assert (t.klucz, t.dom_id, t.alias) == (f"{PREFIKS_DOMU}/day", 12, False)
    t = trasa("GET", "/api/day")
    assert (t.klucz, t.dom_id, t.alias) == (f"{PREFIKS_DOMU}/day", None, True)
    assert trasa("POST", "/api/domy/3/mdm/command").metoda == "_mdm_post"
    # Trasa bez domu nie istnieje pod prefiksem domu i odwrotnie.
    assert trasa("GET", "/api/domy/1/auth/me") is None
    assert trasa("POST", "/api/domy/1/profile/test") is None
    for zla in ("/api/domy/0/day", "/api/domy/-1/day", "/api/domy/x/day", "/api/domy/1",
                "/api/domy/01/day", "/api/domy/1/day/", "/api/domy/1/../day"):
        assert trasa("GET", zla) is None, zla


# ====================================================================== model
def test_wlasciciel_ma_wszystko_podglad_tylko_odczyt_i_wlasne_konto():
    assert ROLE_UPRAWNIENIA["wlasciciel"] == frozenset(UPRAWNIENIA)
    assert ROLE_UPRAWNIENIA[ROLE_VIEWER] == {"konto.wlasne", "podglad.historia"}
    assert uprawnienia.TV_PAUZA not in PODGLAD


def test_efektywne():
    e = uprawnienia.efektywne
    assert e("podglad", {"tv.pauza"}) == PODGLAD | {"tv.pauza"}
    assert e("wlasciciel", odebrane={"mdm.komendy"}) == frozenset(UPRAWNIENIA) - {"mdm.komendy"}
    # Nieznana rola (reczna edycja bazy) i proba odebrania wlasnego konta.
    assert e("admin") == {"konto.wlasne"}
    assert "konto.wlasne" in e("podglad", odebrane={"konto.wlasne"})
    # Nieznana nazwa w bazie niczego nie otwiera.
    assert e("podglad", {"root"}) == PODGLAD


@pytest.mark.parametrize(("zmiany", "blad"), [
    (["tv.pauza"], "zacznij od"),
    (["+tv.pauzy"], "nieznane uprawnienie"),
    (["-konto.wlasne"], "nie da sie go odebrac"),
])
def test_parsuj_zmiany_odrzuca(zmiany, blad):
    with pytest.raises(ValueError, match=blad):
        uprawnienia.parsuj_zmiany(zmiany)


def test_parsuj_zmiany():
    assert uprawnienia.parsuj_zmiany(["+tv.pauza", "-mdm.podglad", "=czas_gry.zmiana",
                                      "-tv.pauza"]) == {
        "tv.pauza": False, "mdm.podglad": False, "czas_gry.zmiana": None}


def test_front_uzywa_tylko_znanych_uprawnien():
    """Literowka w `can(user, 'tv.pauzza')` chowalaby przycisk wlascicielowi."""
    uzyte = set()
    for f in WEB.rglob("*.js*"):
        uzyte |= set(re.findall(r"can\(\s*user\s*,\s*'([^']+)'", f.read_text("utf-8")))
    assert uzyte, "front nie sprawdza uprawnien"
    assert uzyte <= set(UPRAWNIENIA), uzyte - set(UPRAWNIENIA)
    js = (WEB / "utils" / "uprawnienia.js").read_text("utf-8")
    assert set(re.findall(r"'([a-z_]+\.[a-z_]+)'", js)) == set(UPRAWNIENIA)


# ===================================================================== serwer
@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path)))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    auth = PanelAuth(cfg.panel_auth_path)
    auth.add_user("rodzic1", HASLO)
    auth.add_user("rodzic2", HASLO, panel_auth.ROLE_VIEWER)
    srv = start_panel(cfg)
    yield srv, auth
    srv.shutdown()


def naglowki(srv, login: str) -> dict[str, str]:
    c = panel_login(srv.server_address[1], login, HASLO)
    j = dict(x.split("=", 1) for x in c.split("; "))
    return {"Cookie": c, "X-CSRF-Token": j["kidwatch_csrf"]}


ZAMKNIETE_POST = sorted(_get_path(p) for p, (u, _, _) in POST_TRASY.items()
                        if u != PUBLICZNA and u not in PODGLAD)
ZAMKNIETE_GET = sorted(_get_path(p) for p, (u, _) in GET_TRASY.items()
                       if u != PUBLICZNA and u not in PODGLAD)


def test_listy_zamknietych_tras_nie_sa_puste():
    assert "/api/tv/pause" in ZAMKNIETE_POST and "/api/mdm/command" in ZAMKNIETE_POST
    assert "/api/mdm" in ZAMKNIETE_GET


@pytest.mark.parametrize("path", ZAMKNIETE_POST)
def test_podglad_403_na_kazda_zamknieta_trase_POST(server, path):
    srv, _ = server
    status, _, payload = call(srv, "POST", path, {}, naglowki(srv, "rodzic2"))
    assert status == 403 and trasa("POST", path).uprawnienie in payload["error"], (path, payload)
    status, _, payload = call(srv, "POST", path, {}, naglowki(srv, "rodzic1"))
    assert "nie ma uprawnienia" not in (payload or {}).get("error", ""), (path, payload)


@pytest.mark.parametrize("path", ZAMKNIETE_GET)
def test_podglad_403_na_kazda_zamknieta_trase_GET(server, path):
    srv, _ = server
    status, _, payload = call(srv, "GET", path, headers=naglowki(srv, "rodzic2"))
    assert status == 403 and "nie ma uprawnienia" in payload["error"], (path, payload)
    status, _, payload = call(srv, "GET", path, headers=naglowki(srv, "rodzic1"))
    assert "nie ma uprawnienia" not in (payload or {}).get("error", ""), (path, payload)


def test_403_bez_CSRF_sprawdzane_przed_uprawnieniem(server):
    """Brak CSRF to 403 CSRF, nie komunikat o uprawnieniu — kolejnosc jak
    przed modelem uprawnien (sesja, CSRF, uprawnienie)."""
    srv, _ = server
    h = naglowki(srv, "rodzic2")
    h["X-CSRF-Token"] = "zly"
    assert "CSRF" in call(srv, "POST", "/api/tv/pause", {"until": None}, h)[2]["error"]


def test_nadanie_tv_pauza_otwiera_trase_od_razu(server):
    srv, auth = server
    h = naglowki(srv, "rodzic2")
    assert auth.set_permissions("rodzic2", {"tv.pauza": True}) == 1  # wylogowuje
    assert call(srv, "GET", "/api/auth/me", headers=h)[0] == 401
    h = naglowki(srv, "rodzic2")
    me = call(srv, "GET", "/api/auth/me", headers=h)[2]
    assert "tv.pauza" in me["uprawnienia"] and me["rola"] == "podglad"
    # 404: czujnik TV wylaczony w tescie — ale juz nie 403.
    assert call(srv, "POST", "/api/tv/pause", {"until": None}, h)[0] == 404
    assert call(srv, "POST", "/api/game", {}, h)[0] == 403


def test_odebranie_wlascicielowi(server):
    srv, auth = server
    auth.set_permissions("rodzic1", {"mdm.podglad": False})
    h = naglowki(srv, "rodzic1")
    assert call(srv, "GET", "/api/mdm", headers=h)[0] == 403
    assert call(srv, "POST", "/api/mdm/enroll", {"label": "x"}, h)[0] == 404  # komendy zostaly
    auth.set_permissions("rodzic1", {"mdm.podglad": None})
    assert call(srv, "GET", "/api/mdm", headers=naglowki(srv, "rodzic1"))[0] == 200


def test_set_permissions_odrzuca_bez_zapisu(tmp_path):
    auth = PanelAuth(tmp_path / "a.db")
    auth.add_user("rodzic2", HASLO, "podglad")
    for zle in ({"root": True}, {"konto.wlasne": False}):
        with pytest.raises(ValueError):
            auth.set_permissions("rodzic2", zle)
    assert auth.list_users()[0]["odstepstwa"] == []
    with pytest.raises(panel_auth.UnknownUser):
        auth.set_permissions("nikt", {"tv.pauza": True})


# ======================================================================== CLI
def test_cli_user_uprawnienia(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO("haslo-ze-stdin-123\n"))
    assert main(["--config", str(cfg), "user-add", "rodzic2", "--rola", "podglad",
                 "--password-stdin"]) == 0
    capsys.readouterr()
    base = ["--config", str(cfg), "user-uprawnienia", "rodzic2"]

    assert main([*base, "+tv.pauza", "-podglad.historia"]) == 0
    assert main(["--config", str(cfg), "user-list"]) == 0
    assert "rola: podglad (-podglad.historia +tv.pauza)" in capsys.readouterr().out
    assert main(base) == 0
    out = capsys.readouterr().out
    assert "[x] tv.pauza" in out and "[ ] podglad.historia" in out and "[x] konto.wlasne" in out

    assert main([*base, "=podglad.historia"]) == 0
    assert main([*base, "-konto.wlasne"]) == 1
    assert main([*base, "+tv.pauzy"]) == 1
    assert main(["--config", str(cfg), "user-uprawnienia", "nikt", "+tv.pauza"]) == 1
    auth = PanelAuth(tmp_path / "panel-auth.db")
    assert auth.list_users()[0]["odstepstwa"] == ["+tv.pauza"]

    # Zmiana roli kasuje odstepstwa — nie przechodza po cichu na nowa role.
    assert main(["--config", str(cfg), "user-rola", "rodzic2", "wlasciciel"]) == 0
    # Jedyne konto z zarzadzaniem kontami w domu nie spadnie do podgladu...
    assert main(["--config", str(cfg), "user-rola", "rodzic2", "podglad"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("haslo-ze-stdin-456\n"))
    assert main(["--config", str(cfg), "user-add", "rodzic1", "--password-stdin"]) == 0
    # ...dopoki nie ma drugiego.
    assert main(["--config", str(cfg), "user-rola", "rodzic2", "podglad"]) == 0
    u = next(u for u in auth.list_users() if u["login"] == "rodzic2")
    assert u["odstepstwa"] == [] and "tv.pauza" not in u["uprawnienia"]


def test_usuniecie_konta_kasuje_odstepstwa(tmp_path):
    auth = PanelAuth(tmp_path / "a.db")
    auth.add_user("rodzic2", HASLO, "podglad")
    auth.set_permissions("rodzic2", {"tv.pauza": True})
    auth.delete_user("rodzic2")
    auth.add_user("rodzic2", HASLO, "podglad")
    assert auth.list_users()[0]["odstepstwa"] == []
