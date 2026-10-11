"""Rola konta panelu: `wlasciciel` albo `podglad` (uprawnienia.ROLES).

`podglad` (np. osoba z rodziny w grupie Authelii `rodzina`) oglada historie,
ekrany, uzycie i powiadomienia. Nie wysyla komend MDM, nie zmienia czasu gry,
pauzy TV, WhatsAppa ani aplikacji TV — serwer odmawia 403 niezaleznie od
frontu. Rola pochodzi z bazy panelu, nigdy z naglowka SSO. Model uprawnien
i kompletnosc routera: test_uprawnienia.py.
"""

from __future__ import annotations

import io
import sqlite3

import pytest

from conftest import make_config, panel_login
from kidwatch import panel_auth, uprawnienia
from kidwatch.__main__ import PANEL_ROLES, main
from kidwatch.config import PanelConfig, StoreConfig
from kidwatch.panel import start_panel
from kidwatch.panel_auth import PanelAuth
from kidwatch.store import Store
from test_panel_auth import CONFIG
from test_panel_sso import call, cookie, jar

HASLO = "dlugie-haslo-testowe"
UDID = "00008030-000A1B2C3D4E5F6A"

#: Kazda czynnosc administracyjna: (metoda, sciezka, cialo).
ADMIN = [
    ("POST", "/api/game", {"child": "Dziecko", "action": "block"}),
    ("POST", "/api/tv/pause", {"until": None}),
    ("POST", "/api/tv/resume", {}),
    ("POST", "/api/tv/aplikacja/instaluj", {}),
    ("POST", "/api/tv/aplikacja/paruj", {"kod": "123456"}),
    ("POST", "/api/profile/whatsapp/start", {"confirm": HASLO}),
    ("POST", "/api/profile/whatsapp/logout", {"confirm": HASLO}),
    ("POST", "/api/profile/whatsapp/recipient", {"number": "48500100200", "confirm": HASLO}),
    ("POST", "/api/profile/whatsapp/recipients", {"recipients": [], "confirm": HASLO}),
    ("POST", "/api/profile/test", {"channel": "whatsapp"}),
    ("POST", "/api/mdm/refresh", {"udid": UDID}),
    ("POST", "/api/mdm/command", {"udid": UDID, "request_type": "DeviceLock"}),
    ("POST", "/api/mdm/enroll", {"label": "nowy"}),
    ("POST", "/api/mdm/os-update", {"clear": True}),
    ("GET", "/api/mdm", None),
    ("GET", f"/api/mdm/devices/{UDID}", None),
    ("GET", "/api/profile/notify", None),
    ("GET", "/api/profile/whatsapp/qr", None),
    ("GET", "/api/tv/aplikacja", None),
]
#: Podglad: to wolno.
VIEW = ["/api/meta", "/api/devices", "/api/notifications", "/api/day", "/api/usage",
        "/api/screens", "/api/trends", "/api/tv/pause", "/api/export.csv"]


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
    yield srv
    srv.shutdown()


def naglowki(srv, login: str) -> dict[str, str]:
    c = panel_login(srv.server_address[1], login, HASLO)
    j = dict(x.split("=", 1) for x in c.split("; "))
    return {"Cookie": c, "X-CSRF-Token": j["kidwatch_csrf"]}


@pytest.mark.parametrize(("method", "path", "body"), ADMIN)
def test_podglad_dostaje_403_na_kazda_czynnosc_administracyjna(server, method, path, body):
    status, _, payload = call(server, method, path, body, naglowki(server, "rodzic2"))
    assert status == 403, (path, payload)
    assert "nie ma uprawnienia" in payload["error"]


@pytest.mark.parametrize(("method", "path", "body"), ADMIN)
def test_wlasciciel_nie_jest_zatrzymany_rola(server, method, path, body):
    """Ta sama lista dla wlasciciela: inna odpowiedz (zwykle 404 — w tescie nie
    ma MDM, bramki ani TV; QR bota 403 za brak swiezego potwierdzenia), wiec
    odmowa wyzej pochodzi z roli, nie z czegos innego."""
    status, _, payload = call(server, method, path, body, naglowki(server, "rodzic1"))
    assert "uprawnienia" not in (payload or {}).get("error", ""), (path, payload)
    assert status != 403 or path == "/api/profile/whatsapp/qr", (path, payload)


@pytest.mark.parametrize("path", VIEW)
def test_podglad_widzi_ekrany_podgladu(server, path):
    assert call(server, "GET", path, headers=naglowki(server, "rodzic2"))[0] == 200, path


def test_podglad_bez_pauzy_TV_ale_z_wlasnym_kontem(server):
    """Pauza TV wylacza liczenie czasu i powiadomienia o telewizorze — to
    zmiana nadzoru, nie podglad (decyzja wlasciciela, 2026-10-11). Wlasciciel
    dostaje 404 tylko dlatego, ze w tescie czujnik TV jest wylaczony."""
    h = naglowki(server, "rodzic2")
    for path, body in (("/api/tv/pause", {"until": None}), ("/api/tv/resume", {})):
        status, _, payload = call(server, "POST", path, body, h)
        assert status == 403 and "tv.pauza" in payload["error"], (path, payload)
        assert call(server, "POST", path, body, naglowki(server, "rodzic1"))[0] == 404
    assert call(server, "POST", "/api/auth/totp/setup", {}, h)[0] == 200
    assert call(server, "POST", "/api/auth/password",
                {"old": "zle-haslo-zle-haslo", "new": "nowe-haslo-123456"}, h)[0] == 401
    assert call(server, "POST", "/api/auth/logout", {}, h)[0] == 200


def test_me_podaje_role_i_uprawnienia(server):
    me = call(server, "GET", "/api/auth/me", headers=naglowki(server, "rodzic2"))[2]
    assert me["rola"] == "podglad"
    assert me["uprawnienia"] == ["konto.wlasne", "podglad.historia"]
    me = call(server, "GET", "/api/auth/me", headers=naglowki(server, "rodzic1"))[2]
    assert me["rola"] == "wlasciciel"
    assert me["uprawnienia"] == sorted(uprawnienia.UPRAWNIENIA)


@pytest.mark.parametrize(("login", "grupa", "rola"), [
    ("rodzic2", "wlasciciel", "podglad"),   # grupa nie podnosi roli
    ("rodzic1", "rodzina", "wlasciciel"),    # ani jej nie obniza
])
def test_rola_z_bazy_nie_z_naglowka_SSO(server, login, grupa, rola):
    status, headers, me = call(server, "GET", "/api/auth/me",
                               headers={"Remote-User": login, "Remote-Groups": grupa})
    assert status == 200 and me["rola"] == rola and me["sso"] is True
    j = jar(headers)
    h = {"Remote-User": login, "Remote-Groups": grupa,
         "Cookie": cookie(j), "X-CSRF-Token": j["kidwatch_csrf"]}
    status = call(server, "POST", "/api/mdm/command",
                  {"udid": UDID, "request_type": "RestartDevice"}, h)[0]
    assert (status == 403) == (rola == "podglad")


# ======================================================================== baza
def test_baza_sprzed_rol_istniejace_konta_to_wlasciciele(tmp_path):
    """Baza sprzed rol i sprzed tabeli odstepstw: konto zachowuje wszystko."""
    stary = panel_auth.SCHEMA.replace(
        "    totp_last_step   INTEGER,\n"
        "    -- 'wlasciciel' = wszystko, 'podglad' = tylko ogladanie (uprawnienia.py).\n"
        "    rola             TEXT NOT NULL DEFAULT 'wlasciciel'\n",
        "    totp_last_step   INTEGER\n")
    stary = stary[:stary.index("-- Pojedyncze odstepstwa")] + stary[
        stary.index("-- Nieudane hasla przy logowaniu"):]
    assert "rola" not in stary and "user_uprawnienia" not in stary
    path = tmp_path / "stara.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(stary)
        conn.execute("INSERT INTO users (login, password_hash, created_at) "
                     "VALUES ('rodzic1', ?, 0)", (panel_auth.hash_password(HASLO),))
    auth = PanelAuth(path)
    assert auth.list_users()[0]["rola"] == "wlasciciel"
    session = auth.login("rodzic1", HASLO).session
    assert session.rola == "wlasciciel"
    assert session.uprawnienia == frozenset(uprawnienia.UPRAWNIENIA)


def test_nieznana_rola_odrzucona(tmp_path):
    auth = PanelAuth(tmp_path / "a.db")
    with pytest.raises(ValueError, match="rola"):
        auth.add_user("x", HASLO, "admin")


# ========================================================================= CLI
def test_lista_rol_CLI_zgodna_z_panel_auth():
    assert PANEL_ROLES == panel_auth.ROLES
    assert PANEL_ROLES[0] == panel_auth.ROLE_OWNER


def test_user_add_z_rola_podglad_i_zmiana_roli(tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "config.yaml"
    cfg.write_text(CONFIG, encoding="utf-8")
    monkeypatch.setattr("sys.stdin", io.StringIO("haslo-ze-stdin-123\n"))
    assert main(["--config", str(cfg), "user-add", "rodzic2", "--rola", "podglad",
                 "--password-stdin"]) == 0
    assert "rola podglad" in capsys.readouterr().out
    assert main(["--config", str(cfg), "user-list"]) == 0
    assert "rola: podglad" in capsys.readouterr().out

    auth = PanelAuth(tmp_path / "panel-auth.db")
    token = auth.login("rodzic2", "haslo-ze-stdin-123").token
    assert auth.session(token).rola == "podglad"
    assert main(["--config", str(cfg), "user-rola", "rodzic2", "wlasciciel"]) == 0
    assert auth.session(token) is None  # zmiana roli wylogowuje
    assert auth.login("rodzic2", "haslo-ze-stdin-123").session.rola == "wlasciciel"
    assert main(["--config", str(cfg), "user-rola", "nikt", "podglad"]) == 1
    with pytest.raises(SystemExit):
        main(["--config", str(cfg), "user-add", "x", "--rola", "admin"])
