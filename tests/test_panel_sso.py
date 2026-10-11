"""SSO: sesja panelu z naglowka Authelii (panel_sso.py, kontrakt
renacode-infra docs/sso-tozsamosc.md).

Najwazniejsze sa testy z wylaczona flaga: panel bez `SSO_NAGLOWKI=1` stoi za
routerem, ktory `Remote-User` od klienta przepuszcza — kazde zaufanie do
naglowka byloby tam logowaniem bez hasla dla kazdego.
"""

from __future__ import annotations

import http.client
import json
import logging
import sqlite3
import time

import pyotp
import pytest

from conftest import make_config, panel_login
from kidwatch.config import PanelConfig, StoreConfig
from kidwatch.panel import start_panel
from kidwatch.panel_auth import AuthError, PanelAuth, box_from_env
from kidwatch.panel_sso import SsoConfig, config_from_env
from kidwatch.store import Store

HASLO = "dlugie-haslo-testowe"
ADRES = "https://kidwatch.renacode.com/"
WYLOGUJ = "https://auth.renacode.com/logout?rd=https%3A%2F%2Fkidwatch.renacode.com%2F"
OD_AUTHELII = {"Remote-User": "marcin", "Remote-Groups": "admins",
               "Remote-Email": "rodzic@example.com", "Remote-Name": "Marcin"}


def uruchom(tmp_path, monkeypatch, *, sso: bool, totp: bool = False):
    if sso:
        monkeypatch.setenv("SSO_NAGLOWKI", "1")
        monkeypatch.setenv("SSO_ADRES", ADRES)
    else:
        monkeypatch.delenv("SSO_NAGLOWKI", raising=False)
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "index.html").write_text("<!doctype html>", encoding="utf-8")
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path / "web")))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    auth = PanelAuth(cfg.panel_auth_path, box=box_from_env())
    for login in ("marcin", "ania"):
        auth.add_user(login, HASLO)
    secret = None
    if totp:
        # 2FA panelu wlaczone: sesja SSO i tak nie moze o nie pytac.
        session = auth.login("marcin", HASLO).session
        secret = auth.totp_setup(session)["secret"]
        auth.totp_confirm(session, pyotp.TOTP(secret).now())
    return start_panel(cfg), auth, secret


@pytest.fixture
def sso_on(tmp_path, monkeypatch):
    srv, auth, _ = uruchom(tmp_path, monkeypatch, sso=True, totp=True)
    yield srv, auth
    srv.shutdown()


@pytest.fixture
def sso_off(tmp_path, monkeypatch):
    srv, auth, _ = uruchom(tmp_path, monkeypatch, sso=False)
    yield srv, auth
    srv.shutdown()


def call(srv, method, path, body=None, headers=()):
    """`headers` jako lista par — naglowek moze wystapic dwa razy."""
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    conn.putrequest(method, path)
    pairs = list(headers.items() if isinstance(headers, dict) else headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        pairs += [("Content-Type", "application/json"), ("Content-Length", str(len(data)))]
    for k, v in pairs:
        conn.putheader(k, v)
    conn.endheaders(data)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    if not resp.headers.get("Content-Type", "").startswith("application/json"):
        return resp.status, resp.headers, raw
    return resp.status, resp.headers, json.loads(raw) if raw else None


def jar(headers) -> dict[str, str]:
    return dict(c.split(";")[0].split("=", 1) for c in headers.get_all("Set-Cookie") or [])


def cookie(j: dict[str, str]) -> str:
    return "; ".join(f"{k}={v}" for k, v in j.items())


# ================================================================ flaga wylaczona
@pytest.mark.parametrize("path", ["/api/auth/me", "/api/devices"])
def test_bez_flagi_podrobiony_naglowek_nie_loguje(sso_off, path):
    srv, _ = sso_off
    status, headers, body = call(srv, "GET", path, headers=OD_AUTHELII)
    assert status == 401
    assert "kidwatch_session" not in {k for k, v in jar(headers).items() if v}
    assert "logout_url" not in body


def test_bez_flagi_naglowek_nie_zmienia_sesji_z_hasla(sso_off):
    """Zalogowany `marcin` z podrobionym `Remote-User: ania` zostaje soba —
    i odwrotnie, naglowek nie podmienia konta."""
    srv, _ = sso_off
    c = panel_login(srv.server_address[1], "marcin", HASLO)
    status, headers, me = call(srv, "GET", "/api/auth/me",
                               headers={"Cookie": c, "Remote-User": "ania",
                                        "Remote-Groups": "admins"})
    assert status == 200
    assert me["login"] == "marcin"
    assert me["sso"] is False and me["logout_url"] is None
    assert not headers.get_all("Set-Cookie")


def test_bez_flagi_podwojny_naglowek_tez_ignorowany(sso_off):
    srv, _ = sso_off
    status, _, _ = call(srv, "GET", "/api/auth/me",
                        headers=[("Remote-User", "marcin"), ("Remote-User", "ania")])
    assert status == 401  # nie 400: bez flagi panel w ogole naglowka nie czyta


def test_flaga_tylko_dokladnie_1(monkeypatch):
    for wartosc in ("", "0", "true", "tak", " 2"):
        monkeypatch.setenv("SSO_NAGLOWKI", wartosc)
        assert config_from_env() is None, wartosc
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    assert config_from_env() is not None


# ================================================================= flaga wlaczona
def test_naglowek_daje_sesje_bez_hasla_i_bez_TOTP(sso_on):
    srv, auth = sso_on
    status, headers, me = call(srv, "GET", "/api/auth/me", headers=OD_AUTHELII)
    assert status == 200
    assert me["login"] == "marcin"
    assert me["sso"] is True
    assert me["totp_enabled"] is True  # 2FA panelu jest — i nikt o nie nie pytal
    assert me["logout_url"] == WYLOGUJ
    j = jar(headers)
    assert j["kidwatch_session"] and j["kidwatch_csrf"]
    raw = headers.get_all("Set-Cookie")
    assert any("HttpOnly" in c and "Secure" in c for c in raw if c.startswith("kidwatch_session"))

    h = {**OD_AUTHELII, "Cookie": cookie(j)}
    status, headers, _ = call(srv, "GET", "/api/devices", headers=h)
    assert status == 200
    assert not headers.get_all("Set-Cookie")  # ta sama sesja, nie nowa na kazde zadanie
    assert auth.session(j["kidwatch_session"]).kind == "sso"


def test_nieznany_login_403_z_komunikatem_i_wylogowaniem(sso_on):
    srv, _ = sso_on
    status, headers, body = call(srv, "GET", "/api/auth/me",
                                 headers={"Remote-User": "ola", "Remote-Groups": "rodzina"})
    assert status == 403
    assert "Brak konta w Kidwatchu" in body["error"] and "ola" in body["error"]
    assert body["logout_url"] == WYLOGUJ
    assert not headers.get_all("Set-Cookie")


@pytest.mark.parametrize("grupy", [None, "", "dietetyk", "admins-old,dietetyk"])
def test_brak_grupy_z_dostepem_403(sso_on, grupy):
    srv, _ = sso_on
    h = {"Remote-User": "marcin"}
    if grupy is not None:
        h["Remote-Groups"] = grupy
    status, headers, body = call(srv, "GET", "/api/auth/me", headers=h)
    assert status == 403
    assert "grupy" in body["error"]
    assert body["logout_url"] == WYLOGUJ
    assert not headers.get_all("Set-Cookie")


def test_grupa_rodzina_wpuszcza_tak_samo_jak_admins(sso_on):
    """Panel nie ma rol: grupa decyduje o wejsciu, nie o uprawnieniach."""
    srv, _ = sso_on
    status, _, me = call(srv, "GET", "/api/auth/me",
                         headers={"Remote-User": "ania", "Remote-Groups": "dietetyk, rodzina"})
    assert status == 200 and me["login"] == "ania"


def test_podwojny_naglowek_400(sso_on):
    srv, _ = sso_on
    status, _, body = call(srv, "GET", "/api/auth/me", headers=[
        ("Remote-User", "marcin"), ("Remote-User", "ania"), ("Remote-Groups", "admins")])
    assert status == 400
    assert "więcej niż raz" in body["error"]


@pytest.mark.parametrize("login", ["Marcin", "marcin ania", "marcin,ania", "", "m" * 65,
                                   "marciné", "../marcin"])
def test_login_spoza_alfabetu_400(sso_on, login):
    srv, _ = sso_on
    status, _, _ = call(srv, "GET", "/api/auth/me",
                        headers={"Remote-User": login, "Remote-Groups": "admins"})
    assert status == 400


@pytest.mark.parametrize("naglowek", ["X-Remote-User", "Remote_User", "RemoteUser"])
def test_warianty_naglowka_nie_sa_tozsamoscia(sso_on, naglowek):
    srv, _ = sso_on
    status, _, _ = call(srv, "GET", "/api/auth/me",
                        headers={naglowek: "marcin", "Remote-Groups": "admins"})
    assert status == 401


def test_flaga_bez_naglowka_to_zwykle_logowanie_haslem_i_TOTP(tmp_path, monkeypatch):
    """Droga awaryjna (port-forward, Authelia lezy): haslo i WLASNY TOTP panelu."""
    srv, _, secret = uruchom(tmp_path, monkeypatch, sso=True, totp=True)
    try:
        assert call(srv, "GET", "/api/auth/me")[0] == 401
        status, headers, step = call(srv, "POST", "/api/auth/login",
                                     {"login": "marcin", "password": HASLO})
        assert status == 200 and step["mfa_required"] is True
        assert not headers.get_all("Set-Cookie")
        c = panel_login(srv.server_address[1], "marcin", HASLO, secret)
        status, _, me = call(srv, "GET", "/api/auth/me", headers={"Cookie": c})
        assert status == 200
        assert me["sso"] is False
        assert me["logout_url"] is None  # bez Authelii nie ma czego konczyc w portalu
    finally:
        srv.shutdown()


def test_zmiana_uzytkownika_w_authelii_daje_sesje_nowego(sso_on):
    srv, auth = sso_on
    _, headers, _ = call(srv, "GET", "/api/auth/me", headers=OD_AUTHELII)
    stara = jar(headers)
    status, headers, me = call(srv, "GET", "/api/auth/me", headers={
        "Remote-User": "ania", "Remote-Groups": "rodzina", "Cookie": cookie(stara)})
    assert status == 200 and me["login"] == "ania"
    nowa = jar(headers)
    assert nowa["kidwatch_session"] != stara["kidwatch_session"]
    # Sesja marcina z tej przegladarki nie zyje dalej obok.
    assert auth.session(stara["kidwatch_session"]) is None


def test_sesja_z_hasla_tego_samego_uzytkownika_zostaje(tmp_path, monkeypatch):
    srv, auth, secret = uruchom(tmp_path, monkeypatch, sso=True, totp=True)
    try:
        c = panel_login(srv.server_address[1], "marcin", HASLO, secret)
        status, headers, me = call(srv, "GET", "/api/auth/me",
                                   headers={**OD_AUTHELII, "Cookie": c})
        assert status == 200 and me["sso"] is False
        assert not headers.get_all("Set-Cookie")
        assert me["logout_url"] == WYLOGUJ  # przyszlo przez Authelie
    finally:
        srv.shutdown()


def test_sciezka_maszynowa_z_podrobionym_naglowkiem_bez_skutku(sso_on):
    srv, auth = sso_on
    for path in ("/api/health", "/", "/index.html"):
        status, headers, _ = call(srv, "GET", path,
                                  headers={"Remote-User": "ola", "Remote-Groups": "admins"})
        assert status == 200, path
        assert not headers.get_all("Set-Cookie"), path
    with sqlite3.connect(auth.path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM sessions WHERE kind = 'sso'").fetchone()[0] == 0


def test_POST_bez_CSRF_nie_przechodzi_mimo_naglowka(sso_on):
    """Sesja SSO powstala na POST-cie nie zna jeszcze tokenu CSRF — zmiana
    stanu z obcej strony z ciasteczkiem Authelii nie przejdzie."""
    srv, _ = sso_on
    status, _, body = call(srv, "POST", "/api/auth/totp/setup", {}, headers=OD_AUTHELII)
    assert status == 403
    assert "CSRF" in body["error"]


def test_wylogowanie_kasuje_sesje_i_odsyla_na_portal(sso_on):
    srv, auth = sso_on
    _, headers, _ = call(srv, "GET", "/api/auth/me", headers=OD_AUTHELII)
    j = jar(headers)
    status, headers, body = call(srv, "POST", "/api/auth/logout", {}, headers={
        **OD_AUTHELII, "Cookie": cookie(j), "X-CSRF-Token": j["kidwatch_csrf"]})
    assert status == 200
    assert body["logout_url"] == WYLOGUJ
    assert any("Max-Age=0" in c for c in headers.get_all("Set-Cookie"))
    assert auth.session(j["kidwatch_session"]) is None


def test_wylogowanie_bez_sesji_przez_authelie_tez_daje_portal(sso_on):
    srv, _ = sso_on
    status, _, body = call(srv, "POST", "/api/auth/logout", {}, headers=OD_AUTHELII)
    assert status == 200 and body["logout_url"] == WYLOGUJ


def test_adres_wylogowania():
    assert SsoConfig(return_url=ADRES).logout_url == WYLOGUJ
    assert SsoConfig().logout_url == "https://auth.renacode.com/logout"
    assert SsoConfig(portal="https://sso.example/", return_url="https://a/?x=1&y").logout_url \
        == "https://sso.example/logout?rd=https%3A%2F%2Fa%2F%3Fx%3D1%26y"


# ================================================================ czynnosci wrazliwe
def test_sesja_SSO_nie_jest_swiezym_potwierdzeniem(sso_on):
    """Zmiana hasla, wylaczenie 2FA i zmiany WhatsAppa (reauth) dalej chca
    hasla albo kodu panelu — sama sesja SSO ich nie otwiera."""
    srv, auth = sso_on
    _, headers, _ = call(srv, "GET", "/api/auth/me", headers=OD_AUTHELII)
    j = jar(headers)
    h = {**OD_AUTHELII, "Cookie": cookie(j), "X-CSRF-Token": j["kidwatch_csrf"]}
    assert call(srv, "POST", "/api/auth/password",
                {"old": "", "new": "zupelnie-nowe-haslo"}, headers=h)[0] == 401
    assert call(srv, "POST", "/api/auth/totp/disable",
                {"password": "", "code": ""}, headers=h)[0] == 401
    session = auth.session(j["kidwatch_session"])
    with pytest.raises(AuthError) as exc:
        auth.require_fresh_reauth(session)
    assert exc.value.status == 403
    with pytest.raises(AuthError):
        auth.reauth(session, "")


# ==================================================================== panel_auth
def test_sso_login_omija_blokade_hasla_i_jej_nie_zdejmuje(tmp_path):
    """Blokada liczy zgadywanie hasla. Gdyby obowiazywala SSO, kazdy znajacy
    login wylaczalby wlascicielowi panel zlymi haslami na ekranie awaryjnym."""
    auth = PanelAuth(tmp_path / "a.db")
    auth.add_user("marcin", HASLO)
    with sqlite3.connect(auth.path) as conn:
        conn.execute("UPDATE users SET failed_logins = 5, locked_until = ?",
                     (time.time() + 900,))
    _, session = auth.sso_login("marcin")
    assert session.kind == "sso"
    with pytest.raises(AuthError) as exc:
        auth.login("marcin", HASLO)
    assert exc.value.status == 429


def test_dziennik_logowania_SSO_bez_danych_wrazliwych(sso_on, caplog):
    srv, _ = sso_on
    with caplog.at_level(logging.INFO, logger="kidwatch"):
        _, headers, _ = call(srv, "GET", "/api/auth/me", headers=OD_AUTHELII)
        call(srv, "GET", "/api/auth/me", headers={"Remote-User": "ola", "Remote-Groups": "admins"})
    tekst = caplog.text
    assert "logowanie SSO 'marcin'" in tekst
    assert "odmowa SSO" in tekst and "ola" in tekst
    for wrazliwe in ("rodzic@example.com", jar(headers)["kidwatch_session"],
                     jar(headers)["kidwatch_csrf"]):
        assert wrazliwe not in tekst


def test_baza_sprzed_SSO_dostaje_kolumne_a_stare_sesje_zyja(tmp_path):
    path = tmp_path / "stara.db"
    auth = PanelAuth(path)
    auth.add_user("marcin", HASLO)
    token = auth.login("marcin", HASLO).token
    with sqlite3.connect(path) as conn:
        conn.execute("ALTER TABLE sessions DROP COLUMN kind")
    nowa = PanelAuth(path)
    session = nowa.session(token)
    assert session is not None and session.kind == "haslo"
