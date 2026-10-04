"""Profil w panelu: zmiana hasla, WhatsApp przez bramke (po stronie serwera),
dane strukturalne powiadomien i karta "dzis"."""

from __future__ import annotations

import http.client
import json
from datetime import UTC, datetime

import httpx
import pytest

from conftest import local, make_config, panel_login
from kidwatch import panel as panel_mod
from kidwatch.bramka_admin import (
    BramkaAdmin,
    BramkaError,
    normalize_number,
    normalize_recipients,
)
from kidwatch.config import BramkaConfig, PanelConfig, StoreConfig
from kidwatch.formatting import payload, section, sections_text, short_title, short_titles
from kidwatch.models import Notification, NotifyKind
from kidwatch.notifiers.base import Dispatcher
from kidwatch.panel import PanelQueries, start_panel
from kidwatch.panel_auth import AuthError, PanelAuth
from kidwatch.store import Store

HASLO = "dlugie-haslo-testowe"


# ================================================================ formatowanie
def test_skracanie_tytulow_tv():
    assert short_title("Myjka okien | Fiksiki | Zabawa, Nauka") == "Myjka okien"
    assert short_title("x" * 80).endswith("…") and len(short_title("x" * 80)) == 60
    shown, more = short_titles(["A | k", "A | inny", "B", "C", "D", "E", "F", "G"])
    assert shown == ["A", "B", "C", "D", "E"] and more == 2


def test_sekcje_na_tekst_z_punktorami():
    sec = section("Kuba", "2 sesje, 1 h", apps=[("YouTube", 45), ("Roblox", 12)])
    tv = section("TV salon", "1 h", kind="tv", titles=["Bluey", "Fiksiki | Kanal"])
    assert sections_text([sec, tv], "(uwaga)") == (
        "*Kuba* — 2 sesje, 1 h\n• YouTube ~45 min\n• Roblox ~12 min\n\n"
        "*TV salon* — 1 h\n• Bluey\n• Fiksiki\n\n(uwaga)"
    )


# ============================================================== bramka (klient)
def fake_bramka(log: list):
    state = {"status": "BRAK_SESJI", "odbiorca": "", "odbiorcy": []}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "klucz-bramki"
        body = json.loads(request.content) if request.content else None
        log.append((request.method, request.url.path, body))
        path = request.url.path
        if path == "/v1/whatsapp":
            return httpx.Response(200, json={**state, "me": None, "email": True,
                                             "kanal_auto": "email"})
        if path == "/v1/whatsapp/start":
            state["status"] = "SCAN_QR_CODE"
            return httpx.Response(200, json=state)
        if path == "/v1/whatsapp/wyloguj":
            state["status"] = "BRAK_SESJI"
            return httpx.Response(200, json=state)
        if path == "/v1/whatsapp/qr":
            if state["status"] != "SCAN_QR_CODE":
                return httpx.Response(409, json={"blad": "sesja nie czeka na skan"})
            return httpx.Response(200, json={"mimetype": "image/png", "data": "iVBOR"})
        if path == "/v1/whatsapp/odbiorca":
            state["odbiorca"] = body["numer"]
            return httpx.Response(200, json=state)
        if path == "/v1/whatsapp/odbiorcy":
            state["odbiorcy"] = body["odbiorcy"]
            return httpx.Response(200, json=state)
        if path == "/v1/test":
            return httpx.Response(502, json={"ok": False, "bledy": {"email": "Mailgun 401"}})
        return httpx.Response(404, json={"blad": "?"})

    return BramkaAdmin(BramkaConfig(url="http://bramka"), "klucz-bramki",
                       transport=httpx.MockTransport(handler))


def test_klient_bramki_mapuje_bledy():
    calls: list = []
    b = fake_bramka(calls)
    assert b.status()["status"] == "BRAK_SESJI"
    with pytest.raises(BramkaError) as e:
        b.qr()
    assert e.value.status == 409 and "nie czeka" in e.value.message
    with pytest.raises(BramkaError, match="Mailgun 401"):
        b.test()
    assert calls[-1][2] == {"kanal": "auto", "zrodlo": "kidwatch"}


def test_numer_odbiorcy():
    assert normalize_number("+48 600 100 200") == "48600100200"
    assert normalize_number("600100") is None
    assert normalize_number("0048 600-100-200") == "48600100200"
    assert normalize_number("(+48) 600.100.200") is None   # + tylko na poczatku
    # Litery i cyfry spoza ASCII: odrzucone, nie sklejane w inny numer.
    assert normalize_number("+48 600-100-200 wew. 12") is None
    arabskie = "+" + "".join(chr(0x0660 + d) for d in (1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1))
    assert normalize_number(arabskie) is None


def test_polacz_i_rozlacz_bota_wymaga_potwierdzenia(served):
    """Przegląd 04.10: przejęta sesja mogła wylogować bota i zeskanować QR
    własnym telefonem — zmiana NADAWCY powiadomień, nie tylko odbiorcy."""
    _, _, port, h, calls = served
    for path in ("/api/profile/whatsapp/start", "/api/profile/whatsapp/logout"):
        for body in ({}, {"confirm": "zle-haslo-zle-haslo"}):
            status, data = call(port, "POST", path, body, h)
            assert status == 401, (path, data)
    assert not [c for c in calls if c[1] in ("/v1/whatsapp/start", "/v1/whatsapp/wyloguj")]
    assert call(port, "POST", "/api/profile/whatsapp/logout", {"confirm": HASLO}, h)[0] == 200


def test_qr_bota_tylko_po_swiezym_potwierdzeniu(served):
    """Przegląd 04.10, K-1: WAHA wchodzi w SCAN_QR_CODE sama (po każdym
    rozłączeniu), więc QR na samą sesję pozwalał przejętej sesji podpiąć
    obcy numer jako nadawcę. QR tylko po świeżym reauth tej sesji."""
    _, _, port, h, calls = served
    cookie = {"Cookie": h["Cookie"]}
    # Sesja WAHA czeka na skan, ale ta sesja panelu niczego nie potwierdzała.
    calls_before = len(calls)
    status, data = call(port, "GET", "/api/profile/whatsapp/qr", headers=cookie)
    assert status == 403 and "Potwierdź" in data["error"]
    assert not [c for c in calls[calls_before:] if c[1] == "/v1/whatsapp/qr"]
    assert call(port, "POST", "/api/profile/whatsapp/start", {"confirm": HASLO}, h)[0] == 200
    status, qr = call(port, "GET", "/api/profile/whatsapp/qr", headers=cookie)
    assert status == 200 and qr["data"] == "iVBOR"
    # Po wylogowaniu z panelu ta sama sesja nie przejdzie.
    assert call(port, "POST", "/api/auth/logout", {}, h)[0] == 200
    assert call(port, "GET", "/api/profile/whatsapp/qr", headers=cookie)[0] == 401


def test_swiezosc_potwierdzenia_wygasa(tmp_path):
    now = [1_000_000.0]
    auth = PanelAuth(tmp_path / "a.db", clock=lambda: now[0])
    auth.add_user("rodzic", HASLO)
    session = auth.login("rodzic", HASLO, ip="192.0.2.1").session
    with pytest.raises(AuthError) as e:
        auth.require_fresh_reauth(session)
    assert e.value.status == 403
    with pytest.raises(AuthError):
        auth.reauth(session, "zle-haslo-zle-haslo")
    with pytest.raises(AuthError):
        auth.require_fresh_reauth(session)   # nieudane potwierdzenie sie nie liczy
    auth.reauth(session, HASLO)
    now[0] += 300
    auth.require_fresh_reauth(session)
    now[0] += 1
    with pytest.raises(AuthError) as e:
        auth.require_fresh_reauth(session)
    assert e.value.status == 403
    auth.reauth(session, HASLO)
    auth.logout(session)
    with pytest.raises(AuthError):
        auth.require_fresh_reauth(session)


# ======================================================================= panel
def call(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    h = {"Content-Type": "application/json", **(headers or {})}
    conn.request(method, path, json.dumps(body) if body is not None else None, h)
    r = conn.getresponse()
    data = json.loads(r.read() or b"null")
    conn.close()
    return r.status, data


@pytest.fixture
def served(tmp_path, monkeypatch):
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path),
                                        cookie_secure=False))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    store = Store(cfg.store.path)
    calls: list = []
    monkeypatch.setattr(panel_mod, "_bramka_admin", lambda cfg: fake_bramka(calls))
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", HASLO)
    server = start_panel(cfg)
    port = server.server_address[1]
    cookie = panel_login(port, "rodzic", HASLO)
    csrf = next(c.split("=", 1)[1] for c in cookie.split("; ") if c.startswith("kidwatch_csrf"))
    yield cfg, store, port, {"Cookie": cookie, "X-CSRF-Token": csrf}, calls
    server.shutdown()
    store.close()


def test_whatsapp_z_profilu_przez_serwer(served):
    _, _, port, h, calls = served
    assert call(port, "GET", "/api/profile/notify")[0] == 401
    status, data = call(port, "GET", "/api/profile/notify", headers={"Cookie": h["Cookie"]})
    assert status == 200 and data["available"] and data["status"] == "BRAK_SESJI"
    # Zmiana stanu bez CSRF — nie.
    assert call(port, "POST", "/api/profile/whatsapp/start", {},
                {"Cookie": h["Cookie"]})[0] == 403
    assert call(port, "POST", "/api/profile/whatsapp/start", {"confirm": HASLO},
                h)[1]["status"] == "SCAN_QR_CODE"
    status, qr = call(port, "GET", "/api/profile/whatsapp/qr", headers={"Cookie": h["Cookie"]})
    assert status == 200 and qr["data"] == "iVBOR"
    assert call(port, "POST", "/api/profile/whatsapp/recipient", {"number": "123"}, h)[0] == 400
    status, data = call(port, "POST", "/api/profile/whatsapp/recipient",
                        {"number": "+48 600 100 200", "confirm": HASLO}, h)
    assert status == 200 and data["odbiorca"] == "48600100200"
    status, data = call(port, "POST", "/api/profile/test", {}, h)
    assert status == 502 and "Mailgun 401" in data["error"]
    # Klucz bramki nie wychodzi do przegladarki w zadnej odpowiedzi.
    assert all("klucz-bramki" not in json.dumps(c) for c in calls)


def test_zmiana_numeru_odbiorcy_wymaga_hasla_albo_kodu(served):
    """Audyt 3, S2: numer jest wspolny dla wszystkich aplikacji RenaCode, a do
    zmiany wystarczala sesja i CSRF — przejeta sesja przekierowywala pushe."""
    _, _, port, h, calls = served
    for body in ({"number": "48600100999"},
                 {"number": "48600100999", "confirm": "zle-haslo-zle-haslo"}):
        status, data = call(port, "POST", "/api/profile/whatsapp/recipient", body, h)
        assert status == 401, data
    assert not [c for c in calls if c[1] == "/v1/whatsapp/odbiorca"]
    status, data = call(port, "POST", "/api/profile/whatsapp/recipient",
                        {"number": "48600100999", "confirm": HASLO}, h)
    assert status == 200 and data["odbiorca"] == "48600100999"


def test_profil_bez_bramki_albo_bez_klucza(monkeypatch):
    cfg = make_config()
    assert panel_mod._bramka_admin(cfg) is None
    cfg.notifiers.bramka = BramkaConfig()
    monkeypatch.delenv("BRAMKA_KLUCZ", raising=False)
    monkeypatch.delenv("BRAMKA_KLUCZ_ADMIN", raising=False)
    assert panel_mod._bramka_admin(cfg) is None
    monkeypatch.setenv("BRAMKA_KLUCZ", "k")
    assert isinstance(panel_mod._bramka_admin(cfg), BramkaAdmin)


def test_panel_zarzadza_bramka_kluczem_ADMINA_a_nie_wysylkowym(monkeypatch, caplog):
    cfg = make_config()
    cfg.notifiers.bramka = BramkaConfig()
    monkeypatch.setenv("BRAMKA_KLUCZ", "wysylkowy")
    monkeypatch.setenv("BRAMKA_KLUCZ_ADMIN", "admin")
    assert panel_mod._bramka_admin(cfg)._key == "admin"
    # Bez klucza admina: stary wspolny klucz, z ostrzezeniem w logu.
    monkeypatch.delenv("BRAMKA_KLUCZ_ADMIN")
    with caplog.at_level("WARNING", logger=panel_mod.log.name):
        assert panel_mod._bramka_admin(cfg)._key == "wysylkowy"
    assert any("BRAMKA_KLUCZ_ADMIN" in r.getMessage() for r in caplog.records)


def test_zmiana_hasla_wylogowuje_inne_sesje(served):
    _, _, port, h, _ = served
    druga = panel_login(port, "rodzic", HASLO)
    assert call(port, "POST", "/api/auth/password", {"old": HASLO, "new": "nowe-haslo-123456"},
                {"Cookie": h["Cookie"]})[0] == 403  # bez CSRF
    status, data = call(port, "POST", "/api/auth/password",
                        {"old": "zle-haslo-zle", "new": "nowe-haslo-123456"}, h)
    assert status == 401
    assert call(port, "POST", "/api/auth/password", {"old": HASLO, "new": "krotkie"}, h)[0] == 400
    status, data = call(port, "POST", "/api/auth/password",
                        {"old": HASLO, "new": "nowe-haslo-123456"}, h)
    assert status == 200 and data["closed_sessions"] == 1
    # Biezaca sesja dziala, druga zostala wylogowana.
    assert call(port, "GET", "/api/auth/me", headers={"Cookie": h["Cookie"]})[0] == 200
    assert call(port, "GET", "/api/auth/me", headers={"Cookie": druga})[0] == 401
    panel_login(port, "rodzic", "nowe-haslo-123456")


def test_zmiana_hasla_bledne_stare_liczy_sie_do_blokady(tmp_path):
    auth = PanelAuth(tmp_path / "a.db")
    auth.add_user("x", HASLO)
    from kidwatch.panel_auth import Session  # noqa: PLC0415

    sess = Session("x", 1, "t", "c", 9e18)
    for _ in range(5):
        with pytest.raises(AuthError):
            auth.change_password(sess, "zle-haslo-zle", "nowe-haslo-123456")
    with pytest.raises(AuthError) as e:
        auth.change_password(sess, HASLO, "nowe-haslo-123456")
    assert e.value.status == 429


# ============================================ dane powiadomien i karta "dzis"
async def test_powiadomienie_z_danymi_trafia_do_panelu(served):
    cfg, store, _, _, _ = served
    sec = section("Kuba", "1 sesja, 5 min", apps=[("YouTube", 4)])
    note = Notification(kind=NotifyKind.DAILY, title="Podsumowanie", text=sections_text([sec]),
                        dedup_key="d", ts=datetime.now(UTC), data=payload("daily", [sec]))
    await Dispatcher([], store=store).send(note)
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        item = q.notifications(conn, {})["items"][0]
    assert item["data"]["sections"][0]["apps"] == [{"app": "YouTube", "minutes": 4}]


def test_niepotwierdzone_sesje_nie_licza_sie_w_panelu(served):
    cfg, store, _, _, _ = served
    now = datetime.now(cfg.tz).replace(hour=12, minute=0, second=0, microsecond=0)
    real = store.open_session("iPad Kuby", "Kuba", now.replace(hour=10))
    store.record_app_minute(real, "Roblox", now.replace(hour=10))
    store.close_session(real, now.replace(hour=10, minute=40))
    ghost = store.open_session("iPad Kuby", "Kuba", now.replace(hour=11), confirmed=False)
    store.record_app_minute(ghost, "YouTube", now.replace(hour=11))
    store.close_session(ghost, now.replace(hour=11, minute=0, second=1))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        card = q.devices(conn, {"child": "Kuba"})[0]
        day = q.day(conn, {"child": "Kuba"})["devices"][0]
        usage = q.usage(conn, {"child": "Kuba", "days": "1"})
    assert card["today"] == {"minutes": 40, "sessions": 1,
                             "top_app": {"app": "Roblox", "minutes": 1}}
    assert len(day["sessions"]) == 1 and day["top_apps"] == [{"app": "Roblox", "minutes": 1}]
    assert usage["days"][0]["devices"][0]["sessions"] == 1


def _usun_kolumne(conn, tabela: str, kolumna: str) -> None:
    import re  # noqa: PLC0415

    sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (tabela,)
    ).fetchone()[0]
    sql = re.sub(r"--[^\n]*", "", sql)
    sql = re.sub(rf",\s*{kolumna}\b[^,)]*", "", sql, count=1)
    zostaja = [
        r[1] for r in conn.execute(f"PRAGMA table_info({tabela})") if r[1] != kolumna
    ]
    cols = ", ".join(zostaja)
    conn.execute(f"ALTER TABLE {tabela} RENAME TO {tabela}_stara")
    conn.execute(sql)
    conn.execute(f"INSERT INTO {tabela} ({cols}) SELECT {cols} FROM {tabela}_stara")
    conn.execute(f"DROP TABLE {tabela}_stara")


def test_migracja_starych_sesji(tmp_path):
    """Baza sprzed potwierdzania: potwierdzona = taka, o ktorej poszedl push."""
    import sqlite3  # noqa: PLC0415

    db = tmp_path / "old.db"
    s = Store(db)
    # Stara baza budowana wprost, NIE przez ALTER TABLE ... DROP COLUMN: SQLite
    # 3.40 (obraz produkcyjny, runner CI) wywraca DROP COLUMN na komentarzach
    # w CREATE TABLE ("incomplete input"), choc na Macu (3.53) przechodzi.
    _usun_kolumne(s.conn, "sessions", "confirmed")
    _usun_kolumne(s.conn, "notifications", "data")
    t = local(2026, 10, 2, 10, 0).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f%z")
    for notified in (0, 1):
        s.conn.execute(
            "INSERT INTO sessions (device, child, started_at, last_activity_at, start_notified) "
            "VALUES ('iPad Kuby', 'Kuba', ?, ?, ?)", (t, t, notified))
    s.conn.execute("INSERT INTO sessions (device, child, started_at, last_activity_at) "
                   "VALUES ('TV salon', NULL, ?, ?)", (t, t))
    s.close()
    s = Store(db)
    rows = [tuple(r) for r in s.conn.execute("SELECT start_notified, confirmed FROM sessions")]
    assert rows == [(0, 0), (1, 1), (0, 1)]
    assert "data" in {r[1] for r in sqlite3.connect(db).execute("PRAGMA table_info(notifications)")}


# ===================================================== wielu odbiorcow WhatsApp
# Repo jest publiczne: wylacznie fikcyjne numery.
A, B, C = "48500100200", "48500100300", "48500100400"
LISTA = [{"number": "+48 500 100 200", "label": "Ja", "active": True},
         {"number": B, "label": "Druga osoba", "active": True},
         {"number": C, "label": "Wyłączony", "active": False}]


def test_lista_odbiorcow_dla_bramki():
    assert normalize_recipients(LISTA) == [
        {"numer": A, "etykieta": "Ja", "aktywny": True},
        {"numer": B, "etykieta": "Druga osoba", "aktywny": True},
        {"numer": C, "etykieta": "Wyłączony", "aktywny": False},
    ]
    assert normalize_recipients([{"number": A}]) == [{"numer": A, "etykieta": "", "aktywny": True}]
    assert normalize_recipients([]) == []


@pytest.mark.parametrize("lista, fragment", [
    (None, "format"),
    ([{"number": f"4850010030{i}"} for i in range(6)], "Najwyżej 5"),
    ([{"number": "123"}], "Odbiorca 1: podaj numer"),
    ([{"number": 48500100200}], "Odbiorca 1: podaj numer"),
    ([{"number": A}, {"number": "+48 500 100 200"}], "Odbiorca 2: ten numer"),
    ([{"number": A, "label": "x" * 41}], "40 znaków"),
    ([{"number": A, "active": "tak"}], "aktywny"),
    ([A], "zły format"),
])
def test_walidacja_listy_odbiorcow(lista, fragment):
    with pytest.raises(ValueError, match=fragment) as e:
        normalize_recipients(lista)
    assert A not in str(e.value)


def test_klient_bramki_wysyla_cala_liste():
    calls: list = []
    data = fake_bramka(calls).set_recipients(normalize_recipients(LISTA))
    assert calls[-1][:2] == ("POST", "/v1/whatsapp/odbiorcy")
    assert [o["numer"] for o in calls[-1][2]["odbiorcy"]] == [A, B, C]
    assert data["odbiorcy"][2]["aktywny"] is False


def test_zapis_listy_odbiorcow_wymaga_hasla(served, caplog):
    _, _, port, h, calls = served
    url = "/api/profile/whatsapp/recipients"
    # Bez CSRF, bez potwierdzenia, ze zlym haslem - bramka nic nie dostaje.
    assert call(port, "POST", url, {"recipients": LISTA, "confirm": HASLO},
                {"Cookie": h["Cookie"]})[0] == 403
    for body in ({"recipients": LISTA}, {"recipients": LISTA, "confirm": "zle-haslo-zle-haslo"}):
        status, data = call(port, "POST", url, body, h)
        assert status == 401, data
    # Zla lista: 400 przed sprawdzeniem hasla (pomylka w numerze nie liczy
    # sie do blokady konta).
    status, data = call(port, "POST", url, {"recipients": LISTA + [{"number": "1"}],
                                            "confirm": HASLO}, h)
    assert status == 400 and "Odbiorca 4" in data["error"]
    assert not [c for c in calls if c[1] == "/v1/whatsapp/odbiorcy"]

    with caplog.at_level("INFO", logger=panel_mod.log.name):
        status, data = call(port, "POST", url, {"recipients": LISTA, "confirm": HASLO}, h)
    assert status == 200, data
    assert [o["numer"] for o in data["odbiorcy"]] == [A, B, C]
    assert calls[-1][2] == {"odbiorcy": normalize_recipients(LISTA)}
    # Log panelu: liczba i koncowki, nigdy pelny numer.
    linie = " ".join(r.getMessage() for r in caplog.records)
    assert "...200" in linie and "...400 (wyl.)" in linie
    assert all(n not in linie for n in (A, B, C))

    # Profil widzi liste z bramki (pelne numery - to wlasciciel konta).
    status, data = call(port, "GET", "/api/profile/notify", headers={"Cookie": h["Cookie"]})
    assert status == 200 and len(data["odbiorcy"]) == 3


def test_zapis_listy_odbiorcow_kodem_2FA(served):
    import pyotp  # noqa: PLC0415

    _, _, port, h, calls = served
    status, setup = call(port, "POST", "/api/auth/totp/setup", {}, h)
    assert status == 200
    now = datetime.now(UTC).timestamp()
    assert call(port, "POST", "/api/auth/totp/confirm",
                {"code": pyotp.TOTP(setup["secret"]).at(now)}, h)[0] == 200
    url = "/api/profile/whatsapp/recipients"
    assert call(port, "POST", url, {"recipients": LISTA, "confirm": "000000"}, h)[0] == 401
    # Kod z nastepnego kroku: biezacy zuzylo wlaczenie 2FA.
    code = pyotp.TOTP(setup["secret"]).at(now + 30)
    status, data = call(port, "POST", url, {"recipients": LISTA[:1], "confirm": code}, h)
    assert status == 200 and data["odbiorcy"] == [{"numer": A, "etykieta": "Ja", "aktywny": True}]
    assert len([c for c in calls if c[1] == "/v1/whatsapp/odbiorcy"]) == 1


def test_wiadomosc_probna_tylko_whatsappem(served):
    _, _, port, h, calls = served
    status, _ = call(port, "POST", "/api/profile/test", {"channel": "whatsapp"}, h)
    assert status == 502  # atrapa bramki: zaden kanal nie przyjal
    assert calls[-1][1:] == ("/v1/test", {"kanal": "whatsapp", "zrodlo": "kidwatch"})
