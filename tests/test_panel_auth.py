"""Logowanie do panelu WWW: hasla, opcjonalny TOTP, kody zapasowe, blokada,
sesje, CSRF i CLI kont."""

from __future__ import annotations

import base64
import http.client
import io
import json
import os

import pyotp
import pytest

from conftest import make_config, panel_login
from kidwatch import panel_auth
from kidwatch.__main__ import main
from kidwatch.config import PanelConfig, StoreConfig
from kidwatch.panel import start_panel
from kidwatch.panel_auth import (
    BACKUP_CODES,
    LOCKOUT_SECONDS,
    MAX_FAILED,
    MAX_FAILED_PER_TICKET,
    AuthError,
    PanelAuth,
    SecretBox,
    csrf_ok,
)
from kidwatch.store import Store

HASLO = "dlugie-haslo-testowe"
ZLE = "zle-haslo-zle-haslo"


class Clock:
    def __init__(self, t: float = 1_800_000_000.0) -> None:
        self.t = t

    def __call__(self) -> float:
        return self.t


def new_box() -> SecretBox:
    return SecretBox(base64.b64encode(os.urandom(32)).decode())


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def auth(tmp_path, clock):
    a = PanelAuth(tmp_path / "panel-auth.db", box=new_box(), session_seconds=3600, clock=clock)
    a.add_user("rodzic", HASLO)
    return a


def zaloguj_haslem(auth: PanelAuth, login: str = "rodzic", password: str = HASLO):
    r = auth.login(login, password)
    assert not r.mfa_required
    return r.token, r.session


def wlacz_2fa(auth: PanelAuth, clock: Clock, login: str = "rodzic", password: str = HASLO):
    """Logowanie haslem i wlaczenie 2FA z sesji. Zwraca (sekret, sesja, kody)."""
    _, session = zaloguj_haslem(auth, login, password)
    setup = auth.totp_setup(session)
    codes = auth.totp_confirm(session, pyotp.TOTP(setup["secret"]).at(clock.t))
    return setup["secret"], session, codes


def next_code(secret: str, clock: Clock) -> str:
    """Kod z NASTEPNEGO kroku — biezacy jest juz zuzyty."""
    clock.t += 30
    return pyotp.TOTP(secret).at(clock.t)


# ======================================================================= hasla
def test_parametry_argon2_takie_jak_w_traderze(monkeypatch):
    # conftest podmienia hasher na tani; tu sprawdzamy ten prawdziwy.
    monkeypatch.undo()
    h = panel_auth._hasher
    assert (h.time_cost, h.memory_cost, h.parallelism) == (3, 64 * 1024, 4)
    assert panel_auth.hash_password("x" * 12).startswith("$argon2id$")


def test_w_bazie_nie_ma_hasla_tokenu_sekretu_TOTP_ani_kodow(auth, clock, tmp_path):
    token, _ = zaloguj_haslem(auth)
    secret, _, codes = wlacz_2fa(auth, clock)
    raw = (tmp_path / "panel-auth.db").read_bytes()
    assert HASLO.encode() not in raw
    assert token.encode() not in raw
    assert secret.encode() not in raw
    for c in codes:
        assert c.encode() not in raw


def test_haslo_krotsze_niz_12_znakow_odrzucone(auth):
    with pytest.raises(ValueError, match="12"):
        auth.add_user("drugi", "krotkie")


# ========================================================= logowanie bez 2FA
def test_konto_bez_2FA_loguje_sie_samym_haslem(auth):
    token, session = zaloguj_haslem(auth)
    assert auth.session(token) == session
    assert auth.account(session) == {
        "totp_enabled": False, "backup_codes_left": 0, "totp_available": True,
    }


def test_zle_haslo_i_nieznany_login_daja_TEN_SAM_blad(auth):
    """Inna tresc bledu pozwalalaby wyliczyc istniejace konta."""
    with pytest.raises(AuthError) as zle:
        auth.login("rodzic", ZLE)
    with pytest.raises(AuthError) as nieznany:
        auth.login("ktos", ZLE)
    assert zle.value.status == nieznany.value.status == 401
    assert zle.value.message == nieznany.value.message


def test_blokada_po_serii_nieudanych_prob_nawet_przy_dobrym_hasle(auth, clock):
    for _ in range(MAX_FAILED):
        with pytest.raises(AuthError) as err:
            auth.login("rodzic", ZLE)
        assert err.value.status == 401
    with pytest.raises(AuthError) as err:
        auth.login("rodzic", HASLO)
    assert err.value.status == 429

    clock.t += LOCKOUT_SECONDS + 1
    zaloguj_haslem(auth)
    assert auth.list_users()[0]["failed_logins"] == 0


def test_po_wygasnieciu_blokady_licznik_liczy_od_nowa(auth, clock):
    # Audyt runda 4, pkt 6: po wygasnieciu blokady jedna pomylka blokowala
    # od razu na kolejne 15 min — rodzic, ktory raz sie pomylil, czekal.
    for _ in range(MAX_FAILED):
        with pytest.raises(AuthError):
            auth.login("rodzic", ZLE)
    clock.t += LOCKOUT_SECONDS + 1
    with pytest.raises(AuthError) as err:
        auth.login("rodzic", ZLE)
    assert err.value.status == 401
    zaloguj_haslem(auth)
    for _ in range(MAX_FAILED):
        with pytest.raises(AuthError):
            auth.login("rodzic", ZLE)
    with pytest.raises(AuthError) as err:
        auth.login("rodzic", HASLO)
    assert err.value.status == 429


def test_zgadywanie_z_obcego_adresu_nie_blokuje_wlasciciela(auth, clock):
    for _ in range(MAX_FAILED + 3):
        with pytest.raises(AuthError):
            auth.login("rodzic", ZLE, ip="203.0.113.7")
    assert auth.login("rodzic", HASLO, ip="198.51.100.2").token


def test_blokada_wyglada_tak_samo_dla_istniejacego_i_nieznanego_loginu(auth, clock):
    """Wczesniej 429 dostawal tylko istniejacy login — wyrocznia istnienia kont."""
    seen = {}
    for login in ("rodzic", "nieistnieje"):
        codes = []
        for _ in range(MAX_FAILED + 1):
            with pytest.raises(AuthError) as err:
                auth.login(login, ZLE, ip="203.0.113.7")
            codes.append((err.value.status, err.value.message.split(" Spróbuj")[0]))
        seen[login] = codes
    assert seen["rodzic"] == seen["nieistnieje"]
    assert seen["rodzic"][-1][0] == 429


def test_losowe_loginy_z_jednego_adresu_wpadaja_w_limit_adresu(auth, clock):
    """Audyt 3, S1: licznik (login, adres) omijalo sie losowym loginem."""
    for i in range(panel_auth.IP_MAX_FAILED):
        with pytest.raises(AuthError) as err:
            auth.login(f"los-{i}", ZLE, ip="203.0.113.7")
        assert err.value.status == 401
    with pytest.raises(AuthError) as err:
        auth.login("jeszcze-inny", ZLE, ip="203.0.113.7")
    assert err.value.status == 429
    # Rodzic z innego adresu loguje sie normalnie.
    assert auth.login("rodzic", HASLO, ip="198.51.100.2").token

    # Po oknie adres znow moze probowac.
    clock.t += panel_auth.IP_WINDOW_SECONDS + 1
    assert auth.login("rodzic", HASLO, ip="203.0.113.7").token


def test_pomylki_rozlozone_w_czasie_nie_blokuja_adresu(auth, clock):
    for i in range(panel_auth.IP_MAX_FAILED * 2):
        with pytest.raises(AuthError) as err:
            auth.login(f"literowka-{i}", ZLE, ip="198.51.100.2")
        assert err.value.status == 401
        clock.t += panel_auth.IP_WINDOW_SECONDS + 1


def test_rownolegle_proby_z_jednego_adresu_nie_zajmuja_slotu(auth, monkeypatch):
    """Audyt 3, S1: kilka rownoleglych POST-ow trzymalo jedyny slot Argon2,
    a rodzic dostawal 503. Teraz drugi rownolegly z tego samego adresu
    dostaje 429 od razu, a rodzic czeka najwyzej jedna weryfikacje."""
    import threading  # noqa: PLC0415
    import time  # noqa: PLC0415

    started, release = threading.Event(), threading.Event()
    real_verify = panel_auth._verify

    def slow_verify(stored, password):
        if password == ZLE:
            started.set()
            release.wait(5)
        return real_verify(stored, password)

    monkeypatch.setattr(panel_auth, "_verify", slow_verify)
    first = threading.Thread(
        target=lambda: pytest.raises(AuthError, auth.login, "los-1", ZLE, ip="203.0.113.7")
    )
    first.start()
    assert started.wait(5)

    t0 = time.monotonic()
    with pytest.raises(AuthError) as err:
        auth.login("los-2", ZLE, ip="203.0.113.7")
    assert err.value.status == 429
    assert time.monotonic() - t0 < 1  # bez czekania na slot

    parent = {}
    worker = threading.Thread(
        target=lambda: parent.setdefault("r", auth.login("rodzic", HASLO, ip="198.51.100.2"))
    )
    worker.start()
    release.set()
    worker.join(10)
    first.join(10)
    assert parent["r"].token


def test_sesja_wygasa(auth, clock):
    token, _ = zaloguj_haslem(auth)
    clock.t += 3601
    assert auth.session(token) is None


def test_kazde_logowanie_daje_NOWA_sesje(auth):
    """Ochrona przed session fixation: token nie jest nigdy przenoszony."""
    a, _ = zaloguj_haslem(auth)
    b, _ = zaloguj_haslem(auth)
    assert a != b


# ============================================================== wlaczanie 2FA
def test_QR_jest_PNG_liczonym_lokalnie_z_uri_otpauth(auth):
    _, session = zaloguj_haslem(auth)
    setup = auth.totp_setup(session)
    assert setup["uri"].startswith("otpauth://totp/Kidwatch:rodzic?secret=" + setup["secret"])
    assert base64.b64decode(setup["qr_png_base64"]).startswith(b"\x89PNG")


def test_sam_wygenerowany_sekret_NIE_wlacza_2FA(auth):
    _, session = zaloguj_haslem(auth)
    auth.totp_setup(session)
    zaloguj_haslem(auth)  # dalej samo haslo, bez biletu
    with pytest.raises(AuthError) as err:
        auth.totp_confirm(session, "000000")
    assert err.value.status == 401
    assert auth.account(session)["totp_enabled"] is False


def test_wlaczenie_2FA_daje_kody_i_wylogowuje_INNE_sesje(auth, clock):
    inna, _ = zaloguj_haslem(auth)
    secret, session, codes = wlacz_2fa(auth, clock)
    assert len(codes) == BACKUP_CODES == len(set(codes))
    # Sesja, z ktorej wlaczono 2FA, zostaje; ta zalozona samym haslem — nie.
    assert auth.session(inna) is None
    assert auth.account(session) == {
        "totp_enabled": True, "backup_codes_left": BACKUP_CODES, "totp_available": True,
    }
    with pytest.raises(AuthError) as err:
        auth.totp_setup(session)
    assert err.value.status == 409


def test_bez_klucza_wlaczenie_2FA_niedostepne_a_reszta_dziala(tmp_path):
    a = PanelAuth(tmp_path / "a.db", box=None)
    a.add_user("rodzic", HASLO)
    token, session = zaloguj_haslem(a)
    assert a.session(token)
    assert a.account(session)["totp_available"] is False
    with pytest.raises(AuthError) as err:
        a.totp_setup(session)
    assert err.value.status == 503
    assert "PANEL_TOTP_KEY" in err.value.message


# ============================================================ logowanie z 2FA
def test_konto_z_2FA_haslo_daje_tylko_bilet(auth, clock):
    wlacz_2fa(auth, clock)
    r = auth.login("rodzic", HASLO)
    assert r.mfa_required
    assert r.session is None
    # Bilet to nie sesja: niczego nie otwiera.
    assert auth.session(r.challenge) is None


def test_logowanie_haslo_plus_kod(auth, clock):
    secret, _, _ = wlacz_2fa(auth, clock)
    r = auth.login("rodzic", HASLO)
    token, session = auth.mfa(r.challenge, next_code(secret, clock))
    assert auth.session(token) == session


def test_ten_sam_kod_nie_przechodzi_dwa_razy(auth, clock):
    """RFC 6238 §5.2 — przechwycony kod nie moze dac drugiej sesji."""
    secret, _, _ = wlacz_2fa(auth, clock)
    code = next_code(secret, clock)
    auth.mfa(auth.login("rodzic", HASLO).challenge, code)
    with pytest.raises(AuthError):
        auth.mfa(auth.login("rodzic", HASLO).challenge, code)


def test_kod_uzyty_do_wlaczenia_nie_loguje_ponownie(auth, clock):
    secret, _, _ = wlacz_2fa(auth, clock)
    with pytest.raises(AuthError):
        auth.mfa(auth.login("rodzic", HASLO).challenge, pyotp.TOTP(secret).at(clock.t))


def test_kod_zapasowy_dziala_RAZ(auth, clock):
    _, _, codes = wlacz_2fa(auth, clock)
    token, session = auth.mfa(auth.login("rodzic", HASLO).challenge, codes[0].upper())
    assert auth.account(session)["backup_codes_left"] == BACKUP_CODES - 1
    with pytest.raises(AuthError):
        auth.mfa(auth.login("rodzic", HASLO).challenge, codes[0])


def test_bilet_pada_po_serii_zlych_kodow(auth, clock):
    secret, _, _ = wlacz_2fa(auth, clock)
    r = auth.login("rodzic", HASLO)
    for _ in range(MAX_FAILED_PER_TICKET):
        with pytest.raises(AuthError):
            auth.mfa(r.challenge, "000000")
    with pytest.raises(AuthError) as err:
        auth.mfa(r.challenge, next_code(secret, clock))
    assert "Bilet" in err.value.message


def test_bilet_wygasa(auth, clock):
    secret, _, _ = wlacz_2fa(auth, clock)
    r = auth.login("rodzic", HASLO)
    clock.t += panel_auth.MFA_TICKET_SECONDS + 1
    with pytest.raises(AuthError) as err:
        auth.mfa(r.challenge, pyotp.TOTP(secret).at(clock.t))
    assert err.value.status == 401


def test_zle_kody_licza_sie_do_blokady_konta(auth, clock):
    """Bez tego wystarczaloby brac nowy bilet co trzy proby i zgadywac kod
    bez konca — haslo atakujacy juz ma."""
    wlacz_2fa(auth, clock)
    for _ in range(MAX_FAILED):
        r = auth.login("rodzic", HASLO)
        with pytest.raises(AuthError):
            auth.mfa(r.challenge, "000000")
    with pytest.raises(AuthError) as err:
        auth.login("rodzic", HASLO)
    assert err.value.status == 429


def zle_kody(auth: PanelAuth, n: int) -> None:
    """n zlych kodow drugiego skladnika, na tylu biletach, ile trzeba."""
    while n > 0:
        r = auth.login("rodzic", HASLO)
        for _ in range(min(n, MAX_FAILED_PER_TICKET)):
            with pytest.raises(AuthError):
                auth.mfa(r.challenge, "000000")
            n -= 1


def test_licznik_zeruje_PELNE_logowanie_a_nie_samo_haslo(auth, clock):
    secret, _, _ = wlacz_2fa(auth, clock)
    zle_kody(auth, MAX_FAILED - 1)
    r = auth.login("rodzic", HASLO)  # samo haslo — licznik zostaje
    assert auth.list_users()[0]["failed_logins"] == MAX_FAILED - 1
    auth.mfa(r.challenge, next_code(secret, clock))
    assert auth.list_users()[0]["failed_logins"] == 0


def test_blokada_obowiazuje_takze_na_wydanym_bilecie(auth, clock):
    secret, _, _ = wlacz_2fa(auth, clock)
    r = auth.login("rodzic", HASLO)
    zle_kody(auth, MAX_FAILED)
    with pytest.raises(AuthError) as err:
        auth.mfa(r.challenge, next_code(secret, clock))
    assert err.value.status == 429


def test_konto_z_2FA_bez_klucza_NIE_loguje_sie_samym_haslem(auth, clock, tmp_path):
    """Znikniecie klucza nie moze po cichu zdjac drugiego skladnika."""
    wlacz_2fa(auth, clock)
    bez_klucza = PanelAuth(tmp_path / "panel-auth.db", box=None, clock=clock)
    with pytest.raises(AuthError) as err:
        bez_klucza.login("rodzic", HASLO)
    assert err.value.status == 503


def test_zmieniony_klucz_daje_czytelny_blad_a_nie_500(auth, clock, tmp_path):
    secret, _, _ = wlacz_2fa(auth, clock)
    other = PanelAuth(tmp_path / "panel-auth.db", box=new_box(), clock=clock)
    r = other.login("rodzic", HASLO)
    with pytest.raises(AuthError) as err:
        other.mfa(r.challenge, next_code(secret, clock))
    assert err.value.status == 503
    assert "--totp" in err.value.message


# ============================================================= wylaczanie 2FA
def test_wylaczenie_2FA_wymaga_hasla_I_kodu(auth, clock):
    secret, session, _ = wlacz_2fa(auth, clock)
    with pytest.raises(AuthError):
        auth.totp_disable(session, HASLO, "000000")
    with pytest.raises(AuthError):
        auth.totp_disable(session, ZLE, next_code(secret, clock))
    assert auth.account(session)["totp_enabled"] is True

    auth.totp_disable(session, HASLO, next_code(secret, clock))
    assert auth.account(session) == {
        "totp_enabled": False, "backup_codes_left": 0, "totp_available": True,
    }
    assert not auth.login("rodzic", HASLO).mfa_required


def test_wylaczenie_2FA_kodem_zapasowym(auth, clock):
    _, session, codes = wlacz_2fa(auth, clock)
    auth.totp_disable(session, HASLO, codes[3])
    assert auth.account(session)["totp_enabled"] is False


def test_nieudane_wylaczenia_licza_sie_do_blokady(auth, clock):
    """Inaczej formularz wylaczania bylby oknem do zgadywania hasla."""
    _, session, _ = wlacz_2fa(auth, clock)
    for _ in range(MAX_FAILED):
        with pytest.raises(AuthError):
            auth.totp_disable(session, ZLE, "000000")
    with pytest.raises(AuthError) as err:
        auth.login("rodzic", HASLO)
    assert err.value.status == 429


# ==================================================================== reset
def test_potwierdzenie_tozsamosci_haslem_albo_kodem(auth, clock):
    secret, session, codes = wlacz_2fa(auth, clock)
    auth.reauth(session, HASLO)
    auth.reauth(session, next_code(secret, clock))
    auth.reauth(session, codes[0])
    with pytest.raises(AuthError):
        auth.reauth(session, codes[0])  # kod zapasowy jednorazowy
    with pytest.raises(AuthError) as err:
        auth.reauth(session, "")
    assert err.value.status == 401


def test_nieudane_potwierdzenia_licza_sie_do_blokady(auth, clock):
    _, session = zaloguj_haslem(auth)
    for _ in range(MAX_FAILED):
        with pytest.raises(AuthError):
            auth.reauth(session, ZLE)
    with pytest.raises(AuthError) as err:
        auth.reauth(session, HASLO)
    assert err.value.status == 429


def test_reset_hasla_wylogowuje_zdejmuje_blokade_i_ZOSTAWIA_2FA(auth, clock):
    _, session, _ = wlacz_2fa(auth, clock)
    for _ in range(MAX_FAILED):
        with pytest.raises(AuthError):
            auth.login("rodzic", ZLE)
    assert auth.reset_user("rodzic", "nowe-haslo-testowe") == 1
    assert not sesja_istnieje(auth, session)
    assert auth.login("rodzic", "nowe-haslo-testowe").mfa_required


def sesja_istnieje(auth: PanelAuth, session) -> bool:
    # Jawnego tokenu nie mamy pod reka (wlacz_2fa zwraca sesje), wiec po hashu.
    with auth._conn() as conn:
        return conn.execute(
            "SELECT 1 FROM sessions WHERE token_hash = ?", (session.token_hash,)
        ).fetchone() is not None


def test_reset_TOTP_zdejmuje_2FA_i_kasuje_kody(auth, clock):
    _, session, codes = wlacz_2fa(auth, clock)
    assert auth.reset_totp("rodzic") == 1
    assert not sesja_istnieje(auth, session)
    assert not auth.login("rodzic", HASLO).mfa_required


def test_szyfrogram_sekretu_jest_przypiety_do_konta(auth):
    """Podmiana sekretu miedzy wierszami w pliku bazy nie przechodzi."""
    box = auth.box
    blob = box.encrypt("JBSWY3DPEHPK3PXP", 1)
    assert box.decrypt(blob, 1) == "JBSWY3DPEHPK3PXP"
    with pytest.raises(Exception):  # noqa: B017 — InvalidTag
        box.decrypt(blob, 2)


def test_klucz_musi_miec_32_bajty():
    with pytest.raises(ValueError, match="32"):
        SecretBox(base64.b64encode(b"za-krotki").decode())
    with pytest.raises(ValueError, match="base64"):
        SecretBox("to nie jest base64!")


def test_csrf_musi_sie_zgadzac_z_sesja(auth):
    _, session = zaloguj_haslem(auth)
    _, inna = zaloguj_haslem(auth)
    assert csrf_ok(session, session.csrf)
    assert not csrf_ok(session, None)
    assert not csrf_ok(session, "")
    assert not csrf_ok(session, inna.csrf)


# ======================================================================== HTTP
@pytest.fixture
def server(tmp_path):
    cfg = make_config(
        panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path / "web")),
    )
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", HASLO)
    srv = start_panel(cfg)
    yield srv
    srv.shutdown()


def call(srv, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    payload = json.loads(raw) if raw else None
    return resp.status, resp.headers, payload


def zaloguj(srv, totp_secret: str | None = None) -> tuple[str, str]:
    cookie = panel_login(srv.server_address[1], "rodzic", HASLO, totp_secret)
    jar = dict(c.split("=", 1) for c in cookie.split("; "))
    return cookie, jar["kidwatch_csrf"]


@pytest.mark.parametrize("path", ["/api/devices", "/api/notifications", "/api/day",
                                  "/api/auth/me", "/api/nie-ma-takiego"])
def test_api_bez_sesji_zwraca_401(server, path):
    status, _, body = call(server, "GET", path)
    assert status == 401
    assert body["error"]


def test_health_jest_dostepny_bez_sesji(server):
    assert call(server, "GET", "/api/health")[0] == 200


def test_podrobione_ciasteczko_nie_otwiera_api(server):
    status, _, _ = call(server, "GET", "/api/devices",
                        headers={"Cookie": "kidwatch_session=zgadniety-token"})
    assert status == 401


def test_logowanie_ustawia_bezpieczne_ciasteczka(server):
    status, headers, body = call(server, "POST", "/api/auth/login",
                                 {"login": "rodzic", "password": HASLO})
    assert status == 200
    assert body["mfa_required"] is False
    raw = headers.get_all("Set-Cookie")
    sesja = next(c for c in raw if c.startswith("kidwatch_session="))
    csrf = next(c for c in raw if c.startswith("kidwatch_csrf="))
    for attr in ("HttpOnly", "Secure", "SameSite=Strict", "Path=/"):
        assert attr in sesja
    # Front musi przeczytac CSRF, wiec ten jeden NIE jest HttpOnly.
    assert "HttpOnly" not in csrf
    assert "Secure" in csrf

    cookie = "; ".join(c.split(";")[0] for c in raw)
    status, _, me = call(server, "GET", "/api/auth/me", headers={"Cookie": cookie})
    assert status == 200
    assert me["login"] == "rodzic"
    assert me["totp_enabled"] is False
    assert me["totp_available"] is True
    assert call(server, "GET", "/api/devices", headers={"Cookie": cookie})[0] == 200


def test_wlaczenie_2FA_przez_HTTP_i_logowanie_haslo_plus_kod(server):
    cookie, csrf = zaloguj(server)
    auth_h = {"Cookie": cookie, "X-CSRF-Token": csrf}

    # Bez CSRF ani rusz — to zmiana stanu konta.
    assert call(server, "POST", "/api/auth/totp/setup", {}, {"Cookie": cookie})[0] == 403
    status, _, setup = call(server, "POST", "/api/auth/totp/setup", {}, auth_h)
    assert status == 200
    assert base64.b64decode(setup["qr_png_base64"]).startswith(b"\x89PNG")

    code = pyotp.TOTP(setup["secret"]).now()
    status, _, done = call(server, "POST", "/api/auth/totp/confirm", {"code": code}, auth_h)
    assert status == 200
    assert len(done["backup_codes"]) == BACKUP_CODES
    me = call(server, "GET", "/api/auth/me", headers={"Cookie": cookie})[2]
    assert me["totp_enabled"] is True

    # Teraz haslo daje bilet bez ciasteczek, a dane sa dopiero po kodzie.
    status, headers, step = call(server, "POST", "/api/auth/login",
                                 {"login": "rodzic", "password": HASLO})
    assert step["mfa_required"] is True
    assert not headers.get_all("Set-Cookie")
    for c in ("", f"kidwatch_session={step['challenge']}"):
        assert call(server, "GET", "/api/devices", headers={"Cookie": c})[0] == 401
    status, _, _ = call(server, "POST", "/api/auth/mfa",
                        {"challenge": step["challenge"], "code": "000000"})
    assert status == 401
    status, _, _ = call(server, "POST", "/api/auth/mfa",
                        {"challenge": step["challenge"], "code": done["backup_codes"][0]})
    assert status == 200

    cookie2, _ = zaloguj(server, setup["secret"])
    assert call(server, "GET", "/api/devices", headers={"Cookie": cookie2})[0] == 200


def test_wylaczenie_2FA_przez_HTTP_wymaga_hasla_i_kodu(server):
    cookie, csrf = zaloguj(server)
    h = {"Cookie": cookie, "X-CSRF-Token": csrf}
    setup = call(server, "POST", "/api/auth/totp/setup", {}, h)[2]
    codes = call(server, "POST", "/api/auth/totp/confirm",
                 {"code": pyotp.TOTP(setup["secret"]).now()}, h)[2]["backup_codes"]
    assert call(server, "POST", "/api/auth/totp/disable",
                {"password": ZLE, "code": codes[0]}, h)[0] == 401
    assert call(server, "POST", "/api/auth/totp/disable",
                {"password": HASLO, "code": codes[0]}, {"Cookie": cookie})[0] == 403
    assert call(server, "POST", "/api/auth/totp/disable",
                {"password": HASLO, "code": codes[0]}, h)[0] == 200
    assert call(server, "GET", "/api/auth/me", headers={"Cookie": cookie})[2]["totp_enabled"] \
        is False


def test_zle_haslo_przez_http_401_a_po_serii_429(server):
    for _ in range(MAX_FAILED):
        status, _, body = call(server, "POST", "/api/auth/login",
                               {"login": "rodzic", "password": ZLE})
        assert status == 401
        assert body["error"] == "Nieprawidłowy login lub hasło"
    status, _, body = call(server, "POST", "/api/auth/login",
                           {"login": "rodzic", "password": HASLO})
    assert status == 429
    assert "Zbyt wiele nieudanych prób" in body["error"]


def test_logowanie_przyjmuje_tylko_json(server):
    """Formularz z obcej strony idzie bez preflightu CORS — JSON nie."""
    status, _, _ = call(server, "POST", "/api/auth/login",
                        body=f"login=rodzic&password={HASLO}".encode(),
                        headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert status == 415
    status, _, _ = call(server, "POST", "/api/auth/login", body=b"{nie json")
    assert status == 400


def test_wylogowanie_wymaga_tokenu_CSRF(server):
    cookie, csrf = zaloguj(server)
    status, _, _ = call(server, "POST", "/api/auth/logout", {}, headers={"Cookie": cookie})
    assert status == 403
    status, _, _ = call(server, "POST", "/api/auth/logout", {},
                        headers={"Cookie": cookie, "X-CSRF-Token": "zly"})
    assert status == 403
    # Sesja nadal wazna — odrzucony POST niczego nie zmienil.
    assert call(server, "GET", "/api/auth/me", headers={"Cookie": cookie})[0] == 200


def test_wylogowanie_uniewaznia_sesje_po_stronie_serwera(server):
    cookie, csrf = zaloguj(server)
    status, headers, _ = call(server, "POST", "/api/auth/logout", {},
                              headers={"Cookie": cookie, "X-CSRF-Token": csrf})
    assert status == 200
    assert any("Max-Age=0" in c for c in headers.get_all("Set-Cookie"))
    # Stare ciasteczko, nawet odeslane recznie, juz nic nie otwiera.
    assert call(server, "GET", "/api/devices", headers={"Cookie": cookie})[0] == 401


def test_panel_bez_klucza_dziala_tylko_2FA_niedostepne(tmp_path, monkeypatch):
    monkeypatch.delenv(panel_auth.TOTP_KEY_ENV)
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path)))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", HASLO)
    srv = start_panel(cfg)
    try:
        cookie, csrf = zaloguj(srv)
        me = call(srv, "GET", "/api/auth/me", headers={"Cookie": cookie})[2]
        assert me["totp_available"] is False
        assert call(srv, "GET", "/api/devices", headers={"Cookie": cookie})[0] == 200
        status, _, body = call(srv, "POST", "/api/auth/totp/setup", {},
                               {"Cookie": cookie, "X-CSRF-Token": csrf})
        assert status == 503
        assert "PANEL_TOTP_KEY" in body["error"]
    finally:
        srv.shutdown()


# ========================================================================= CLI
CONFIG = """
source:
  kind: nextdns
  nextdns:
    profile_id: test
devices:
  - display_name: iPad
    child: Dziecko
    source_ids: [ipad]
store:
  path: k.db
"""


@pytest.fixture
def config_file(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(CONFIG, encoding="utf-8")
    return p


def generated_password(out: str) -> str:
    return next(line.split(": ", 1)[1] for line in out.splitlines() if line.startswith("haslo: "))


def test_user_add_losuje_haslo_wypisuje_je_raz_i_da_sie_nim_zalogowac(
    config_file, tmp_path, capsys
):
    assert main(["--config", str(config_file), "user-add", "marcin"]) == 0
    password = generated_password(capsys.readouterr().out)
    # Domyslnie obok bazy glownej — w klastrze to /data/panel-auth.db.
    auth = PanelAuth(tmp_path / "panel-auth.db", box=new_box())
    token, _ = zaloguj_haslem(auth, "marcin", password)
    assert auth.session(token).login == "marcin"


def test_user_add_z_haslem_ze_stdin_nie_wypisuje_go(config_file, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO("haslo-ze-stdin-123\n"))
    assert main(["--config", str(config_file), "user-add", "marcin", "--password-stdin"]) == 0
    assert "haslo-ze-stdin-123" not in capsys.readouterr().out
    zaloguj_haslem(PanelAuth(tmp_path / "panel-auth.db"), "marcin", "haslo-ze-stdin-123")


def test_user_add_odrzuca_duplikat_i_krotkie_haslo(config_file, monkeypatch, capsys):
    assert main(["--config", str(config_file), "user-add", "marcin"]) == 0
    assert main(["--config", str(config_file), "user-add", "marcin"]) == 1
    monkeypatch.setattr("sys.stdin", io.StringIO("krotkie\n"))
    assert main(["--config", str(config_file), "user-add", "inny", "--password-stdin"]) == 1


def test_user_reset_zmienia_haslo_i_wylogowuje(config_file, tmp_path, monkeypatch, capsys):
    assert main(["--config", str(config_file), "user-add", "marcin"]) == 0
    old = generated_password(capsys.readouterr().out)
    auth = PanelAuth(tmp_path / "panel-auth.db")
    token, _ = zaloguj_haslem(auth, "marcin", old)

    monkeypatch.setattr("sys.stdin", io.StringIO("zupelnie-nowe-haslo\n"))
    assert main(["--config", str(config_file), "user-reset", "marcin", "--password-stdin"]) == 0
    assert auth.session(token) is None
    with pytest.raises(AuthError):
        auth.login("marcin", old)
    zaloguj_haslem(auth, "marcin", "zupelnie-nowe-haslo")
    assert main(["--config", str(config_file), "user-reset", "nikt"]) == 1


def test_user_reset_totp_zdejmuje_2FA(config_file, tmp_path, capsys, clock):
    assert main(["--config", str(config_file), "user-add", "marcin"]) == 0
    password = generated_password(capsys.readouterr().out)
    auth = PanelAuth(tmp_path / "panel-auth.db", box=new_box(), clock=clock)
    wlacz_2fa(auth, clock, "marcin", password)
    assert main(["--config", str(config_file), "user-list"]) == 0
    assert "2FA wlaczone, kodow zapasowych: 8" in capsys.readouterr().out

    assert main(["--config", str(config_file), "user-reset", "marcin", "--totp"]) == 0
    assert "haslo: " not in capsys.readouterr().out  # haslo bez zmian
    zaloguj_haslem(auth, "marcin", password)

    assert main(["--config", str(config_file), "user-list"]) == 0
    assert "bez 2FA" in capsys.readouterr().out
    assert main(["--config", str(config_file), "user-reset", "nikt", "--totp"]) == 1


def test_sciezka_bazy_logowania_z_konfiguracji(tmp_path):
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(CONFIG + "panel:\n  auth_db: inna/auth.db\n", encoding="utf-8")
    from kidwatch.config import Config  # noqa: PLC0415

    assert Config.load(cfg_path).panel_auth_path == str(tmp_path / "inna" / "auth.db")
