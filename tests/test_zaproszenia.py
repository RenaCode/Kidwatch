"""Etap E4: zaproszenia do domu (docs/architektura-domy.md §7 E4).

Kazda bariera ma test i kanarek: ten sam sprawdzian z bariera wylaczona
mutacja w kodzie MUSI znalezc naruszenie — inaczej jego cisza niczego by
nie dowodzila. Sprawdziany (`_naruszenia_*`) zwracaja liste naruszen.

Konta, loginy i tokeny wylacznie generyczne albo losowane w locie
(tests/test_repo_prywatnosc.py).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from pathlib import Path

import pyotp
import pytest

import test_domy_panel
from kidwatch import domy as dm
from kidwatch import uprawnienia as u
from kidwatch import zaproszenia as zp
from kidwatch.panel import WYMAGA_2FA, start_panel
from kidwatch.panel_auth import AuthError, PanelAuth, box_from_env
from kidwatch.store import Store
from test_domy_e2 import kek  # noqa: F401 — fikstura KIDWATCH_KEK (wymagana przez domy)
from test_domy_panel import DOM_A, DOM_B, DOM_GET, HASLO, _konfiguracja, _sciezka, sso
from test_panel_sso import call, cookie, jar


@pytest.fixture
def domy(tmp_path, monkeypatch):
    """Domy A i B z test_domy_panel.py (SSO wlaczone, konta czlonkow)."""
    yield from test_domy_panel.domy.__wrapped__(tmp_path, monkeypatch)


GOSC = "gosc-1"
#: Stale sprzed mutacji kanarkow (kanarek podmienia je w module).
MAX_PROB, IP_MAX_FAILED = zp.MAX_PROB, zp.IP_MAX_FAILED
GRUPA_GOSCI = "kidwatch-goscie"


# ================================================================ pomocnicze
def zapros(srv, kto: str, dom: int, rola: str = "podglad", *, dla: str | None = None,
           grupy: str = "wlasciciel", waznosc_h: int | None = None, confirm: str = HASLO):
    body = {"rola": rola, "confirm": confirm}
    if dla is not None:
        body["dla"] = dla
    if waznosc_h is not None:
        body["waznosc_h"] = waznosc_h
    return call(srv, "POST", f"/api/domy/{dom}/zaproszenia/utworz", body, sso(srv, kto, grupy))


def token_od(srv, kto: str = "czlonek-b", dom: int = DOM_B, **kw) -> str:
    status, _, body = zapros(srv, kto, dom, **kw)
    assert status == 200, body
    return body["token"]


def gosc(login: str = GOSC, grupy: str = GRUPA_GOSCI, ip: str | None = None) -> dict:
    h = {"Remote-User": login, "Remote-Groups": grupy}
    if ip:
        h["X-Forwarded-For"] = ip
    return h


def przyjmij(srv, token: str, h: dict, potwierdzam=True):
    return call(srv, "POST", "/api/zaproszenia/przyjmij",
                {"token": token, "potwierdzam": potwierdzam}, h)


def _db(srv) -> sqlite3.Connection:
    conn = sqlite3.connect(srv.cfg.panel_auth_path)
    conn.row_factory = sqlite3.Row
    return conn


def _konto(srv, login: str) -> bool:
    with _db(srv) as conn:
        return conn.execute("SELECT 1 FROM users WHERE login = ?", (login,)).fetchone() is not None


def _domy_konta(srv, login: str) -> list[int]:
    with _db(srv) as conn:
        return [r[0] for r in conn.execute(
            "SELECT c.dom_id FROM czlonkostwa c JOIN users u ON u.id = c.user_id "
            "WHERE u.login = ? ORDER BY c.dom_id", (login,))]


def _wiersz(srv, zid: int) -> sqlite3.Row:
    with _db(srv) as conn:
        return conn.execute("SELECT * FROM zaproszenia WHERE id = ?", (zid,)).fetchone()


def _sesja_goscia(srv, login: str = GOSC) -> dict:
    h = gosc(login)
    status, headers, me = call(srv, "GET", "/api/auth/me", headers=h)
    assert status == 200, me
    return {**h, "Cookie": cookie(jar(headers))}


# ============================================== Gotowe, gdy: gosc widzi tylko dom
def test_gosc_z_grupy_kidwatch_goscie_przyjmuje_i_widzi_tylko_ten_dom(domy):
    """Konto spoza panelu (grupa `kidwatch-goscie`) przyjmuje zaproszenie do
    domu B: konto powstaje w locie, czlonkostwo tylko w B, sesja od razu."""
    token = token_od(domy, dla=GOSC)
    assert call(domy, "GET", "/api/auth/me", headers=gosc())[0] == 403  # brak konta
    status, headers, body = przyjmij(domy, token, gosc())
    assert status == 200 and body["konto_zalozone"] and body["dom_id"] == DOM_B, body
    assert "kidwatch_session" in jar(headers)
    h = {**gosc(), "Cookie": cookie(jar(headers))}
    me = call(domy, "GET", "/api/auth/me", headers=h)[2]
    assert [(d["id"], d["rola"]) for d in me["domy"]] == [(DOM_B, "podglad")]
    assert me["wymaga_totp"] is False  # SSO: 2FA zrobila Authelia
    dzien = call(domy, "GET", f"/api/domy/{DOM_B}/day", headers=h)
    assert dzien[0] == 200 and "TYLKO-B" in json.dumps(dzien[2])
    assert _domy_konta(domy, GOSC) == [DOM_B]
    with _db(domy) as conn:
        wpis = conn.execute("SELECT login, opis FROM audyt WHERE akcja = 'zaproszenie.przyjete'"
                            ).fetchone()
        zid = conn.execute("SELECT zaproszenie_id FROM czlonkostwa WHERE dom_id = ? AND "
                           "user_id = (SELECT id FROM users WHERE login = ?)",
                           (DOM_B, GOSC)).fetchone()[0]
    assert wpis["login"] == GOSC and "prywatności potwierdzona" in wpis["opis"]
    assert zid is not None


def _naruszenia_innych_domow(srv, h: dict) -> list[str]:
    """Trasy GET Domu A (dom zapraszajacego, nie zaproszenia), ktore
    odpowiadaja czymkolwiek innym niz 404, i A w /api/auth/me."""
    zle = [k for k in DOM_GET if call(srv, "GET", _sciezka(k, DOM_A), headers=h)[0] != 404]
    me = call(srv, "GET", "/api/auth/me", headers=h)[2]
    if any(d["id"] == DOM_A for d in me["domy"]):
        zle.append("auth/me: dom A")
    return zle


def test_przyjecie_nie_daje_innych_domow_zapraszajacego(domy):
    """`obu` jest w A i w B; zaprasza do B. Gosc nie dostaje A."""
    token = token_od(domy, "obu", DOM_B)
    assert przyjmij(domy, token, gosc())[0] == 200
    assert _naruszenia_innych_domow(domy, _sesja_goscia(domy)) == []


def test_kanarek_przyjecie_z_domami_zapraszajacego(domy, monkeypatch):
    """Mutacja: przyjecie dopisuje tez czlonkostwo w pierwszym domu
    zapraszajacego — sprawdzian musi to wykryc."""
    prawdziwa = dm.ustaw_czlonkostwo_conn

    def z_domem_a(conn, dom_id, user_id, rola, *a, **kw):
        prawdziwa(conn, dom_id, user_id, rola, *a, **kw)
        prawdziwa(conn, DOM_A, user_id, rola, *a, **kw)

    monkeypatch.setattr(zp.dm, "ustaw_czlonkostwo_conn", z_domem_a)
    token = token_od(domy, "obu", DOM_B)
    assert przyjmij(domy, token, gosc())[0] == 200
    assert _naruszenia_innych_domow(domy, _sesja_goscia(domy))


# =========================================================== jednorazowosc
def test_token_jednorazowy(domy):
    token = token_od(domy)
    assert przyjmij(domy, token, gosc())[0] == 200
    status, _, body = przyjmij(domy, token, gosc("gosc-2"))
    assert status == 410 and "wykorzystane" in body["error"]
    assert not _konto(domy, "gosc-2")


def test_kanarek_jednorazowosc_trzyma_tez_sama_transakcja(domy, monkeypatch):
    """Bariera stanu (`Zaproszenie.stan`) wylaczona: drugie przyjecie nadal
    pada na warunkowym UPDATE w transakcji — i nie zostawia konta."""
    token = token_od(domy)
    assert przyjmij(domy, token, gosc())[0] == 200
    monkeypatch.setattr(zp.Zaproszenie, "stan", lambda self, teraz: zp.OCZEKUJE)
    assert przyjmij(domy, token, gosc("gosc-2"))[0] == 410
    assert not _konto(domy, "gosc-2")


def test_rownolegle_przyjecia_przechodzi_jedno(domy):
    token = token_od(domy)
    wyniki: list[int] = []
    bariera = threading.Barrier(4)

    def proba(i: int) -> None:
        bariera.wait()
        wyniki.append(przyjmij(domy, token, gosc(f"gosc-r{i}"))[0])

    watki = [threading.Thread(target=proba, args=(i,)) for i in range(4)]
    for w in watki:
        w.start()
    for w in watki:
        w.join()
    assert sorted(wyniki).count(200) == 1, wyniki
    assert sum(_konto(domy, f"gosc-r{i}") for i in range(4)) == 1


# =============================================================== wygasanie
def test_wygasle_zaproszenie_odrzucone_i_bez_konta(domy):
    status, _, body = zapros(domy, "czlonek-b", DOM_B)
    with _db(domy) as conn:
        conn.execute("UPDATE zaproszenia SET wygasa_at = 1 WHERE id = ?",
                     (body["zaproszenie"]["id"],))
    status, _, body2 = przyjmij(domy, body["token"], gosc())
    assert status == 410 and "wygasło" in body2["error"]
    assert not _konto(domy, GOSC)


def test_kanarek_wygasanie_trzyma_tez_transakcja(domy, monkeypatch):
    status, _, body = zapros(domy, "czlonek-b", DOM_B)
    with _db(domy) as conn:
        conn.execute("UPDATE zaproszenia SET wygasa_at = 1 WHERE id = ?",
                     (body["zaproszenie"]["id"],))
    monkeypatch.setattr(zp.Zaproszenie, "stan", lambda self, teraz: zp.OCZEKUJE)
    assert przyjmij(domy, body["token"], gosc())[0] == 410
    assert not _konto(domy, GOSC)


def test_waznosc_domyslna_72h_max_7_dni(domy):
    body = zapros(domy, "czlonek-b", DOM_B)[2]
    z = _wiersz(domy, body["zaproszenie"]["id"])
    assert z["wygasa_at"] - z["utworzone_at"] == pytest.approx(72 * 3600)
    for zla in (0, 7 * 24 + 1, "72", True):
        status, _, b = zapros(domy, "czlonek-b", DOM_B, waznosc_h=zla)
        assert status == 400, (zla, b)
    assert zapros(domy, "czlonek-b", DOM_B, waznosc_h=7 * 24)[0] == 200


def test_sprzatanie_po_30_dniach(tmp_path):
    teraz = [1_000_000.0]
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path, box=box_from_env())
    dm.RejestrDomow(path).migruj()
    auth.add_user("wlasciciel-x", HASLO)
    z = zp.Zaproszenia(path, clock=lambda: teraz[0])
    _, stare = z.utworz(DOM_A, kto_id=None, kto_login="wlasciciel-x", rola="podglad")
    _, odwolane = z.utworz(DOM_A, kto_id=None, kto_login="wlasciciel-x", rola="podglad")
    z.odwolaj(DOM_A, odwolane.id, kto_login="wlasciciel-x")
    teraz[0] += zp.SPRZATANIE_PO_SECONDS + 72 * 3600 - 1
    _, nowe = z.utworz(DOM_A, kto_id=None, kto_login="wlasciciel-x", rola="podglad")
    assert z.sprzataj() == 1  # odwolane (30 dni od odwolania); wygasle jeszcze nie
    teraz[0] += 2
    assert z.sprzataj() == 1
    assert [x.id for x in z.lista(DOM_A)] == [nowe.id]
    assert stare.id != nowe.id


# =============================================================== odwolanie
def test_odwolane_nie_otwiera_a_przyjetego_nie_odwolasz(domy):
    body = zapros(domy, "czlonek-b", DOM_B)[2]
    zid = body["zaproszenie"]["id"]
    h = sso(domy, "czlonek-b")
    status, _, r = call(domy, "POST", f"/api/domy/{DOM_B}/zaproszenia/odwolaj", {"id": zid}, h)
    assert status == 200 and r["zaproszenie"]["stan"] == "odwolane"
    status, _, r = przyjmij(domy, body["token"], gosc())
    assert status == 410 and "odwołane" in r["error"]
    assert not _konto(domy, GOSC)
    token = token_od(domy)
    assert przyjmij(domy, token, gosc())[0] == 200
    przyjete = [z for z in call(domy, "GET", f"/api/domy/{DOM_B}/zaproszenia", headers=h)[2][
        "zaproszenia"] if z["stan"] == "przyjete"][0]
    assert przyjete["przyjete_przez"] == GOSC
    assert call(domy, "POST", f"/api/domy/{DOM_B}/zaproszenia/odwolaj", {"id": przyjete["id"]},
                h)[0] == 409


# =============================================================== zly dom
def test_zly_dom(domy):
    """Zaproszenie domu B nie istnieje dla tras domu A, a konto bez B nie
    zaprosi do B (404, jak kazda trasa obcego domu)."""
    body = zapros(domy, "czlonek-b", DOM_B)[2]
    zid = body["zaproszenie"]["id"]
    a = sso(domy, "czlonek-a")
    assert zapros(domy, "czlonek-a", DOM_B)[0] == 404
    assert call(domy, "GET", f"/api/domy/{DOM_B}/zaproszenia", headers=a)[0] == 404
    assert call(domy, "POST", f"/api/domy/{DOM_A}/zaproszenia/odwolaj", {"id": zid},
                a)[0] == 404
    assert _wiersz(domy, zid)["odwolane_at"] is None
    lista_a = call(domy, "GET", f"/api/domy/{DOM_A}/zaproszenia", headers=a)[2]["zaproszenia"]
    assert zid not in [z["id"] for z in lista_a]
    # Przyjecie daje dom zaproszenia, nie dom tras, z ktorych przyszlo.
    assert przyjmij(domy, body["token"], gosc())[0] == 200
    assert _domy_konta(domy, GOSC) == [DOM_B]


# ============================================================== sufit roli
def _naruszenia_sufitu(srv) -> list[str]:
    """Zarzadca z nadanym `dom.zaproszenia` probuje kazdej roli; zle =
    utworzone zaproszenie z rola wyzsza od zarzadcy."""
    zle = []
    for rola in u.ROLE_DOMU:
        status, _, body = zapros(srv, "zarz", DOM_B, rola)
        if status == 200 and zp.RANGA[rola] > zp.RANGA[u.ROLA_ZARZADCA]:
            zle.append(rola)
        elif status not in (200, 403):
            zle.append(f"{rola}: {status} {body}")
    return zle


@pytest.fixture
def z_zarzadca(domy):
    domy.auth.add_user("zarz", HASLO, "zarzadca", dom_id=DOM_B)
    domy.auth.set_permissions("zarz", {u.DOM_ZAPROSZENIA: True}, dom_id=DOM_B)
    return domy


def test_sufit_roli(z_zarzadca):
    srv = z_zarzadca
    assert _naruszenia_sufitu(srv) == []
    # Zarzadca zaprasza do wlasnej roli i nizej.
    assert zapros(srv, "zarz", DOM_B, "zarzadca")[0] == 200
    assert zapros(srv, "zarz", DOM_B, "podglad")[0] == 200
    # Odmowa PRZED potwierdzeniem haslem: zla rola nie zjada proby.
    assert zapros(srv, "zarz", DOM_B, "wlasciciel-domu", confirm="zle-haslo")[0] == 403
    with _db(srv) as conn:
        assert conn.execute("SELECT failed_logins FROM users WHERE login = 'zarz'"
                            ).fetchone()[0] == 0
    # Lista podaje tylko role, ktore wolno nadac.
    lista = call(srv, "GET", f"/api/domy/{DOM_B}/zaproszenia", headers=sso(srv, "zarz"))[2]
    assert lista["role"] == ["zarzadca", "podglad"]
    # Wlasciciel domu i administrator — dowolna rola.
    assert zapros(srv, "czlonek-b", DOM_B, "wlasciciel-domu")[0] == 200
    assert zapros(srv, "admin", DOM_B, "wlasciciel-domu", grupy="admins")[0] == 200
    # Bez `dom.zaproszenia` (podglad) — 403 z uprawnienia.
    status, _, body = zapros(srv, "obu", DOM_A, "podglad")
    assert status == 403 and u.DOM_ZAPROSZENIA in body["error"]


def test_kanarek_sufit_roli(z_zarzadca, monkeypatch):
    monkeypatch.setattr(zp, "dozwolone_role", lambda *a, **kw: list(u.ROLE_DOMU))
    assert _naruszenia_sufitu(z_zarzadca) == ["wlasciciel-domu"]


def test_zaproszenie_nie_podnosi_roli_czlonka_i_nie_przepada(domy):
    """`obu` jest `podglad` w A; zaproszenie do A z rola wlasciciela nie
    zmienia jego roli, a zaproszenie zostaje do wykorzystania."""
    body = zapros(domy, "czlonek-a", DOM_A, "wlasciciel-domu")[2]
    status, _, r = przyjmij(domy, body["token"], gosc("obu", "rodzina"))
    assert status == 409 and "Należysz już" in r["error"]
    assert domy.rejestr.czlonkostwo(domy.auth.user_id("obu"), DOM_A).rola == "podglad"
    z = _wiersz(domy, body["zaproszenie"]["id"])
    assert z["przyjete_at"] is None and z["proby"] == 0


def test_konto_administracyjne_nie_przyjmuje(domy):
    token = token_od(domy)
    status, _, r = przyjmij(domy, token, gosc("admin", "admins"))
    assert status == 409 and "administracyjne" in r["error"]
    assert _domy_konta(domy, "admin") == []


# ============================================================ dla != Remote-User
def _naruszenia_dla(srv) -> list[str]:
    token = token_od(srv, dla=GOSC)
    status, _, _ = przyjmij(srv, token, gosc("ktos-inny"))
    zle = []
    if status != 403:
        zle.append(f"status {status}")
    if _konto(srv, "ktos-inny") or _domy_konta(srv, "ktos-inny"):
        zle.append("konto albo czlonkostwo dla innego loginu")
    return zle


def test_dla_rozne_od_remote_user(domy):
    assert _naruszenia_dla(domy) == []
    token = token_od(domy, dla=GOSC)
    przyjmij(domy, token, gosc("ktos-inny"))
    # Wlasciwa osoba nadal przyjmie.
    assert przyjmij(domy, token, gosc())[0] == 200


def _spalone_przez_zalogowanego(srv) -> list[str]:
    """Zalogowany w SSO z niewlasciwym loginem probuje wiele razy (podglad
    i przyjecie). To nie zgadywanie — token nie moze sie spalic ani adres
    zablokowac; wlasciwa osoba przyjmuje dalej (przeglad #72, 3c)."""
    body = zapros(srv, "czlonek-b", DOM_B, dla=GOSC)[2]
    ip = "203.0.113.5"
    for _ in range(MAX_PROB + IP_MAX_FAILED):
        call(srv, "POST", "/api/zaproszenia/sprawdz", {"token": body["token"]},
             gosc("ktos-inny", ip=ip))
        przyjmij(srv, body["token"], gosc("ktos-inny", ip=ip))
    zle = []
    if _wiersz(srv, body["zaproszenie"]["id"])["proby"] != 0:
        zle.append("proby tokenu")
    status = przyjmij(srv, body["token"], gosc(ip=ip))[0]
    if status != 200:
        zle.append(f"wlasciwa osoba: {status}")
    return zle


def test_zly_login_zalogowanego_nie_pali_zaproszenia(domy):
    assert _spalone_przez_zalogowanego(domy) == []


def test_kanarek_zly_login_zalogowanego_liczony(domy, monkeypatch):
    prawdziwa = zp.Zaproszenia._token
    monkeypatch.setattr(zp.Zaproszenia, "_token",
                        lambda self, token, ip, login, *_: prawdziwa(self, token, ip, login, False))
    assert _spalone_przez_zalogowanego(domy)


def test_kanarek_dla(domy, monkeypatch):
    prawdziwa = zp.Zaproszenia._token
    monkeypatch.setattr(zp.Zaproszenia, "_token",
                        lambda self, token, ip, login, *_: prawdziwa(self, token, ip, None))
    assert _naruszenia_dla(domy)


def test_sprawdz_pokazuje_dom_i_informacje_o_prywatnosci(domy):
    token = token_od(domy, dla=GOSC)
    status, _, info = call(domy, "POST", "/api/zaproszenia/sprawdz", {"token": token}, gosc())
    assert status == 200, info
    assert info["dom"] == "Dom B" and info["rola"] == "podglad" and info["tryb"] == "sso"
    assert info["konto_istnieje"] is False and "Administrator" in info["informacja"]
    assert call(domy, "POST", "/api/zaproszenia/sprawdz", {"token": token},
                gosc("ktos-inny"))[0] == 403


def test_przyjecie_wymaga_potwierdzenia_informacji(domy):
    token = token_od(domy)
    for zle in (None, False, "tak", 1):
        assert przyjmij(domy, token, gosc(), potwierdzam=zle)[0] == 400
    assert not _konto(domy, GOSC)
    assert przyjmij(domy, token, gosc())[0] == 200


# ============================================================ token tylko jako hash
def _naruszenia_hasha(srv, token: str) -> list[str]:
    """Token w jawnej postaci gdziekolwiek w plikach bazy panelu (takze WAL
    i dziennik) = naruszenie; brak hasha = test niczego nie sprawdzil."""
    katalog = Path(srv.cfg.panel_auth_path).parent
    zle = []
    for plik in katalog.glob(Path(srv.cfg.panel_auth_path).name + "*"):
        if token.encode() in plik.read_bytes():
            zle.append(plik.name)
    with _db(srv) as conn:
        hashe = {r[0] for r in conn.execute("SELECT token_hash FROM zaproszenia")}
    if zp.hash_tokenu(token) not in hashe and token not in hashe:
        zle.append("brak wiersza zaproszenia")
    return zle


def test_token_w_bazie_tylko_jako_sha256(domy):
    token = token_od(domy)
    assert _naruszenia_hasha(domy, token) == []
    assert len(token) >= 43  # 32 B z token_urlsafe


def test_kanarek_token_jawnie(domy, monkeypatch):
    monkeypatch.setattr(zp, "hash_tokenu", lambda t: t)
    assert _naruszenia_hasha(domy, token_od(domy))


# =================================================================== logi
def _naruszenia_logu(srv, caplog, mutacja=None) -> list[str]:
    caplog.set_level(logging.DEBUG)
    token = token_od(srv, dla=GOSC)
    call(srv, "POST", "/api/zaproszenia/sprawdz", {"token": token}, gosc())
    przyjmij(srv, token, gosc("ktos-inny"))
    przyjmij(srv, token + "x", gosc())
    przyjmij(srv, token, gosc())
    przyjmij(srv, token, gosc())  # juz zuzyty
    zle = []
    if token in caplog.text:
        zle.append("log")
    with _db(srv) as conn:
        if any(token in r[0] for r in conn.execute("SELECT opis FROM audyt")):
            zle.append("audyt")
    return zle


def test_token_nie_trafia_do_logu_ani_dziennika(domy, caplog):
    assert _naruszenia_logu(domy, caplog) == []
    assert "zaproszenie #" in caplog.text  # kontrola pozytywna: log jest


def test_kanarek_token_w_logu(domy, caplog, monkeypatch):
    prawdziwa = zp.hash_tokenu

    def gadatliwa(token: str) -> str:
        logging.getLogger("kidwatch.zaproszenia").debug("token %s", token)
        return prawdziwa(token)

    monkeypatch.setattr(zp, "hash_tokenu", gadatliwa)
    assert _naruszenia_logu(domy, caplog)


# ============================================================ limit prob
HASLO_GOSCIA = "nowe-haslo-goscia-1"


def _nowe_konto(srv, token: str, login: str, ip: str):
    return call(srv, "POST", "/api/zaproszenia/przyjmij",
                {"token": token, "potwierdzam": True, "login": login, "haslo": HASLO_GOSCIA},
                {"X-Forwarded-For": ip})


def _naruszenia_limitu_tokenu(srv) -> list[str]:
    """MAX_PROB nieudanych prob na token bez uwierzytelnienia (ekran „ustaw
    haslo”, zly login wzgledem `dla`) — potem nie przyjmie nawet wlasciwa
    osoba."""
    token = _token_bez_sso(srv, dla=GOSC)
    for i in range(MAX_PROB):
        assert _nowe_konto(srv, token, f"ktos-{i}", f"192.0.2.{i + 1}")[0] == 403
    status = _nowe_konto(srv, token, GOSC, "192.0.2.100")[0]
    return [] if status == 410 and not _konto(srv, GOSC) else [f"przyjete po probach ({status})"]


def test_limit_prob_na_token(tmp_path, monkeypatch):
    srv = _bez_sso(tmp_path, monkeypatch)
    try:
        assert _naruszenia_limitu_tokenu(srv) == []
        with _db(srv) as conn:
            # MAX_PROB zlych loginow + proba wlasciwej osoby na zablokowanym.
            assert conn.execute("SELECT proby FROM zaproszenia").fetchone()[0] == MAX_PROB + 1
    finally:
        srv.shutdown()


def test_kanarek_limit_prob_na_token(tmp_path, monkeypatch):
    monkeypatch.setattr(zp, "MAX_PROB", 10**6)
    srv = _bez_sso(tmp_path, monkeypatch)
    try:
        assert _naruszenia_limitu_tokenu(srv)
    finally:
        srv.shutdown()


def test_limit_prob_per_adres_takze_dla_nieistniejacych_tokenow(domy):
    token = token_od(domy)
    ip = "198.51.100.7"
    for i in range(IP_MAX_FAILED):
        assert przyjmij(domy, f"zgadywany-{i}", gosc(ip=ip))[0] == 404
    status, _, body = przyjmij(domy, token, gosc(ip=ip))
    assert status == 429, body
    assert not _konto(domy, GOSC)
    # Inny adres — dziala.
    assert przyjmij(domy, token, gosc(ip="198.51.100.8"))[0] == 200


def test_kanarek_limit_per_adres(domy, monkeypatch):
    monkeypatch.setattr(zp, "IP_MAX_FAILED", 10**6)
    token = token_od(domy)
    for i in range(10):
        przyjmij(domy, f"zgadywany-{i}", gosc(ip="198.51.100.9"))
    assert przyjmij(domy, token, gosc(ip="198.51.100.9"))[0] == 200


# ===================================================== konto w locie (SSO)
def _konta_bez_waznego_tokenu(srv) -> list[str]:
    """Kazda nieudana droga przyjecia nie moze zostawic konta."""
    zle = []
    body = zapros(srv, "czlonek-b", DOM_B)[2]
    zid = body["zaproszenie"]["id"]
    with _db(srv) as conn:
        conn.execute("UPDATE zaproszenia SET odwolane_at = 1 WHERE id = ?", (zid,))
    proby = {
        "nieznany": "nie-ma-takiego-tokenu",
        "pusty": "",
        "odwolany": body["token"],
    }
    for nazwa, token in proby.items():
        login = f"gosc-{nazwa}"
        przyjmij(srv, token, gosc(login))
        if _konto(srv, login):
            zle.append(nazwa)
    return zle


def test_konto_SSO_w_locie_tylko_z_waznym_tokenem(domy):
    assert _konta_bez_waznego_tokenu(domy) == []
    # Grupa spoza listy panelu nie wejdzie nawet z waznym tokenem.
    token = token_od(domy)
    assert przyjmij(domy, token, gosc(grupy="dietetyk"))[0] == 403
    assert not _konto(domy, GOSC)


def test_kanarek_konto_bez_tokenu(domy, monkeypatch):
    """Mutacja: wyszukanie zaproszenia ignoruje token (bierze dowolne
    oczekujace) — konto powstaje z tokenem, ktorego nie ma."""
    def bez_sprawdzenia(self, token, ip, login, *_):
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM zaproszenia WHERE przyjete_at IS NULL AND "
                               "odwolane_at IS NULL ORDER BY id").fetchone()
        return zp._zaproszenie(row)

    token_od(domy)  # oczekujace zaproszenie w bazie
    monkeypatch.setattr(zp.Zaproszenia, "_token", bez_sprawdzenia)
    assert _konta_bez_waznego_tokenu(domy)


# ============================================== istniejace konto z sesja haslem
def test_istniejace_konto_haslem_tylko_z_2FA(tmp_path, monkeypatch):
    from conftest import panel_login  # noqa: PLC0415

    srv = _bez_sso(tmp_path, monkeypatch)
    try:
        token = _token_bez_sso(srv)
        c = panel_login(srv.server_address[1], "czlonek-a", HASLO)
        h = {"Cookie": c, "X-CSRF-Token": dict(x.split("=", 1) for x in c.split("; "))[
            "kidwatch_csrf"]}
        status, _, body = przyjmij(srv, token, h)
        assert status == 403 and "dwuetapowej" in body["error"]
        # Bez CSRF — 403 CSRF, zanim cokolwiek sprawdzi.
        assert "CSRF" in przyjmij(srv, token, {"Cookie": c})[2]["error"]
        sesja = srv.auth.login("czlonek-a", HASLO).session
        secret = srv.auth.totp_setup(sesja)["secret"]
        srv.auth.totp_confirm(sesja, pyotp.TOTP(secret).now())
        c = panel_login(srv.server_address[1], "czlonek-a", HASLO, secret)
        h = {"Cookie": c, "X-CSRF-Token": dict(x.split("=", 1) for x in c.split("; "))[
            "kidwatch_csrf"]}
        status, headers, body = przyjmij(srv, token, h)
        assert status == 200 and body["zaloguj_ponownie"], body
        assert jar(headers).get("kidwatch_session") == ""  # sesja zamknieta
        assert _domy_konta(srv, "czlonek-a") == [DOM_A, DOM_B]
    finally:
        srv.shutdown()


# ======================================================= bez SSO: haslo + 2FA
def _bez_sso(tmp_path, monkeypatch):
    monkeypatch.delenv("SSO_NAGLOWKI", raising=False)
    (tmp_path / "web").mkdir()
    cfg = _konfiguracja(tmp_path, "A", tmp_path / "kidwatch.db")
    Store(cfg.store.path).close()
    auth = PanelAuth(cfg.panel_auth_path, box=box_from_env())
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj()
    assert rejestr.dodaj_dom("Dom B") == DOM_B
    Store(str(dm.sciezka_bazy_domu(DOM_B, cfg.store.path))).close()
    auth.add_user("czlonek-a", HASLO)
    auth.add_user("czlonek-b", HASLO, "wlasciciel-domu", dom_id=DOM_B)
    srv = start_panel(cfg)
    srv.auth, srv.rejestr, srv.cfg = auth, rejestr, cfg
    return srv


def _token_bez_sso(srv, dla: str | None = None) -> str:
    from conftest import panel_login  # noqa: PLC0415

    c = panel_login(srv.server_address[1], "czlonek-b", HASLO)
    csrf = dict(x.split("=", 1) for x in c.split("; "))["kidwatch_csrf"]
    status, _, body = call(srv, "POST", f"/api/domy/{DOM_B}/zaproszenia/utworz",
                           {"rola": "podglad", "confirm": HASLO, **({"dla": dla} if dla else {})},
                           {"Cookie": c, "X-CSRF-Token": csrf})
    assert status == 200, body
    assert body["instrukcja_sso"] is None  # bez SSO nie ma Authelii
    return body["token"]


def _naruszenia_totp(srv, login: str, haslo: str) -> list[str]:
    from conftest import panel_login  # noqa: PLC0415

    c = panel_login(srv.server_address[1], login, haslo)
    me = call(srv, "GET", "/api/auth/me", headers={"Cookie": c})[2]
    zle = []
    if me["wymaga_totp"] is not True:
        zle.append("auth/me bez wymaga_totp")
    for k in DOM_GET:
        status, _, body = call(srv, "GET", _sciezka(k, DOM_B), headers={"Cookie": c})
        if status != 403 or body.get("error") != WYMAGA_2FA:
            zle.append(f"{k}: {status}")
    return zle


def test_zaproszony_bez_SSO_ustawia_haslo_i_musi_wlaczyc_2FA(tmp_path, monkeypatch):
    from conftest import panel_login  # noqa: PLC0415

    srv = _bez_sso(tmp_path, monkeypatch)
    try:
        token = _token_bez_sso(srv)
        info = call(srv, "POST", "/api/zaproszenia/sprawdz", {"token": token})[2]
        assert info["tryb"] == "haslo" and info["min_haslo"] == 12
        haslo = "nowe-haslo-goscia-1"
        # Polityka hasla i login.
        for zle in ({"login": GOSC, "haslo": "krotkie"}, {"login": "Duze", "haslo": haslo}):
            assert call(srv, "POST", "/api/zaproszenia/przyjmij",
                        {"token": token, "potwierdzam": True, **zle})[0] == 400
        # Login zajety — 409, zaproszenie zostaje.
        assert call(srv, "POST", "/api/zaproszenia/przyjmij",
                    {"token": token, "potwierdzam": True, "login": "czlonek-a",
                     "haslo": haslo})[0] == 409
        status, _, body = call(srv, "POST", "/api/zaproszenia/przyjmij",
                               {"token": token, "potwierdzam": True, "login": GOSC,
                                "haslo": haslo})
        assert status == 200 and body["wymaga_totp"], body
        assert _naruszenia_totp(srv, GOSC, haslo) == []
        # Wlaczenie 2FA otwiera dom.
        sesja = srv.auth.login(GOSC, haslo).session
        secret = srv.auth.totp_setup(sesja)["secret"]
        srv.auth.totp_confirm(sesja, pyotp.TOTP(secret).now())
        c = panel_login(srv.server_address[1], GOSC, haslo, secret)
        me = call(srv, "GET", "/api/auth/me", headers={"Cookie": c})[2]
        assert me["wymaga_totp"] is False and [d["id"] for d in me["domy"]] == [DOM_B]
        assert call(srv, "GET", f"/api/domy/{DOM_B}/day", headers={"Cookie": c})[0] == 200
        assert call(srv, "GET", f"/api/domy/{DOM_A}/day", headers={"Cookie": c})[0] == 404
    finally:
        srv.shutdown()


def test_kanarek_bez_SSO_dane_bez_2FA(tmp_path, monkeypatch):
    srv = _bez_sso(tmp_path, monkeypatch)
    try:
        token = _token_bez_sso(srv)
        haslo = "nowe-haslo-goscia-1"
        assert call(srv, "POST", "/api/zaproszenia/przyjmij",
                    {"token": token, "potwierdzam": True, "login": GOSC,
                     "haslo": haslo})[0] == 200
        monkeypatch.setattr(zp.Zaproszenia, "wymaga_totp", lambda self, *a: False)
        assert _naruszenia_totp(srv, GOSC, haslo)
    finally:
        srv.shutdown()


def test_bez_klucza_TOTP_nie_zaklada_konta_haslem(tmp_path, monkeypatch):
    from kidwatch import panel_auth  # noqa: PLC0415

    monkeypatch.delenv(panel_auth.TOTP_KEY_ENV)
    srv = _bez_sso(tmp_path, monkeypatch)
    try:
        token = _token_bez_sso(srv)
        status, _, body = call(srv, "POST", "/api/zaproszenia/przyjmij",
                               {"token": token, "potwierdzam": True, "login": GOSC,
                                "haslo": "nowe-haslo-goscia-1"})
        assert status == 503 and "PANEL_TOTP_KEY" in body["error"]
        assert not _konto(srv, GOSC)
    finally:
        srv.shutdown()


def test_za_authelia_bez_naglowka_nie_zaklada_konta_haslem(domy):
    """Port-forward przy wlaczonym SSO: ekran „ustaw haslo” nie istnieje."""
    token = token_od(domy)
    status, _, _ = call(domy, "POST", "/api/zaproszenia/przyjmij",
                        {"token": token, "potwierdzam": True, "login": GOSC,
                         "haslo": "nowe-haslo-goscia-1"})
    assert status == 401
    assert not _konto(domy, GOSC)


# ====================================================== usuniecie czlonka
def test_usuniecie_czlonka_zamyka_sesje_dziennik_i_sugestia_rotacji(domy):
    from kidwatch.panel_auth import token_hash  # noqa: PLC0415

    token = token_od(domy, rola="wlasciciel-domu")
    assert przyjmij(domy, token, gosc())[0] == 200
    hg = _sesja_goscia(domy)
    sesja = dict(x.split("=", 1) for x in hg["Cookie"].split("; "))["kidwatch_session"]
    h = sso(domy, "czlonek-b")
    status, _, body = call(domy, "POST", f"/api/domy/{DOM_B}/konta/usun",
                           {"login": GOSC, "confirm": HASLO}, h)
    assert status == 200 and "dom-klucz-rotuj 2" in body["sugestia"], body
    with _db(domy) as conn:
        wpis = conn.execute("SELECT opis FROM audyt WHERE akcja = 'konta.usun'").fetchone()
        stara = conn.execute("SELECT 1 FROM sessions WHERE token_hash = ?",
                             (token_hash(sesja),)).fetchone()
    assert GOSC in wpis[0] and "dom-klucz-rotuj" in wpis[0]
    assert stara is None  # sesja goscia zamknieta
    # Konto bez domow znika (jak „Usun” sprzed E4) — z naglowkiem Authelii 403.
    assert not _konto(domy, GOSC)
    assert call(domy, "GET", "/api/auth/me", headers=gosc())[0] == 403
    # Bez dostepu do integracji — bez sugestii.
    token = token_od(domy, rola="podglad")
    assert przyjmij(domy, token, gosc("gosc-2"))[0] == 200
    body = call(domy, "POST", f"/api/domy/{DOM_B}/konta/usun",
                {"login": "gosc-2", "confirm": HASLO}, sso(domy, "czlonek-b"))[2]
    assert body["sugestia"] is None


# ============================================ powiadomienie zapraszajacego
def test_zapraszajacy_dostaje_powiadomienie_przez_powiadamiacz(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path, box=box_from_env())
    rejestr = dm.RejestrDomow(path)
    rejestr.migruj()
    auth.add_user("wlasciciel-x", HASLO)
    wyslane = []
    p = zp.PanelZaproszenia(auth, zp.Zaproszenia(path), sso_wlaczone=True,
                            powiadom=lambda *a: wyslane.append(a))
    token, _ = p.z.utworz(DOM_A, kto_id=auth.user_id("wlasciciel-x"), kto_login="wlasciciel-x",
                          rola="podglad")
    p.przyjmij(token, ip="192.0.2.1", login=GOSC, sso=True, zaloz=True)
    assert wyslane == [("wlasciciel-x", "Dom 1", GOSC, "podglad")]


async def test_powiadomienie_tylko_z_jawnym_odbiorca(monkeypatch):
    """Bez funkcji `odbiorca` w bramce nic nie wychodzi (trasy Domu 1
    rozeslalyby je rodzinie); z nia — tylko do kanalu zapraszajacego."""
    from kidwatch.notifiers import bramka  # noqa: PLC0415
    from kidwatch.odbiorcy import Profil  # noqa: PLC0415

    wyslane = []

    class Bramka:
        def __init__(self, cfg, key):
            pass

        async def obsluguje_odbiorcow(self):
            return Bramka.odbiorca

        async def send(self, note, odbiorca=None):
            wyslane.append((note.title, odbiorca))
            return True

        async def aclose(self):
            pass

    class Profile:
        def kanaly_osoby(self, login):
            return Profil(login=login, rola="", uprawnienia=frozenset(), email="x@example.com",
                          kanal="email")

    monkeypatch.setattr(bramka, "BramkaNotifier", Bramka)
    Bramka.odbiorca = False
    assert await zp._wyslij(object(), "k", Profile(), "wlasciciel-x", "Dom 1", GOSC,
                            "podglad") is False
    assert wyslane == []
    Bramka.odbiorca = True
    assert await zp._wyslij(object(), "k", Profile(), "wlasciciel-x", "Dom 1", GOSC, "podglad")
    assert wyslane == [("Zaproszenie przyjęte", {"kanal": "email", "email": "x@example.com"})]


def test_bez_bramki_powiadamiacz_nic_nie_robi():
    assert zp.powiadamiacz(None, None, None) is zp._nic


# ==================================================== potwierdzenie tworzenia
def _bez_potwierdzenia(srv) -> list[str]:
    """Tworzenie bez swiezego hasla/2FA (brak, zle) musi byc odmowione
    i nie zostawic wiersza."""
    zle = []
    for confirm in ("", "zle-haslo"):
        status, _, body = zapros(srv, "czlonek-b", DOM_B, confirm=confirm)
        if status == 200:
            zle.append(f"utworzone z confirm={confirm!r}")
    with _db(srv) as conn:
        if conn.execute("SELECT COUNT(*) FROM zaproszenia").fetchone()[0]:
            zle.append("wiersz w bazie")
    return zle


def test_tworzenie_wymaga_hasla_albo_2FA(domy):
    assert _bez_potwierdzenia(domy) == []
    assert zapros(domy, "czlonek-b", DOM_B)[0] == 200  # kontrola pozytywna


def test_kanarek_tworzenie_bez_potwierdzenia(domy, monkeypatch):
    monkeypatch.setattr(PanelAuth, "reauth", lambda self, session, secret: None)
    assert _bez_potwierdzenia(domy)


# ============================================ prawo zapraszajacego przy przyjeciu
def _linki_po_utracie_prawa(srv) -> list[str]:
    """Oczekujace linki osoby, ktora stracila prawo zapraszania (wypisana
    z domu, odebrane `dom.zaproszenia`, rola obnizona pod sufit) nie
    otwieraja domu (przeglad #72, 2)."""
    auth = srv.auth
    auth.add_user("zarz2", HASLO, "zarzadca", dom_id=DOM_B)
    auth.set_permissions("zarz2", {u.DOM_ZAPROSZENIA: True}, dom_id=DOM_B)
    tokeny = {
        "wypisany": token_od(srv, "obu", DOM_B, rola="wlasciciel-domu"),
        "bez prawa": token_od(srv, "zarz2", DOM_B, rola="podglad"),
    }
    auth.add_user("zarz3", HASLO, "zarzadca", dom_id=DOM_B)
    auth.set_permissions("zarz3", {u.DOM_ZAPROSZENIA: True}, dom_id=DOM_B)
    tokeny["obnizony"] = token_od(srv, "zarz3", DOM_B, rola="zarzadca")
    auth.remove_membership("obu", DOM_B)
    auth.set_permissions("zarz2", {u.DOM_ZAPROSZENIA: None}, dom_id=DOM_B)
    auth.set_role("zarz3", "podglad", dom_id=DOM_B)
    auth.set_permissions("zarz3", {u.DOM_ZAPROSZENIA: True}, dom_id=DOM_B)
    zle = []
    for i, (nazwa, token) in enumerate(tokeny.items()):
        login = f"gosc-p{i}"
        podglad = call(srv, "POST", "/api/zaproszenia/sprawdz", {"token": token}, gosc(login))[0]
        status = przyjmij(srv, token, gosc(login))[0]
        if status != 410 or podglad != 410 or _konto(srv, login):
            zle.append(f"{nazwa}: {podglad}/{status}")
    return zle


def test_zaproszenie_traci_waznosc_z_prawem_zapraszajacego(domy):
    assert _linki_po_utracie_prawa(domy) == []
    # Kontrola pozytywna: prawo jest — link dziala.
    assert przyjmij(domy, token_od(domy), gosc())[0] == 200


def test_kanarek_prawo_zapraszajacego_tylko_przy_tworzeniu(domy, monkeypatch):
    monkeypatch.setattr(zp, "zapraszajacy_moze", lambda conn, z: True)
    assert _linki_po_utracie_prawa(domy)


# ============================================================ jednostkowe
def test_dozwolone_role():
    wszystkie = u.ROLE_UPRAWNIENIA[u.ROLE_OWNER]
    assert zp.dozwolone_role("wlasciciel-domu", frozenset(), admin=False) == list(u.ROLE_DOMU)
    assert zp.dozwolone_role(None, frozenset(), admin=True) == list(u.ROLE_DOMU)
    zarz = u.ROLE_DOMU_UPRAWNIENIA["zarzadca"] | {u.DOM_ZAPROSZENIA}
    assert zp.dozwolone_role("zarzadca", zarz, admin=False) == ["zarzadca", "podglad"]
    # Zarzadca bez czesci uprawnien roli nie nada jej innym.
    assert zp.dozwolone_role("zarzadca", zarz - {u.TV_PAUZA}, admin=False) == ["podglad"]
    assert zp.dozwolone_role("nieznana", wszystkie, admin=False) == []


def test_utworz_waliduje(tmp_path):
    path = tmp_path / "panel-auth.db"
    PanelAuth(path, box=box_from_env())
    dm.RejestrDomow(path).migruj()
    z = zp.Zaproszenia(path)
    with pytest.raises(ValueError):
        z.utworz(DOM_A, kto_id=None, kto_login="x", rola="wlasciciel")
    with pytest.raises(ValueError):
        z.utworz(DOM_A, kto_id=None, kto_login="x", rola="podglad", dla="Zly Login")
    with pytest.raises(LookupError):
        z.utworz(99, kto_id=None, kto_login="x", rola="podglad")
    with pytest.raises(AuthError):
        z.przyjmij("x" * (zp.MAX_TOKEN + 1), ip="192.0.2.1", login=GOSC, sso=True, zaloz=True)
