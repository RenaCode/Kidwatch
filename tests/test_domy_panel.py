"""Etap E3a domow: izolacja panelu i API (docs/architektura-domy.md §4.4).

Dwa BLIZNIACZE domy — te same nazwy dzieci, urzadzen i identyfikatorow
zrodla, rozne tylko znaczniki w danych (aplikacja i tytul `TYLKO-A`
/ `TYLKO-B`). Kazdy test izolacji ma kontrole pozytywna (wlasny znacznik
JEST w odpowiedzi), a bariery maja kanarki: test z wylaczona bariera musi
znalezc naruszenie — inaczej jego cisza niczego by nie dowodzila.

Dane wylacznie generyczne: publiczne repo (tests/test_repo_prywatnosc.py).
"""

from __future__ import annotations

import io
import json
import logging
import sqlite3
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pyotp
import pytest

from kidwatch import domy as dm
from kidwatch import odbiorcy as o
from kidwatch import uprawnienia as u
from kidwatch.__main__ import main
from kidwatch.classifier import Classifier
from kidwatch.config import (
    Config,
    DeviceConfig,
    EngineConfig,
    NextDnsConfig,
    PanelConfig,
    SourceConfig,
    StoreConfig,
)
from kidwatch.engine import Engine
from kidwatch.gametime import GameRequests
from kidwatch.models import DnsEvent, Notification, NotifyKind
from kidwatch.notifiers.base import Dispatcher, Outbox
from kidwatch.panel import GET_TRASY, POST_TRASY, start_panel
from kidwatch.panel_auth import PanelAuth, box_from_env
from kidwatch.panel_domy import PREFIKS_DOMU
from kidwatch.rollup import refresh_rollups
from kidwatch.store import Store
from test_domy_e2 import kek  # noqa: F401 — fikstura KIDWATCH_KEK
from test_panel_sso import call, cookie, jar

HASLO = "haslo-testowe-123"
TZ = ZoneInfo("Europe/Warsaw")
UDID = "00000000-0000000000000001"
APP_MAP = """
noise:
  - apple.com
apps:
  "TYLKO-A":
    - tylko-a.example.com
  "TYLKO-B":
    - tylko-b.example.com
"""
DOM_A, DOM_B = 1, 2

#: Trasy domu z tablic routera — nowa trasa trafia tu sama.
DOM_GET = sorted(k for k, (_, z) in GET_TRASY.items() if z == u.ZAKRES_DOM)
DOM_POST = sorted(k for k, (_, _, z) in POST_TRASY.items() if z == u.ZAKRES_DOM)
#: Trasy z danymi monitoringu — w nich MUSI byc wlasny znacznik.
Z_DANYMI = {"/day", "/notifications", "/usage", "/screens", "/devices", "/trends",
            "/export.csv"}


def _sciezka(klucz: str, dom_id: int) -> str:
    p = klucz.replace(PREFIKS_DOMU, f"/api/domy/{dom_id}")
    return p + UDID if p.endswith("/") else p


def _konfiguracja(tmp_path, nazwa: str, baza) -> Config:
    """Ten sam ksztalt w obu domach: dziecko, urzadzenie, identyfikator."""
    mapa = tmp_path / "app_map.yaml"
    mapa.write_text(APP_MAP, encoding="utf-8")
    return Config(
        timezone="Europe/Warsaw",
        source=SourceConfig(kind="nextdns", nextdns=NextDnsConfig(profile_id="profil")),
        devices=[DeviceConfig(display_name="iPad Dziecka 1", child="Dziecko 1",
                              source_ids=["ipad-1"])],
        engine=EngineConfig(confirm_moments=1),
        panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path / "web")),
        store=StoreConfig(path=str(baza)),
        app_map_path=str(mapa),
    )


def _zasiej(cfg: Config, znacznik: str) -> None:
    """Sesja z aplikacja-znacznikiem, powiadomienie i agregat — dzis."""
    store = Store(cfg.store.path)
    engine = Engine(cfg, store, Classifier(cfg.app_map_path))
    dzis = datetime.now(TZ).date()
    t0 = datetime.combine(dzis, time(0, 5), tzinfo=TZ)
    for i in range(4):
        engine.handle(DnsEvent(ts=(t0 + timedelta(minutes=i)).astimezone(UTC),
                               device_id="ipad-1", domain=f"{znacznik.lower()}.example.com"))
    store.record_notification(Notification(
        kind=NotifyKind.APP, title=f"{znacznik} tytul", text=f"{znacznik} tresc",
        dedup_key=f"k-{znacznik}", ts=t0.astimezone(UTC), device="iPad Dziecka 1",
        app=znacznik), {}, datetime.now(UTC))
    refresh_rollups(cfg, store, datetime.now(UTC), force=True)
    store.close()


@pytest.fixture
def domy(tmp_path, monkeypatch):
    """Dom A (= Dom 1, config.yaml) i dom B (z bazy) z tymi samymi nazwami.
    Konta: `czlonek-a`, `czlonek-b` (wlasciciele), `obu` (podglad w A,
    wlasciciel w B), `admin` (bez domow, flaga administratora)."""
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    (tmp_path / "web").mkdir()
    cfg = _konfiguracja(tmp_path, "A", tmp_path / "kidwatch.db")
    auth = PanelAuth(cfg.panel_auth_path, box=box_from_env())
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj()
    assert rejestr.dodaj_dom("Dom B") == DOM_B
    cfg_b = _konfiguracja(tmp_path, "B", dm.sciezka_bazy_domu(DOM_B, cfg.store.path))
    _zasiej(cfg, "TYLKO-A")
    _zasiej(cfg_b, "TYLKO-B")
    auth.add_user("czlonek-a", HASLO)
    auth.add_user("czlonek-b", HASLO, "wlasciciel-domu", dom_id=DOM_B)
    auth.add_user("obu", HASLO, "podglad")
    auth.set_role("obu", "wlasciciel-domu", dom_id=DOM_B)
    auth.add_user("admin", HASLO, dom_id=None)
    rejestr.ustaw_admin_instancji(auth.user_id("admin"), True)
    srv = start_panel(cfg, konfiguracja_domu=lambda dom: cfg_b if dom.id == DOM_B else None)
    srv.auth, srv.rejestr, srv.cfg = auth, rejestr, cfg
    yield srv
    srv.shutdown()


def sso(srv, login: str, grupy: str = "wlasciciel") -> dict[str, str]:
    """Naglowki zadania przez Authelie + ciasteczka sesji i CSRF dla POST."""
    h = {"Remote-User": login, "Remote-Groups": grupy}
    status, headers, me = call(srv, "GET", "/api/auth/me", headers=h)
    assert status == 200, me
    j = jar(headers)
    return {**h, "Cookie": cookie(j), "X-CSRF-Token": j["kidwatch_csrf"]}


def _audyt(srv, dom_id: int) -> list[tuple[str, str]]:
    with sqlite3.connect(srv.cfg.panel_auth_path) as conn:
        return conn.execute("SELECT login, akcja FROM audyt WHERE dom_id = ? AND "
                            "akcja LIKE 'admin.%' ORDER BY id", (dom_id,)).fetchall()


# ========================================================= p. 1: blizniaki
def _przecieki(srv, h: dict, dom_id: int, obcy: str, swoj: str) -> list[str]:
    """Trasy GET domu, ktorych odpowiedz zawiera obcy znacznik albo — przy
    trasach z danymi — nie zawiera wlasnego (kontrola pozytywna)."""
    zle = []
    for klucz in DOM_GET:
        status, _, body = call(srv, "GET", _sciezka(klucz, dom_id), headers=h)
        tekst = body.decode("utf-8") if isinstance(body, bytes) else json.dumps(
            body, ensure_ascii=False)
        if obcy in tekst:
            zle.append(f"{klucz}: {obcy}")
        rest = klucz.removeprefix(PREFIKS_DOMU)
        if rest in Z_DANYMI and (status != 200 or swoj not in tekst):
            zle.append(f"{klucz}: brak {swoj} ({status})")
    return zle


def test_blizniacze_domy_nic_nie_przecieka(domy):
    assert _przecieki(domy, sso(domy, "czlonek-a"), DOM_A, "TYLKO-B", "TYLKO-A") == []
    assert _przecieki(domy, sso(domy, "czlonek-b"), DOM_B, "TYLKO-A", "TYLKO-B") == []
    # Konto obu domow: kazdy dom pod swoim adresem, bez mieszania.
    h = sso(domy, "obu")
    assert _przecieki(domy, h, DOM_A, "TYLKO-B", "TYLKO-A") == []
    assert _przecieki(domy, h, DOM_B, "TYLKO-A", "TYLKO-B") == []


def test_kanarek_blizniakow_zapytania_domu_B_na_bazie_A(domy, monkeypatch):
    """Bariera „PanelQueries per dom” usunieta: dom B czyta baze A."""
    from kidwatch import panel_domy  # noqa: PLC0415

    oryginal = panel_domy.DomyPanelu.queries
    monkeypatch.setattr(panel_domy.DomyPanelu, "queries",
                        lambda self, dom: oryginal(self, self.rejestr.dom(DOM_A)))
    assert _przecieki(domy, sso(domy, "czlonek-b"), DOM_B, "TYLKO-A", "TYLKO-B")


# ======================================================= p. 2: macierz
def _blad(body) -> str | None:
    return body.get("error") if isinstance(body, dict) else None


def _macierz(srv, h: dict, dom_id: int) -> list[str]:
    """Trasy domu, ktore NIE odpowiedzialy 404 „nie ma takiego domu”."""
    zle = []
    for klucz in DOM_GET:
        status, _, body = call(srv, "GET", _sciezka(klucz, dom_id), headers=h)
        if (status, _blad(body)) != (404, "Nie ma takiego domu"):
            zle.append(f"GET {klucz}: {status}")
    for klucz in DOM_POST:
        status, _, body = call(srv, "POST", _sciezka(klucz, dom_id), {}, h)
        if (status, _blad(body)) != (404, "Nie ma takiego domu"):
            zle.append(f"POST {klucz}: {status}")
    return zle


def test_obcy_dom_to_404_na_kazdej_trasie(domy):
    assert _macierz(domy, sso(domy, "czlonek-a"), DOM_B) == []
    assert _macierz(domy, sso(domy, "czlonek-b"), DOM_A) == []
    # Dom, ktorego nie ma, wyglada dokladnie tak samo jak cudzy.
    assert _macierz(domy, sso(domy, "czlonek-a"), 99) == []
    assert _audyt(domy, DOM_B) == []


def test_kanarek_macierzy_bez_sprawdzenia_czlonkostwa(domy, monkeypatch):
    """Bariera czlonkostwa usunieta: kazde konto „jest” czlonkiem A."""
    oryginal = dm.RejestrDomow.czlonkostwo

    def zawsze(self, user_id, dom_id):
        return oryginal(self, user_id, dom_id) or oryginal(self, rej_uid, DOM_A)

    rej_uid = domy.auth.user_id("czlonek-a")
    monkeypatch.setattr(dm.RejestrDomow, "czlonkostwo", zawsze)
    assert _macierz(domy, sso(domy, "czlonek-b"), DOM_A)


def test_flaga_administratora_bez_grupy_admins_nic_nie_otwiera(domy):
    """Flaga omylkowo nadana prywatnemu kontu (grupa `wlasciciel`) i konto
    administracyjne wpuszczone inna grupa: 404 jak dla obcego."""
    domy.rejestr.ustaw_admin_instancji(domy.auth.user_id("czlonek-a"), True)
    assert _macierz(domy, sso(domy, "czlonek-a", "wlasciciel"), DOM_B) == []
    assert _macierz(domy, sso(domy, "admin", "rodzina"), DOM_B) == []
    me = call(domy, "GET", "/api/auth/me", headers=sso(domy, "admin", "rodzina"))[2]
    assert me["domy"] == [] and me["admin_instancji"] is False
    assert _audyt(domy, DOM_B) == []


def test_administrator_widzi_kazdy_dom_a_kazde_wejscie_jest_w_dzienniku(domy):
    h = sso(domy, "admin", "admins")
    me = call(domy, "GET", "/api/auth/me", headers=h)[2]
    assert me["admin_instancji"] is True
    assert [(d["id"], d["administracja"], d["rola"]) for d in me["domy"]] == [
        (DOM_A, True, None), (DOM_B, True, None)]
    # Wglad: dane domu B sa, a GET-y daja jeden wpis na sesje i dom.
    assert _przecieki(domy, h, DOM_B, "TYLKO-A", "TYLKO-B") == []
    assert _audyt(domy, DOM_B) == [("admin", "admin.wglad")]
    # Kazdy POST to osobny wpis, 1:1.
    for klucz in DOM_POST:
        call(domy, "POST", _sciezka(klucz, DOM_B), {}, h)
    wpisy = _audyt(domy, DOM_B)
    assert len(wpisy) == 1 + len(DOM_POST)
    assert [a for _, a in wpisy[1:]] == [
        "admin." + k.removeprefix(PREFIKS_DOMU + "/").replace("/", ".") for k in DOM_POST]
    # Nowa sesja (inne urzadzenie) = nowy wpis wgladu.
    call(domy, "GET", f"/api/domy/{DOM_B}/meta", headers={k: v for k, v in h.items()
                                                          if k.startswith("Remote-")})
    assert _audyt(domy, DOM_B).count(("admin", "admin.wglad")) == 2
    # Czlonkowie domu z zarzadzaniem kontami widza wpisy w dzienniku.
    dziennik = call(domy, "GET", f"/api/domy/{DOM_B}/dziennik",
                    headers=sso(domy, "czlonek-b"))[2]["wpisy"]
    assert {w["akcja"] for w in dziennik} >= {"admin.wglad", "admin.game"}
    # Podglad z A nie widzi dziennika A.
    assert call(domy, "GET", f"/api/domy/{DOM_A}/dziennik", headers=sso(domy, "obu"))[0] == 403


def test_administrator_czlonek_dziala_jak_czlonek_bez_wpisow(domy):
    domy.auth.set_role("admin", "podglad", dom_id=DOM_B)
    h = sso(domy, "admin", "admins")
    assert call(domy, "GET", f"/api/domy/{DOM_B}/day", headers=h)[0] == 200
    assert call(domy, "POST", f"/api/domy/{DOM_B}/game", {}, h)[0] == 403  # rola podglad
    assert _audyt(domy, DOM_B) == []


def test_administrator_z_haslem_tylko_z_wlaczonym_TOTP(tmp_path, monkeypatch):
    """Droga awaryjna (port-forward, bez naglowka SSO): flaga dziala tylko
    przy koncie z 2FA."""
    from conftest import panel_login  # noqa: PLC0415

    monkeypatch.delenv("SSO_NAGLOWKI", raising=False)
    (tmp_path / "web").mkdir()
    cfg = _konfiguracja(tmp_path, "A", tmp_path / "kidwatch.db")
    Store(cfg.store.path).close()
    auth = PanelAuth(cfg.panel_auth_path, box=box_from_env())
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    auth.add_user("admin", HASLO, dom_id=None)
    rejestr.ustaw_admin_instancji(auth.user_id("admin"), True)
    srv = start_panel(cfg)
    try:
        h = {"Cookie": panel_login(srv.server_address[1], "admin", HASLO)}
        assert call(srv, "GET", f"/api/domy/{DOM_A}/day", headers=h)[0] == 404
        session = auth.login("admin", HASLO).session
        secret = auth.totp_setup(session)["secret"]
        auth.totp_confirm(session, pyotp.TOTP(secret).now())
        h = {"Cookie": panel_login(srv.server_address[1], "admin", HASLO, secret)}
        assert call(srv, "GET", f"/api/domy/{DOM_A}/day", headers=h)[0] == 200
    finally:
        srv.shutdown()


# =========================================================== aliasy
def test_stare_trasy_jedynego_domu_dzialaja_a_przy_dwoch_409(domy):
    assert call(domy, "GET", "/api/day", headers=sso(domy, "czlonek-a"))[0] == 200
    assert call(domy, "GET", "/api/day", headers=sso(domy, "czlonek-b"))[0] == 200
    for login, grupy in (("obu", "wlasciciel"), ("admin", "admins")):
        h = sso(domy, login, grupy)
        status, _, body = call(domy, "GET", "/api/day", headers=h)
        assert status == 409 and "wybierz dom" in body["error"], login
        assert call(domy, "POST", "/api/game", {"child": "Dziecko 1", "action": "block"},
                    h)[0] == 409
    # Konto bez zadnego domu: 404, nie 409.
    assert call(domy, "GET", "/api/day", headers=sso(domy, "admin", "rodzina"))[0] == 404


def test_alias_jedynego_domu_B_nie_czyta_A(domy):
    body = call(domy, "GET", "/api/notifications", headers=sso(domy, "czlonek-b"))[2]
    assert "TYLKO-B" in json.dumps(body) and "TYLKO-A" not in json.dumps(body)


# =========================================================== /api/auth/me
def test_me_podaje_domy_i_uprawnienia_per_dom(domy):
    me = call(domy, "GET", "/api/auth/me", headers=sso(domy, "obu"))[2]
    assert [(d["id"], d["rola"]) for d in me["domy"]] == [(DOM_A, "podglad"),
                                                         (DOM_B, "wlasciciel-domu")]
    a, b = me["domy"]
    assert u.CZAS_GRY not in a["uprawnienia"] and u.CZAS_GRY in b["uprawnienia"]
    assert me["rola"] is None and me["uprawnienia"] == [u.KONTO_WLASNE]
    me = call(domy, "GET", "/api/auth/me", headers=sso(domy, "czlonek-a"))[2]
    assert me["rola"] == "wlasciciel"
    assert me["uprawnienia"] == sorted(set(u.UPRAWNIENIA) - {u.WHATSAPP})


#: Trasy z zakresem instancji (bot WhatsApp bramki) z tablic routera.
INST_GET = sorted(k for k, (_, z) in GET_TRASY.items() if z == u.ZAKRES_INSTANCJA)
INST_POST = sorted(k for k, (_, _, z) in POST_TRASY.items() if z == u.ZAKRES_INSTANCJA)


def _instancja_403(srv, h: dict) -> list[str]:
    """Trasy bota WhatsApp, ktore NIE odpowiedzialy 403 za brak uprawnienia."""
    zle = []
    for metoda, klucze in (("GET", INST_GET), ("POST", INST_POST)):
        for k in klucze:
            st, _, b = call(srv, metoda, k, {} if metoda == "POST" else None, h)
            if st != 403 or u.WHATSAPP not in (_blad(b) or ""):
                zle.append(f"{metoda} {k}: {st}")
    return zle


def test_bot_whatsapp_tylko_dla_aktywnego_administratora(domy):
    """Decyzja wlasciciela 2026-10-12 (§2.3): konfiguracja bota WhatsApp
    (zakres instancji) WYLACZNIE dla aktywnego administratora instalacji —
    nie dla wlasciciela Domu 1 ani zadnego innego domu."""
    assert INST_GET and INST_POST
    for login in ("czlonek-a", "czlonek-b", "obu"):
        assert _instancja_403(domy, sso(domy, login)) == [], login
    # Flaga bez grupy `admins` (prywatne konto, inna grupa) — dalej 403.
    domy.rejestr.ustaw_admin_instancji(domy.auth.user_id("czlonek-a"), True)
    assert _instancja_403(domy, sso(domy, "czlonek-a", "wlasciciel")) == []
    assert _instancja_403(domy, sso(domy, "admin", "rodzina")) == []
    me = call(domy, "GET", "/api/auth/me", headers=sso(domy, "czlonek-a"))[2]
    assert u.WHATSAPP not in me["uprawnienia"]
    assert all(u.WHATSAPP not in d["uprawnienia"] for d in me["domy"])
    with sqlite3.connect(domy.cfg.panel_auth_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audyt WHERE akcja LIKE 'instancja.p%'"
                            ).fetchone()[0] == 0
    # Aktywny administrator: dostep (tu bramka wylaczona — 200/404, nie 403)
    # i kazdy POST w dzienniku instancji (dom NULL).
    h = sso(domy, "admin", "admins")
    for k in INST_GET:
        st, _, b = call(domy, "GET", k, headers=h)
        # QR: 403 tylko za brak swiezego potwierdzenia haslem, nie za uprawnienie.
        assert st != 403 or u.WHATSAPP not in (_blad(b) or ""), (k, b)
    for k in INST_POST:
        st, _, b = call(domy, "POST", k, {}, h)
        assert st != 403 or u.WHATSAPP not in (_blad(b) or ""), (k, b)
    with sqlite3.connect(domy.cfg.panel_auth_path) as conn:
        wpisy = conn.execute("SELECT dom_id, login, akcja FROM audyt WHERE akcja LIKE "
                             "'instancja.p%' ORDER BY id").fetchall()
    assert wpisy == [(None, "admin", "instancja." + k.removeprefix("/api/").replace("/", "."))
                     for k in INST_POST]
    me = call(domy, "GET", "/api/auth/me", headers=h)[2]
    assert u.WHATSAPP in me["uprawnienia"]


async def test_wysylka_przez_bramke_nie_zalezy_od_prawa_do_bota(domy):
    """Prawo do bota to tylko KONFIGURACJA. Powiadomienia Domu 1 ida przez
    bramke jak dzis: w trybie tras (domyslnym) i w trybie kont do wlasciciela
    Domu 1, ktory prawa do bota juz nie ma."""
    note = Notification(kind=NotifyKind.NIGHT, title="t", text="x", dedup_key="n1",
                        ts=datetime.now(UTC), priority=5)
    konta = o.ProfilePowiadomien(domy.cfg.panel_auth_path)
    assert u.WHATSAPP not in u.w_domu(konta.profil("czlonek-a").uprawnienia)
    # Tryb tras (produkcja dzis): jedna wysylka do bramki, bez odbiorcy.
    store = Store(":memory:")
    bramka = Bramka(zna_odbiorce=True)
    outbox = Outbox(Dispatcher([bramka], store=store), store, konta=konta, dom_id=DOM_A)
    await outbox.send_all([note])
    assert await outbox.flush() == 1 and bramka.wyslane == [("n1", None)]
    store.close()
    # Tryb kont: wlasciciel Domu 1 z kanalem dostaje notke.
    konta.ustaw_kanaly("czlonek-a", whatsapp="48500100200", email=None)
    konta.ustaw_tryb(o.TRYB_KONTA)
    store = Store(":memory:")
    bramka = Bramka(zna_odbiorce=True)
    outbox = Outbox(Dispatcher([bramka], store=store), store, konta=konta, dom_id=DOM_A)
    await outbox.send_all([note])
    await outbox.flush()
    assert [o_.get("whatsapp") for _, o_ in bramka.wyslane] == ["48500100200"]
    store.close()


# ===================================================== kolejki z domem
def test_czas_gry_z_panelu_trafia_do_kolejki_swojego_domu(tmp_path, monkeypatch):
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    (tmp_path / "web").mkdir()
    cfg = _konfiguracja(tmp_path, "A", tmp_path / "kidwatch.db")
    cfg.game_time.enabled = True
    Store(cfg.store.path).close()
    auth = PanelAuth(cfg.panel_auth_path)
    auth.add_user("czlonek-a", HASLO)
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.dodaj_dom("Dom B")
    srv = start_panel(cfg, konfiguracja_domu=lambda dom: cfg)
    try:
        auth.set_role("czlonek-a", "wlasciciel-domu", dom_id=DOM_B)
        h = sso(srv, "czlonek-a")
        assert call(srv, "POST", f"/api/domy/{DOM_B}/game",
                    {"child": "Dziecko 1", "action": "block"}, h)[0] == 202
        assert call(srv, "POST", f"/api/domy/{DOM_A}/game",
                    {"child": "Dziecko 1", "action": "allow"}, h)[0] == 202
        a = GameRequests(cfg.panel_auth_path, dom_id=DOM_A).pending()
        b = GameRequests(cfg.panel_auth_path, dom_id=DOM_B).pending()
        assert [r["action"] for r in a] == ["allow"] and [r["action"] for r in b] == ["block"]
        assert call(srv, "POST", f"/api/domy/{DOM_B}/game",
                    {"child": "Obce", "action": "block"}, h)[0] == 400
    finally:
        srv.shutdown()


# ================================================== p. 5: powiadomienia
def test_odbiorcy_domu_to_tylko_jego_czlonkowie(domy):
    path = domy.cfg.panel_auth_path
    a = o.ProfilePowiadomien(path)
    b = a.dla_domu(DOM_B)
    assert {p.login for p in a.profile()} == {"czlonek-a", "obu"}
    assert {p.login for p in b.profile()} == {"czlonek-b", "obu"}
    for k in (a, b):
        for login in ("czlonek-a", "czlonek-b", "obu", "admin"):
            k.ustaw_kanaly(login, whatsapp=None, email=f"{login}@example.com")
    note = Notification(kind=NotifyKind.NIGHT, title="t", text="x", dedup_key="n",
                        ts=datetime.now(UTC), device="iPad Dziecka 1", priority=5)
    adresaci = o.adresaci(note, b.profile(), dziecko={"iPad Dziecka 1": "Dziecko 1"},
                          tz=TZ, now=datetime.now(UTC))
    assert {x.login for x in adresaci.adresaci} == {"czlonek-b", "obu"}
    # Role i uprawnienia z domu: `obu` w A to podglad (bez czujki), w B wlasciciel.
    assert u.POWIADOMIENIA_TECHNICZNE not in a.profil("obu").uprawnienia
    assert u.POWIADOMIENIA_TECHNICZNE in b.profil("obu").uprawnienia


def test_preferencje_per_dom_i_lustro_domu_1(domy):
    path = domy.cfg.panel_auth_path
    a = o.ProfilePowiadomien(path)
    b = a.dla_domu(DOM_B)
    a.ustaw_preferencje("obu", kategorie=[o.SESJE], cisza_od="22:00", cisza_do="07:00")
    b.ustaw_preferencje("obu", kategorie=[o.ALARMY, o.MDM])
    assert a.profil("obu").kategorie == {o.SESJE}
    assert b.profil("obu").kategorie == {o.ALARMY, o.MDM}
    # Lustro dla obrazu sprzed domow: preferencje Domu 1, nie B.
    with sqlite3.connect(path) as conn:
        assert json.loads(conn.execute(
            "SELECT p.kategorie FROM user_powiadomienia p JOIN users u ON u.id = p.user_id "
            "WHERE u.login = 'obu'").fetchone()[0]) == [o.SESJE]
        # Stary obraz zmienia preferencje (nowszy updated_at) -> wracaja przy starcie.
        conn.execute("UPDATE user_powiadomienia SET kategorie = ?, updated_at = updated_at + 5 "
                     "WHERE user_id = (SELECT id FROM users WHERE login = 'obu')",
                     (json.dumps([o.RAPORTY]),))
        conn.execute("UPDATE powiadomienia_ustawienia SET wartosc = 'konta' WHERE klucz = 'tryb'")
        conn.execute("INSERT OR IGNORE INTO powiadomienia_ustawienia VALUES ('tryb', 'konta')")
    nowy = o.ProfilePowiadomien(path)
    assert nowy.profil("obu").kategorie == {o.RAPORTY}
    assert nowy.tryb() == o.TRYB_KONTA
    assert nowy.dla_domu(DOM_B).profil("obu").kategorie == {o.ALARMY, o.MDM}
    # Konto spoza domu nie ma w nim preferencji.
    with pytest.raises(LookupError):
        b.ustaw_preferencje("czlonek-a", kategorie=None)


def test_tryb_tras_tylko_w_domu_1(domy):
    b = o.ProfilePowiadomien(domy.cfg.panel_auth_path).dla_domu(DOM_B)
    assert b.tryb() == o.TRYB_KONTA
    with pytest.raises(ValueError, match="Domu 1"):
        b.ustaw_tryb(o.TRYB_TRASY)
    st, _, body = call(domy, "POST", f"/api/domy/{DOM_B}/konta/tryb",
                       {"tryb": "trasy", "confirm": HASLO}, sso(domy, "czlonek-b"))
    assert st == 400 and "Domu 1" in body["error"]


class Bramka:
    """Atrapa kanalu per konto. Liczy KAZDE wywolanie — „zero zadan do
    bramki” ma byc zmierzone, nie zalozone."""

    name = "bramka"
    per_konto = True

    def __init__(self, zna_odbiorce: bool) -> None:
        self.zna = zna_odbiorce
        self.wyslane: list = []

    async def obsluguje_odbiorcow(self) -> bool:
        return self.zna

    async def send(self, note, odbiorca=None):
        self.wyslane.append((note.dedup_key, odbiorca))
        return True

    async def aclose(self):
        pass


@pytest.mark.parametrize("dom_id", [DOM_B, DOM_A])
async def test_dom_bez_trybu_tras_wstrzymuje_wysylke_bez_odbiorcy(domy, dom_id, caplog):
    store = Store(":memory:")
    bramka = Bramka(zna_odbiorce=False)
    konta = o.ProfilePowiadomien(domy.cfg.panel_auth_path).dla_domu(dom_id)
    outbox = Outbox(Dispatcher([bramka], store=store), store, konta=konta, dom_id=dom_id)
    note = Notification(kind=NotifyKind.SESSION_START, title="t", text="x", dedup_key="s",
                        ts=datetime.now(UTC), device="iPad Dziecka 1")
    await outbox.send_all([note])
    with caplog.at_level(logging.ERROR):
        wyslane = await outbox.flush()
    if dom_id == DOM_B:
        # Zero zadan do bramki; notka czeka nierozdzielona, nie ginie.
        assert (wyslane, bramka.wyslane) == (0, [])
        assert len(store.outbox_pending(odbiorca=None, limit=10)) == 1
        assert "WSTRZYMANE" in caplog.text
    else:
        # Kanarek: Dom 1 w trybie tras wysyla trasami (stare zachowanie).
        assert wyslane == 1 and len(bramka.wyslane) == 1
    store.close()


async def test_dom_B_w_trybie_kont_wysyla_tylko_swoim(domy):
    path = domy.cfg.panel_auth_path
    konta = o.ProfilePowiadomien(path).dla_domu(DOM_B)
    for login in ("czlonek-a", "czlonek-b", "obu"):
        konta.ustaw_kanaly(login, whatsapp=None, email=f"{login}@example.com")
    store = Store(":memory:")
    bramka = Bramka(zna_odbiorce=True)
    outbox = Outbox(Dispatcher([bramka], store=store), store, konta=konta, dom_id=DOM_B)
    await outbox.send_all([Notification(kind=NotifyKind.NIGHT, title="t", text="x",
                                        dedup_key="n", ts=datetime.now(UTC), priority=5)])
    await outbox.flush()
    assert sorted(o_.get("email") for _, o_ in bramka.wyslane) == [
        "czlonek-b@example.com", "obu@example.com"]
    store.close()


# ===================================================== p. 6: kanarek sekretu
def test_haslo_z_potwierdzenia_nie_trafia_do_dziennika_ani_logu(domy, caplog):
    kanarek = "kanarek-" + "x7q9" * 4
    h = sso(domy, "admin", "admins")
    with caplog.at_level(logging.DEBUG):
        for klucz in DOM_POST:
            call(domy, "POST", _sciezka(klucz, DOM_B),
                 {"confirm": kanarek, "login": "czlonek-b", "whatsapp": "48500100200"}, h)
    with sqlite3.connect(domy.cfg.panel_auth_path) as conn:
        dziennik = json.dumps(conn.execute("SELECT * FROM audyt").fetchall())
    assert kanarek not in dziennik and kanarek not in caplog.text
    assert "admin.konta.kanaly" in dziennik  # kontrola: wpisy sa


# ================================================ konta w domu (panel)
def test_zarzadca_domu_B_nie_widzi_ani_nie_zmienia_kont_A(domy):
    h = sso(domy, "czlonek-b")
    lista = call(domy, "GET", f"/api/domy/{DOM_B}/konta", headers=h)[2]
    assert {k["login"] for k in lista["konta"]} == {"czlonek-b", "obu"}
    assert u.WHATSAPP not in {x["id"] for x in lista["uprawnienia"]}
    for akcja, body in (("rola", {"rola": "podglad"}), ("usun", {}),
                        ("uprawnienia", {"zmiany": {u.TV_PAUZA: True}})):
        st, _, b = call(domy, "POST", f"/api/domy/{DOM_B}/konta/{akcja}",
                        {"login": "czlonek-a", "confirm": HASLO, **body}, h)
        assert st == 404, (akcja, b)
    # Kanaly czlonka OBU domow: zarzadca B nie zarzadza A — odmowa.
    st, _, b = call(domy, "POST", f"/api/domy/{DOM_B}/konta/kanaly",
                    {"login": "obu", "whatsapp": "48500100200", "confirm": HASLO}, h)
    assert st == 403 and "innego domu" in b["error"]


def test_usuniecie_z_domu_wypisuje_a_konto_bez_domow_znika(domy):
    h = sso(domy, "czlonek-b")
    st, _, b = call(domy, "POST", f"/api/domy/{DOM_B}/konta/usun",
                    {"login": "obu", "confirm": HASLO}, h)
    assert st == 200 and b["konto_usuniete"] is False
    assert [c.dom_id for c in domy.rejestr.czlonkostwa(domy.auth.user_id("obu"))] == [DOM_A]
    call(domy, "POST", f"/api/domy/{DOM_B}/konta/dodaj",
         {"login": "gosc", "rola": "podglad", "confirm": HASLO}, h)
    st, _, b = call(domy, "POST", f"/api/domy/{DOM_B}/konta/usun",
                    {"login": "gosc", "confirm": HASLO}, h)
    assert st == 200 and b["konto_usuniete"] is True
    assert "gosc" not in {x["login"] for x in domy.auth.list_users()}


def test_ostatni_zarzadzajacy_nie_znika(domy):
    uid, obu = domy.auth.user_id("czlonek-b"), domy.auth.user_id("obu")
    # Dwoch zarzadzajacych: jednego mozna wypisac...
    assert domy.rejestr.usun_czlonkostwo(DOM_B, obu) is True
    # ...ostatniego juz nie — ani wypisac, ani zdegradowac.
    with pytest.raises(dm.OstatniZarzadzajacy):
        domy.rejestr.usun_czlonkostwo(DOM_B, uid)
    with pytest.raises(dm.OstatniZarzadzajacy):
        domy.rejestr.ustaw_czlonkostwo(DOM_B, uid, "zarzadca")
    with pytest.raises(dm.OstatniZarzadzajacy):
        domy.auth.set_permissions("czlonek-b", {u.KONTA: False}, dom_id=DOM_B)
    assert domy.rejestr.czlonkostwo(uid, DOM_B).rola == "wlasciciel-domu"
    assert {c.login for c in domy.rejestr.czlonkowie(DOM_B)} == {"czlonek-b"}
    # Swiezy dom bez zarzadzajacego moze przyjac podglad.
    nowy = domy.rejestr.dodaj_dom("Dom C")
    domy.rejestr.ustaw_czlonkostwo(nowy, obu, "podglad")


def test_zmiana_czlonkostwa_wylogowuje(domy):
    from conftest import panel_login  # noqa: PLC0415

    h = {"Cookie": panel_login(domy.server_address[1], "obu", HASLO)}
    assert call(domy, "GET", f"/api/domy/{DOM_B}/day", headers=h)[0] == 200
    domy.rejestr.ustaw_czlonkostwo(DOM_B, domy.auth.user_id("obu"), "podglad")
    assert call(domy, "GET", "/api/auth/me", headers=h)[0] == 401
    h = {"Cookie": panel_login(domy.server_address[1], "obu", HASLO)}
    domy.auth.remove_membership("obu", DOM_B)
    assert call(domy, "GET", "/api/auth/me", headers=h)[0] == 401


# ============================================================ CLI i start
def test_konto_administracyjne_z_CLI_bez_domu_i_bez_powrotu(tmp_path, capsys):
    from test_panel_auth import CONFIG  # noqa: PLC0415

    cfg = tmp_path / "config.yaml"
    cfg.write_text(CONFIG, encoding="utf-8")
    base = ["--config", str(cfg)]
    import sys  # noqa: PLC0415

    for login in ("konto-prywatne", "konto-admin"):
        sys.stdin = io.StringIO("haslo-ze-stdin-123\n")
        try:
            assert main([*base, "user-add", login, "--password-stdin"]) == 0
        finally:
            sys.stdin = sys.__stdin__
    path = tmp_path / "panel-auth.db"
    rejestr = dm.RejestrDomow(path)
    auth = PanelAuth(path, box=box_from_env())
    uid = auth.user_id("konto-admin")
    # U-1: bez wlaczonego 2FA panelu — odmowa i ZERO zmian (dalej czlonek, bez flagi).
    assert main([*base, "user-admin", "konto-admin", "on"]) == 1
    assert "2FA" in capsys.readouterr().err
    assert [c.dom_id for c in rejestr.czlonkostwa(uid)] == [DOM_A]
    assert not rejestr.admin_instancji(uid)
    # Wlasciciel konta loguje sie haslem i wlacza 2FA, potem dopiero `on`.
    session = auth.login("konto-admin", "haslo-ze-stdin-123").session
    auth.totp_confirm(session, pyotp.TOTP(auth.totp_setup(session)["secret"]).now())
    # §6 p. 2: user-admin on — konto wypada z Domu 1.
    assert main([*base, "user-admin", "konto-admin", "on"]) == 0
    # Prywatne konto to teraz jedyny zarzadzajacy: nie zostanie wypisane
    # (--tylko-sso omija wymog 2FA, nie te regule).
    assert main([*base, "user-admin", "konto-prywatne", "on", "--tylko-sso"]) == 1
    assert "jedyne konto zarzadzajace" in capsys.readouterr().err
    # U-3: nie ma opcji zostawienia kontu domow razem z rola administratora.
    with pytest.raises(SystemExit):
        main([*base, "user-admin", "konto-prywatne", "on", "--zostaw-domy"])
    assert rejestr.czlonkostwa(uid) == [] and rejestr.admin_instancji(uid)
    # Lustro dla obrazu sprzed domow: rola nieznana = tylko wlasne konto.
    with sqlite3.connect(path) as conn:
        assert conn.execute("SELECT rola FROM users WHERE id = ?", (uid,)).fetchone()[0] == \
            dm.BEZ_DOMU
    # Kolejne starty nie dopisuja go do Domu 1.
    assert not rejestr.migruj().zmiany
    PanelAuth(path)
    assert rejestr.czlonkostwa(uid) == []
    capsys.readouterr()
    assert main([*base, "domy"]) == 0
    out = capsys.readouterr().out
    assert "administratorzy instalacji: konto-admin" in out
    assert main([*base, "user-admin", "konto-admin", "off"]) == 0
    assert not rejestr.admin_instancji(uid)
    # Wpisy instancji w dzienniku (dom NULL).
    with sqlite3.connect(path) as conn:
        assert [r[0] for r in conn.execute(
            "SELECT opis FROM audyt WHERE akcja = 'instancja.admin' ORDER BY id")] == [
            "administrator instalacji: nadany", "administrator instalacji: odebrany"]


def test_dom_dodaj_i_dom_czlonek_z_CLI(tmp_path, capsys):
    from test_panel_auth import CONFIG  # noqa: PLC0415

    cfg = tmp_path / "config.yaml"
    cfg.write_text(CONFIG, encoding="utf-8")
    base = ["--config", str(cfg)]
    import sys  # noqa: PLC0415

    sys.stdin = io.StringIO("haslo-ze-stdin-123\n")
    try:
        assert main([*base, "user-add", "konto-a", "--password-stdin", "--bez-domu"]) == 0
    finally:
        sys.stdin = sys.__stdin__
    assert main([*base, "dom-dodaj", "Dom testowy"]) == 0
    baza = Config.load(cfg).store.path
    assert dm.sciezka_bazy_domu(DOM_B, baza).is_file()
    assert main([*base, "dom-czlonek", "2", "konto-a", "zarzadca"]) == 0
    assert main([*base, "dom-czlonek", "2", "konto-a", "--usun"]) == 0
    assert main([*base, "dom-czlonek", "9", "konto-a", "podglad"]) == 1
    rejestr = dm.RejestrDomow(tmp_path / "panel-auth.db")
    assert [d.nazwa for d in rejestr.domy()] == ["Dom 1", "Dom testowy"]
    assert rejestr.czlonkowie(DOM_B) == [] and rejestr.czlonkowie(DOM_A) == []


def test_gosc_innego_domu_nie_wpada_do_domu_1_po_restarcie(tmp_path):
    """E4: konto z czlonkostwem tylko w Domu 2 po starcie dalej bez Domu 1."""
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    rejestr = dm.RejestrDomow(path)
    rejestr.dodaj_dom("Dom B")
    auth.add_user("gosc", HASLO, "podglad", dom_id=DOM_B)
    uid = auth.user_id("gosc")
    PanelAuth(path)
    assert not rejestr.migruj().zmiany  # start niczego nie dopisuje ani nie sprzata
    assert [c.dom_id for c in rejestr.czlonkostwa(uid)] == [DOM_B]
    assert rejestr.uprawnienia(uid, DOM_A) == frozenset()


def test_stary_obraz_E1_dopisuje_bez_domu_a_powrot_to_sprzata(tmp_path):
    """Obraz E1 przy starcie daje KAZDEMU kontu czlonkostwo w Domu 1 z rola
    z `users` — dla lustra BEZ_DOMU rola nieznana (tylko konto.wlasne).
    Powrot E3a takie czlonkostwo usuwa. Na prawdziwym kodzie E1 sprawdzone
    recznie (git archive origin/main), tu — jego SQL."""
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("konto-x", HASLO, dom_id=None)
    uid = auth.user_id("konto-x")
    with sqlite3.connect(path) as conn:  # uzgodnij_konto_conn z E1
        conn.execute("INSERT INTO czlonkostwa (dom_id, user_id, rola, od) VALUES (1, ?, ?, 0)",
                     (uid, dm.BEZ_DOMU))
    assert dm.RejestrDomow(path).uprawnienia(uid, DOM_A) == {u.KONTO_WLASNE}
    raport = dm.RejestrDomow(path).migruj()
    assert raport.uzgodnione == ("konto-x",)
    assert dm.RejestrDomow(path).czlonkostwa(uid) == []


def test_front_zna_te_same_trasy_domu_co_serwer():
    """utils/domy.js dokleja prefiks domu WYLACZNIE trasom z zakresem `dom`.
    Trasa domu nieznana frontowi szlaby aliasem (409 przy dwoch domach),
    a trasa konta z prefiksem — w 404."""
    import re  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    js = (Path(__file__).resolve().parents[1] / "web" / "src" / "utils" / "domy.js").read_text(
        "utf-8")
    blok = js[js.index("export const TRASY_DOMU"):js.index("];", js.index("TRASY_DOMU"))]
    front = set(re.findall(r"'([^']+)'", blok))
    serwer = {k.removeprefix(PREFIKS_DOMU + "/") for k in (*DOM_GET, *DOM_POST)}
    assert front == serwer, (front ^ serwer)


# ================================================== Dom 1 w trybie `baza`
@pytest.mark.usefixtures("kek")
@pytest.mark.parametrize("zrodlo", ["yaml", "baza"])
def test_run_panel_domu_1_z_bazy_pokazuje_ten_sam_dom(tmp_path, monkeypatch, zrodlo):
    """Przeglad E3a, B-1: `run` budowal panel bez konfiguracji domu, wiec po
    `dom-zrodlo 1 baza` (E2) Dom 1 w panelu byl pusty — bez urzadzen, dzieci,
    czasu gry i pauzy TV. Sciezka produkcyjna: `dom-importuj`, potem
    `kidwatch run`; panel odpytany w trakcie startu."""
    import secrets  # noqa: PLC0415

    import kidwatch.__main__ as cli  # noqa: PLC0415
    from conftest import panel_login  # noqa: PLC0415
    from kidwatch import panel as panel_mod  # noqa: PLC0415
    from test_domy_e2 import Puste, _prosta, _zapisz_konfig  # noqa: PLC0415

    monkeypatch.setenv("NEXTDNS_API_KEY", "klucz-" + secrets.token_hex(8))
    monkeypatch.setenv("KIDWATCH_HEARTBEAT", str(tmp_path / "hb"))
    data = _prosta(tmp_path)
    (tmp_path / "web").mkdir()
    data["panel"] = {"enabled": True, "port": 0, "host": "127.0.0.1",
                     "static_dir": str(tmp_path / "web"), "cookie_secure": False}
    data["game_time"] = {"enabled": True}
    data["tv"] = {"enabled": True, "name": "TV wspolny", "host": "192.0.2.20",
                  "adb_key_dir": str(tmp_path / "adb")}
    cfg_path = _zapisz_konfig(tmp_path, data)
    PanelAuth(Config.load(cfg_path).panel_auth_path).add_user("konto-a", HASLO)
    if zrodlo == "baza":
        assert main(["--config", str(cfg_path), "dom-importuj", "1", "--zapisz"]) == 0
        assert dm.RejestrDomow(Config.load(cfg_path).panel_auth_path).dom(
            DOM_A).zrodlo_konfiguracji == "baza"
    monkeypatch.setattr(cli, "build_source", lambda cfg, store: Puste())
    # Bez sieci: czujnika TV nie budujemy (laczylby sie z telewizorem); kolejka
    # pauzy TV w panelu zalezy od `tv.enabled` konfiguracji domu, nie od niego.
    monkeypatch.setattr(cli, "build_tv_watcher", lambda *a, **kw: None)
    widziane = {}
    prawdziwy = panel_mod.start_panel

    def start_i_odpytaj(*a, **kw):
        srv = prawdziwy(*a, **kw)
        h = {"Cookie": panel_login(srv.server_address[1], "konto-a", HASLO)}
        h["X-CSRF-Token"] = dict(x.split("=", 1) for x in h["Cookie"].split("; "))[
            "kidwatch_csrf"]
        widziane["meta"] = call(srv, "GET", f"/api/domy/{DOM_A}/meta", headers=h)[2]
        widziane["game"] = call(srv, "POST", f"/api/domy/{DOM_A}/game",
                                {"child": "Kuba", "action": "block"}, h)[0]
        widziane["day"] = call(srv, "GET", f"/api/domy/{DOM_A}/day", headers=h)[2]
        widziane["tv"] = call(srv, "GET", f"/api/domy/{DOM_A}/tv/pause", headers=h)[2]
        widziane["pauza"] = call(srv, "POST", f"/api/domy/{DOM_A}/tv/pause",
                                 {"until": None}, h)[0]
        return srv

    monkeypatch.setattr(panel_mod, "start_panel", start_i_odpytaj)
    assert main(["--config", str(cfg_path), "run"]) == 1  # koniec atrapy zrodla
    assert widziane["meta"]["children"] == ["Kuba", "Zosia"], widziane
    assert [d["name"] for d in widziane["day"]["devices"]] == ["iPad Kuby", "iPad Zosi",
                                                              "TV wspolny"]
    assert widziane["game"] == 202  # czas gry wlaczony w Domu 1, dziecko znane
    assert widziane["tv"]["available"] is True and widziane["tv"]["name"] == "TV wspolny"
    assert widziane["pauza"] == 202  # pauza TV Domu 1 trafia do kolejki


def test_blad_zapisu_dziennika_to_503_i_brak_zmiany(domy, monkeypatch):
    """Przeglad E3a, U-2: wejscie administratora bez wpisu w `audyt` nie moze
    sie zdarzyc — ani do domu (GET i POST), ani zmiana instancji."""
    h = sso(domy, "admin", "admins")

    def pada(*_a, **_kw):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(dm.RejestrDomow, "zapisz_audyt", pada)
    st, _, body = call(domy, "GET", f"/api/domy/{DOM_B}/day", headers=h)
    assert st == 503 and "TYLKO-B" not in json.dumps(body)
    st, _, _ = call(domy, "POST", f"/api/domy/{DOM_B}/konta/dodaj",
                    {"login": "nowe-konto", "rola": "podglad", "confirm": HASLO}, h)
    assert st == 503
    assert "nowe-konto" not in {u_["login"] for u_ in domy.auth.list_users()}
    st, _, body = call(domy, "POST", "/api/profile/test", {}, h)
    assert st == 503 and "dzienniku" in body["error"]
    # Kontrola: bez awarii dziennika te same zadania przechodza.
    monkeypatch.undo()
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    h = sso(domy, "admin", "admins")
    assert call(domy, "GET", f"/api/domy/{DOM_B}/day", headers=h)[0] == 200
    assert call(domy, "POST", f"/api/domy/{DOM_B}/konta/dodaj",
                {"login": "nowe-konto", "rola": "podglad", "confirm": HASLO}, h)[0] == 200


def test_admin_tylko_sso_nie_dostaje_roli_haslem_nawet_z_2FA(tmp_path, monkeypatch, capsys):
    """Przeglad E3a, B-2: `user-admin on --tylko-sso` przy wylaczonym SSO
    (produkcja): kto zna haslo, logowal sie, wlaczal 2FA na ekranie „Brak
    domu” i zostawal administratorem wszystkich domow. Teraz tryb jest
    zapisany w bazie: haslo panelu nie otwiera temu kontu nawet sesji, a
    sesja z hasla (np. sprzed nadania) i tak nie daje roli."""
    from conftest import panel_login  # noqa: PLC0415
    from kidwatch.panel_auth import AuthError, Session  # noqa: PLC0415
    from kidwatch.panel_domy import admin_aktywny  # noqa: PLC0415
    from test_panel_auth import CONFIG  # noqa: PLC0415

    monkeypatch.delenv("SSO_NAGLOWKI", raising=False)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(CONFIG, encoding="utf-8")
    base = ["--config", str(cfg_path)]
    monkeypatch.setattr("sys.stdin", io.StringIO(HASLO + "\n"))
    assert main([*base, "user-add", "konto-admin", "--bez-domu", "--password-stdin"]) == 0
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path, box=box_from_env())
    # Sesja hasla otwarta PRZED nadaniem (user-admin ja zamyka, ale gdyby...).
    przed = auth.login("konto-admin", HASLO).session
    secret = auth.totp_setup(przed)["secret"]
    auth.totp_confirm(przed, pyotp.TOTP(secret).now())
    assert main([*base, "user-admin", "konto-admin", "on", "--tylko-sso"]) == 0
    assert "WYLACZNIE" in capsys.readouterr().out
    uid = auth.user_id("konto-admin")
    assert dm.RejestrDomow(path).admin_instancji(uid)
    # 1) Haslo (i kod) nie otwiera sesji.
    with pytest.raises(AuthError) as e:
        auth.login("konto-admin", HASLO)
    assert e.value.status == 403 and "Authelię" in e.value.message
    # 2) Sesja z hasla z TOTP — gdyby jakas przetrwala — roli nie daje.
    with sqlite3.connect(path) as conn:
        assert dm.tryb_admina(conn, uid) == dm.ADMIN_TYLKO_SSO
    s = Session("konto-admin", uid, "t", "c", 0, kind="haslo", admin_instancji=True,
                admin_tylko_sso=True, totp=True)
    assert not admin_aktywny(s, None)
    assert admin_aktywny(s, ("admins",))  # przez Authelie z grupa — tak
    assert not admin_aktywny(s, ("wlasciciel",))
    # 3) Przez HTTP przy wylaczonym SSO: logowanie haslem odrzucone.
    cfg = Config.load(cfg_path)
    cfg.panel.port = 0
    cfg.panel.static_dir = str(tmp_path)
    srv = start_panel(cfg)
    try:
        with pytest.raises(AssertionError):
            panel_login(srv.server_address[1], "konto-admin", HASLO, secret)
    finally:
        srv.shutdown()
    # Kontrola: zwykly tryb (bez --tylko-sso) z TOTP przechodzi haslem.
    assert main([*base, "user-admin", "konto-admin", "on"]) == 0
    s = auth.login("konto-admin", HASLO)
    assert s.mfa_required


def test_dom_czlonek_ostrzega_przy_koncie_administracyjnym(tmp_path, capsys):
    from test_panel_auth import CONFIG  # noqa: PLC0415

    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(CONFIG, encoding="utf-8")
    base = ["--config", str(cfg_path)]
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("konto-admin", HASLO, dom_id=None)
    auth.add_user("konto-zwykle", HASLO, dom_id=None)
    dm.RejestrDomow(path).ustaw_admin_instancji(auth.user_id("konto-admin"), True)
    capsys.readouterr()
    assert main([*base, "dom-czlonek", "1", "konto-zwykle", "podglad"]) == 0
    assert "UWAGA" not in capsys.readouterr().err
    assert main([*base, "dom-czlonek", "1", "konto-admin", "podglad"]) == 0
    err = capsys.readouterr().err
    assert "UWAGA" in err and "konto administracyjne" in err


def test_sesja_z_hasla_konta_tylko_sso_jest_odrzucana(domy):
    """Przeglad E3a (trzeci), U-4: sesja `haslo` konta w trybie tylko-SSO
    (np. zalozona starym obrazem w czasie wycofania, ktory trybu nie zna)
    nie moze dalej dzialac — 401, a nie tylko brak roli. Sesja z Authelii
    z grupa `admins` dziala; zwykle konto bez zmian."""
    from conftest import panel_login  # noqa: PLC0415

    port = domy.server_address[1]
    uid = domy.auth.user_id("admin")
    # Sesje z hasla zalozone, zanim konto przeszlo w tryb tylko-SSO (tak
    # jak w starym obrazie): ustawienie flagi bez wylogowania (bez CLI).
    h_admin = {"Cookie": panel_login(port, "admin", HASLO)}
    h_zwykle = {"Cookie": panel_login(port, "czlonek-a", HASLO)}
    token = dict(x.split("=", 1) for x in h_admin["Cookie"].split("; "))["kidwatch_session"]
    assert domy.auth.session(token) is not None
    domy.rejestr.ustaw_admin_instancji(uid, True, tylko_sso=True)

    assert domy.auth.session(token) is None
    assert call(domy, "GET", "/api/auth/me", headers=h_admin)[0] == 401
    # Zwykle konto: sesja z hasla dziala jak dotad.
    assert call(domy, "GET", "/api/auth/me", headers=h_zwykle)[0] == 200
    # Przez Authelie z grupa admins: rola administratora.
    me = call(domy, "GET", "/api/auth/me", headers=sso(domy, "admin", "admins"))[2]
    assert me["admin_instancji"] is True
    # Konto w trybie zwyklym (1): sesja z hasla znowu wazna.
    domy.rejestr.ustaw_admin_instancji(uid, True, tylko_sso=False)
    h_admin = {"Cookie": panel_login(port, "admin", HASLO)}
    assert call(domy, "GET", "/api/auth/me", headers=h_admin)[0] == 200


def test_bilet_2FA_konta_tylko_sso_nie_konczy_logowania(tmp_path):
    """Przeglad #56, N-1: bilet 2FA wydany, zanim konto przeszlo w tryb
    tylko-SSO (np. w starym obrazie), nie konczy logowania — 403 jak przy
    hasle, kod zapasowy NIE zostaje zuzyty, bilet przepada. Zwykle konto
    z 2FA konczy logowanie jak dotad."""
    from kidwatch.panel_auth import AuthError  # noqa: PLC0415

    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path, box=box_from_env())
    rejestr = dm.RejestrDomow(path)
    kody = {}
    for login in ("konto-admin", "konto-zwykle"):
        auth.add_user(login, HASLO, dom_id=None)
        s = auth.login(login, HASLO).session
        sekret = auth.totp_setup(s)["secret"]
        kody[login] = auth.totp_confirm(s, pyotp.TOTP(sekret).now())
    bilet_admin = auth.login("konto-admin", HASLO).challenge
    bilet_zwykly = auth.login("konto-zwykle", HASLO).challenge
    uid = auth.user_id("konto-admin")
    rejestr.ustaw_admin_instancji(uid, True, tylko_sso=True)

    def wolne(login: str) -> int:
        with sqlite3.connect(path) as conn:
            return conn.execute(
                "SELECT COUNT(*) FROM backup_codes b JOIN users u ON u.id = b.user_id "
                "WHERE u.login = ? AND b.used_at IS NULL", (login,)).fetchone()[0]

    przed = wolne("konto-admin")
    with pytest.raises(AuthError) as e:
        auth.mfa(bilet_admin, kody["konto-admin"][0])
    assert e.value.status == 403 and "Authelię" in e.value.message
    assert wolne("konto-admin") == przed  # kod zapasowy nietkniety
    with pytest.raises(AuthError) as e:  # bilet przepadl
        auth.mfa(bilet_admin, kody["konto-admin"][1])
    assert e.value.status == 401
    assert wolne("konto-admin") == przed
    # Kontrola: zwykle konto konczy logowanie kodem zapasowym.
    _, sesja = auth.mfa(bilet_zwykly, kody["konto-zwykle"][0])
    assert sesja.login == "konto-zwykle"
