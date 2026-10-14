# ruff: noqa: F811 — fixtura kek importowana z test_domy_e2
"""Kidwatch <-> kidwatch-mdm per dom (E3b, §4.3, §4.4 p. 4 i 8): panel i czujka.

PRAWDZIWY serwer MDM z dwoma domami: iPad A w Domu 1 (config.yaml, token
instancji — jak przed E3b), iPad B w Domu 2 (konfiguracja w bazie, wlasny
token domu z sejfu). Kazda bariera sprawdzana osobno:

  * panel: UDID spoza domu = 404, zanim panel zawola serwer (przy wylaczonym
    filtrze serwera — mutacja);
  * serwer: test_mdm_domy.py;
  * kanarek: obie bariery wylaczone — komenda przechodzi, test to widzi.

Dane generyczne: etykiety `dziecko1`, UDID-y z zerami, tokeny z secrets.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime

import pytest

from kidwatch import domy as dm
from kidwatch import mdm as mdm_mod
from kidwatch.config import MdmConfig
from kidwatch.konfiguracja_domu import zbuduj_dom
from kidwatch.mdm import (
    ZAKRES_DOM,
    ZAKRES_INSTANCJA,
    ZAKRES_SERWER,
    MdmApi,
    MdmWatcher,
    udid_w_domie,
    zakres_tokenu,
)
from kidwatch.models import NotifyKind
from kidwatch.panel import start_panel
from kidwatch.sejf import Sejf
from kidwatch.store import Store
from kidwatch_mdm import server as mdm_server
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import DevicePolicy, Policy
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.store import Store as MdmStore
from test_domy_e2 import kek  # noqa: F401 — fikstura KIDWATCH_KEK
from test_integracje_panel import (
    HASLO,
    SIEC_DOMU,
    _nowy_sekret,
    _rozwiaz,
    _uruchom_panel,
    sso,
)
from test_mdm_service import TOPIC, FakeIpad, FakePusher
from test_panel_sso import call

UDID_A = "00008030-000000000000000A"  # Dom 1
UDID_B = "00008030-000000000000000B"  # Dom 2
DOM_1, DOM_2 = 1, 2


def _enroll(svc: MDMService, label: str, udid: str, dom_id: int = DOM_1) -> None:
    token = svc.create_enrollment(label, dom_id)["token"]
    ipad = FakeIpad(svc.enrollment_profile(token).body, udid)
    svc.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC))
    svc.checkin(*ipad.msg(MessageType="TokenUpdate", Topic=TOPIC, Token=b"\x01", PushMagic="M"))


@pytest.fixture
def mdm2(tmp_path):
    """Serwer MDM: iPad A w Domu 1, iPad B w Domu 2, token Domu 2."""
    instancja = secrets.token_urlsafe(32)
    svc = MDMService(
        store=MdmStore(tmp_path / "mdm.db"),
        ca=CA.create(tmp_path / "ca", org="RenaCode"),
        policy=Policy(devices={"dziecko1": DevicePolicy(name="iPad Domu 1"),
                               "2/dziecko1": DevicePolicy(name="iPad Domu 2")}),
        public_url="https://mdm.example.com",
        pusher=FakePusher(),
    )
    _enroll(svc, "dziecko1", UDID_A)
    _enroll(svc, "dziecko1", UDID_B, DOM_2)
    _, token_2 = svc.store.create_home_token(DOM_2)
    admin = mdm_server.start(mdm_server.make_admin_handler(svc, instancja), 0, "127.0.0.1")
    yield svc, f"http://127.0.0.1:{admin.server_port}", instancja, token_2
    admin.shutdown()


@pytest.fixture
def panel2(tmp_path, monkeypatch, kek, mdm2):
    """Panel: Dom 1 z config.yaml (MDM_ADMIN_TOKEN = token instancji), Dom 2
    z bazy z integracja MDM (token Domu 2) i iPadem B w `urzadzenia`."""
    svc, url, instancja, token_2 = mdm2
    monkeypatch.setenv("MDM_ADMIN_TOKEN", instancja)
    cfg, auth, rejestr = _uruchom_panel(tmp_path, monkeypatch, None)
    cfg.mdm = MdmConfig(enabled=True, url=url)
    assert rejestr.dodaj_dom("Dom 2") == DOM_2
    # iPad z UDID musi miec tez adres (walidator odczytu wprost) — w sieci domu.
    rejestr.ustaw_sieci(DOM_2, sieci=[SIEC_DOMU])
    with rejestr._conn() as conn:
        cur = conn.execute("INSERT INTO dzieci (dom_id, nazwa) VALUES (?, 'Dziecko A')",
                           (DOM_2,))
        conn.execute(
            "INSERT INTO urzadzenia (dom_id, dziecko_id, rodzaj, nazwa, source_ids, udid, "
            "host, mdm) VALUES (?, ?, 'ipad', 'iPad A', '[\"ipad-a\"]', ?, '192.0.2.10', 1)",
            (DOM_2, cur.lastrowid, UDID_B))
    sejf = Sejf(kek)
    rejestr.zapisz_integracje(DOM_2, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": "abc999"},
                              sekrety={"api_key": _nowy_sekret("K")}, resolver=_rozwiaz)
    rejestr.zapisz_integracje(DOM_2, "mdm", sejf=sejf, wlaczona=True, ustawienia={},
                              sekrety={"token": token_2}, resolver=_rozwiaz)
    auth.add_user("rodzic-1", HASLO)  # wlasciciel Domu 1
    auth.add_user("rodzic-2", HASLO, "wlasciciel-domu", dom_id=DOM_2)
    srv = start_panel(cfg, konfiguracja_domu=lambda dom: zbuduj_dom(
        rejestr, dom.id, sejf, materializuj=False) if dom.id == DOM_2 else None)
    srv.svc, srv.rejestr, srv.sejf = svc, rejestr, sejf
    yield srv
    srv.shutdown()


def _komenda(srv, dom: int, login: str, udid: str):
    st, _, body = call(srv, "POST", f"/api/domy/{dom}/mdm/command",
                       {"udid": udid, "request_type": "DeviceLock"}, headers=sso(srv, login))
    wyslane = [r for r in srv.svc.store.commands_for(udid) if r["origin"] == "api"]
    return st, body, wyslane


# ======================================================= panel, obie bariery
def test_panel_kazdy_dom_tylko_swoje(panel2):
    srv = panel2
    st, body = call(srv, "GET", f"/api/domy/{DOM_1}/mdm", headers=sso(srv, "rodzic-1"))[::2]
    assert st == 200 and [d["udid"] for d in body["devices"]] == [UDID_A]
    assert body["health"]["devices"] == 1
    assert all(e.get("udid") != UDID_B for e in body["events"])
    st, body = call(srv, "GET", f"/api/domy/{DOM_2}/mdm", headers=sso(srv, "rodzic-2"))[::2]
    assert st == 200 and [d["udid"] for d in body["devices"]] == [UDID_B], body
    assert all(e.get("udid") != UDID_A for e in body["events"])
    for dom, login, obcy in ((DOM_1, "rodzic-1", UDID_B), (DOM_2, "rodzic-2", UDID_A)):
        st, _, _ = call(srv, "GET", f"/api/domy/{dom}/mdm/devices/{obcy}",
                        headers=sso(srv, login))
        assert st == 404


@pytest.mark.parametrize(("dom", "login", "obcy"),
                         [(DOM_1, "rodzic-1", UDID_B), (DOM_2, "rodzic-2", UDID_A)])
def test_komenda_na_obcy_udid_404(panel2, dom, login, obcy):
    """§4.4 p. 4: komenda na UDID z innego domu = 404 w panelu."""
    st, _, wyslane = _komenda(panel2, dom, login, obcy)
    assert st == 404 and wyslane == []
    st, _, _ = call(panel2, "POST", f"/api/domy/{dom}/mdm/refresh", {"udid": obcy},
                    headers=sso(panel2, login))
    assert st == 404


def test_dom_1_nie_jest_odciety(panel2):
    """iPad Domu 1 bez `udid` w config.yaml (zapisany przed domami) — Dom 1
    dalej steruje nim tokenem instancji; Dom 2 swoim iPadem tokenem domu."""
    st, body, wyslane = _komenda(panel2, DOM_1, "rodzic-1", UDID_A)
    assert st == 200 and len(wyslane) == 1, body
    st, body, wyslane = _komenda(panel2, DOM_2, "rodzic-2", UDID_B)
    assert st == 200 and len(wyslane) == 1, body


# ======================================================= bariera panelu sama
def _bez_filtra_serwera(monkeypatch):
    monkeypatch.setattr(MdmStore, "device_in", lambda self, udid, dom_id: self.device(udid))


def test_bariera_panelu_dziala_bez_filtra_serwera(panel2, monkeypatch):
    """Bariera panelu sama: filtr serwera wylaczony (mutacja), a komenda Domu 2
    na iPada Domu 1 i tak konczy sie 404 bez wywolania serwera."""
    _bez_filtra_serwera(monkeypatch)
    st, _, wyslane = _komenda(panel2, DOM_2, "rodzic-2", UDID_A)
    assert st == 404 and wyslane == []


def test_kanarek_obie_bariery_wylaczone(panel2, monkeypatch):
    """§4.4 p. 8: bez obu barier ta sama komenda PRZECHODZI — test wyzej
    rozroznia te stany, wiec jego 404 cos dowodzi."""
    _bez_filtra_serwera(monkeypatch)
    monkeypatch.setattr("kidwatch.panel.udid_w_domie", lambda *a, **k: True)
    monkeypatch.setattr("kidwatch.panel.urzadzenie_domu", lambda *a: True)
    st, _, wyslane = _komenda(panel2, DOM_2, "rodzic-2", UDID_A)
    assert st == 200 and len(wyslane) == 1


def test_token_instancji_w_domie_2_nie_daje_mdm(panel2, monkeypatch):
    """Dom 2 z tokenem instancji widzialby iPady Domu 1 — panel wylacza mu MDM."""
    srv = panel2
    srv.rejestr.zapisz_integracje(DOM_2, "mdm", sejf=srv.sejf, wlaczona=True, ustawienia={},
                                  sekrety={"token": mdm_mod.token_instancji()},
                                  resolver=_rozwiaz)
    srv.domy_panelu.zapomnij(DOM_2)
    st, _, body = call(srv, "GET", f"/api/domy/{DOM_2}/mdm", headers=sso(srv, "rodzic-2"))
    assert st == 200 and body["available"] is False
    st, _, wyslane = _komenda(srv, DOM_2, "rodzic-2", UDID_A)
    assert st == 404 and wyslane == []


# ================================================================ jednostkowe
def test_udid_w_domie(monkeypatch):
    class Home:
        devices = [type("D", (), {"udid": "00008030-00000000000000CC"})()]

    wlasciciele = {UDID_B: DOM_2}
    dom_udidu = wlasciciele.get
    assert udid_w_domie(UDID_B, DOM_2, None, dom_udidu)
    assert not udid_w_domie(UDID_B, DOM_1, None, dom_udidu)
    # Niczyj UDID: Dom 1 tak (zgodnosc), inny dom tylko z konfiguracji.
    assert udid_w_domie(UDID_A, DOM_1, None, dom_udidu)
    assert not udid_w_domie(UDID_A, DOM_2, None, dom_udidu)
    assert udid_w_domie("00008030-00000000000000cc", DOM_2, Home(), dom_udidu)


def test_zakres_tokenu(monkeypatch):
    inst = secrets.token_urlsafe(32)
    monkeypatch.setenv("MDM_ADMIN_TOKEN", inst)
    assert zakres_tokenu(DOM_1, inst) == ZAKRES_INSTANCJA
    assert zakres_tokenu(DOM_2, inst) is None
    assert zakres_tokenu(DOM_2, "inny-" + inst) == ZAKRES_DOM
    assert zakres_tokenu(DOM_1, "inny-" + inst) == ZAKRES_DOM
    assert zakres_tokenu(DOM_1, None) is None


# ============================================================ czujka per dom
def test_czujka_domu_i_czujka_instancji(mdm2, tmp_path):
    """Token domu: zdarzenia i cisza tylko jego iPadow, bez alarmow serwera.
    Czujka instancji: alarmy serwera i zdarzenia bez domu, bez zdarzen domow."""
    svc, url, instancja, token_2 = mdm2
    cfg = MdmConfig(enabled=True, url=url, reconcile_alert_minutes=10)
    s2, si = Store(tmp_path / "d2.db"), Store(tmp_path / "inst.db")
    try:
        dom2 = MdmWatcher(MdmApi(cfg, token_2), s2, cfg, ZAKRES_DOM)
        serwer = MdmWatcher(MdmApi(cfg, instancja), si, cfg, ZAKRES_SERWER)
        now = datetime.now(UTC)
        assert dom2.poll(now) == [] and serwer.poll(now) == []
        svc.store.event("checkout", UDID_A)
        svc.store.event("checkout", UDID_B)
        svc.store.event("unknown_identity", "00008030-00000000000000EE", {"fingerprint": "x"})
        svc.store.set_setting("last_reconcile_ok_at", "2000-01-01T00:00:00+00:00")
        n2 = dom2.poll(now)
        assert [n.title for n in n2] == ["iPad Domu 2: profil MDM zdjety"]
        ns = serwer.poll(now)
        assert all("iPad Domu" not in n.title for n in ns), [n.title for n in ns]
        assert any("uzgadnianie" in n.title for n in ns)
        assert any(n.kind == NotifyKind.MDM and "podszycia" in n.title for n in ns)
    finally:
        s2.close()
        si.close()


async def test_czujka_instancji_nieaktywna_przy_tokenie_instancji(mdm2, tmp_path):
    """Do wydania tokenu Domu 1 alarmy serwera daje czujka Domu 1 (jak przed
    E3b); czujka instancji nie dubluje ich."""
    from kidwatch.mdm import AlarmyInstancji, mdm_loop

    svc, url, instancja, _ = mdm2
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(tmp_path / "inst.db")
    alarmy = []

    async def alarm(t, x):
        alarmy.append(t)

    wolania = []
    w = MdmWatcher(MdmApi(cfg, instancja), store, cfg, ZAKRES_SERWER)
    oryginal = w.poll_async

    async def poll_async(now):
        wolania.append(now)
        return await oryginal(now)

    w.poll_async = poll_async
    await mdm_loop(w, AlarmyInstancji(alarm), 0, max_iterations=2, aktywny=lambda: False)
    assert wolania == []
    await mdm_loop(w, AlarmyInstancji(alarm), 0, max_iterations=1, aktywny=lambda: True)
    assert len(wolania) == 1
    store.close()


def test_dom_udidu(panel2):
    assert panel2.rejestr.dom_udidu(UDID_B.lower()) == DOM_2
    assert panel2.rejestr.dom_udidu(UDID_A) is None
    assert dm.DOM_1 == DOM_1


# ============================================================ poprawki z przegladu
UDID_C = "00008030-000000000000000C"  # Dom 2, ale jeszcze NIE w `urzadzenia`


def test_dom_1_nie_siega_ipada_innego_domu_spoza_urzadzen(panel2):
    """Wyjatek Domu 1 (UDID niczyj w `urzadzenia`) nie otwiera iPada, ktory
    serwer zapisal do innego domu: panel sprawdza `dom_id` z serwera."""
    srv = panel2
    _enroll(srv.svc, "dziecko2", UDID_C, DOM_2)
    st, _, _ = call(srv, "GET", f"/api/domy/{DOM_1}/mdm/devices/{UDID_C}",
                    headers=sso(srv, "rodzic-1"))
    assert st == 404
    st, _, wyslane = _komenda(srv, DOM_1, "rodzic-1", UDID_C)
    assert st == 404 and wyslane == []
    st, _, body = call(srv, "GET", f"/api/domy/{DOM_1}/mdm", headers=sso(srv, "rodzic-1"))
    assert UDID_C not in {d["udid"] for d in body["devices"]}
    # Druga strona: Dom 2 tez nie steruje nim, dopoki nie wpisze go do urzadzen.
    st, _, wyslane = _komenda(srv, DOM_2, "rodzic-2", UDID_C)
    assert st == 404 and wyslane == []


def test_kanarek_bez_sprawdzenia_domu_z_serwera(panel2, monkeypatch):
    srv = panel2
    _enroll(srv.svc, "dziecko2", UDID_C, DOM_2)
    monkeypatch.setattr("kidwatch.panel.urzadzenie_domu", lambda *a: True)
    st, _, wyslane = _komenda(srv, DOM_1, "rodzic-1", UDID_C)
    assert st == 200 and len(wyslane) == 1


def test_filtr_wierszy_po_dom_id(panel2):
    """Dom 1 z tokenem instancji widzi caly dziennik serwera — wiersze innych
    domow bez UDID (np. zaproszenie Domu 2) odcina filtr `dom_id` panelu."""
    srv = panel2
    serwer = srv.svc.store.last_events(50)
    assert any(e["dom_id"] == DOM_2 and e["udid"] is None for e in serwer)
    st, _, body = call(srv, "GET", f"/api/domy/{DOM_1}/mdm", headers=sso(srv, "rodzic-1"))
    assert st == 200 and all(e.get("dom_id") in (None, DOM_1) for e in body["events"])


def test_dom_2_z_tokenem_instancji_bez_env(panel2, monkeypatch):
    """MDM_ADMIN_TOKEN nieustawiony: porownanie nic nie wie, rozstrzyga serwer."""
    srv = panel2
    inst = mdm_mod.token_instancji()
    srv.rejestr.zapisz_integracje(DOM_2, "mdm", sejf=srv.sejf, wlaczona=True, ustawienia={},
                                  sekrety={"token": inst}, resolver=_rozwiaz)
    monkeypatch.delenv("MDM_ADMIN_TOKEN")
    srv.domy_panelu.zapomnij(DOM_2)
    st, _, body = call(srv, "GET", f"/api/domy/{DOM_2}/mdm", headers=sso(srv, "rodzic-2"))
    assert st == 200 and body["available"] is False


def test_zakres_czujki_z_serwera(mdm2, tmp_path, monkeypatch):
    """Bez MDM_ADMIN_TOKEN Dom 1 z tokenem instancji to zakres instancji wg
    serwera — alarmy serwera nie gina. Dom 2 z tokenem instancji albo Dom 1
    z tokenem Domu 2 — odmowa (403), zero danych."""
    svc, url, instancja, token_2 = mdm2
    monkeypatch.delenv("MDM_ADMIN_TOKEN", raising=False)
    mdm_mod.ZAKRESY_CZUJEK.clear()
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(tmp_path / "k.db")
    try:
        assert zakres_tokenu(DOM_1, instancja) == ZAKRES_DOM  # samo przypuszczenie
        w = MdmWatcher(MdmApi(cfg, instancja), store, cfg, ZAKRES_DOM, dom_id=DOM_1)
        w.poll(datetime.now(UTC))
        assert w.zakres == ZAKRES_INSTANCJA
        assert mdm_mod.ZAKRESY_CZUJEK == {DOM_1: ZAKRES_INSTANCJA}
        assert not mdm_mod.czujka_instancji_potrzebna()
        for dom, token in ((DOM_2, instancja), (DOM_1, token_2)):
            obcy = MdmWatcher(MdmApi(cfg, token), store, cfg, ZAKRES_DOM, dom_id=dom)
            with pytest.raises(mdm_mod.MdmError) as exc:
                obcy.poll(datetime.now(UTC))
            assert exc.value.status == 403
        w2 = MdmWatcher(MdmApi(cfg, token_2), Store(tmp_path / "d2.db"), cfg, ZAKRES_DOM,
                        dom_id=DOM_2)
        w2.poll(datetime.now(UTC))
        mdm_mod.ZAKRESY_CZUJEK.pop(DOM_1)
        assert mdm_mod.czujka_instancji_potrzebna()
    finally:
        mdm_mod.ZAKRESY_CZUJEK.clear()
        store.close()


def test_serwer_bez_whoami_zostaje_przy_przypuszczeniu(mdm2, tmp_path, monkeypatch):
    svc, url, instancja, _ = mdm2
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(tmp_path / "k.db")
    oryginal = MdmApi.request

    def bez_whoami(self, method, path, body=None):
        if path == "/api/whoami":
            raise mdm_mod.MdmError(404, "nie ma takiego zasobu")
        return oryginal(self, method, path, body)

    monkeypatch.setattr(MdmApi, "request", bez_whoami)
    try:
        w = MdmWatcher(MdmApi(cfg, instancja), store, cfg, ZAKRES_INSTANCJA, dom_id=DOM_1)
        w.poll(datetime.now(UTC))
        assert w.zakres == ZAKRES_INSTANCJA
    finally:
        mdm_mod.ZAKRESY_CZUJEK.clear()
        store.close()


async def test_czujka_instancji_po_przerwie_nie_wysyla_zaleglosci(mdm2, tmp_path):
    from kidwatch.mdm import AlarmyInstancji, mdm_loop

    svc, url, instancja, _ = mdm2
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(tmp_path / "inst.db")
    alarmy = []

    async def alarm(t, x):
        alarmy.append(t)

    w = MdmWatcher(MdmApi(cfg, instancja), store, cfg, ZAKRES_SERWER)
    stan = {"aktywna": True}
    try:
        await mdm_loop(w, AlarmyInstancji(alarm), 0, max_iterations=1,
                       aktywny=lambda: stan["aktywna"])
        # Przerwa (dom trzymal token instancji), w tym czasie zdarzenie serwera.
        svc.store.event("unknown_identity", "00008030-00000000000000EE", {"fingerprint": "x"})
        await mdm_loop(w, AlarmyInstancji(alarm), 0, max_iterations=1, aktywny=lambda: False)
        await mdm_loop(w, AlarmyInstancji(alarm), 0, max_iterations=1, aktywny=lambda: True)
        assert alarmy == []
        # Nowe zdarzenie PO wznowieniu — juz alarm.
        svc.store.event("unknown_identity", "00008030-00000000000000EF", {"fingerprint": "y"})
        await mdm_loop(w, AlarmyInstancji(alarm), 0, max_iterations=1, aktywny=lambda: True)
        assert alarmy == ["MDM: odrzucona proba podszycia"]
    finally:
        store.close()


def test_blad_whoami_inny_niz_404_nie_ustala_zakresu(mdm2, tmp_path, monkeypatch):
    """503/500 z /api/whoami: obieg przerwany, zakres NIEustalony (ponowienie
    w nastepnym obiegu) — nie przejscie na porownanie z MDM_ADMIN_TOKEN."""
    svc, url, instancja, token_2 = mdm2
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(tmp_path / "k.db")
    oryginal = MdmApi.request
    stan = {"blad": True}

    def chwilowo_nie(self, method, path, body=None):
        if path == "/api/whoami" and stan["blad"]:
            raise mdm_mod.MdmError(503, "serwer MDM nieosiagalny")
        return oryginal(self, method, path, body)

    monkeypatch.setattr(MdmApi, "request", chwilowo_nie)
    mdm_mod.ZAKRESY_CZUJEK.clear()
    try:
        # Przypuszczenie z env (instancja) dla tokenu Domu 2 — serwer by je obalil.
        w = MdmWatcher(MdmApi(cfg, token_2), store, cfg, ZAKRES_INSTANCJA, dom_id=DOM_1)
        with pytest.raises(mdm_mod.MdmError) as exc:
            w.poll(datetime.now(UTC))
        assert exc.value.status == 503
        assert mdm_mod.ZAKRESY_CZUJEK == {} and store.get_meta(mdm_mod.CURSOR_KEY) is None
        stan["blad"] = False
        with pytest.raises(mdm_mod.MdmError) as exc:
            w.poll(datetime.now(UTC))
        assert exc.value.status == 403  # nastepny obieg pyta serwer od nowa
    finally:
        mdm_mod.ZAKRESY_CZUJEK.clear()
        store.close()


def test_panel_ponawia_whoami_po_bledzie(panel2, monkeypatch):
    """Nieudane /api/whoami domu != 1: brak MDM w tym zadaniu, ale nastepne
    zadanie pyta znowu (bez czekania na przeladowanie konfiguracji)."""
    srv = panel2
    oryginal = MdmApi.request
    stan = {"blad": True}

    def chwilowo_nie(self, method, path, body=None):
        if path == "/api/whoami" and stan["blad"]:
            raise mdm_mod.MdmError(503, "serwer MDM nieosiagalny")
        return oryginal(self, method, path, body)

    monkeypatch.setattr(MdmApi, "request", chwilowo_nie)
    srv.domy_panelu.zapomnij(DOM_2)
    url = f"/api/domy/{DOM_2}/mdm"
    st, _, body = call(srv, "GET", url, headers=sso(srv, "rodzic-2"))
    assert st == 200 and body["available"] is False
    stan["blad"] = False
    st, _, body = call(srv, "GET", url, headers=sso(srv, "rodzic-2"))
    assert st == 200 and body["available"] is True
    assert [d["udid"] for d in body["devices"]] == [UDID_B]
