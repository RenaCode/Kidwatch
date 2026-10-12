# ruff: noqa: F811 — fixtura kek importowana z test_domy_e2
"""Ekran integracji domu: API panelu i przeladowanie domu (decyzja 2026-10-12).

Sekrety i ustawienia integracji wpisuje przez panel administrator
instalacji. Testy pilnuja:
  * wartosc sekretu NIGDZIE nie wraca — odpowiedzi, log, audyt, plik bazy;
    detektor najpierw musi zlapac celowo wstawiony przeciek (kanarek),
    inaczej jego cisza niczego by nie dowodzila;
  * odmowe dla kont bez roli administratora (403 czlonek, 404 obcy dom),
    dla domu w trybie `yaml` (409) i dla adresu spoza sieci domu (SSRF);
  * pusty sekret = bez zmian, usuniecie osobna akcja;
  * zmiane, po ktorej dzialajacy dom by nie wystartowal — wycofana;
  * przeladowanie domu przez nadzorce po zmianie `domy.wersja` (albo
    komunikat o restarcie, gdy przeladowania nie ma).

Dane generyczne: dokumentacyjne adresy RFC 5737, sekrety z secrets.token_*.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import sqlite3

import pytest

from kidwatch import domy as dm
from kidwatch import straznik
from kidwatch.__main__ import przeladowanie_domow
from kidwatch.config import (
    Config,
    DeviceConfig,
    EngineConfig,
    MissingSecretError,
    NextDnsConfig,
    PanelConfig,
    SourceConfig,
    StoreConfig,
)
from kidwatch.panel import start_panel
from kidwatch.panel_auth import PanelAuth, box_from_env
from kidwatch.panel_integracje import bez_sekretow, pola_ustawien
from kidwatch.sejf import Sejf
from test_domy_e2 import _dziecko_z_urzadzeniem, kek  # noqa: F401 — fikstura KIDWATCH_KEK
from test_panel_sso import call, cookie, jar

HASLO = "haslo-testowe-123"
DOM_1, DOM_B = 1, 2
SIEC_DOMU = "192.0.2.0/28"
UNIFI_W_SIECI = "https://192.0.2.5"
UNIFI_POZA_SIECIA = "https://192.0.2.200"
ODCISK = "ab" * 32
PUBLICZNY = "9.9.9.9"


def _rozwiaz(host: str, port: int) -> list[str]:
    """Bez prawdziwego DNS: hosty API publiczne, literal IP bez zmian."""
    adres = straznik.adres_literalny(host)
    return [str(adres)] if adres is not None else [PUBLICZNY]


def _config(tmp_path) -> Config:
    mapa = tmp_path / "app_map.yaml"
    mapa.write_text("noise: []\napps: {}\n", encoding="utf-8")
    return Config(
        timezone="Europe/Warsaw",
        source=SourceConfig(kind="nextdns", nextdns=NextDnsConfig(profile_id="profil")),
        devices=[DeviceConfig(display_name="iPad Dziecka 1", child="Dziecko 1",
                              source_ids=["ipad-1"])],
        engine=EngineConfig(confirm_moments=1),
        panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path / "web")),
        store=StoreConfig(path=str(tmp_path / "kidwatch.db")),
        app_map_path=str(mapa),
    )


def _nowy_sekret(prefiks: str) -> str:
    return f"{prefiks}-{secrets.token_urlsafe(24)}"


def _uruchom_panel(tmp_path, monkeypatch, stany):
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    monkeypatch.setattr(straznik, "rozwiaz_systemowo", _rozwiaz)
    (tmp_path / "web").mkdir(exist_ok=True)
    cfg = _config(tmp_path)
    auth = PanelAuth(cfg.panel_auth_path, box=box_from_env())
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj()
    return cfg, auth, rejestr


@pytest.fixture
def inst(tmp_path, monkeypatch, kek):
    """Dom 1 (config.yaml) i Dom B z konfiguracja w bazie, dzialajaca: NextDNS
    z kluczem-kanarkiem i UniFi w sieci domu. Konta: `admin` (bez domow,
    flaga administratora), `wlasciciel-b` (wlasciciel-domu w B — ma
    `dom.integracje`, ale nie role administratora), `podglad-b`, `obcy`
    (tylko Dom 1)."""
    stany = dm.StanyDomow()
    cfg, auth, rejestr = _uruchom_panel(tmp_path, monkeypatch, stany)
    assert rejestr.dodaj_dom("Dom B") == DOM_B
    rejestr.ustaw_sieci(DOM_B, sieci=[SIEC_DOMU])
    _dziecko_z_urzadzeniem(rejestr, DOM_B, "phone-android")
    sejf = Sejf(kek)
    klucz_nextdns = _nowy_sekret("NEXTDNS")
    klucz_unifi = _nowy_sekret("UNIFI")
    rejestr.zapisz_integracje(DOM_B, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": "abc999"},
                              sekrety={"api_key": klucz_nextdns}, resolver=_rozwiaz)
    rejestr.zapisz_integracje(DOM_B, "unifi", sejf=sejf, wlaczona=True,
                              ustawienia={"url": UNIFI_W_SIECI, "cert_sha256": ODCISK},
                              sekrety={"api_key": klucz_unifi}, resolver=_rozwiaz)
    auth.add_user("admin", HASLO, dom_id=None)
    rejestr.ustaw_admin_instancji(auth.user_id("admin"), True)
    auth.add_user("wlasciciel-b", HASLO, "wlasciciel-domu", dom_id=DOM_B)
    auth.add_user("podglad-b", HASLO, "podglad", dom_id=DOM_B)
    auth.add_user("obcy", HASLO)
    stany.ustaw(DOM_B, dm.StanDomu(rejestr.dom(DOM_B).wersja))
    srv = start_panel(cfg, stany=stany)
    srv.cfg, srv.auth, srv.rejestr, srv.sejf, srv.stany = cfg, auth, rejestr, sejf, stany
    srv.kanarki = {"nextdns": klucz_nextdns, "unifi": klucz_unifi}
    yield srv
    srv.shutdown()


def sso(srv, login: str, grupy: str = "wlasciciel") -> dict[str, str]:
    h = {"Remote-User": login, "Remote-Groups": grupy}
    status, headers, me = call(srv, "GET", "/api/auth/me", headers=h)
    assert status == 200, me
    j = jar(headers)
    return {**h, "Cookie": cookie(j), "X-CSRF-Token": j["kidwatch_csrf"]}


def admin(srv) -> dict[str, str]:
    return sso(srv, "admin", "admins")


URL = f"/api/domy/{DOM_B}/integracje"


def _zapisz(srv, h, body, confirm=HASLO):
    return call(srv, "POST", f"{URL}/zapisz", {**body, "confirm": confirm}, headers=h)


# ============================================================ detektor
class Slady:
    """Wszystko, co wyszlo poza sejf: odpowiedzi HTTP, log, dziennik `audyt`
    i surowy plik bazy panelu."""

    def __init__(self, srv, caplog) -> None:
        self.srv, self.caplog = srv, caplog
        self.odpowiedzi: list[str] = []

    def zapisz(self, wynik):
        status, _, body = wynik
        self.odpowiedzi.append(body.decode("utf-8", "replace") if isinstance(body, bytes)
                               else repr(body))
        return wynik

    def przecieki(self, *sekrety: str) -> list[str]:
        with sqlite3.connect(self.srv.cfg.panel_auth_path) as conn:
            audyt = "\n".join(" ".join(map(str, r)) for r in conn.execute("SELECT * FROM audyt"))
            zrzut = "\n".join(conn.iterdump())
        surowy = open(self.srv.cfg.panel_auth_path, "rb").read()  # noqa: SIM115
        zle = []
        for s in sekrety:
            for nazwa, tekst in (("odpowiedz", "\n".join(self.odpowiedzi)),
                                 ("log", self.caplog.text), ("audyt", audyt),
                                 ("baza (zrzut)", zrzut)):
                if s in tekst:
                    zle.append(f"{nazwa}: {s[:8]}…")
            if s.encode() in surowy:
                zle.append(f"baza (plik): {s[:8]}…")
        return zle


def test_detektor_lapie_celowy_przeciek(inst, caplog):
    """Kanarek: sekret wstawiony celowo w kazde miejsce MUSI byc znaleziony."""
    caplog.set_level(logging.DEBUG)
    s = Slady(inst, caplog)
    sekret = _nowy_sekret("PRZECIEK")
    assert s.przecieki(sekret) == []
    s.odpowiedzi.append(f'{{"error": "{sekret}"}}')
    logging.getLogger("kidwatch.panel").warning("x %s", sekret)
    inst.rejestr.zapisz_audyt(DOM_B, "admin", "test", f"opis {sekret}")
    znalezione = s.przecieki(sekret)
    assert {z.split(":")[0] for z in znalezione} >= {"odpowiedz", "log", "audyt",
                                                     "baza (zrzut)", "baza (plik)"}


def test_bez_sekretow_wycina_wartosci_z_komunikatu():
    assert bez_sekretow("blad: klucz-abcdef i dalej", ["klucz-abcdef"]) == "blad: *** i dalej"
    # Krotkie wartosci zostaja (wycinanie psuloby zwykle slowa).
    assert bez_sekretow("tak", ["ta"]) == "tak"


def test_sekret_nigdzie_nie_wraca(inst, caplog):
    caplog.set_level(logging.DEBUG)
    s = Slady(inst, caplog)
    h = admin(inst)
    nowy_unifi = _nowy_sekret("NOWY-UNIFI")
    odrzucony = _nowy_sekret("ODRZUCONY")
    zly_haslo = _nowy_sekret("ZLE-POTW")

    status, _, lista = s.zapisz(call(inst, "GET", URL, headers=h))
    assert status == 200, lista
    unifi = next(i for i in lista["integracje"] if i["typ"] == "unifi")
    api_key = next(x for x in unifi["sekrety"] if x["pole"] == "api_key")
    assert api_key["ustawiony"] and api_key["maska"] == "…" + inst.kanarki["unifi"][-4:]

    # Zapis nowego klucza.
    status, _, body = s.zapisz(_zapisz(inst, h, {
        "typ": "unifi", "wlaczona": True,
        "ustawienia": {"url": UNIFI_W_SIECI, "cert_sha256": ODCISK, "site": "inna"},
        "sekrety": {"api_key": nowy_unifi}}))
    assert status == 200, body
    # Kontrola pozytywna: zapis naprawde doszedl do sejfu.
    assert inst.rejestr.sekrety_domu(DOM_B, inst.sejf).get("unifi", "api_key") == nowy_unifi
    # Odmowa straznika z sekretem w ciele.
    status, _, body = s.zapisz(_zapisz(inst, h, {
        "typ": "unifi", "ustawienia": {"url": UNIFI_POZA_SIECIA, "cert_sha256": ODCISK},
        "sekrety": {"api_key": odrzucony}}))
    assert status == 400, body
    # Blad walidacji modelu z sekretem w ciele.
    status, _, body = s.zapisz(_zapisz(inst, h, {
        "typ": "unifi", "ustawienia": {"url": UNIFI_W_SIECI, "cert_sha256": "nie-odcisk"},
        "sekrety": {"api_key": odrzucony}}))
    assert status == 400, body
    # Sekret wpisany w ustawienia (pomylka pola) — nazwa w bledzie, wartosc nie.
    status, _, body = s.zapisz(_zapisz(inst, h, {
        "typ": "unifi", "ustawienia": {"url": UNIFI_W_SIECI, "api_key": odrzucony}}))
    assert status == 400 and "api_key" in body["error"], body
    # Zle potwierdzenie.
    status, _, body = s.zapisz(_zapisz(inst, h, {
        "typ": "unifi", "sekrety": {"api_key": zly_haslo}}, confirm="zle-haslo"))
    assert status == 403, body
    # Usuniecie i odczyt po wszystkim.
    s.zapisz(call(inst, "POST", f"{URL}/usun-sekret",
                  {"typ": "unifi", "pole": "api_key", "confirm": HASLO}, headers=h))
    s.zapisz(call(inst, "GET", URL, headers=h))

    assert s.przecieki(nowy_unifi, odrzucony, zly_haslo, inst.kanarki["unifi"],
                       inst.kanarki["nextdns"]) == []
    assert inst.rejestr.sekrety_domu(DOM_B, inst.sejf).get("unifi", "api_key") is None


# ============================================================== dostep
@pytest.mark.parametrize(("login", "grupy", "status"), [
    ("wlasciciel-b", "wlasciciel", 403),   # ma dom.integracje, nie jest administratorem
    ("podglad-b", "wlasciciel", 403),
    ("obcy", "wlasciciel", 404),           # cudzy dom wyglada jak brak domu
    ("admin", "wlasciciel", 404),          # flaga bez grupy `admins` nic nie otwiera
])
def test_odmowa_bez_roli_administratora(inst, login, grupy, status):
    h = sso(inst, login, grupy)
    wersja = inst.rejestr.dom(DOM_B).wersja
    st, _, body = call(inst, "GET", URL, headers=h)
    assert st == status, body
    assert "maska" not in repr(body)
    st, _, body = _zapisz(inst, h, {"typ": "unifi", "wlaczona": False})
    assert st == status, body
    st, _, body = call(inst, "POST", f"{URL}/usun-sekret",
                       {"typ": "unifi", "pole": "api_key", "confirm": HASLO}, headers=h)
    assert st == status, body
    assert inst.rejestr.dom(DOM_B).wersja == wersja
    assert inst.rejestr.integracja(DOM_B, "unifi").wlaczona


def test_bez_csrf_odmowa(inst):
    h = admin(inst)
    del h["X-CSRF-Token"]
    st, _, _ = _zapisz(inst, h, {"typ": "unifi", "wlaczona": False})
    assert st == 403
    assert inst.rejestr.integracja(DOM_B, "unifi").wlaczona


def test_dom_yaml_odmowa_z_komunikatem(inst):
    h = admin(inst)
    wersja = inst.rejestr.dom(DOM_1).wersja
    st, _, body = call(inst, "GET", f"/api/domy/{DOM_1}/integracje", headers=h)
    assert st == 409 and "config.yaml" in body["error"], body
    st, _, body = call(inst, "POST", f"/api/domy/{DOM_1}/integracje/zapisz",
                       {"typ": "nextdns", "wlaczona": True, "confirm": HASLO}, headers=h)
    assert st == 409 and "config.yaml" in body["error"], body
    assert inst.rejestr.dom(DOM_1).wersja == wersja
    assert inst.rejestr.integracje(DOM_1) == []


# ================================================================ SSRF
def test_ssrf_adres_poza_siecia_domu_odrzucony(inst):
    h = admin(inst)
    wersja = inst.rejestr.dom(DOM_B).wersja
    st, _, body = _zapisz(inst, h, {
        "typ": "unifi", "ustawienia": {"url": UNIFI_POZA_SIECIA, "cert_sha256": ODCISK}})
    assert st == 400
    assert "poza siecią domu" in body["error"] and "dom-sieci" in body["error"], body
    st, _, body = _zapisz(inst, h, {
        "typ": "nextdns", "ustawienia": {"profile_id": "abc999",
                                         "base_url": "https://nextdns.example.com"}})
    assert st == 400 and "spoza listy dozwolonych" in body["error"], body
    assert inst.rejestr.integracja(DOM_B, "unifi").ustawienia["url"] == UNIFI_W_SIECI
    assert inst.rejestr.dom(DOM_B).wersja == wersja
    # Odmowa zostawia slad w dzienniku domu (bez adresu i wartosci).
    with sqlite3.connect(inst.cfg.panel_auth_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM audyt WHERE akcja = 'integracja.odmowa' "
                            "AND dom_id = ?", (DOM_B,)).fetchone()[0] == 2


# ======================================================= sekrety: zapis
def test_pusty_sekret_bez_zmian(inst):
    h = admin(inst)
    przed = inst.rejestr.integracja(DOM_B, "nextdns").zmienione_at
    for sekrety in ({"api_key": ""}, {"api_key": "   "}, {"api_key": None}, {}):
        st, _, body = _zapisz(inst, h, {"typ": "nextdns", "wlaczona": True,
                                        "ustawienia": {"profile_id": "abc999"},
                                        "sekrety": sekrety})
        assert st == 200, body
        assert inst.rejestr.sekrety_domu(DOM_B, inst.sejf).get("nextdns", "api_key") \
            == inst.kanarki["nextdns"]
    assert inst.rejestr.integracja(DOM_B, "nextdns").zmienione_at > przed


def test_usuniecie_sekretu_osobna_akcja_i_bezpiecznik_startu(inst):
    h = admin(inst)
    # Klucz UniFi nie jest wymagany do startu — usuwa sie.
    st, _, body = call(inst, "POST", f"{URL}/usun-sekret",
                       {"typ": "unifi", "pole": "api_key", "confirm": HASLO}, headers=h)
    assert st == 200, body
    assert not next(x for x in body["integracja"]["sekrety"] if x["pole"] == "api_key")["ustawiony"]
    # Klucz NextDNS (jedyne zrodlo DNS) — dom by nie wystartowal: odmowa, klucz zostaje.
    wersja = inst.rejestr.dom(DOM_B).wersja
    st, _, body = call(inst, "POST", f"{URL}/usun-sekret",
                       {"typ": "nextdns", "pole": "api_key", "confirm": HASLO}, headers=h)
    assert st == 400 and "nie wystartuje" in body["error"], body
    assert inst.rejestr.sekrety_domu(DOM_B, inst.sejf).get("nextdns", "api_key") \
        == inst.kanarki["nextdns"]
    assert inst.rejestr.dom(DOM_B).wersja == wersja


def test_wylaczenie_jedynego_zrodla_dns_wycofane(inst):
    h = admin(inst)
    st, _, body = _zapisz(inst, h, {"typ": "nextdns", "wlaczona": False})
    assert st == 400 and "nie wystartuje" in body["error"], body
    assert inst.rejestr.integracja(DOM_B, "nextdns").wlaczona


def test_zapis_wymaga_potwierdzenia(inst):
    h = admin(inst)
    st, _, body = call(inst, "POST", f"{URL}/zapisz", {"typ": "unifi", "wlaczona": False},
                       headers=h)
    # 403, nie 401: sesja jest wazna, front nie ma wracac do logowania.
    assert st == 403, body
    assert inst.rejestr.integracja(DOM_B, "unifi").wlaczona


def test_audyt_odczytu_i_zapisu_bez_wartosci(inst):
    h = admin(inst)
    call(inst, "GET", URL, headers=h)
    st, _, body = _zapisz(inst, h, {
        "typ": "unifi", "wlaczona": True,
        "ustawienia": {"url": UNIFI_W_SIECI, "cert_sha256": ODCISK, "site": "inna"},
        "sekrety": {"api_key": _nowy_sekret("AUDYT")}})
    assert st == 200, body
    with sqlite3.connect(inst.cfg.panel_auth_path) as conn:
        wpisy = conn.execute("SELECT login, akcja, opis FROM audyt WHERE dom_id = ? "
                             "ORDER BY id", (DOM_B,)).fetchall()
    assert ("admin", "integracje.odczyt",
            "odczyt ustawień integracji (sekrety jako maski)") in wpisy
    zapis = [w for w in wpisy if w[1] == "integracja.zapis" and w[0] == "admin"]
    assert zapis == [("admin", "integracja.zapis", "integracja unifi: wlaczona; "
                      "ustawienia zmienione: site; sekrety zmienione: api_key")]
    # Administrator bez czlonkostwa: kazdy POST takze jako admin.<trasa> (§2.3).
    assert ("admin", "admin.integracje.zapisz", "POST integracje.zapisz") in wpisy


def test_lista_ma_formularz_i_maski(inst):
    st, _, body = call(inst, "GET", URL, headers=admin(inst))
    assert st == 200
    assert [i["typ"] for i in body["integracje"]] == list(dm.TYPY_INTEGRACJI)
    assert body["sieci"] == [SIEC_DOMU]
    assert body["start"] is None
    nextdns = next(i for i in body["integracje"] if i["typ"] == "nextdns")
    assert nextdns["wlaczona"] and nextdns["ustawienia"]["profile_id"] == "abc999"
    pola = {p["pole"]: p for p in nextdns["pola"]}
    assert pola["profile_id"]["wymagane"] and pola["raw"]["rodzaj"] == "bool"
    assert "api_key" not in pola
    tv = {p["pole"]: p for p in pola_ustawien("tv")}
    assert "adb_key_dir" not in tv and "enabled" not in tv
    assert tv["nextdns_ids"]["rodzaj"] == "lista" and tv["apps"]["rodzaj"] == "slownik"
    assert tv["unifi_mac"]["rodzaj"] == "tekst"


def test_brak_kek_to_503(inst, monkeypatch):
    monkeypatch.delenv("KIDWATCH_KEK")
    st, _, body = call(inst, "GET", URL, headers=admin(inst))
    assert st == 503 and "KIDWATCH_KEK" in body["error"]


# ========================================================= przeladowanie
def test_odpowiedz_mowi_o_przeladowaniu(inst):
    h = admin(inst)
    st, _, body = _zapisz(inst, h, {"typ": "unifi", "wlaczona": True,
                                    "ustawienia": {"url": UNIFI_W_SIECI, "cert_sha256": ODCISK,
                                                   "site": "inna"}})
    assert st == 200, body
    p = body["przeladowanie"]
    assert p["automatyczne"] and not p["aktualna"]
    assert p["wersja"] == inst.rejestr.dom(DOM_B).wersja == p["wersja_dzialajaca"] + 1
    # Nadzorca przelaczyl dom — ekran widzi biezaca wersje.
    inst.stany.ustaw(DOM_B, dm.StanDomu(p["wersja"]))
    st, _, body = call(inst, "GET", URL, headers=h)
    assert body["przeladowanie"]["aktualna"]


def test_bez_przeladowania_komunikat_o_restarcie(tmp_path, monkeypatch, kek):
    """Panel bez nadzorcy z przeladowaniem: ekran nie udaje, ze zmiana dziala."""
    cfg, auth, rejestr = _uruchom_panel(tmp_path, monkeypatch, None)
    rejestr.dodaj_dom("Dom B")
    auth.add_user("admin", HASLO, dom_id=None)
    rejestr.ustaw_admin_instancji(auth.user_id("admin"), True)
    srv = start_panel(cfg)
    try:
        st, _, body = call(srv, "POST", f"{URL}/zapisz",
                           {"typ": "ntfy", "wlaczona": False, "ustawienia": {},
                            "confirm": HASLO}, headers=admin(srv))
        assert st == 200, body
        p = body["przeladowanie"]
        assert p == {"automatyczne": False, "wersja": rejestr.dom(DOM_B).wersja,
                     "komunikat": "Kidwatch nie przeładowuje tego domu automatycznie — "
                                  "zmiana zadziała po restarcie Kidwatcha."}
        # Swiezy dom bez zrodla DNS: zapis wolno, ekran mowi, czego brakuje.
        assert "zrodlo DNS" in body["start"]
    finally:
        srv.shutdown()


class Srodowisko:
    """Atrapa HomeRuntime dla nadzorcy: jedna wieczna petla, zapis zdarzen."""

    def __init__(self, dom_id, home, zdarzenia):
        self.dom_id, self.home, self.zdarzenia = dom_id, home, zdarzenia
        self.wersja = None

    def start(self):
        self.zdarzenia.append(f"start {self.home}")
        return [asyncio.create_task(asyncio.sleep(3600), name=f"petla {self.home}")]

    async def zamknij(self, flush_seconds):
        self.zdarzenia.append(f"zamknij {self.home}")


async def _czekaj(warunek, limit=2.0):
    for _ in range(int(limit / 0.01)):
        if warunek():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("warunek nie spelniony")


async def test_nadzorca_przeladowuje_dom_po_zmianie_wersji():
    zdarzenia: list[str] = []
    wersja = {DOM_B: 1}
    konfiguracje = {2: "home-v2", 3: ValueError("nowa konfiguracja zla"), 4: "home-v4"}
    wolania: list[int] = []
    po_zmianie: list[str] = []

    def konfiguracja(dom_id):
        w = wersja[dom_id]
        wolania.append(w)
        wynik = konfiguracje[w]
        if isinstance(wynik, Exception):
            raise wynik
        return wynik

    p = dm.Przeladowanie(
        wersja=lambda dom_id: wersja[dom_id], konfiguracja=konfiguracja,
        runtime=lambda dom_id, home: Srodowisko(dom_id, home, zdarzenia),
        po_zmianie=lambda dom_id, rt: po_zmianie.append(rt.home), okres=0.01)
    nadzorca = dm.Nadzorca([Srodowisko(DOM_B, "home-v1", zdarzenia)], przeladowanie=p)
    stop = asyncio.Event()
    zadanie = asyncio.create_task(nadzorca.run(stop))
    await _czekaj(lambda: p.stany.get(DOM_B) == dm.StanDomu(1))

    # Zmiana w panelu: nowa wersja -> stary dom zamkniety, nowy uruchomiony.
    wersja[DOM_B] = 2
    await _czekaj(lambda: "start home-v2" in zdarzenia)
    assert zdarzenia == ["start home-v1", "zamknij home-v1", "start home-v2"]
    assert po_zmianie == ["home-v2"] and p.stany.get(DOM_B).wersja == 2

    # Zla konfiguracja: stary dom chodzi dalej, blad w stanie, bez ponawiania.
    wersja[DOM_B] = 3
    await _czekaj(lambda: p.stany.get(DOM_B).nieudana == 3)
    await asyncio.sleep(0.1)
    stan = p.stany.get(DOM_B)
    assert (stan.wersja, stan.blad) == (2, "nowa konfiguracja zla")
    assert wolania.count(3) == 1
    assert zdarzenia[-1] == "start home-v2" and nadzorca.domy[0].home == "home-v2"

    # Kolejna zmiana naprawia.
    wersja[DOM_B] = 4
    await _czekaj(lambda: "start home-v4" in zdarzenia)
    assert p.stany.get(DOM_B) == dm.StanDomu(4)
    stop.set()
    assert await zadanie == 0
    await nadzorca.zamknij(1.0)
    assert zdarzenia[-1] == "zamknij home-v4"


async def test_nadzorca_wraca_do_starej_konfiguracji_gdy_srodowisko_nie_wstaje():
    zdarzenia: list[str] = []
    wersja = {DOM_B: 1}

    def runtime(dom_id, home):
        if home == "home-v2":
            raise MissingSecretError("Dom 2: brak sekretu nextdns.api_key")
        return Srodowisko(dom_id, home, zdarzenia)

    p = dm.Przeladowanie(wersja=lambda d: wersja[d], konfiguracja=lambda d: "home-v2",
                         runtime=runtime, okres=0.01)
    nadzorca = dm.Nadzorca([Srodowisko(DOM_B, "home-v1", zdarzenia)], przeladowanie=p)
    stop = asyncio.Event()
    zadanie = asyncio.create_task(nadzorca.run(stop))
    await asyncio.sleep(0.03)
    wersja[DOM_B] = 2
    await _czekaj(lambda: zdarzenia.count("start home-v1") == 2)
    assert zdarzenia == ["start home-v1", "zamknij home-v1", "start home-v1"]
    stan = p.stany.get(DOM_B)
    assert (stan.wersja, stan.nieudana) == (1, 2) and "nextdns.api_key" in stan.blad
    stop.set()
    assert await zadanie == 0


async def test_nadzorca_bez_przeladowania_jak_dotad():
    """Bez `przeladowanie` (Dom 1 z config.yaml): koniec zadania = kod 1."""
    zdarzenia: list[str] = []

    class Konczy(Srodowisko):
        def start(self):
            return [asyncio.create_task(asyncio.sleep(0), name="konczy")]

    assert await dm.Nadzorca([Konczy(DOM_1, "x", zdarzenia)]).run(asyncio.Event()) == 1


def test_przeladowanie_domow_z_prawdziwej_bazy(tmp_path, monkeypatch, kek):
    """`run`: wersja tylko dla domu w trybie `baza`; konfiguracja z sejfu
    z kontrola wymaganych sekretow; po zmianie panel bierze nowa konfiguracje."""
    monkeypatch.setattr(straznik, "rozwiaz_systemowo", _rozwiaz)
    cfg = _config(tmp_path)
    inst_cfg, _ = cfg.split()
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj()
    rejestr.dodaj_dom("Dom B")
    _dziecko_z_urzadzeniem(rejestr, DOM_B, "phone-android")
    sejf = Sejf(kek)
    rejestr.zapisz_integracje(DOM_B, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": "abc999"},
                              sekrety={"api_key": _nowy_sekret("K")}, resolver=_rozwiaz)
    konfiguracje: dict = {}
    zapomniane: list[int] = []

    class Panel:
        def zapomnij(self, dom_id):
            zapomniane.append(dom_id)

    p = przeladowanie_domow(rejestr, inst_cfg, konfiguracje, dm.StanyDomow(), Panel())
    assert p.wersja(DOM_1) is None  # config.yaml — bez przeladowania
    assert p.wersja(DOM_B) == rejestr.dom(DOM_B).wersja
    home = p.konfiguracja(DOM_B)
    assert home.source.nextdns.profile_id == "abc999"

    class Rt:
        pass

    rt = Rt()
    rt.home = home
    p.po_zmianie(DOM_B, rt)
    assert konfiguracje[DOM_B] is home and zapomniane == [DOM_B]
    # Klucz usuniety poza panelem (bez bezpiecznika) — przeladowanie odmawia.
    rejestr.zapisz_integracje(DOM_B, "nextdns", sejf=sejf, sekrety={"api_key": None},
                              resolver=_rozwiaz)
    with pytest.raises(MissingSecretError, match="nextdns.api_key"):
        p.konfiguracja(DOM_B)


def test_token_tv_ze_srodowiska_nie_podbija_wersji(tmp_path, kek):
    """Sparowanie aplikacji TV zapisuje token przez srodowisko domu — to,
    co dom juz ma w pamieci, nie moze wywolac przeladowania."""
    rejestr = dm.RejestrDomow(tmp_path / "panel-auth.db")
    rejestr.migruj()
    dom = rejestr.dodaj_dom("Dom B")
    sejf = Sejf(kek)
    wersja = rejestr.dom(dom).wersja
    rejestr.sekrety_domu(dom, sejf).zapisz("tv", "app_token", _nowy_sekret("T"))
    assert rejestr.dom(dom).wersja == wersja
    assert rejestr.integracja(dom, "tv").sekrety_pola == ("app_token",)


# ======================================================= poprawki po przegladzie
def test_przelaczenie_zrodla_dns_w_jednym_zapisie(inst):
    h = admin(inst)
    wersja = inst.rejestr.dom(DOM_B).wersja
    st, _, body = _zapisz(inst, h, {
        "typ": "adguard", "wlaczona": True,
        "ustawienia": {"base_url": "https://adguard.example.com", "username": "kidwatch"},
        "sekrety": {"password": _nowy_sekret("ADGUARD")}, "wersja": wersja})
    assert st == 200, body
    assert {i["typ"]: i["wlaczona"] for i in body["zmienione"]} == {"adguard": True,
                                                                    "nextdns": False}
    assert inst.rejestr.integracja(DOM_B, "adguard").wlaczona
    assert not inst.rejestr.integracja(DOM_B, "nextdns").wlaczona
    assert body["start"] is None and body["dom"]["wersja"] == inst.rejestr.dom(DOM_B).wersja
    # Samo wylaczenie jedynego zrodla dalej odrzucone.
    st, _, body = _zapisz(inst, h, {"typ": "adguard", "wlaczona": False})
    assert st == 400 and "nie wystartuje" in body["error"], body


def test_zapis_z_nieaktualnej_wersji_409(inst):
    h = admin(inst)
    stara = inst.rejestr.dom(DOM_B).wersja
    st, _, _ = _zapisz(inst, h, {"typ": "ntfy", "wlaczona": False, "ustawienia": {},
                                 "wersja": stara})
    assert st == 200
    st, _, body = _zapisz(inst, h, {"typ": "unifi", "wlaczona": False, "wersja": stara})
    assert st == 409 and "odśwież" in body["error"], body
    assert inst.rejestr.integracja(DOM_B, "unifi").wlaczona


def test_stan_do_odswiezania_bez_wpisu_w_dzienniku(inst):
    h = admin(inst)

    def odczyty():
        with sqlite3.connect(inst.cfg.panel_auth_path) as conn:
            return conn.execute("SELECT COUNT(*) FROM audyt WHERE akcja = "
                                "'integracje.odczyt'").fetchone()[0]

    przed = odczyty()
    for _ in range(3):
        st, _, body = call(inst, "GET", f"{URL}/stan", headers=h)
        assert st == 200 and set(body) == {"dom", "start", "przeladowanie"}, body
    assert odczyty() == przed
    st, _, _ = call(inst, "GET", f"{URL}/stan", headers=sso(inst, "wlasciciel-b"))
    assert st == 403


def test_blad_po_udanym_zapisie_to_sukces_z_ostrzezeniem(inst, monkeypatch):
    h = admin(inst)

    def zepsute_maski(self, dom_id, sejf):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(dm.RejestrDomow, "maski", zepsute_maski)
    st, _, body = _zapisz(inst, h, {"typ": "unifi", "wlaczona": False})
    assert st == 200 and body["ok"] and "odśwież" in body["ostrzezenie"], body
    assert not inst.rejestr.integracja(DOM_B, "unifi").wlaczona


def test_bledy_startu_i_przeladowania_bez_sekretow(inst, caplog):
    """Pola `start` i `przeladowanie.blad` niosa komunikaty z budowy domu —
    tez bez wartosci sekretow."""
    caplog.set_level(logging.DEBUG)
    s = Slady(inst, caplog)
    h = admin(inst)
    # Konfiguracja, na ktorej dom nie wstaje (poza panelem, bez bezpiecznika).
    with sqlite3.connect(inst.cfg.panel_auth_path) as conn:
        conn.execute("UPDATE integracje SET ustawienia = ? WHERE dom_id = ? AND typ = 'nextdns'",
                     ('{"profile_id": "abc999", "base_url": "https://obcy.example.com"}',
                      DOM_B))
    p = przeladowanie_domow(inst.rejestr, inst.cfg.split()[0], {}, inst.stany)
    with pytest.raises(Exception) as exc:
        p.konfiguracja(DOM_B)
    inst.stany.ustaw(DOM_B, dm.StanDomu(1, inst.rejestr.dom(DOM_B).wersja, str(exc.value)))
    st, _, body = s.zapisz(call(inst, "GET", URL, headers=h))
    assert st == 200 and "spoza listy" in body["start"], body
    assert body["przeladowanie"]["blad"]
    s.zapisz(call(inst, "GET", f"{URL}/stan", headers=h))
    assert s.przecieki(inst.kanarki["nextdns"], inst.kanarki["unifi"]) == []


def test_mdm_w_panelu_z_tokenem_domu_z_bazy(tmp_path, monkeypatch, kek):
    """Dom 1 w trybie `baza`: posrednik MDM panelu bierze token z sejfu domu
    (ekran integracji), nie z MDM_ADMIN_TOKEN."""
    from kidwatch import mdm as mdm_mod  # noqa: PLC0415
    from kidwatch.konfiguracja_domu import zbuduj_dom  # noqa: PLC0415

    monkeypatch.setenv("MDM_ADMIN_TOKEN", "TOKEN-Z-ENV-" + secrets.token_hex(6))
    cfg, auth, rejestr = _uruchom_panel(tmp_path, monkeypatch, None)
    auth.add_user("wlasciciel", HASLO)
    rejestr.ustaw_zrodlo(DOM_1, dm.ZRODLO_BAZA)
    _dziecko_z_urzadzeniem(rejestr, DOM_1, "phone-android")
    sejf = Sejf(kek)
    rejestr.zapisz_integracje(DOM_1, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": "abc999"},
                              sekrety={"api_key": _nowy_sekret("K")}, resolver=_rozwiaz)
    token = _nowy_sekret("MDM")
    rejestr.zapisz_integracje(DOM_1, "mdm", sejf=sejf, wlaczona=True, ustawienia={},
                              sekrety={"token": token}, resolver=_rozwiaz)
    naglowki = []

    def request(self, method, path, body=None):
        naglowki.append(self._client.headers["Authorization"])
        return {} if path != "/api/devices" else []

    monkeypatch.setattr(mdm_mod.MdmApi, "request", request)
    srv = start_panel(cfg, konfiguracja_domu=lambda dom: zbuduj_dom(
        rejestr, dom.id, sejf, materializuj=False))
    try:
        st, _, body = call(srv, "GET", f"/api/domy/{DOM_1}/mdm",
                           headers=sso(srv, "wlasciciel"))
        assert st == 200 and body["available"], body
        assert naglowki and set(naglowki) == {f"Bearer {token}"}
        # Integracja MDM wylaczona w bazie: panel nie wraca po cichu do tokenu z env.
        rejestr.zapisz_integracje(DOM_1, "mdm", sejf=sejf, wlaczona=False)
        srv.domy_panelu.zapomnij(DOM_1)
        st, _, body = call(srv, "GET", f"/api/domy/{DOM_1}/mdm",
                           headers=sso(srv, "wlasciciel"))
        assert st == 200 and body["available"] is False, body
    finally:
        srv.shutdown()
