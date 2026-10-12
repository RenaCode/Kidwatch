# ruff: noqa: F811 — fixtura kek importowana z test_domy_e2
"""Przeladowanie domu przez nadzorce (§5.1) — awarie, ponowienia, alarmy,
kopia ostatniej dobrej konfiguracji i start `run` na niej.

Atrapy srodowisk zapisuja zdarzenia (start/zamknij/pliki), zegar nadzorcy
jest podstawiany, wiec odstepy alarmow i ponowien sprawdzamy bez czekania.
Dane generyczne: dokumentacyjne adresy RFC 5737, sekrety z secrets.token_*.
"""

from __future__ import annotations

import asyncio
import secrets
import sqlite3
import threading

import pytest

from kidwatch import domy as dm
from kidwatch import straznik
from kidwatch.__main__ import przeladowanie_domow, start_domu_z_bazy
from kidwatch.config import Config, MissingSecretError, PanelConfig, StoreConfig
from kidwatch.konfiguracja_domu import zbuduj_dom_z_kopii
from kidwatch.sejf import Sejf, SejfError
from test_domy_e2 import _dziecko_z_urzadzeniem, kek  # noqa: F401 — fikstura KIDWATCH_KEK

DOM = 2
PUBLICZNY = "9.9.9.9"


def _rozwiaz(host: str, port: int) -> list[str]:
    adres = straznik.adres_literalny(host)
    return [str(adres)] if adres is not None else [PUBLICZNY]


class Zegar:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Srodowisko:
    """Atrapa HomeRuntime: jedna wieczna petla, zapis zdarzen."""

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


class Uklad:
    """Nadzorca z atrapami: `wersja[DOM]` to `domy.wersja`, `konfiguracje`
    — wynik (albo wyjatek) budowy danej wersji."""

    def __init__(self, konfiguracje: dict, *, runtime=None, ostatnia_dobra=None) -> None:
        self.zdarzenia: list[str] = []
        self.wersja = {DOM: 1}
        self.konfiguracje = konfiguracje
        self.wolania: list[int] = []
        self.alarmy: list[str] = []
        self.dziennik: list[tuple] = []
        self.zegar = Zegar()

        def konfiguracja(dom_id):
            w = self.wersja[dom_id]
            self.wolania.append(w)
            wynik = self.konfiguracje[w]
            if callable(wynik):
                wynik = wynik()
            if isinstance(wynik, BaseException):
                raise wynik
            return wynik

        async def alarm(tytul, tresc):
            self.alarmy.append(tytul)

        self.p = dm.Przeladowanie(
            wersja=lambda dom_id: self.wersja[dom_id], konfiguracja=konfiguracja,
            runtime=runtime or (lambda dom_id, home: Srodowisko(dom_id, home, self.zdarzenia)),
            materializuj=lambda dom_id, home: self.zdarzenia.append(f"pliki {home}"),
            zapamietaj=lambda dom_id, w: self.dziennik.append(("ok", w)),
            zapisz_blad=lambda dom_id, w, blad: self.dziennik.append(("blad", w, blad)),
            ostatnia_dobra=ostatnia_dobra or (lambda dom_id: None),
            alarm=alarm, okres=0.01, zegar=self.zegar)
        self.nadzorca = dm.Nadzorca([Srodowisko(DOM, "home-v1", self.zdarzenia)],
                                    przeladowanie=self.p)
        self.stop = asyncio.Event()

    async def start(self):
        self.zadanie = asyncio.create_task(self.nadzorca.run(self.stop))
        await _czekaj(lambda: self.p.stany.get(DOM) is not None)

    async def koniec(self) -> int:
        self.stop.set()
        return await self.zadanie

    def stan(self) -> dm.StanDomu:
        return self.p.stany.get(DOM)


# ============================================================ kolejnosc
async def test_pliki_z_sekretow_dopiero_po_zatrzymaniu_starego():
    u = Uklad({2: "home-v2", 3: ValueError("zla")})
    await u.start()
    u.wersja[DOM] = 3
    await _czekaj(lambda: u.stan().nieudana == 3)
    # Nieudana budowa: stary dom bez zmian, jego pliki nietkniete.
    assert u.zdarzenia == ["start home-v1"]
    u.wersja[DOM] = 2
    await _czekaj(lambda: "start home-v2" in u.zdarzenia)
    assert u.zdarzenia == ["start home-v1", "zamknij home-v1", "pliki home-v2", "start home-v2"]
    assert await u.koniec() == 0


async def test_zapis_w_trakcie_przeladowania_nie_ginie():
    """Zmiana zapisana, gdy nadzorca buduje poprzednia: po skonczeniu dom
    przechodzi i na nia (najwyzej jedno dodatkowe przeladowanie)."""
    budowa_trwa, wolno_skonczyc = threading.Event(), threading.Event()

    def wolna_v2():
        budowa_trwa.set()
        assert wolno_skonczyc.wait(5)
        return "home-v2"

    u = Uklad({2: wolna_v2, 3: "home-v3"})
    await u.start()
    u.wersja[DOM] = 2
    await asyncio.to_thread(budowa_trwa.wait, 5)
    u.wersja[DOM] = 3  # zapis w panelu w trakcie budowy wersji 2
    wolno_skonczyc.set()
    await _czekaj(lambda: "start home-v3" in u.zdarzenia)
    assert u.stan() == dm.StanDomu(3)
    assert u.dziennik == [("ok", 2), ("ok", 3)]
    assert await u.koniec() == 0


# ============================================================ awarie
async def test_blad_konfiguracji_dziennik_raz_alarm_z_rosnacym_odstepem():
    u = Uklad({2: MissingSecretError("Dom 2: brak sekretu nextdns.api_key"), 3: "home-v3"})
    await u.start()
    u.wersja[DOM] = 2
    await _czekaj(lambda: u.alarmy)
    await asyncio.sleep(0.1)
    # Blad konfiguracji: jedna proba, jeden wpis, jeden alarm — nie co tick.
    assert u.wolania.count(2) == 1
    assert u.dziennik == [("blad", 2, "Dom 2: brak sekretu nextdns.api_key")]
    assert u.alarmy == ["Dom 2: nowa konfiguracja nie wystartowala"]
    assert (u.stan().wersja, u.stan().nieudana, u.stan().ponowienie) == (1, 2, False)
    # Powtorki: po 1 h, potem po 2 h (odstep od awarii domu, nie od komunikatu).
    u.zegar.t += 3600
    await _czekaj(lambda: len(u.alarmy) == 2)
    u.zegar.t += 3600
    await asyncio.sleep(0.1)
    assert len(u.alarmy) == 2
    u.zegar.t += 3600
    await _czekaj(lambda: len(u.alarmy) == 3)
    assert u.alarmy[1:] == ["Dom 2: nadal bez nowej konfiguracji"] * 2
    # Poprawka w panelu: dom wstaje, jeden alarm „znow dziala”, koniec powtorek.
    u.wersja[DOM] = 3
    await _czekaj(lambda: "start home-v3" in u.zdarzenia)
    await _czekaj(lambda: u.alarmy[-1] == "Dom 2: konfiguracja znow dziala")
    u.zegar.t += 10 * 24 * 3600
    await asyncio.sleep(0.1)
    assert len(u.alarmy) == 4
    assert await u.koniec() == 0


async def test_blad_przejsciowy_ponawiany_po_1_5_30_min():
    proby = iter([sqlite3.OperationalError("database is locked"), OSError("dns"),
                  OSError("dns"), "home-v2"])
    u = Uklad({2: lambda: next(proby)})
    await u.start()
    u.wersja[DOM] = 2
    await _czekaj(lambda: u.wolania.count(2) == 1)
    await asyncio.sleep(0.1)
    assert u.stan().ponowienie and u.wolania.count(2) == 1
    for odstep, proba in ((60, 2), (300, 3), (1800, 4)):
        # Termin ponowienia liczy sie po bledzie, nie przy wywolaniu — zegar
        # przesuwamy dopiero, gdy nadzorca go zapisal (pod obciazeniem watek
        # konczy sie pozniej niz licznik wywolan).
        await _czekaj(lambda proba=proba: u.nadzorca._ponow.get(DOM, (0, 0, 0))[1] == proba - 1)
        u.zegar.t += odstep - 1
        await asyncio.sleep(0.05)
        assert u.wolania.count(2) == proba - 1, odstep
        u.zegar.t += 1
        await _czekaj(lambda proba=proba: u.wolania.count(2) == proba)
    await _czekaj(lambda: "start home-v2" in u.zdarzenia)
    # Wpis w dzienniku raz na wersje, nie na probe.
    assert [d[0] for d in u.dziennik] == ["blad", "ok"]
    assert await u.koniec() == 0


def test_klasyfikacja_bledow():
    from kidwatch.straznik import OdmowaSieci  # noqa: PLC0415

    for blad in (ValueError("x"), MissingSecretError("x"), OdmowaSieci("x"), SejfError("x"),
                 LookupError("x")):
        assert not dm.blad_przejsciowy(blad), blad
    for blad in (sqlite3.OperationalError("locked"), OSError("dns"), TimeoutError()):
        assert dm.blad_przejsciowy(blad), blad


async def test_srodowisko_nie_wstaje_wraca_poprzednia_potem_kopia_potem_koniec():
    def runtime(dom_id, home):
        if home in ("home-v2", "home-v1"):
            raise MissingSecretError(f"nie wstaje {home}")
        return Srodowisko(dom_id, home, u.zdarzenia)

    u = Uklad({2: "home-v2"}, runtime=runtime, ostatnia_dobra=lambda dom_id: (1, "home-kopia"))
    await u.start()
    u.wersja[DOM] = 2
    await _czekaj(lambda: "start home-kopia" in u.zdarzenia)
    assert u.zdarzenia == ["start home-v1", "zamknij home-v1", "pliki home-v2", "pliki home-v1",
                           "pliki home-kopia", "start home-kopia"]
    assert (u.stan().wersja, u.stan().nieudana) == (1, 2)
    assert await u.koniec() == 0

    # Bez kopii: alarm „monitoring zatrzymany” i koniec procesu (kod 1).
    v = Uklad({2: "home-v2"}, runtime=runtime)
    await v.start()
    v.wersja[DOM] = 2
    assert await asyncio.wait_for(v.zadanie, 2) == 1
    assert v.alarmy[-1] == "Dom 2: monitoring zatrzymany"


async def test_blad_pierwszego_odczytu_wersji_nie_zabija_nadzorcy():
    u = Uklad({1: "home-v1-znowu"})
    licznik = {"n": 0}

    def wersja(dom_id):
        licznik["n"] += 1
        if licznik["n"] == 1:
            raise sqlite3.OperationalError("database is locked")
        return 1

    u.p.wersja = wersja
    zadanie = asyncio.create_task(u.nadzorca.run(u.stop))
    # Wersja nieznana: pierwszy udany odczyt przeladowuje (zbedne, nie zgubione).
    await _czekaj(lambda: "start home-v1-znowu" in u.zdarzenia)
    u.stop.set()
    assert await zadanie == 0


async def test_wersja_ze_startu_nie_jest_czytana_drugi_raz():
    """`run` podaje wersje odczytana PRZED budowa: zmiana w trakcie startu
    = jedno przeladowanie, nie zgubiona zmiana."""
    u = Uklad({2: "home-v2"})
    u.nadzorca.domy[0].wersja = 1
    u.wersja[DOM] = 2  # zmiana miedzy budowa a startem nadzorcy
    await u.start()
    await _czekaj(lambda: "start home-v2" in u.zdarzenia)
    assert await u.koniec() == 0


async def test_zamkniecie_srodowiska_sprzata_wszystko_mimo_bledow(tmp_path):
    from kidwatch.store import Store  # noqa: PLC0415

    zdarzenia = []

    class Kolejka:
        async def flush(self):
            zdarzenia.append("flush")

        async def aclose(self):
            raise RuntimeError("kolejka")

    class Zrodlo:
        async def aclose(self):
            zdarzenia.append("zrodlo")

    async def zla_sonda():
        raise RuntimeError("sonda")

    async def dobra_sonda():
        zdarzenia.append("sonda")

    store = Store(tmp_path / "k.db")
    rt = dm.HomeRuntime(DOM, None, store, None, Kolejka(), Zrodlo())  # type: ignore[arg-type]
    rt.dodaj_sprzatanie(zla_sonda)
    rt.dodaj_sprzatanie(dobra_sonda)
    await rt.zamknij(1.0)
    assert zdarzenia == ["sonda", "flush", "zrodlo"]
    with pytest.raises(sqlite3.ProgrammingError):
        store.conn.execute("SELECT 1")


# ===================================================== kopia w bazie
def _config(tmp_path) -> Config:
    from kidwatch.config import DeviceConfig, NextDnsConfig, SourceConfig  # noqa: PLC0415

    mapa = tmp_path / "app_map.yaml"
    mapa.write_text("noise: []\napps: {}\n", encoding="utf-8")
    return Config(
        timezone="Europe/Warsaw",
        source=SourceConfig(kind="nextdns", nextdns=NextDnsConfig(profile_id="profil")),
        devices=[DeviceConfig(display_name="iPad Dziecka 1", child="Dziecko 1",
                              source_ids=["ipad-1"])],
        panel=PanelConfig(enabled=False, port=0),
        store=StoreConfig(path=str(tmp_path / "kidwatch.db")),
        app_map_path=str(mapa),
    )


@pytest.fixture
def dom(tmp_path, monkeypatch, kek):
    """Dom 2 z konfiguracja w bazie: NextDNS z kluczem, telefon dziecka."""
    monkeypatch.setattr(straznik, "rozwiaz_systemowo", _rozwiaz)
    cfg = _config(tmp_path)
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj()
    assert rejestr.dodaj_dom("Dom B") == DOM
    _dziecko_z_urzadzeniem(rejestr, DOM, "phone-android")
    sejf = Sejf(kek)
    klucz = f"KLUCZ-{secrets.token_urlsafe(16)}"
    rejestr.zapisz_integracje(DOM, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": "abc999"}, sekrety={"api_key": klucz},
                              resolver=_rozwiaz)
    return {"cfg": cfg, "inst": cfg.split()[0], "rejestr": rejestr, "sejf": sejf,
            "klucz": klucz, "tmp": tmp_path}


def test_kopia_ostatniej_dobrej_konfiguracji(dom):
    rejestr, sejf = dom["rejestr"], dom["sejf"]
    assert zbuduj_dom_z_kopii(rejestr, DOM, sejf) is None
    w = rejestr.dom(DOM).wersja
    assert not rejestr.zapamietaj_dobra(DOM, w - 1)  # wersja juz inna: bez kopii
    assert rejestr.zapamietaj_dobra(DOM, w)
    # Zla zmiana PO kopii (poza panelem — bez bezpiecznika).
    rejestr.zapisz_integracje(DOM, "nextdns", sejf=sejf, sekrety={"api_key": None},
                              resolver=_rozwiaz)
    wersja_kopii, home = zbuduj_dom_z_kopii(rejestr, DOM, sejf)
    assert wersja_kopii == w and home.source.nextdns.api_key() == dom["klucz"]
    # Kopia trzyma sekrety zaszyfrowane — w pliku bazy nie ma klucza.
    assert dom["klucz"].encode() not in open(rejestr.path, "rb").read()  # noqa: SIM115
    # Nowy klucz domu (dom-klucz-rotuj) przeszyfrowuje tez kopie.
    rejestr.rotuj_dek(DOM, sejf)
    assert zbuduj_dom_z_kopii(rejestr, DOM, sejf)[1].source.nextdns.api_key() == dom["klucz"]
    with sqlite3.connect(rejestr.path) as conn:
        akcje = [r[0] for r in conn.execute("SELECT akcja FROM audyt WHERE dom_id = ?", (DOM,))]
    assert akcje.count("dom.przeladowanie") == 1


def test_blad_przeladowania_trwaly_w_dzienniku(dom):
    rejestr = dom["rejestr"]
    rejestr.zapisz_blad_przeladowania(DOM, 7, "dom 2: brak sekretu nextdns.api_key")
    assert rejestr.blad_przeladowania(DOM, 7) == "dom 2: brak sekretu nextdns.api_key"
    assert rejestr.blad_przeladowania(DOM, 8) is None
    assert rejestr.audyt(DOM)[0]["akcja"] == "dom.przeladowanie.blad"


async def test_start_na_ostatniej_dobrej_gdy_biezaca_nie_wstaje(dom):
    rejestr, sejf, inst = dom["rejestr"], dom["sejf"], dom["inst"]
    alarmy: list[tuple[str, str]] = []

    async def alarm(tytul, tresc):
        alarmy.append((tytul, tresc))

    # Pierwszy start: biezaca wersja wstaje i zostaje kopia.
    stany = dm.StanyDomow()
    rt = await start_domu_z_bazy(rejestr, inst, stany, alarm, DOM)
    dobra = rejestr.dom(DOM).wersja
    assert rt is not None and rt.wersja == dobra and stany.get(DOM) == dm.StanDomu(dobra)
    await rt.zamknij(0.1)
    # Zla zmiana poza panelem, restart poda.
    rejestr.zapisz_integracje(DOM, "nextdns", sejf=sejf, sekrety={"api_key": None},
                              resolver=_rozwiaz)
    zla = rejestr.dom(DOM).wersja
    stany = dm.StanyDomow()
    rt = await start_domu_z_bazy(rejestr, inst, stany, alarm, DOM)
    assert rt is not None, "proces ma zyc (panel), a dom chodzic na kopii"
    assert rt.wersja == dobra and rt.home.source.nextdns.api_key() == dom["klucz"]
    stan = stany.get(DOM)
    assert (stan.wersja, stan.nieudana) == (dobra, zla) and "nextdns.api_key" in stan.blad
    assert "nextdns.api_key" in rejestr.blad_przeladowania(DOM, zla)
    assert alarmy[-1][0] == "Dom 2: start na ostatniej dobrej konfiguracji"
    assert dom["klucz"] not in repr(alarmy) + repr(stan)
    await rt.zamknij(0.1)
    # Nadzorca startujacy z tego stanu nie probuje zlej wersji co tick.
    u = Uklad({})
    u.p.stany = stany
    u.nadzorca.domy[0].wersja = dobra
    u.wersja[DOM] = zla
    await u.start()
    await asyncio.sleep(0.1)
    assert u.wolania == []
    assert await u.koniec() == 0


async def test_start_bez_kopii_jak_dotad_kod_2_z_alarmem(dom):
    rejestr, sejf = dom["rejestr"], dom["sejf"]
    rejestr.zapisz_integracje(DOM, "nextdns", sejf=sejf, sekrety={"api_key": None},
                              resolver=_rozwiaz)
    alarmy = []

    async def alarm(tytul, tresc):
        alarmy.append(tytul)

    assert await start_domu_z_bazy(rejestr, dom["inst"], dm.StanyDomow(), alarm, DOM) is None
    assert alarmy == ["Dom 2: Kidwatch nie wystartowal"]


def test_przeladowanie_domow_nie_zapisuje_plikow_przy_budowie(dom, tmp_path, monkeypatch):
    monkeypatch.setenv("KIDWATCH_KATALOG_SEKRETOW", str(tmp_path / "run"))
    rejestr, sejf = dom["rejestr"], dom["sejf"]
    token = f"TOKEN-{secrets.token_urlsafe(12)}"
    rejestr.zapisz_integracje(DOM, "tv", sejf=sejf, wlaczona=False,
                              sekrety={"app_token": token}, resolver=_rozwiaz)
    p = przeladowanie_domow(rejestr, dom["inst"], {}, dm.StanyDomow())
    home = p.konfiguracja(DOM)
    plik = tmp_path / "run" / "domy" / str(DOM) / "tv-app" / "token"
    assert not plik.exists()
    p.materializuj(DOM, home)
    assert plik.read_text().strip() == token
