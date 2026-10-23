# ruff: noqa: F811 — fixtura kek importowana z test_domy_e2
"""Start kolejnych domow obok Domu 1 w jednym procesie (przed E6,
renacode-infra: docs/projekty/kidwatch/architektura-domy.md §5.1, §7 E3b
„Nie zrobione w E3b”, E6).

Prawdziwy `Nadzorca`, prawdziwe `przeladowanie_domow`, `build_home_runtime`
i rejestr domow z sejfem. Atrapy tylko na brzegach: zrodlo DNS odtwarza
plik `.jsonl`, kanal powiadomien zbiera notki, tik silnika dostaje czas
ostatniego zdarzenia zamiast zegara sciennego (jak `kidwatch replay`).

Dom 1 z config.yaml odtwarza `day.jsonl`, Dom 2 (konfiguracja w bazie,
NextDNS + telefon z Androidem) — `telefon_android.jsonl`, rownolegle.
Wynik kazdego domu ma byc taki sam jak przy odtworzeniu osobno, bez
przeciekow notek i zdarzen miedzy domami. Do tego: dom ≠ 1 rzucajacy przy
starcie nie przerywa Domu 1, dom dodany w trakcie startuje sam, dom
nieskonfigurowany czeka bez alarmu, dom znikajacy z listy jest zatrzymany.

Dane generyczne (tests/test_repo_prywatnosc.py), sekrety losowane w tescie.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import yaml

import kidwatch.__main__ as cli
from kidwatch import domy as dm
from kidwatch import scheduler, straznik
from kidwatch.classifier import Classifier
from kidwatch.config import Config
from kidwatch.engine import Engine
from kidwatch.konfiguracja_domu import czego_brakuje, zbuduj_dom
from kidwatch.models import DnsEvent
from kidwatch.sejf import Sejf
from kidwatch.store import Store
from test_domy_e2 import kek  # noqa: F401 — fikstura KIDWATCH_KEK

pytestmark = pytest.mark.usefixtures("bez_sieci")

FIXTURES = Path(__file__).parent / "fixtures"
APP_MAP = Path(__file__).resolve().parents[1] / "app_map.yaml"
DAY = FIXTURES / "day.jsonl"
ANDROID = FIXTURES / "telefon_android.jsonl"
PROFIL_1 = "fixture"  # tests/fixtures/config.yaml
PROFIL_2 = "abc999"
DOM_2 = 2
PUBLICZNY = "9.9.9.9"
POLA = ("kind", "title", "text", "dedup_key", "ts", "device", "app", "priority", "tags",
        "data")


def _rozwiaz(host: str, port: int) -> list[str]:
    adres = straznik.adres_literalny(host)
    return [str(adres)] if adres is not None else [PUBLICZNY]


def _wiersze(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _ts(row: dict) -> datetime:
    return datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))


def _urzadzenia(path: Path) -> set[str]:
    return {r["device"] for r in _wiersze(path)}


# ===================================================================== atrapy
class Kolektor:
    name = "kolektor"

    def __init__(self) -> None:
        self.notes = []

    async def send(self, note):
        self.notes.append(note)
        return True

    async def aclose(self):
        return None


class ZrodloZPliku:
    """Odtwarza plik i potem wisi jak prawdziwy strumien (koniec petli zrodla
    nadzorca traktuje jako awarie domu)."""

    name = "nextdns"

    def __init__(self, path: Path) -> None:
        self.rows = _wiersze(path)
        self.koniec = asyncio.Event()
        self.zamkniete = False

    @property
    def ostatni(self) -> datetime:
        return _ts(self.rows[-1])

    async def events(self):
        for row in self.rows:
            yield DnsEvent(ts=_ts(row), device_id=row["device"], domain=row["domain"])
        self.koniec.set()
        await asyncio.Event().wait()

    async def aclose(self):
        self.zamkniete = True


class Swiat:
    """Brzegi procesu: zrodlo i kanal per dom (po profilu NextDNS), tik po
    ostatnim zdarzeniu zamiast zegara."""

    def __init__(self, monkeypatch) -> None:
        self.pliki = {PROFIL_1: DAY, PROFIL_2: ANDROID}
        self.kolektory = {PROFIL_1: Kolektor(), PROFIL_2: Kolektor()}
        self.zrodla: dict[Path, ZrodloZPliku] = {}
        self.alarmy: list[tuple[str, str]] = []
        monkeypatch.setattr(cli, "build_source", self.build_source)
        monkeypatch.setattr(cli, "build_notifiers", self.build_notifiers)
        monkeypatch.setattr(scheduler, "tick_loop", self.tick_loop)

    def build_source(self, cfg, store):
        zrodlo = ZrodloZPliku(self.pliki[cfg.source.nextdns.profile_id])
        self.zrodla[Path(store.path)] = zrodlo
        return zrodlo

    def build_notifiers(self, cfg, bramka, **_kw):
        return [self.kolektory[cfg.source.nextdns.profile_id]]

    async def tick_loop(self, engine, dispatcher, store, *, tetno=None, **_kw):
        zrodlo = self.zrodla[Path(store.path)]
        await zrodlo.koniec.wait()
        idle = engine.cfg.engine.idle_minutes
        await dispatcher.send_all(engine.tick(zrodlo.ostatni + timedelta(minutes=idle + 1)))
        while True:
            if tetno is not None:
                tetno()
            await asyncio.sleep(0.02)

    async def alarm(self, tytul: str, tresc: str) -> None:
        self.alarmy.append((tytul, tresc))

    def tytuly(self) -> list[str]:
        return [t for t, _ in self.alarmy]


def oczekiwane(home, path: Path) -> list:
    """To samo zrodlo odtworzone OSOBNO, jednym silnikiem, bez nadzorcy."""
    rows = _wiersze(path)
    with Store(":memory:") as store:
        engine = Engine(home, store, Classifier(str(APP_MAP)))
        out = []
        for row in rows:
            out += engine.handle(DnsEvent(ts=_ts(row), device_id=row["device"],
                                          domain=row["domain"]))
        out += engine.tick(_ts(rows[-1]) + timedelta(minutes=home.engine.idle_minutes + 1))
    return out


def _pola(notes) -> list[tuple]:
    return [tuple(getattr(n, p) for p in POLA) for n in notes]


async def _czekaj(warunek, limit: float = 15.0) -> None:
    for _ in range(int(limit / 0.02)):
        if warunek():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("warunek nie spelniony")


# ===================================================================== uklad
def _config(tmp_path: Path) -> Path:
    data = yaml.safe_load((FIXTURES / "config.yaml").read_text(encoding="utf-8"))
    data["store"]["path"] = str(tmp_path / "kidwatch.db")
    data["app_map_path"] = str(APP_MAP)
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return path


def _telefon(rejestr: dm.RejestrDomow, dom_id: int) -> None:
    """Dziecko z telefonem z Androidem — nazwa jak w telefon_android.jsonl."""
    with rejestr._conn() as conn, dm._transakcja(conn):
        cur = conn.execute("INSERT INTO dzieci (dom_id, nazwa) VALUES (?, 'Kuba')", (dom_id,))
        conn.execute("INSERT INTO urzadzenia (dom_id, dziecko_id, rodzaj, nazwa, source_ids) "
                     "VALUES (?, ?, 'phone-android', 'Telefon Kuby', '[\"Telefon Kuby\"]')",
                     (dom_id, cur.lastrowid))


def _nextdns(rejestr: dm.RejestrDomow, dom_id: int, sejf: Sejf, **kw) -> None:
    rejestr.zapisz_integracje(dom_id, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": PROFIL_2},
                              sekrety={"api_key": f"KLUCZ-{secrets.token_urlsafe(12)}"},
                              resolver=_rozwiaz, **kw)


@pytest.fixture
def uklad(tmp_path, monkeypatch, kek):
    monkeypatch.setattr(straznik, "rozwiaz_systemowo", _rozwiaz)
    cfg_path = _config(tmp_path)
    cfg = Config.load(cfg_path)
    inst, home = cfg.split()
    rejestr = dm.RejestrDomow(inst.panel_auth_path)
    rejestr.migruj(strefa=home.timezone)
    return {"cfg_path": cfg_path, "cfg": cfg, "inst": inst, "home": home,
            "rejestr": rejestr, "sejf": Sejf(kek), "swiat": Swiat(monkeypatch),
            "tmp": tmp_path}


def _dom_2(u, *, skonfigurowany: bool = True) -> int:
    rejestr = u["rejestr"]
    assert rejestr.dodaj_dom("Dom testowy") == DOM_2
    if skonfigurowany:
        _telefon(rejestr, DOM_2)
        _nextdns(rejestr, DOM_2, u["sejf"])
    return DOM_2


class Proces:
    """To, co `run` sklada z Domu 1 z config.yaml: nadzorca z izolacja awarii
    i z kolejnymi domami (`przeladowanie_domow(..., kolejne_domy=True)`)."""

    def __init__(self, u, *, runtime=None) -> None:
        self.u = u
        inst, home = u["inst"], u["home"]
        self.konfiguracje = {dm.DOM_1: home}
        self.stany = dm.StanyDomow()
        self.p = cli.przeladowanie_domow(u["rejestr"], inst, self.konfiguracje, self.stany,
                                         alarm=u["swiat"].alarm, dom_1_z_bazy=False,
                                         kolejne_domy=True)
        self.p.okres = 0.02
        if runtime is not None:
            self.p.runtime = runtime
        dom_1 = cli.build_home_runtime(dm.DOM_1, inst, home, Classifier(inst.app_map_path))
        self.nadzorca = dm.Nadzorca(
            [dom_1], przeladowanie=self.p, flush_seconds=1.0,
            odbuduj=lambda dom_id, h: cli.build_home_runtime(
                dom_id, inst, h, Classifier(inst.app_map_path)),
            alarm=u["swiat"].alarm, okres_nadzoru=0.02)
        self.stop = asyncio.Event()

    def start(self) -> None:
        self.zadanie = asyncio.create_task(self.nadzorca.run(self.stop))

    def dzialajace(self) -> list[int]:
        return [rt.dom_id for rt in self.nadzorca.domy]

    async def koniec(self) -> int:
        assert not self.zadanie.done(), "nadzorca skonczyl sie sam"
        self.stop.set()
        rc = await asyncio.wait_for(self.zadanie, 10)
        await self.nadzorca.zamknij(1.0)
        return rc


def _audyt(rejestr: dm.RejestrDomow, dom_id: int) -> list[str]:
    with sqlite3.connect(rejestr.path) as conn:
        return [r[0] for r in conn.execute("SELECT akcja FROM audyt WHERE dom_id = ? "
                                           "ORDER BY id", (dom_id,))]


def _zrodla_w_bazie(path: Path) -> set[str]:
    with sqlite3.connect(path) as conn:
        return {r[0] for r in conn.execute("SELECT DISTINCT source_id FROM events")}


# ================================================================ e2e (E6)
async def test_dom_2_rownolegle_z_domem_1_wyniki_jak_osobno_bez_przeciekow(uklad):
    u, swiat = uklad, uklad["swiat"]
    _dom_2(u)
    home_2 = zbuduj_dom(u["rejestr"], DOM_2, u["sejf"], materializuj=False)
    oczek_1, oczek_2 = oczekiwane(u["home"], DAY), oczekiwane(home_2, ANDROID)
    assert oczek_1 and oczek_2

    proc = Proces(u)
    proc.start()
    k1, k2 = swiat.kolektory[PROFIL_1], swiat.kolektory[PROFIL_2]
    await _czekaj(lambda: len(k1.notes) >= len(oczek_1) and len(k2.notes) >= len(oczek_2))
    await asyncio.sleep(0.2)  # nic wiecej nie dochodzi
    assert proc.dzialajace() == [1, DOM_2]
    # Panel i komendy widza konfiguracje dzialajacego Domu 2.
    assert proc.konfiguracje[DOM_2].source.nextdns.profile_id == PROFIL_2
    assert proc.stany.get(DOM_2) == dm.StanDomu(u["rejestr"].dom(DOM_2).wersja)
    assert await proc.koniec() == 0

    # Wynik kazdego domu jak przy odtworzeniu osobno, pole w pole.
    assert _pola(k1.notes) == _pola(oczek_1)
    assert _pola(k2.notes) == _pola(oczek_2)
    # Zero przeciekow: notki z domem swojej kolejki, urzadzenia tylko swoje.
    assert {n.dom_id for n in k1.notes} == {1}
    assert {n.dom_id for n in k2.notes} == {DOM_2}
    urz_1 = {d.display_name for d in u["home"].devices}
    urz_2 = {d.display_name for d in home_2.devices}
    assert {n.device for n in k1.notes if n.device} <= urz_1
    assert {n.device for n in k2.notes if n.device} <= urz_2
    # Zdarzenia w bazach domow — kazdy dom tylko swoje zrodla.
    baza_1 = u["tmp"] / "kidwatch.db"
    baza_2 = dm.sciezka_bazy_domu(DOM_2, baza_1)
    assert _zrodla_w_bazie(baza_1) == _urzadzenia(DAY)
    assert _zrodla_w_bazie(baza_2) == _urzadzenia(ANDROID)
    assert not _urzadzenia(DAY) & _urzadzenia(ANDROID)
    # Zadnego alarmu instancji przy zdrowych domach.
    assert swiat.alarmy == []


# ===================================================== izolacja startu domu
async def test_dom_rzucajacy_przy_starcie_nie_przerywa_domu_1(uklad):
    u, swiat = uklad, uklad["swiat"]
    _dom_2(u)
    psuj = {"tak": True}

    def runtime(dom_id, home):
        if dom_id == DOM_2 and psuj["tak"]:
            raise RuntimeError("awaria-testowa przy budowie domu")
        return cli.build_home_runtime(dom_id, u["inst"], home, Classifier(str(APP_MAP)))

    proc = Proces(u, runtime=runtime)
    proc.start()
    oczek_1 = oczekiwane(u["home"], DAY)
    k1 = swiat.kolektory[PROFIL_1]
    await _czekaj(lambda: len(k1.notes) >= len(oczek_1))
    await asyncio.sleep(0.3)  # wiele obiegow nadzorcy
    assert proc.dzialajace() == [1]
    assert _pola(k1.notes) == _pola(oczek_1), "Dom 1 chodzi jak sam"
    w = u["rejestr"].dom(DOM_2).wersja
    stan = proc.stany.get(DOM_2)
    assert (stan.wersja, stan.nieudana, stan.czeka) == (None, w, None)
    assert "awaria-testowa" in stan.blad
    # Alarm instancji raz (bramka z dziennika), bez tresci wyjatku.
    await _czekaj(lambda: "dom.start.alarm" in _audyt(u["rejestr"], DOM_2))
    assert swiat.tytuly() == ["Dom 2: monitoring nie wystartowal"]
    assert "awaria-testowa" not in swiat.alarmy[0][1]
    assert _audyt(u["rejestr"], DOM_2).count("dom.przeladowanie.blad") == 1
    # Blad konfiguracji czeka na zmiane wersji — nie co obieg.
    proc.p.okres = 0.02
    await asyncio.sleep(0.2)
    assert swiat.tytuly() == ["Dom 2: monitoring nie wystartowal"]

    # Poprawka w panelu (nowa wersja): dom wstaje bez restartu poda.
    psuj["tak"] = False
    _nextdns(u["rejestr"], DOM_2, u["sejf"])
    await _czekaj(lambda: DOM_2 in proc.dzialajace())
    await _czekaj(lambda: "Dom 2: monitoring wystartowal" in swiat.tytuly())
    assert proc.stany.get(DOM_2) == dm.StanDomu(u["rejestr"].dom(DOM_2).wersja)
    assert DOM_2 in proc.konfiguracje
    assert await proc.koniec() == 0


async def test_przeladowanie_domu_2_bez_zadnej_konfiguracji_nie_konczy_procesu(uklad):
    """Dzialajacy Dom 2: nowa wersja, poprzednia i kopia nie wstaja — przed
    zmiana proces konczyl sie kodem 1 (restart poda przerywal zdrowy Dom 1)."""
    u, swiat = uklad, uklad["swiat"]
    _dom_2(u)
    psuj = {"tak": False}

    def runtime(dom_id, home):
        if dom_id == DOM_2 and psuj["tak"]:
            raise RuntimeError("awaria-testowa")
        return cli.build_home_runtime(dom_id, u["inst"], home, Classifier(str(APP_MAP)))

    proc = Proces(u, runtime=runtime)
    proc.start()
    await _czekaj(lambda: DOM_2 in proc.dzialajace())
    psuj["tak"] = True
    _nextdns(u["rejestr"], DOM_2, u["sejf"])
    await _czekaj(lambda: "Dom 2: monitoring nie wystartowal" in swiat.tytuly())
    await asyncio.sleep(0.2)
    assert proc.dzialajace() == [1]
    assert DOM_2 not in proc.konfiguracje
    assert proc.stany.get(DOM_2).wersja is None
    psuj["tak"] = False
    _nextdns(u["rejestr"], DOM_2, u["sejf"])
    await _czekaj(lambda: DOM_2 in proc.dzialajace())
    assert await proc.koniec() == 0


# ========================================== nowy dom w trakcie, bez konfiguracji
async def test_dom_dodany_w_trakcie_czeka_cicho_i_startuje_po_konfiguracji(uklad):
    u, swiat = uklad, uklad["swiat"]
    proc = Proces(u)
    proc.start()
    await _czekaj(lambda: proc.nadzorca._wersje.get(1, "x") is None)
    assert proc.dzialajace() == [1]

    # `kidwatch dom-dodaj` w trakcie pracy poda: dom bez integracji.
    _dom_2(u, skonfigurowany=False)
    await _czekaj(lambda: proc.stany.get(DOM_2) is not None)
    stan = proc.stany.get(DOM_2)
    assert stan.czeka == "brak wlaczonego zrodla DNS (integracja NextDNS)"
    assert (stan.wersja, stan.nieudana, stan.blad) == (None, None, None)
    # Panel (Ustawienia -> Integracje) pokazuje „czeka”, nie blad.
    from kidwatch.panel_auth import PanelAuth  # noqa: PLC0415
    from kidwatch.panel_integracje import PanelIntegracje  # noqa: PLC0415

    panel = PanelIntegracje(PanelAuth(u["inst"].panel_auth_path), lambda: u["sejf"],
                            stany=proc.stany)
    widok = panel.przeladowanie(u["rejestr"].dom(DOM_2))
    assert widok["czeka"] == stan.czeka and widok["blad"] is None
    # Sam klucz bez urzadzenia — dalej czeka, nadal bez alarmu.
    _nextdns(u["rejestr"], DOM_2, u["sejf"])
    await _czekaj(lambda: proc.stany.get(DOM_2).czeka == "brak urzadzenia dziecka")
    await asyncio.sleep(0.2)
    assert swiat.alarmy == []
    assert proc.dzialajace() == [1]
    assert not {"dom.start.alarm", "dom.przeladowanie.blad"} & set(
        _audyt(u["rejestr"], DOM_2))

    # Urzadzenie zapisane w panelu (podbija wersje) — dom startuje sam.
    _telefon(u["rejestr"], DOM_2)
    with u["rejestr"]._conn() as conn, dm._transakcja(conn):
        dm._podbij_wersje(conn, DOM_2)
    k2 = swiat.kolektory[PROFIL_2]
    oczek_2 = oczekiwane(zbuduj_dom(u["rejestr"], DOM_2, u["sejf"], materializuj=False),
                         ANDROID)
    await _czekaj(lambda: len(k2.notes) >= len(oczek_2))
    assert proc.dzialajace() == [1, DOM_2]
    assert proc.stany.get(DOM_2).czeka is None
    assert DOM_2 in proc.konfiguracje
    assert swiat.alarmy == []
    assert await proc.koniec() == 0


def test_nieskonfigurowany_a_blad_konfiguracji(uklad):
    """`czego_brakuje`: brak zrodla, jego sekretu albo urzadzenia = czeka;
    zla wartosc (wylaczone oba zrodla tez) to nie „czeka”, tylko blad startu."""
    u = uklad
    rejestr, sejf = u["rejestr"], u["sejf"]
    _dom_2(u, skonfigurowany=False)
    assert "zrodla DNS" in czego_brakuje(rejestr.dane_domu(DOM_2))
    rejestr.zapisz_integracje(DOM_2, "nextdns", sejf=sejf, wlaczona=True,
                              ustawienia={"profile_id": PROFIL_2}, resolver=_rozwiaz)
    assert czego_brakuje(rejestr.dane_domu(DOM_2)) == "brak sekretu nextdns.api_key"
    _nextdns(rejestr, DOM_2, sejf)
    assert czego_brakuje(rejestr.dane_domu(DOM_2)) == "brak urzadzenia dziecka"
    _telefon(rejestr, DOM_2)
    assert czego_brakuje(rejestr.dane_domu(DOM_2)) is None
    # Dom, ktory kiedys wstal (kopia), nie jest „swiezy”: brak klucza = awaria.
    p = cli.przeladowanie_domow(rejestr, u["inst"], {}, dm.StanyDomow(), kolejne_domy=True)
    assert p.czeka(DOM_2) is None
    assert rejestr.zapamietaj_dobra(DOM_2, rejestr.dom(DOM_2).wersja)
    rejestr.zapisz_integracje(DOM_2, "nextdns", sejf=sejf, sekrety={"api_key": None},
                              resolver=_rozwiaz)
    assert czego_brakuje(rejestr.dane_domu(DOM_2)) is not None
    assert p.czeka(DOM_2) is None
    assert p.domy() == [DOM_2]


# ======================================================== dom znika z listy
async def test_dom_znikajacy_z_listy_zatrzymany_z_oproznieniem_kolejki(uklad):
    u, swiat = uklad, uklad["swiat"]
    _dom_2(u)
    proc = Proces(u)
    lista = proc.p.domy
    ukryj = {"tak": False}
    proc.p.domy = lambda: [] if ukryj["tak"] else lista()
    proc.start()
    await _czekaj(lambda: DOM_2 in proc.dzialajace())
    rt = next(r for r in proc.nadzorca.domy if r.dom_id == DOM_2)
    oprozniona = []
    flush = rt.outbox.flush

    async def flush_i_zapisz():
        oprozniona.append(True)
        return await flush()

    rt.outbox.flush = flush_i_zapisz
    ukryj["tak"] = True
    await _czekaj(lambda: DOM_2 not in proc.dzialajace())
    assert oprozniona, "kolejka domu oprozniona przy zatrzymaniu"
    assert swiat.zrodla[Path(rt.store.path)].zamkniete
    assert DOM_2 not in proc.konfiguracje
    assert proc.stany.get(DOM_2) is None
    assert proc.dzialajace() == [1]
    assert await proc.koniec() == 0


# ===================================================================== run
@pytest.mark.parametrize("wariant", ["dziala", "rzuca", "nieskonfigurowany"])
def test_run_startuje_dom_2_obok_domu_1(uklad, monkeypatch, wariant):
    """`kidwatch run`: Dom 1 z config.yaml jak dotad, Dom 2 z bazy przez
    nadzorce. Blad Domu 2 nie zmienia kodu wyjscia ani nie zatrzymuje Domu 1."""
    u = uklad
    _dom_2(u, skonfigurowany=wariant != "nieskonfigurowany")
    monkeypatch.setenv("KIDWATCH_HEARTBEAT", str(u["tmp"] / "hb"))
    monkeypatch.delenv(cli.WYMUSZENIE_DOMU_1_ENV, raising=False)
    if wariant == "rzuca":
        prawdziwy = cli.build_home_runtime

        def build(dom_id, *a, **kw):
            if dom_id == DOM_2:
                raise RuntimeError("awaria-testowa")
            return prawdziwy(dom_id, *a, **kw)

        monkeypatch.setattr(cli, "build_home_runtime", build)
    widziane: dict = {}
    oryginal = dm.Nadzorca._sprawdz_domy
    oryginalny_run = dm.Nadzorca.run

    async def run(self, stop):
        self._stop_testu = stop
        return await oryginalny_run(self, stop)

    async def sprawdz(self):
        # Pierwsze sprawdzenie listy jest w `run` tuz po starcie Domu 1 —
        # po nim koniec (jak SIGTERM), zeby test nie czekal okresu nadzorcy.
        await oryginal(self)
        widziane["stan"] = self.przeladowanie.stany.get(DOM_2)
        widziane["dzialajace"] = [rt.dom_id for rt in self.domy]
        widziane["wersja_1"] = self._wersje.get(1, "brak")
        self._stop_testu.set()

    monkeypatch.setattr(dm.Nadzorca, "run", run)
    monkeypatch.setattr(dm.Nadzorca, "_sprawdz_domy", sprawdz)
    assert cli.main(["--config", str(u["cfg_path"]), "run"]) == 0
    stan = widziane["stan"]
    assert stan is not None, "nadzorca nie zajal sie Domem 2"
    # Dom 1 z config.yaml: bez przeladowania (wersja nieznana), jak dotad.
    assert widziane["wersja_1"] is None
    if wariant == "dziala":
        assert widziane["dzialajace"] == [1, DOM_2] and stan.czeka is None
        assert stan.wersja == u["rejestr"].dom(DOM_2).wersja
    elif wariant == "rzuca":
        assert widziane["dzialajace"] == [1] and stan.nieudana is not None
        # Bez bramki alarm idzie do logu, ale bramka odstepu i tak go zapisuje.
        assert "dom.start.alarm" in _audyt(u["rejestr"], DOM_2)
    else:
        assert widziane["dzialajace"] == [1] and stan.czeka is not None
        assert "dom.start.alarm" not in _audyt(u["rejestr"], DOM_2)


# ========================================== kolejka domu ≠ 1 wstrzymana: alarm
class BramkaBezOdbiorcy:
    """Kanal per konto, ktory nie zna pola `odbiorca` — dom ≠ 1 nie moze
    wysylac (§4.2), kolejka wstrzymuje wysylke."""

    name = "bramka"
    per_konto = True

    def __init__(self) -> None:
        self.wyslane: list = []

    async def obsluguje_odbiorcow(self) -> bool:
        return False

    async def send(self, note, odbiorca=None):
        self.wyslane.append(note)
        return True

    async def aclose(self):
        pass


async def test_wstrzymana_kolejka_domu_2_daje_alarm_instancji_raz(uklad, monkeypatch):
    """Dom ≠ 1 bez trybu kont: notki czekaja (logika Outbox bez zmian), a
    administrator dostaje alarm instancji — raz na przejscie i nie czesciej
    niz co ALARM_WSTRZYMANIA_ODSTEP mimo przeladowan domu."""
    from kidwatch.models import Notification, NotifyKind  # noqa: PLC0415
    from kidwatch.notifiers.base import Dispatcher, Outbox  # noqa: PLC0415

    monkeypatch.setattr(cli, "_ALARMY_WSTRZYMANIA", {})
    alarmy: list[str] = []

    async def alarm(tytul, tresc):
        alarmy.append(tytul)

    for proba in range(2):  # dwa srodowiska domu (przeladowanie) = jedna seria
        with Store(":memory:") as store:
            bramka = BramkaBezOdbiorcy()
            outbox = Outbox(Dispatcher([bramka], store=store), store, dom_id=DOM_2)
            outbox.na_wstrzymanie = cli.alarm_wstrzymania(DOM_2, alarm)
            note = Notification(kind=NotifyKind.SESSION_START, title="t", text="x",
                                dedup_key=f"s{proba}", ts=datetime.now().astimezone())
            await outbox.send_all([note])
            assert await outbox.flush() == 0 and await outbox.flush() == 0
            assert bramka.wyslane == []
            await asyncio.sleep(0.05)
    assert alarmy == ["Dom 2: powiadomienia wstrzymane"]
    # Dom 1 nie dostaje haka w build_home_runtime (tryb tras jest jego).
    rt = cli.build_home_runtime(dm.DOM_1, uklad["inst"], uklad["home"],
                                Classifier(str(APP_MAP)), alarm=alarm)
    assert rt.outbox.na_wstrzymanie is None
    await rt.zamknij(0.1)
