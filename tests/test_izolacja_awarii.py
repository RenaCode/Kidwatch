"""Izolacja awarii petli domu (E3b, docs/architektura-domy.md §5.1).

Dom 1 i dom testowy pod jednym nadzorca. Petla domu testowego rzuca
wyjatek: Dom 1 chodzi dalej, proces nie konczy sie, dom testowy wraca po
narastajacym odstepie (1, 2, 4... min), z alarmem instancji i czujka domu.
Tik stojacy dluzej niz 3x okres = restart tylko tego domu. Tetno procesu
(liveness) dotyka nadzorca. Kanarek: nadzorca BEZ izolacji (E1) — ta sama
awaria konczy proces; test to widzi.

Zegar nadzorcy jest podstawiany, wiec odstepy sprawdzamy bez czekania.
"""

from __future__ import annotations

import asyncio

from kidwatch import domy as dm
from kidwatch.models import NotifyKind

DOM_1, DOM_T = 1, 2


class Zegar:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


class Kolejka:
    def __init__(self) -> None:
        self.notki = []

    async def send_all(self, notes):
        self.notki += list(notes)

    async def flush(self):
        return None

    async def aclose(self):
        return None


class Nic:
    async def aclose(self):
        return None

    def close(self):
        return None


class Swiat:
    """Atrapy srodowisk: Dom 1 z petla liczaca obiegi, dom testowy z petla,
    ktora rzuca, dopoki `psuj` jest prawda. `budowy` liczy zbudowane srodowiska."""

    def __init__(self) -> None:
        self.obiegi = {DOM_1: 0, DOM_T: 0}
        self.psuj = {DOM_1: False, DOM_T: True}
        #: Czy petla domu dotyka tetna (jak tick_loop po udanym tiku).
        self.tik = {DOM_1: True, DOM_T: True}
        #: Okres tiku srodowiska; duzy = bez sprawdzania tetna (skoki zegara
        #: w testach odstepow nie moga udawac stojacego tiku).
        self.okres = {DOM_1: 1e9, DOM_T: 1e9}
        self.budowy: list[int] = []
        self.kolejki: dict[int, list[Kolejka]] = {DOM_1: [], DOM_T: []}
        self.alarmy: list[tuple[str, str]] = []
        self.tetna = 0
        self.zegar = Zegar()

    def srodowisko(self, dom_id: int, home=None) -> dm.HomeRuntime:
        self.budowy.append(dom_id)
        kolejka = Kolejka()
        self.kolejki[dom_id].append(kolejka)
        rt = dm.HomeRuntime(dom_id, home or f"home-{dom_id}", Nic(), None, kolejka, Nic())  # type: ignore[arg-type]

        async def petla():
            while True:
                self.obiegi[dom_id] += 1
                if self.psuj[dom_id]:
                    raise RuntimeError("awaria petli domu")
                if self.tik[dom_id]:
                    rt.tetno = self.zegar()
                await asyncio.sleep(0.005)

        rt.okres_tiku = self.okres[dom_id]
        rt.dodaj_petle("petla", petla)
        return rt

    async def alarm(self, tytul: str, tresc: str) -> None:
        self.alarmy.append((tytul, tresc))

    def tetno(self) -> None:
        self.tetna += 1

    def nadzorca(self, *, izolacja: bool = True) -> dm.Nadzorca:
        return dm.Nadzorca(
            [self.srodowisko(DOM_1), self.srodowisko(DOM_T)],
            flush_seconds=0.1,
            odbuduj=self.srodowisko if izolacja else None,
            alarm=self.alarm,
            tetno_procesu=self.tetno,
            zegar=self.zegar,
            okres_nadzoru=0.01,
        )


async def _czekaj(warunek, limit=3.0):
    for _ in range(int(limit / 0.01)):
        if warunek():
            return
        await asyncio.sleep(0.01)
    raise AssertionError("warunek nie spelniony")


async def _uruchom(swiat: Swiat, n: dm.Nadzorca):
    stop = asyncio.Event()
    zadanie = asyncio.create_task(n.run(stop))
    return stop, zadanie


async def test_awaria_domu_testowego_nie_przerywa_domu_1():
    s = Swiat()
    n = s.nadzorca()
    stop, zadanie = await _uruchom(s, n)
    await _czekaj(lambda: DOM_T in n._restarty)
    przed = s.obiegi[DOM_1]
    await asyncio.sleep(0.1)
    # Dom 1 dalej pracuje, proces trwa, dom testowy czeka na restart.
    assert s.obiegi[DOM_1] > przed
    assert not zadanie.done()
    assert [rt.dom_id for rt in n.domy] == [DOM_1]
    # Alarm instancji (od razu) i czujka w kolejce domu testowego.
    assert len(s.alarmy) == 1 and s.alarmy[0][0] == "Dom 2: awaria monitoringu"
    assert "RuntimeError" in s.alarmy[0][1] and "1 min" in s.alarmy[0][1]
    czujki = s.kolejki[DOM_T][0].notki
    assert len(czujki) == 1 and czujki[0].kind == NotifyKind.WATCHDOG
    assert s.kolejki[DOM_1][0].notki == []
    assert s.tetna > 0
    stop.set()
    assert await zadanie == 0


async def test_restart_z_narastajacym_odstepem_i_alarmy_rzadziej():
    s = Swiat()
    n = s.nadzorca()
    stop, zadanie = await _uruchom(s, n)
    await _czekaj(lambda: DOM_T in n._restarty)
    kiedy = n._restarty[DOM_T][0]
    assert kiedy - s.zegar.t == dm.RESTART_PIERWSZY
    # Przed terminem — bez restartu.
    s.zegar.t += 30
    await asyncio.sleep(0.05)
    assert s.budowy.count(DOM_T) == 1
    # Po terminie — nowe srodowisko, znowu pada: odstep 2 min, bez drugiego alarmu.
    s.zegar.t += 31
    await _czekaj(lambda: s.budowy.count(DOM_T) == 2 and DOM_T in n._restarty)
    assert n._restarty[DOM_T][0] - s.zegar.t == 2 * dm.RESTART_PIERWSZY
    assert len(s.alarmy) == 1
    # Kolejne proby: 4, 8, 16, 30, 30 min.
    odstepy = []
    for _ in range(5):
        s.zegar.t = n._restarty[DOM_T][0]
        budowy = s.budowy.count(DOM_T)
        await _czekaj(lambda b=budowy: s.budowy.count(DOM_T) == b + 1 and DOM_T in n._restarty)
        odstepy.append(n._restarty[DOM_T][0] - s.zegar.t)
    assert odstepy == [240.0, 480.0, 960.0, 1800.0, 1800.0]
    # Po godzinie od pierwszego alarmu — nastepny (seria nadal trwa).
    assert len(s.alarmy) == 2
    # Naprawa: dom wstaje i zostaje.
    s.psuj[DOM_T] = False
    s.zegar.t = n._restarty[DOM_T][0]
    await _czekaj(lambda: [rt.dom_id for rt in n.domy] == [DOM_1, DOM_T])
    obiegi = s.obiegi[DOM_T]
    await asyncio.sleep(0.05)
    assert s.obiegi[DOM_T] > obiegi
    stop.set()
    assert await zadanie == 0


async def test_seria_konczy_sie_po_spokoju():
    s = Swiat()
    n = s.nadzorca()
    stop, zadanie = await _uruchom(s, n)
    await _czekaj(lambda: DOM_T in n._restarty)
    s.psuj[DOM_T] = False
    s.zegar.t = n._restarty[DOM_T][0]
    await _czekaj(lambda: len(n.domy) == 2)
    # Pol godziny spokoju, potem nowa awaria: odstep znow 1 min i alarm od razu.
    s.zegar.t += dm.RESTART_STABILNY
    s.psuj[DOM_T] = True
    await _czekaj(lambda: DOM_T in n._restarty)
    assert n._restarty[DOM_T][0] - s.zegar.t == dm.RESTART_PIERWSZY
    assert len(s.alarmy) == 2
    stop.set()
    await zadanie


async def test_tik_stojacy_restartuje_tylko_ten_dom():
    s = Swiat()
    s.psuj[DOM_T] = False
    s.tik[DOM_T] = False  # petla zyje, ale tik nie przechodzi
    s.okres[DOM_T] = 30.0
    n = s.nadzorca()
    stop, zadanie = await _uruchom(s, n)
    await _czekaj(lambda: s.obiegi[DOM_T] > 0)  # nadzorca wystartowal srodowiska
    dom1 = n.domy[0]
    # Dom testowy cichy od ponad 3x okresu (Dom 1 bez limitu w atrapie).
    s.zegar.t += 3 * 30 + 1
    await _czekaj(lambda: DOM_T in n._restarty)
    assert n.domy == [dom1]
    assert "tik stoi" in s.alarmy[0][1]
    stop.set()
    await zadanie


async def test_nieudana_budowa_przy_restarcie_planuje_kolejny():
    s = Swiat()
    n = s.nadzorca()
    stop, zadanie = await _uruchom(s, n)
    await _czekaj(lambda: DOM_T in n._restarty)

    def zepsuta(dom_id, home):
        raise ValueError("brak sekretu")

    n.odbuduj = zepsuta
    s.zegar.t = n._restarty[DOM_T][0]
    await _czekaj(lambda: DOM_T in n._restarty and n._restarty[DOM_T][0] > s.zegar.t + 61)
    assert not zadanie.done() and [rt.dom_id for rt in n.domy] == [DOM_1]
    stop.set()
    await zadanie


async def test_kanarek_bez_izolacji_awaria_konczy_proces():
    """§4.4 p. 8: nadzorca E1 (bez `odbuduj`) — ta sama awaria domu
    testowego konczy caly proces kodem 1, a Dom 1 staje. Gdyby test izolacji
    nie odroznial tych zachowan, niczego by nie dowodzil."""
    s = Swiat()
    n = s.nadzorca(izolacja=False)
    rc = await asyncio.wait_for(n.run(asyncio.Event()), timeout=3)
    assert rc == 1
    assert s.alarmy == [] and s.budowy == [DOM_1, DOM_T]


async def test_tick_loop_dotyka_tetna_domu_a_nie_pliku(tmp_path):
    """build_home_runtime: tik dotyka tetna DOMU; plik liveness tylko na zyczenie."""
    from kidwatch.scheduler import tick_loop

    class Silnik:
        def tick(self):
            return []

    class Baza:
        def get_meta(self, key):
            return "2999-01-01T00:00:00.000000+00:00"

    dotkniete = []
    plik = tmp_path / "hb"
    await tick_loop(Silnik(), Kolejka(), Baza(), max_iterations=2, sleep=lambda s: asyncio.sleep(0),
                    heartbeat_path=None, tetno=lambda: dotkniete.append(1))
    assert len(dotkniete) == 2 and not plik.exists()
    await tick_loop(Silnik(), Kolejka(), Baza(), max_iterations=1, sleep=lambda s: asyncio.sleep(0),
                    heartbeat_path=plik)
    assert plik.exists()
