# ruff: noqa: F811 — fixtury kek/dom importowane z test_domy_e2 i test_przeladowanie
"""Poprawki po drugim przegladzie Kidwatch#60: alarm startu bez kopii
(odstep z dziennika, blad bramki), tresc alarmow, kopia przy rotacji klucza
domu i w `domy --sprawdz`, zamykanie klienta MDM panelu.

Dane generyczne, sekrety z secrets.token_*."""

from __future__ import annotations

import json
import secrets
import sqlite3

from kidwatch import domy as dm
from kidwatch.__main__ import start_domu_z_bazy
from kidwatch.panel_domy import DomyPanelu
from test_domy_e2 import kek  # noqa: F401 — fikstura KIDWATCH_KEK
from test_przeladowanie import DOM, Uklad, _czekaj, _rozwiaz, dom  # noqa: F401


def _zepsuj_biezaca(d) -> None:
    d["rejestr"].zapisz_integracje(DOM, "nextdns", sejf=d["sejf"], sekrety={"api_key": None},
                                   resolver=_rozwiaz)


def _alarmy_startu(rejestr) -> int:
    with sqlite3.connect(rejestr.path) as conn:
        return conn.execute("SELECT COUNT(*) FROM audyt WHERE akcja = 'dom.start.alarm'"
                            ).fetchone()[0]


# ================================================ 1. blad bramki przy kodzie 2
async def test_start_bez_kopii_blad_bramki_nie_zmienia_kodu_2(dom):
    _zepsuj_biezaca(dom)

    async def bramka_lezy(tytul, tresc):
        raise TimeoutError("bramka nie odpowiada")

    assert await start_domu_z_bazy(dom["rejestr"], dom["inst"], dm.StanyDomow(),
                                   bramka_lezy, DOM) is None


# ============================================ 2. CrashLoop: odstep z dziennika
async def test_crashloop_bez_kopii_alarm_z_odstepem_nie_co_restart(dom):
    _zepsuj_biezaca(dom)
    alarmy = []

    async def alarm(tytul, tresc):
        alarmy.append(tytul)

    for _ in range(5):  # piec restartow poda pod rzad
        assert await start_domu_z_bazy(dom["rejestr"], dom["inst"], dm.StanyDomow(),
                                       alarm, DOM) is None
    assert alarmy == ["Dom 2: Kidwatch nie wystartowal"]
    assert _alarmy_startu(dom["rejestr"]) == 1


def test_bramka_alarmu_startu_rosnacy_odstep(dom):
    r = dom["rejestr"]
    t = 1_000_000.0
    assert r.alarm_startu(DOM, t)                # pierwszy: od razu
    assert not r.alarm_startu(DOM, t + 3599)     # przed 1 h — nie
    assert r.alarm_startu(DOM, t + 3600)         # po 1 h
    assert not r.alarm_startu(DOM, t + 3600 + 7199)
    assert r.alarm_startu(DOM, t + 3600 + 7200)  # potem po 2 h
    t2 = t + 3600 + 7200
    assert not r.alarm_startu(DOM, t2 + 14399)
    assert r.alarm_startu(DOM, t2 + 14400)       # 4 h
    # Przerwa dluzsza niz dwie doby = nowa awaria: odstep znowu 1 h.
    t3 = t2 + 14400 + 3 * 24 * 3600
    assert r.alarm_startu(DOM, t3)
    assert not r.alarm_startu(DOM, t3 + 3599)
    assert r.alarm_startu(DOM, t3 + 3600)


def test_bramka_alarmu_startu_odstep_najwyzej_doba(dom):
    r = dom["rejestr"]
    t = 2_000_000.0
    odstep = 3600.0
    assert r.alarm_startu(DOM, t)
    for _ in range(8):
        t += odstep
        assert r.alarm_startu(DOM, t)
        odstep = min(odstep * 2, 24 * 3600)
    assert not r.alarm_startu(DOM, t + 24 * 3600 - 1)
    assert r.alarm_startu(DOM, t + 24 * 3600)


# ===================================================== 3. tresc alarmu
def test_opis_bledu_tylko_typ_dla_nieznanych():
    from pydantic import BaseModel, ValidationError  # noqa: PLC0415

    from kidwatch.config import MissingSecretError  # noqa: PLC0415
    from kidwatch.straznik import OdmowaSieci  # noqa: PLC0415

    tajne = "TAJNE-" + secrets.token_hex(8)

    class M(BaseModel):
        x: int

    try:
        M(x=tajne)
    except ValidationError as exc:
        walidacja = exc
    for nieznany in (RuntimeError(f"cos z {tajne}"), KeyError(tajne), walidacja,
                     OSError(f"polaczenie {tajne}")):
        opis = dm.opis_bledu(nieznany)
        assert tajne not in opis and type(nieznany).__name__ in opis, opis
    assert dm.opis_bledu(MissingSecretError("Dom 2: brak sekretu x")) == "Dom 2: brak sekretu x"
    assert dm.opis_bledu(OdmowaSieci("adres poza siecia")) == "adres poza siecia"
    assert dm.opis_bledu(ValueError("zly model")) == "zly model"


async def test_alarm_startu_bez_tresci_nieznanego_wyjatku(dom, monkeypatch):
    import kidwatch.__main__ as cli  # noqa: PLC0415

    tajne = "TAJNE-" + secrets.token_hex(8)

    def wybuch(rejestr, dom_id):
        raise RuntimeError(f"polaczenie z {tajne}")

    monkeypatch.setattr(cli, "home_domu_z_bazy", wybuch)
    alarmy = []

    async def alarm(tytul, tresc):
        alarmy.append(tresc)

    assert await start_domu_z_bazy(dom["rejestr"], dom["inst"], dm.StanyDomow(),
                                   alarm, DOM) is None
    assert alarmy and "RuntimeError" in alarmy[0] and tajne not in alarmy[0]


async def test_alarm_nadzorcy_bez_tresci_nieznanego_wyjatku():
    tajne = "TAJNE-" + secrets.token_hex(8)
    u = Uklad({2: RuntimeError(f"cos z {tajne}")})
    tresci = []

    async def alarm(tytul, tresc):
        tresci.append(tresc)

    u.p.alarm = alarm
    await u.start()
    u.wersja[DOM] = 2
    await _czekaj(lambda: tresci)
    assert "RuntimeError" in tresci[0] and tajne not in tresci[0]
    # Stan dla panelu (administrator) dalej ma pelny opis.
    assert tajne in u.stan().blad
    u.zegar.t += 3600
    await _czekaj(lambda: len(tresci) == 2)
    assert tajne not in tresci[1]
    assert await u.koniec() == 0


# ============================================ 4. rotacja klucza domu a kopia
def _zepsuj_kopie(rejestr) -> None:
    with sqlite3.connect(rejestr.path) as conn:
        dane = json.loads(conn.execute("SELECT dane FROM domy_kopia WHERE dom_id = ?",
                                       (DOM,)).fetchone()[0])
        for i in dane["integracje"]:
            if i["sekrety"]:
                i["sekrety"] = secrets.token_bytes(40).hex()
        conn.execute("UPDATE domy_kopia SET dane = ? WHERE dom_id = ?",
                     (json.dumps(dane), DOM))


def test_rotacja_klucza_z_zepsuta_kopia_usuwa_kopie_zamiast_wycofac(dom):
    r, sejf = dom["rejestr"], dom["sejf"]
    assert r.zapamietaj_dobra(DOM, r.dom(DOM).wersja)
    _zepsuj_kopie(r)
    assert r.rotuj_dek(DOM, sejf) == ["nextdns"]
    # Rotacja przeszla: integracje pod nowym kluczem, kopii nie ma.
    assert r.sekrety_domu(DOM, sejf).get("nextdns", "api_key") == dom["klucz"]
    assert r.kopia_domu(DOM, sejf) is None
    assert any(w["akcja"] == "dom.kopia.usunieta" for w in r.audyt(DOM))


# ================================================ 5. domy --sprawdz a kopia
def test_sprawdz_raport_obejmuje_kopie(dom):
    r, sejf = dom["rejestr"], dom["sejf"]
    assert r.zapamietaj_dobra(DOM, r.dom(DOM).wersja)
    raport = r.sprawdz_raport(sejf)
    assert raport.potwierdzone and raport.kopie == 1
    _zepsuj_kopie(r)
    raport = r.sprawdz_raport(sejf)
    assert not raport.potwierdzone
    assert [(d, t) for d, t, _ in raport.bledy] == [(DOM, "kopia:nextdns")]


# ============================================== 6. klient MDM po przeladowaniu
def test_zapomnij_zamyka_klienta_mdm(tmp_path):
    zamkniete = []

    class Api:
        def close(self):
            zamkniete.append(True)

    class Zapytania:
        def __init__(self):
            self.mdm = Api()

    domy = DomyPanelu(str(tmp_path / "panel-auth.db"), lambda dom: Zapytania())
    domy.rejestr.migruj()
    domy.queries(domy.rejestr.dom(1))
    domy.zapomnij(1)
    assert zamkniete == [True]
    domy.zapomnij(1)  # nic do zamkniecia
    assert zamkniete == [True]
