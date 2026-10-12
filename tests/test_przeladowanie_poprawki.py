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


def _wyslij(r, t) -> bool:
    """Restart poda o czasie t: alarm, jesli bramka odstepu pozwala, i wpis
    po udanej wysylce (jak start_domu_z_bazy)."""
    odstep = r.alarm_startu(DOM, t)
    if odstep is None:
        return False
    r.zapisz_alarm_startu(DOM, odstep, "test", t)
    return True


def test_bramka_alarmu_startu_rosnacy_odstep(dom):
    r = dom["rejestr"]
    t = 1_000_000.0
    assert _wyslij(r, t)                 # pierwszy: od razu
    assert not _wyslij(r, t + 3599)      # przed 1 h — nie
    assert _wyslij(r, t + 3600)          # po 1 h
    assert not _wyslij(r, t + 3600 + 7199)
    assert _wyslij(r, t + 3600 + 7200)   # potem po 2 h
    t2 = t + 3600 + 7200
    assert not _wyslij(r, t2 + 14399)
    assert _wyslij(r, t2 + 14400)        # 4 h
    # Przerwa dluzsza niz dwie doby = nowa awaria: odstep znowu 1 h.
    t3 = t2 + 14400 + 3 * 24 * 3600
    assert _wyslij(r, t3)
    assert not _wyslij(r, t3 + 3599)
    assert _wyslij(r, t3 + 3600)


def test_bramka_alarmu_startu_odstep_najwyzej_doba(dom):
    r = dom["rejestr"]
    t = 2_000_000.0
    odstep = 3600.0
    assert _wyslij(r, t)
    for _ in range(8):
        t += odstep
        assert _wyslij(r, t)
        odstep = min(odstep * 2, 24 * 3600)
    assert not _wyslij(r, t + 24 * 3600 - 1)
    assert _wyslij(r, t + 24 * 3600)


def test_udany_start_konczy_awarie_alarm_nowej_od_razu(dom):
    """Przypadek z przegladu: awaria A 36 h, 6 h pracy, awaria B — alarm o B
    ma isc od razu, nie po resztce odstepu z A."""
    r = dom["rejestr"]
    t = 3_000_000.0
    for krok in range(0, 36 * 3600, 600):   # A: restart co 10 min przez 36 h
        _wyslij(r, t + krok)
    t_ok = t + 36 * 3600
    assert r.zapisz_start_ok(DOM, 5, t_ok)            # pod wstal
    assert not r.zapisz_start_ok(DOM, 5, t_ok + 60)   # bez awarii — bez wpisu
    assert _wyslij(r, t_ok + 6 * 3600)                # B: od razu
    assert not _wyslij(r, t_ok + 6 * 3600 + 600)      # i dalej z odstepem od 1 h
    assert _wyslij(r, t_ok + 7 * 3600)


async def test_udany_start_poda_konczy_awarie_na_prawdziwym_starcie(dom):
    r = dom["rejestr"]
    alarmy = []

    async def alarm(tytul, tresc):
        alarmy.append(tytul)

    _zepsuj_biezaca(dom)
    assert await start_domu_z_bazy(r, dom["inst"], dm.StanyDomow(), alarm, DOM) is None
    # Naprawa i udany start (wpis dom.start.ok), potem nowa awaria.
    r.zapisz_integracje(DOM, "nextdns", sejf=dom["sejf"], sekrety={"api_key": dom["klucz"]},
                        resolver=_rozwiaz)
    rt = await start_domu_z_bazy(r, dom["inst"], dm.StanyDomow(), alarm, DOM)
    assert rt is not None
    await rt.zamknij(0.1)
    with sqlite3.connect(r.path) as conn:
        conn.execute("DELETE FROM domy_kopia")  # bez kopii: znow kod 2
    _zepsuj_biezaca(dom)
    assert await start_domu_z_bazy(r, dom["inst"], dm.StanyDomow(), alarm, DOM) is None
    assert alarmy == ["Dom 2: Kidwatch nie wystartowal"] * 2


async def test_nieudana_wysylka_nie_blokuje_odstepu(dom):
    _zepsuj_biezaca(dom)
    proby = []

    async def lezy(tytul, tresc):
        proby.append(tytul)
        raise TimeoutError("bramka")

    for _ in range(3):
        assert await start_domu_z_bazy(dom["rejestr"], dom["inst"], dm.StanyDomow(),
                                       lezy, DOM) is None
    # Zadnego wpisu — kazdy restart probuje znowu, az alarm wyjdzie.
    assert len(proby) == 3 and _alarmy_startu(dom["rejestr"]) == 0


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


# ===================================== komunikaty CLI: kiedy zmiana dziala
def test_kiedy_zadziala_tylko_dom_1_w_bazie_bez_restartu(monkeypatch):
    from kidwatch.__main__ import kiedy_zadziala  # noqa: PLC0415

    monkeypatch.delenv("KIDWATCH_DOM_1_ZRODLO", raising=False)
    szybko = ("Zadziala w ciagu ok. 10 s, bez restartu poda (przeladowanie domu), "
              "jesli Kidwatch dziala juz w trybie baza; inaczej po restarcie poda.")
    restart = "Dziala po restarcie poda."
    assert kiedy_zadziala(1, True, True) == szybko
    assert kiedy_zadziala(1, False, True) == restart   # yaml -> baza: pod chodzi na yaml
    assert kiedy_zadziala(1, True, False) == restart   # baza -> yaml
    assert kiedy_zadziala(2, True, True) == restart    # kolejne domy: E3b
    monkeypatch.setenv("KIDWATCH_DOM_1_ZRODLO", "yaml")
    assert kiedy_zadziala(1, True, True) == restart    # wymuszony config.yaml


def test_dom_sieci_komunikat_zalezy_od_trybu_domu(tmp_path, kek, capsys, monkeypatch):
    import kidwatch.__main__ as cli  # noqa: PLC0415
    from test_domy_e2 import _prosta, _zapisz_konfig  # noqa: PLC0415

    monkeypatch.delenv("KIDWATCH_DOM_1_ZRODLO", raising=False)
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    argv = ["--config", str(cfg_path), "dom-sieci", "1", "--dodaj", "192.0.2.0/24"]
    assert cli.main(argv) == 0
    assert "Dziala po restarcie poda." in capsys.readouterr().out
    dm.RejestrDomow(tmp_path / "panel-auth.db").ustaw_zrodlo(1, dm.ZRODLO_BAZA)
    assert cli.main([*argv[:4], "--dodaj", "198.51.100.0/24"]) == 0
    out = capsys.readouterr().out
    assert "Zadziala w ciagu ok. 10 s, bez restartu poda" in out and "E3b" not in out


# =============================== powtorka alarmu po starcie z kopii (przeciek)
async def test_powtorka_alarmu_po_starcie_z_kopii_bez_tresci_wyjatku(dom, monkeypatch):
    import kidwatch.__main__ as cli  # noqa: PLC0415

    r = dom["rejestr"]
    rt = await start_domu_z_bazy(r, dom["inst"], dm.StanyDomow(), None, DOM)  # kopia
    await rt.zamknij(0.1)
    dobra = r.dom(DOM).wersja
    tajne = "SEKRET-" + secrets.token_hex(8)

    def wybuch(rejestr, dom_id):
        raise KeyError(tajne)

    monkeypatch.setattr(cli, "home_domu_z_bazy", wybuch)
    stany = dm.StanyDomow()
    tresci = []

    async def alarm(tytul, tresc):
        tresci.append(tresc)

    rt = await start_domu_z_bazy(r, dom["inst"], stany, alarm, DOM)
    assert rt is not None and rt.wersja == dobra
    await rt.zamknij(0.1)
    assert tajne in stany.get(DOM).blad          # panel: pelny opis
    # Nadzorca startuje z tym stanem; po 1 h powtorka alarmu.
    u = Uklad({})
    u.p.stany = stany
    u.p.alarm = alarm
    u.nadzorca.domy[0].wersja = dobra
    u.wersja[DOM] = stany.get(DOM).nieudana
    await u.start()
    await _czekaj(lambda: DOM in u.nadzorca._alarmy)  # nadzorca przejal stan ze startu
    u.zegar.t += 3600
    await _czekaj(lambda: len(tresci) == 2)
    assert "KeyError" in tresci[1] and all(tajne not in t for t in tresci), tresci
    assert await u.koniec() == 0


def test_rotacja_z_nieczytelna_kopia_json(dom):
    r, sejf = dom["rejestr"], dom["sejf"]
    assert r.zapamietaj_dobra(DOM, r.dom(DOM).wersja)
    with sqlite3.connect(r.path) as conn:
        conn.execute("UPDATE domy_kopia SET dane = '{\"bez\": 1}' WHERE dom_id = ?", (DOM,))
    assert r.rotuj_dek(DOM, sejf) == ["nextdns"]
    assert r.kopia_domu(DOM, sejf) is None
    raport = r.sprawdz_raport(sejf)
    assert raport.potwierdzone and raport.kopie == 0


# ============================== trzeci przeglad: koniec awarii i klucze-potwierdz
def _otworz_awarie(r, t: float) -> None:
    assert _wyslij(r, t)
    assert r.alarm_startu(DOM, t + 60) is None  # awaria otwarta: odstep trwa


async def test_start_z_yaml_konczy_awarie_startu(tmp_path, monkeypatch):
    """A (baza, alarm) -> start ratunkowy z config.yaml -> B = alarm od razu."""
    import kidwatch.__main__ as cli  # noqa: PLC0415
    from test_przeladowanie import _config  # noqa: PLC0415

    cfg = _config(tmp_path)
    inst, home = cfg.split()
    r = dm.RejestrDomow(cfg.panel_auth_path)
    r.migruj()
    t = 4_000_000.0
    assert r.alarm_startu(1, t) is not None
    r.zapisz_alarm_startu(1, 3600.0, "A", t)
    assert r.alarm_startu(1, t + 60) is None
    monkeypatch.setattr(cli, "build_home_runtime", lambda *a, **k: object())
    await cli.start_domu_z_yaml(r, inst, home, None)
    assert r.alarm_startu(1, t + 120) is not None


async def test_naprawa_po_starcie_z_kopii_konczy_awarie(dom):
    """Nadzorca przeladowal dom na dobra wersje po starcie z kopii: wpis
    `dom.start.ok`, nastepna awaria startu alarmuje od razu."""
    r = dom["rejestr"]
    t = 5_000_000.0
    _otworz_awarie(r, t)
    u = Uklad({2: "home-v2"})
    u.p.start_ok = lambda dom_id, w: r.zapisz_start_ok(dom_id, w, t + 100)
    await u.start()
    u.wersja[DOM] = 2
    await _czekaj(lambda: "start home-v2" in u.zdarzenia)
    await _czekaj(lambda: r.alarm_startu(DOM, t + 200) is not None)
    assert await u.koniec() == 0


def test_klucze_potwierdz_blad_kopii_tylko_ostrzezenie(dom, kek, monkeypatch, capsys):
    """Kopia jest pod kluczem domu (DEK), nie KEK — jej blad nie blokuje
    potwierdzenia klucza (ani usuniecia KIDWATCH_KEK_POPRZEDNI)."""
    import base64  # noqa: PLC0415
    import io  # noqa: PLC0415

    import kidwatch.__main__ as cli  # noqa: PLC0415
    from test_domy_e2 import _prosta, _zapisz_konfig  # noqa: PLC0415

    r = dom["rejestr"]
    assert r.zapamietaj_dobra(DOM, r.dom(DOM).wersja)
    _zepsuj_kopie(r)
    (dom["tmp"] / "cfg").mkdir()
    cfg_path = _zapisz_konfig(dom["tmp"] / "cfg", _prosta(dom["tmp"] / "cfg"))
    monkeypatch.setattr("sys.stdin", io.StringIO(base64.b64encode(kek).decode() + "\n"))
    assert cli.main(["--config", str(cfg_path), "klucze-potwierdz", "--baza", r.path]) == 0
    out = capsys.readouterr()
    tekst = out.out + out.err
    assert "UWAGA: kopia ostatniej dobrej konfiguracji nie odszyfrowuje sie" in tekst
    assert "ODMOWA" not in tekst
