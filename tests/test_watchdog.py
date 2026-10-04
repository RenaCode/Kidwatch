"""Testy czujki wlasnej niesprawnosci.

Na iPadach bez nadzoru to jedyny mechanizm, ktory odroznia "dziecko nie uzywa
iPada" od "dziecko zdjelo profil DNS". Bez niego wylaczenie DNS-a jest
niewidoczne, a serwis milczy i wyglada na sprawny.
"""

from __future__ import annotations

from datetime import timedelta

from conftest import ev, local, make_config
from kidwatch.engine import Engine
from kidwatch.models import NotifyKind
from kidwatch.store import Store


def _wd(notes):
    return [n for n in notes if n.kind is NotifyKind.WATCHDOG]


# ============================================================== cisza strumienia
def test_bez_zadnego_zdarzenia_czujka_milczy(engine):
    """Swiezy start to nie awaria — nie ma jeszcze czego porownac."""
    assert _wd(engine.tick(local(2026, 9, 27, 12, 0))) == []


def test_cisza_calego_strumienia_podnosi_alarm(engine):
    t = local(2026, 9, 27, 12, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com"))

    assert _wd(engine.tick(t + timedelta(minutes=19))) == []

    notes = _wd(engine.tick(t + timedelta(minutes=21)))
    assert len(notes) == 1
    assert "nie widzi ruchu DNS" in notes[0].title
    assert notes[0].priority == 4
    # Tresc musi mowic, dlaczego cisza to awaria, a nie brak aktywnosci.
    assert "spiac" in notes[0].text


def test_alarm_o_ciszy_nie_powtarza_sie_na_kazdym_tiku(engine):
    t = local(2026, 9, 27, 12, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com"))
    assert len(_wd(engine.tick(t + timedelta(minutes=21)))) == 1
    # Kolejne tiki w ciagu nastepnych 20 minut: cisza.
    assert _wd(engine.tick(t + timedelta(minutes=25))) == []
    assert _wd(engine.tick(t + timedelta(minutes=39))) == []


def test_odstep_powtorzen_rosnie_wykladniczo(engine):
    """Jedna awaria nie moze zrobic 10 maili na dobe — odstep sie podwaja."""
    t = local(2026, 9, 27, 12, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com"))

    assert len(_wd(engine.tick(t + timedelta(minutes=21)))) == 1        # 1. alarm
    assert len(_wd(engine.tick(t + timedelta(minutes=41)))) == 1        # po 20 min
    assert _wd(engine.tick(t + timedelta(minutes=70))) == []            # 40 min jeszcze nie minelo
    assert len(_wd(engine.tick(t + timedelta(minutes=82)))) == 1        # po 40 min
    assert _wd(engine.tick(t + timedelta(minutes=130))) == []           # czeka 80 min
    assert len(_wd(engine.tick(t + timedelta(minutes=165)))) == 1       # po 80 min


def test_odstep_powtorzen_ma_sufit(classifier):
    cfg = make_config(watchdog={"repeat_backoff_max_minutes": 60})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 12, 0)
    eng.handle(ev(t, "gsp-ssl.ls.apple.com"))
    for _ in range(6):
        eng.tick(t)
        t += timedelta(minutes=61)
        assert len(_wd(eng.tick(t))) == 1, "po przekroczeniu sufitu odstep zostaje na 60 min"


def test_powrot_strumienia_jest_zglaszany(engine):
    t = local(2026, 9, 27, 12, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com"))
    assert len(_wd(engine.tick(t + timedelta(minutes=21)))) == 1

    # Ruch wraca.
    engine.handle(ev(t + timedelta(minutes=30), "gsp-ssl.ls.apple.com"))
    notes = _wd(engine.tick(t + timedelta(minutes=31)))
    assert len(notes) == 1
    assert "znowu widzi" in notes[0].title
    # I nie powtarza sie w nieskonczonosc.
    assert _wd(engine.tick(t + timedelta(minutes=32))) == []


# ============================================================ cisza urzadzenia
def test_milczace_urzadzenie_przy_zywym_strumieniu_to_alarm(engine):
    """Najwazniejszy test w projekcie: tak wyglada zdjety profil DNS."""
    t = local(2026, 9, 27, 8, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-zosi"))

    # Zosia raportuje dalej, Kuba zamilkl.
    now = t
    for i in range(1, 13):
        now = t + timedelta(minutes=i * 15)
        engine.handle(ev(now, "gsp-ssl.ls.apple.com", device="ipad-zosi"))

    notes = _wd(engine.tick(now))
    assert len(notes) == 1
    assert "iPad Kuby nie zglasza sie" in notes[0].title
    assert "zdjety profil" in notes[0].text
    # Zosia jest zdrowa, o niej nie ma alarmu.
    assert "Zosi" not in notes[0].title


def test_urzadzenie_ma_prawo_milczec_krocej_niz_prog(engine):
    t = local(2026, 9, 27, 8, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    now = t
    for i in range(1, 9):  # 2 godziny, prog to 3
        now = t + timedelta(minutes=i * 15)
        engine.handle(ev(now, "gsp-ssl.ls.apple.com", device="ipad-zosi"))
    assert _wd(engine.tick(now)) == []


def test_w_cichych_godzinach_nie_alarmujemy_o_milczacym_ipadzie(engine):
    """Noca iPad ma prawo byc wylaczony — alarm o tym budzilby bez powodu."""
    t = local(2026, 9, 27, 18, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    now = t
    for i in range(1, 33):  # do 2:00 w nocy
        now = t + timedelta(minutes=i * 15)
        engine.handle(ev(now, "gsp-ssl.ls.apple.com", device="ipad-zosi"))

    assert now.astimezone(now.tzinfo).hour >= 22 or now.hour < 7
    assert _wd(engine.tick(now)) == []


def test_alarm_o_urzadzeniu_wraca_po_cichych_godzinach(classifier):
    cfg = make_config(watchdog={"device_silence_ignore_quiet_hours": False})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 22, 0)
    eng.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    now = t
    for i in range(1, 15):
        now = t + timedelta(minutes=i * 15)
        eng.handle(ev(now, "gsp-ssl.ls.apple.com", device="ipad-zosi"))
    # Z wylaczonym wyjatkiem alarm pada takze noca.
    assert len(_wd(eng.tick(now))) == 1


def test_padniety_strumien_nie_generuje_alarmow_o_kazdym_urzadzeniu(engine):
    """Gdy padnie zrodlo, kazdy iPad milczy. Jeden alarm, nie trzy."""
    t = local(2026, 9, 27, 8, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-zosi"))

    notes = _wd(engine.tick(t + timedelta(hours=6)))
    assert len(notes) == 1
    assert "nie widzi ruchu DNS" in notes[0].title


def test_powrot_urzadzenia_jest_zglaszany(engine):
    t = local(2026, 9, 27, 8, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    now = t
    for i in range(1, 13):
        now = t + timedelta(minutes=i * 15)
        engine.handle(ev(now, "gsp-ssl.ls.apple.com", device="ipad-zosi"))
    assert len(_wd(engine.tick(now))) == 1

    # Kuba wraca do logow.
    engine.handle(ev(now + timedelta(minutes=1), "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    notes = _wd(engine.tick(now + timedelta(minutes=2)))
    assert len(notes) == 1
    assert "iPad Kuby znowu widoczny" in notes[0].title


def test_czujke_da_sie_wylaczyc(classifier):
    cfg = make_config(watchdog={"enabled": False})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 12, 0)
    eng.handle(ev(t, "gsp-ssl.ls.apple.com"))
    assert _wd(eng.tick(t + timedelta(days=1))) == []


# ================================ audyt 3, K1: druga awaria w ciagu 7 dni
def test_druga_awaria_strumienia_tego_samego_dnia_daje_alarm_i_powrot(engine):
    """Klucz dedupu mial sam licznik zgloszen (`wd:stream:0`), zerowany po
    powrocie, a `sent` trzyma klucze 7 dni. Druga awaria trafiala na zajety
    klucz: ani alarmu, ani "wrocilo"."""
    t = local(2026, 9, 27, 12, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com"))
    assert len(_wd(engine.tick(t + timedelta(minutes=21)))) == 1
    t2 = t + timedelta(minutes=30)
    engine.handle(ev(t2, "gsp-ssl.ls.apple.com"))
    assert [n.title for n in _wd(engine.tick(t2 + timedelta(minutes=1)))] == [
        "kidwatch znowu widzi ruch DNS"
    ]

    second = _wd(engine.tick(t2 + timedelta(minutes=25)))
    assert [n.title for n in second] == ["kidwatch nie widzi ruchu DNS"]
    assert "przypomnienie" not in second[0].text  # nowy epizod, nie przypomnienie
    t3 = t2 + timedelta(minutes=40)
    engine.handle(ev(t3, "gsp-ssl.ls.apple.com"))
    assert [n.title for n in _wd(engine.tick(t3 + timedelta(minutes=1)))] == [
        "kidwatch znowu widzi ruch DNS"
    ]


def test_druga_cisza_iPada_w_tygodniu_daje_alarm(store, classifier):
    cfg = make_config(watchdog={"device_silence_ignore_quiet_hours": False})
    engine = Engine(cfg, store, classifier)
    t = local(2026, 9, 27, 8, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
    titles = []
    for day in range(3):  # cisza iPada Kuby, inne urzadzenia raportuja
        base = t + timedelta(days=day)
        for minute in range(0, 200, 10):
            now = base + timedelta(minutes=minute)
            engine.handle(ev(now, "gsp-ssl.ls.apple.com", device="ipad-zosi"))
            titles += [n.title for n in _wd(engine.tick(now))]
        # wieczorem iPad Kuby wraca
        back = base + timedelta(hours=12)
        engine.handle(ev(back, "gsp-ssl.ls.apple.com", device="ipad-kuby"))
        engine.handle(ev(back, "gsp-ssl.ls.apple.com", device="ipad-zosi"))
        titles += [n.title for n in _wd(engine.tick(back))]
    alarms = [x for x in titles if "nie zglasza sie" in x]
    backs = [x for x in titles if "znowu widoczny" in x]
    assert len(alarms) >= 3 and len(backs) == 3
