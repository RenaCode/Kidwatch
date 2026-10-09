"""Alarm nocnego uzywania i raport tygodniowy."""

from __future__ import annotations

from datetime import UTC, date, time, timedelta
from pathlib import Path

import yaml

from conftest import ev, local, make_config
from kidwatch.__main__ import main, parse_week
from kidwatch.config import Config
from kidwatch.engine import Engine, report_week, week_label
from kidwatch.models import NotifyKind
from kidwatch.notifiers.bramka import kategoria
from kidwatch.store import Store, to_iso

MOON = "\U0001F319"


def night(notes):
    return [n for n in notes if n.kind is NotifyKind.NIGHT or "w nocy" in n.title]


# ======================================================================== noc
def test_start_w_nocy_to_jeden_push_z_obecnoscia(engine):
    t = local(2026, 9, 27, 23, 12)
    engine.store.set_json("presence:iPad Kuby", {
        "home": True, "since": to_iso(t), "checked": to_iso(t), "essid": "dom",
    })
    notes = engine.handle(ev(t, "www.youtube.com"))
    assert len(notes) == 1
    n = notes[0]
    # Alarm, nie informacja o sesji: trasa kidwatch:alarm, rodzina go nie
    # dostaje (audyt 2026-10-09, S5 — wczesniej SESSION_START, trasa rodziny).
    assert n.kind is NotifyKind.NIGHT
    assert kategoria(n.kind) == "alarm"
    assert n.title == f"{MOON} Kuba uzywa iPada w nocy"
    assert n.text == "23:12, YouTube, w domu"
    assert n.priority == 5
    # Tick tuz po starcie nie dubluje pusha.
    assert night(engine.tick(t + timedelta(minutes=1))) == []


def test_nieswieza_obecnosc_nie_trafia_do_pusha(engine):
    t = local(2026, 9, 27, 23, 12)
    old = to_iso(t - timedelta(hours=2))
    engine.store.set_json("presence:iPad Kuby", {"home": False, "since": old, "checked": old})
    assert engine.handle(ev(t, "www.youtube.com"))[0].text == "23:12, YouTube"


def test_przypomnienie_co_30_minut_trwania(engine):
    t = local(2026, 9, 27, 23, 0)
    engine.handle(ev(t, "www.youtube.com"))
    out = []
    for minute in range(1, 66):
        now = t + timedelta(minutes=minute)
        out += engine.handle(ev(now, "ecsv3.roblox.com"))
        out += engine.tick(now)
    reminders = [n for n in out if n.kind is NotifyKind.NIGHT]
    assert [n.ts.astimezone(local(2026, 9, 27, 0, 0).tzinfo).strftime("%H:%M")
            for n in reminders] == ["23:30", "00:00"]
    assert reminders[0].title == f"{MOON} Kuba nadal uzywa iPada w nocy"
    assert "Roblox" in reminders[0].text and "od 23:00" in reminders[0].text
    # Dedup: powtorny tik w tej samej chwili nic nie daje.
    assert engine.tick(t + timedelta(minutes=65)) == []


def test_sesja_zaczeta_wieczorem_dostaje_push_gdy_wejdzie_w_noc(engine):
    t = local(2026, 9, 27, 21, 0)
    first = engine.handle(ev(t, "www.youtube.com"))
    assert "w nocy" not in first[0].title
    out = []
    for minute in range(1, 45):
        now = t + timedelta(minutes=minute)
        out += engine.handle(ev(now, "www.youtube.com"))
        out += engine.tick(now)
    nocne = [n for n in out if n.kind is NotifyKind.NIGHT]
    assert len(nocne) == 1
    assert nocne[0].title == f"{MOON} Kuba uzywa iPada w nocy"
    assert "od 21:00" in nocne[0].text


def test_aktywnosc_przed_noca_w_otwartej_sesji_nie_alarmuje(engine):
    """Sesja otwarta jeszcze przez idle_minutes po ostatniej aktywnosci 21:25
    — o 21:31 dziecko juz nic nie robi i nie ma o czym alarmowac."""
    t = local(2026, 9, 27, 21, 25)
    engine.handle(ev(t, "www.youtube.com"))
    assert night(engine.tick(local(2026, 9, 27, 21, 31))) == []


def test_wlasne_okno_nocy_niezalezne_od_cichych_godzin(classifier):
    cfg = make_config(engine={"quiet_hours": None,
                              "night": {"start": time(23, 0), "end": time(6, 0)}})
    eng = Engine(cfg, Store(":memory:"), classifier)
    assert "w nocy" not in eng.handle(ev(local(2026, 9, 27, 22, 30), "www.youtube.com"))[0].title
    notes = eng.handle(ev(local(2026, 9, 28, 3, 0), "www.youtube.com", device="ipad-zosi"))
    [n] = [x for x in notes if x.dedup_key.startswith("start:")]
    assert n.kind is NotifyKind.NIGHT
    assert n.title == f"{MOON} Zosia uzywa iPada w nocy"
    assert n.priority == 5


def test_noc_wylaczona_bez_przypomnien(classifier):
    cfg = make_config(engine={"night": {"enabled": False}})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 23, 0)
    eng.handle(ev(t, "www.youtube.com"))
    out = []
    for minute in range(1, 40):
        out += eng.handle(ev(t + timedelta(minutes=minute), "www.youtube.com"))
        out += eng.tick(t + timedelta(minutes=minute))
    assert [n for n in out if n.kind is NotifyKind.NIGHT] == []


# ========================================================== raport tygodniowy
def play(engine, start, minutes, domain="www.youtube.com", device="ipad-kuby"):
    for m in range(minutes + 1):
        engine.handle(ev(start + timedelta(minutes=m), domain, device=device))
    engine.tick(start + timedelta(minutes=minutes + 15))


def test_tydzien_raportu():
    assert report_week(date(2026, 10, 4)) == date(2026, 9, 28)   # niedziela: biezacy
    assert report_week(date(2026, 10, 5)) == date(2026, 9, 28)   # poniedzialek: poprzedni
    assert week_label(date(2026, 9, 28)) == "2026-W40"
    assert parse_week("2026-W40") == date(2026, 9, 28)


def test_raport_tygodniowy_tresc(engine):
    # Poprzedni tydzien: 60 min. Biezacy: 30 + 90 min, w tym sesja nocna.
    play(engine, local(2026, 9, 23, 10, 0), 60)
    play(engine, local(2026, 9, 29, 15, 0), 30, "ecsv3.roblox.com")
    play(engine, local(2026, 10, 3, 23, 0), 90)
    note = engine.build_weekly(date(2026, 9, 28), local(2026, 10, 4, 19, 0).astimezone(UTC))
    assert note.kind is NotifyKind.WEEKLY
    assert note.dedup_key == "weekly:2026-W40"
    assert note.title == "Raport tygodnia 28.09–04.10"
    kuba, zosia, note_line = note.text.split("\n\n")
    assert kuba.split("\n") == [
        "*Kuba* — 2 h (+100% wzgledem 1 h)",
        "\u2022 2 sesje, aktywne dni: 2/7",
        "\u2022 najdluzsza sesja: 1 h 30 min (sob 03.10 23:00)",
        "\u2022 w nocy: 1 raz",
        "Top aplikacje:",
        "\u2022 YouTube ~1 h 31 min",
        "\u2022 Roblox ~31 min",
    ]
    assert zosia == "*Zosia* — brak aktywnosci (poprzednio 0)"
    assert note_line.startswith("(czasy szacunkowe")
    # Te same dane w postaci dla panelu.
    sec = note.data["sections"][0]
    assert note.data["type"] == "weekly" and sec["label"] == "Kuba"
    assert sec["apps"][0] == {"app": "YouTube", "minutes": 91}


def test_raport_wychodzi_raz_o_wlasciwej_porze(engine):
    play(engine, local(2026, 9, 29, 15, 0), 30)
    assert [n for n in engine.tick(local(2026, 10, 4, 18, 59)) if n.kind is NotifyKind.WEEKLY] == []
    sent = [n for n in engine.tick(local(2026, 10, 4, 19, 0)) if n.kind is NotifyKind.WEEKLY]
    assert len(sent) == 1
    later = engine.tick(local(2026, 10, 4, 19, 30))
    assert [n for n in later if n.kind is NotifyKind.WEEKLY] == []
    # Inny dzien tygodnia — nic.
    assert [n for n in engine.tick(local(2026, 10, 5, 19, 0)) if n.kind is NotifyKind.WEEKLY] == []


def test_raport_z_telewizorem(engine):
    from kidwatch.config import TvConfig  # noqa: PLC0415

    engine.cfg.tv = TvConfig(enabled=True, host="10.0.0.2")
    start = local(2026, 9, 30, 18, 0).astimezone(UTC)
    sid = engine.store.open_session("TV salon", None, start)
    engine.store.mark_start_notified(sid)
    engine.store.open_tv_segment(sid, "TV salon", start, "pkg", "YouTube", "Bluey", None)
    engine.store.close_tv_segments("TV salon", start + timedelta(minutes=40))
    engine.store.touch_session(sid, start + timedelta(minutes=40))
    engine.store.close_session(sid, start + timedelta(minutes=40))
    note = engine.build_weekly(date(2026, 9, 28), local(2026, 10, 4, 19, 0).astimezone(UTC))
    assert "*TV salon* — 40 min, 1 sesja\n\u2022 Bluey 40 min" in note.text


FIXTURE = Path(__file__).parent / "fixtures" / "config.yaml"
APP_MAP = Path(__file__).parent.parent / "app_map.yaml"


def test_CLI_weekly_nie_zajmuje_dedupu(tmp_path, capsys):
    data = yaml.safe_load(FIXTURE.read_text(encoding="utf-8"))
    data["store"]["path"] = str(tmp_path / "k.db")
    data["app_map_path"] = str(APP_MAP)
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")

    for _ in range(2):
        assert main(["--config", str(cfg_path), "weekly", "--week", "2026-W40", "--dry-run"]) == 0
        assert "Raport tygodnia 28.09" in capsys.readouterr().out

    cfg = Config.load(cfg_path)
    with Store(cfg.store.path) as store:
        assert not store.already_sent("weekly:2026-W40")
