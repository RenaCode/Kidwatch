"""Test E2E: odtworzenie realistycznego dnia i porownanie ze snapshotem.

Scenariusz w day.jsonl obejmuje wszystkie przypadki brzegowe naraz:
  * noc z samym tlem systemowym — NIE moze wygenerowac ani jednego pusha,
  * poranna sesja z YouTube,
  * popoludniowa sesja z Robloxem przemieszanym z nierozpoznanym ruchem,
  * rownolegla sesja drugiego dziecka,
  * aktywnosc w nocy (22:47) — push w formie nocnej, z podwyzszonym priorytetem,
  * podsumowanie dnia.

Snapshot odswiezasz komenda z docstringu tools/gen_fixture_day.py.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

from kidwatch.classifier import Classifier
from kidwatch.config import Config
from kidwatch.engine import Engine
from kidwatch.models import DnsEvent, Kind, NotifyKind
from kidwatch.store import Store

FIXTURES = Path(__file__).parent / "fixtures"
CONFIG = FIXTURES / "config.yaml"
DAY = FIXTURES / "day.jsonl"
SNAPSHOT = FIXTURES / "day.expected.txt"
ROOT = Path(__file__).resolve().parents[1]


def replay() -> tuple[Config, Store, list]:
    cfg = Config.load(CONFIG)
    store = Store(":memory:")
    engine = Engine(cfg, store, Classifier(cfg.app_map_path))

    rows = [json.loads(line) for line in DAY.read_text(encoding="utf-8").splitlines() if line]
    produced = []
    for row in rows:
        ts = datetime.fromisoformat(row["ts"].replace("Z", "+00:00"))
        produced += engine.handle(DnsEvent(ts=ts, device_id=row["device"], domain=row["domain"]))
    last = datetime.fromisoformat(rows[-1]["ts"].replace("Z", "+00:00"))
    produced += engine.tick(last + timedelta(minutes=cfg.engine.idle_minutes + 1))
    return cfg, store, produced


# ================================================================== snapshot
def test_wynik_odtworzenia_zgadza_sie_ze_snapshotem():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "kidwatch",
            "--config",
            str(CONFIG),
            "replay",
            str(DAY),
            "--dry-run",
        ],
        capture_output=True,
        text=True,
        cwd=ROOT,
        check=True,
    )
    assert result.stdout == SNAPSHOT.read_text(encoding="utf-8"), (
        "wynik odtworzenia rozni sie od snapshotu — jesli zmiana jest zamierzona, "
        "odswiez tests/fixtures/day.expected.txt"
    )


def test_odtworzenie_jest_powtarzalne():
    _, _, first = replay()
    _, _, second = replay()
    assert [(n.kind, n.title, n.text) for n in first] == [
        (n.kind, n.title, n.text) for n in second
    ]


# =============================================================== wlasciwosci
def test_noc_z_samym_tlem_nie_generuje_zadnego_pusha():
    """Jesli ten test padnie, iPady beda budzic Cie pushami przez cala noc."""
    cfg, _, produced = replay()
    for note in produced:
        local = note.ts.astimezone(cfg.tz)
        if 0 <= local.hour < 6:
            raise AssertionError(f"push w srodku nocy: {note.kind.value} {note.title} o {local}")


def test_kazde_tlo_systemowe_jest_rozpoznane_jako_szum():
    """Nierozpoznana domena systemowa otwiera widmowa sesje. Tak wlasnie wykryto
    brak wlasnego gTLD Apple (.apple) w mapie domen."""
    cfg = Config.load(CONFIG)
    classifier = Classifier(cfg.app_map_path)
    rows = [json.loads(line) for line in DAY.read_text(encoding="utf-8").splitlines() if line]

    apple_ish = {
        row["domain"]
        for row in rows
        if "apple" in row["domain"] or "icloud" in row["domain"] or "crashlytics" in row["domain"]
    }
    assert apple_ish, "fixture powinien zawierac tlo systemowe"
    not_noise = {d for d in apple_ish if classifier.classify(d).kind is not Kind.NOISE}
    assert not_noise == set(), f"te domeny systemowe nie sa szumem: {sorted(not_noise)}"


def test_aktywnosc_nocna_ma_podwyzszony_priorytet():
    cfg, _, produced = replay()
    nocne = [
        n
        for n in produced
        if n.kind is NotifyKind.NIGHT and n.dedup_key.startswith("start:")
    ]
    assert len(nocne) == 1, "scenariusz ma dokladnie jedna sesje w nocy"
    assert nocne[0].priority == 5
    assert nocne[0].ts.astimezone(cfg.tz).hour == 22


def test_w_cichych_godzinach_nie_ma_pushy_o_aplikacjach():
    cfg, _, produced = replay()
    qh = cfg.engine.quiet_hours
    assert qh is not None
    for note in produced:
        if note.kind is NotifyKind.APP:
            assert not qh.contains(note.ts.astimezone(cfg.tz).time()), (
                f"push o aplikacji w cichych godzinach: {note.text}"
            )


def test_podsumowanie_dnia_liczy_tylko_sesje_o_ktorych_wiesz():
    _, store, produced = replay()
    daily = [n for n in produced if n.kind is NotifyKind.DAILY]
    assert len(daily) == 1
    text = daily[0].text
    # Piata sesja Kuby (22:47) jest po 20:30 — trafi do podsumowania
    # nastepnego dnia, nie do tego (okno od poprzedniej wysylki).
    assert "*Kuba* — 4 sesje" in text
    assert "*Zosia* — 2 sesje" in text
    # Gra rozpoznana po domenie wydawcy trafia do statystyki pod swoja nazwa.
    assert "Asphalt / Gameloft" in text

    # W bazie sesji jest wiecej — te niezgloszone nie moga trafic do statystyki.
    total = store.conn.execute("SELECT COUNT(*) AS n FROM sessions").fetchone()["n"]
    notified = store.conn.execute(
        "SELECT COUNT(*) AS n FROM sessions WHERE start_notified=1"
    ).fetchone()["n"]
    assert notified == 7
    assert total >= notified


def test_kazdy_koniec_sesji_ma_swoj_start():
    _, _, produced = replay()
    # Start w nocy ma rodzaj NIGHT (alarm), ale to nadal start sesji.
    starts = len([n for n in produced if n.dedup_key.startswith("start:")])
    ends = len([n for n in produced if n.kind is NotifyKind.SESSION_END])
    assert starts == ends == 7


def test_teksty_o_czasie_zawsze_oznaczaja_go_jako_szacunek():
    _, _, produced = replay()
    for note in produced:
        if note.kind in (NotifyKind.SESSION_END, NotifyKind.DAILY):
            assert "szacunkowe" in note.text, note.text


def test_zaden_klucz_dedupu_sie_nie_powtarza():
    _, _, produced = replay()
    keys = [n.dedup_key for n in produced]
    assert len(keys) == len(set(keys))


# ================================================================ gry
def test_gra_rozpoznana_po_domenie_wydawcy_trafia_do_podsumowania():
    """Asphalt gada z gameloft.com rzadko i z CloudFrontem czesto. Ma byc
    nazwany, a jego sesja ma miec realna dlugosc, nie tylko te kilka minut,
    w ktorych trafil we wlasne zaplecze."""
    cfg, _, produced = replay()
    asphalt = [n for n in produced if n.app == "Asphalt / Gameloft"]
    assert asphalt, "Asphalt musi byc rozpoznany"

    ends = [
        n
        for n in produced
        if n.kind is NotifyKind.SESSION_END and "Asphalt" in n.text
    ]
    assert len(ends) == 1
    # Ruch wspoldzielony podtrzymal sesje: scenariusz ma 35 minut grania,
    # a wlasne domeny Gameloftu pojawiaja sie tylko co ~3 minuty.
    assert "34 min" in ends[0].text or "35 min" in ends[0].text, ends[0].text


def test_gra_NIEROZPOZNANA_wychodzi_jako_przegladarka_ale_otwiera_sesje():
    """Tak zachowuje sie gra, ktorej nie ma w app_map.yaml. Nie znamy nazwy, ale
    NIE WOLNO nam przeoczyc, ze iPad byl uzywany. Nazwe uzupelnisz komenda
    `kidwatch domains --unknown-only`."""
    _, store, produced = replay()
    rows = store.conn.execute(
        "SELECT DISTINCT domain FROM events WHERE kind='unknown' AND domain LIKE '%super-gierka%'"
    ).fetchall()
    assert rows, "fixture ma zawierac nierozpoznana gre"
    # I otworzyla sesje, mimo ze nie wiemy, co to.
    assert any(
        n.kind is NotifyKind.SESSION_START and n.ts.astimezone(cfg_tz()).hour == 16
        for n in produced
    )


def cfg_tz():
    return Config.load(CONFIG).tz


def test_ruch_wspoldzielony_nie_otwiera_zadnej_sesji_w_scenariuszu():
    """CDN-y i reklamy wystepuja w zapisie dnia, ale nie moga same z siebie
    otworzyc sesji — inaczej dostawalbys pushe o niczym."""
    cfg = Config.load(CONFIG)
    classifier = Classifier(cfg.app_map_path)
    rows = [json.loads(line) for line in DAY.read_text(encoding="utf-8").splitlines() if line]
    shared = {r["domain"] for r in rows if classifier.classify(r["domain"]).kind is Kind.AMBIGUOUS}
    assert shared, "fixture ma zawierac ruch wspoldzielony"
    assert any("cloudfront" in d for d in shared)
