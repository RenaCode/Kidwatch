"""Regresje z audytu runda 4 (integracja, restarty, DST, odpornosc).
Kazdy test opisuje blad, ktory naprawil — bez poprawki test pada."""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, timedelta

from conftest import ev, local, make_config
from kidwatch.engine import Engine, FakeClock
from kidwatch.models import Notification, NotifyKind
from kidwatch.notifiers.base import OUTBOX_MAX_ATTEMPTS, Dispatcher, Outbox
from kidwatch.scheduler import tick_loop
from kidwatch.store import Store
from test_e2e_replay import CONFIG, DAY


async def _no_sleep(_):
    return None


# ============================================ pkt 1: alarm nocny z samego tla
def test_ruch_wspoldzielony_po_odlozeniu_iPada_nie_daje_alarmu_nocnego(store, classifier):
    """Roblox do 21:24, potem SDK reklamowe co 4 min. Ruch wspoldzielony
    przedluzal last_activity_at w cisze nocna (21:30) i o 21:32 szedl push
    "uzywa iPada w nocy" z prio 5."""
    engine = Engine(make_config(), store, classifier)
    t0 = local(2026, 10, 3, 21, 0)
    out = []
    for minute in range(25):
        out += engine.handle(ev(t0 + timedelta(minutes=minute), "roblox.com"))
    for minute in range(28, 53, 4):
        ts = t0 + timedelta(minutes=minute)
        out += engine.handle(ev(ts, "applovin.com"))
        out += engine.tick(ts.astimezone(UTC))
    assert [n for n in out if n.kind is NotifyKind.NIGHT] == []


def test_prawdziwa_aplikacja_w_nocy_dalej_daje_alarm(store, classifier):
    engine = Engine(make_config(), store, classifier)
    t0 = local(2026, 10, 3, 21, 0)
    out = []
    for minute in range(40):
        ts = t0 + timedelta(minutes=minute)
        out += engine.handle(ev(ts, "roblox.com"))
        out += engine.tick(ts.astimezone(UTC))
    night = [n for n in out if n.kind is NotifyKind.NIGHT]
    assert len(night) == 1 and night[0].text.startswith("21:30, Roblox")


# ================================================ pkt 3: restart z przestojem
def test_restart_z_przestojem_nie_rozbija_sesji_ani_nie_budzi_czujki(tmp_path, classifier):
    """Pod lezal 25 min, dziecko gralo dalej. Pierwszy tik po starcie szedl
    przed nadrobieniem strumienia: "koniec", "nie widzi ruchu DNS", potem
    nowa sesja z zaleglosci i "znowu widzi"."""
    cfg = make_config()
    db = tmp_path / "k.db"
    t0 = local(2026, 10, 3, 14, 0)
    store = Store(db)
    engine = Engine(cfg, store, classifier)
    for sec in range(0, 600, 30):
        engine.handle(ev(t0 + timedelta(seconds=sec), "roblox.com"))
    store.close()

    store = Store(db)
    engine = Engine(cfg, store, classifier)
    now = (t0 + timedelta(minutes=35)).astimezone(UTC)
    out = engine.tick(now)
    for sec in range(600, 2100, 30):
        out += engine.handle(ev(t0 + timedelta(seconds=sec), "roblox.com"))
    out += engine.tick(now + timedelta(seconds=30))
    kinds = {n.kind for n in out}
    assert NotifyKind.SESSION_END not in kinds
    assert NotifyKind.WATCHDOG not in kinds
    assert NotifyKind.SESSION_START not in kinds
    assert store.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    store.close()


def test_po_restarcie_martwy_strumien_i_tak_zglasza_czujka(tmp_path, classifier):
    cfg = make_config()
    db = tmp_path / "k.db"
    t0 = local(2026, 10, 3, 14, 0)
    store = Store(db)
    Engine(cfg, store, classifier).handle(ev(t0, "apple.com"))
    store.close()

    store = Store(db)
    engine = Engine(cfg, store, classifier)
    now = (t0 + timedelta(minutes=35)).astimezone(UTC)
    assert engine.tick(now) == []
    later = engine.tick(now + Engine.CATCHUP_MAX)
    assert [n.title for n in later if n.kind is NotifyKind.WATCHDOG] == [
        "kidwatch nie widzi ruchu DNS"
    ]
    store.close()


# ======================================== pkt 5: wieczor poza podsumowaniami
def _session(engine, start, minutes=5):
    for m in range(minutes):
        engine.handle(ev(start + timedelta(minutes=m), "roblox.com"))
    engine.tick((start + timedelta(minutes=minutes + 15)).astimezone(UTC))


def test_sesja_po_godzinie_podsumowania_trafia_do_nastepnego_dokladnie_raz(store, classifier):
    engine = Engine(make_config(), store, classifier)
    first = engine.tick(local(2026, 10, 3, 20, 31).astimezone(UTC))
    _session(engine, local(2026, 10, 3, 21, 0))
    second = engine.tick(local(2026, 10, 4, 20, 31).astimezone(UTC))
    daily = [n for n in first + second if n.kind is NotifyKind.DAILY]
    assert len(daily) == 2
    assert "*Kuba* — brak aktywnosci" in daily[0].text
    assert "*Kuba* — 1 sesja" in daily[1].text


def test_niedzielny_wieczor_trafia_do_raportu_kolejnego_tygodnia(store, classifier):
    engine = Engine(make_config(), store, classifier)
    sunday = local(2026, 10, 4, 19, 1).astimezone(UTC)
    first = [n for n in engine.tick(sunday) if n.kind is NotifyKind.WEEKLY]
    _session(engine, local(2026, 10, 4, 21, 0))
    nxt = local(2026, 10, 11, 19, 1).astimezone(UTC)
    second = [n for n in engine.tick(nxt) if n.kind is NotifyKind.WEEKLY]
    assert len(first) == len(second) == 1
    assert "*Kuba* — brak aktywnosci" in first[0].text
    assert "*Kuba* — 4 min" in second[0].text
    # Wieczor poprzedniej niedzieli nie jest aktywnym dniem nowego tygodnia.
    assert "aktywne dni: 0/7" in second[0].text


# ========================================== pkt 8: wyjatek w srodku tiku
def test_wyjatek_w_pozniejszym_kroku_tiku_nie_gubi_podsumowania(store, classifier):
    engine = Engine(make_config(), store, classifier)

    def boom(now):
        raise RuntimeError("awaria czujki")

    engine._watchdog = boom
    out = engine.tick(local(2026, 10, 3, 20, 31).astimezone(UTC))
    assert [n.kind for n in out] == [NotifyKind.DAILY]


# =============================================== pkt 4: kolejka wyjsciowa
class Hanging:
    name = "bramka"

    async def send(self, note):
        await asyncio.sleep(100)
        return True

    async def aclose(self):
        return None


class Recording:
    name = "ntfy"

    def __init__(self):
        self.notes = []

    async def send(self, note):
        self.notes.append(note)
        return True

    async def aclose(self):
        return None


def _note(key="daily:2026-10-03"):
    return Notification(kind=NotifyKind.DAILY, title="Podsumowanie dnia 03.10",
                        text="tresc", dedup_key=key, ts=local(2026, 10, 3, 20, 30),
                        priority=2, tags=("bar_chart",), data={"kind": "daily"})


async def test_wiszacy_kanal_nie_blokuje_tiku_ani_tetna(tmp_path, classifier):
    """Bramka wisiala ~60 s na notke; tik z 3 notkami przekraczal 180 s,
    liveness restartowal pod, a zajete klucze dedupu gubily pushe."""
    store = Store(tmp_path / "k.db")
    engine = Engine(make_config(), store, classifier,
                    clock=FakeClock(local(2026, 10, 3, 20, 31).astimezone(UTC)))
    outbox = Outbox(Dispatcher([Hanging()], store=store), store)
    beat = tmp_path / "beat"
    await asyncio.wait_for(
        tick_loop(engine, outbox, store, sleep=_no_sleep, max_iterations=1,
                  heartbeat_path=beat),
        timeout=2,
    )
    assert beat.exists()
    assert [i.note.dedup_key for i in store.outbox_pending()] == ["daily:2026-10-03"]
    store.close()


async def test_powiadomienie_z_kolejki_wychodzi_po_restarcie(tmp_path):
    db = tmp_path / "k.db"
    store = Store(db)
    await Outbox(Dispatcher([Hanging()], store=store), store).send_all([_note()])
    store.close()  # proces zabity przed wysylka

    store = Store(db)
    channel = Recording()
    outbox = Outbox(Dispatcher([channel], store=store), store)
    assert await outbox.flush() == 1
    assert channel.notes == [_note()]
    assert store.outbox_pending() == []
    row = store.conn.execute("SELECT title, delivered, data FROM notifications").fetchone()
    assert row["title"] == "Podsumowanie dnia 03.10" and row["delivered"] == 1
    assert json.loads(row["data"]) == {"kind": "daily"}
    store.close()


async def test_kolejka_porzuca_wpis_po_limicie_prob(tmp_path):
    store = Store(tmp_path / "k.db")
    channel = Recording()
    outbox = Outbox(Dispatcher([channel], store=store), store)
    await outbox.send_all([_note("a"), _note("b")])
    first_id = store.outbox_pending()[0].id
    for _ in range(OUTBOX_MAX_ATTEMPTS):
        store.outbox_attempt(first_id)
    assert await outbox.flush() == 1
    assert [n.dedup_key for n in channel.notes] == ["b"]
    # Porzucenie nie jest juz ciche — alarm czujki czeka (tests/test_outbox.py).
    assert [i.note.kind for i in store.outbox_pending()] == [NotifyKind.WATCHDOG]
    store.close()


# ================================ luka w testach: odtworzenie z tikiem co 30 s
def test_odtworzenie_dnia_z_tikiem_co_30_s():
    """tests/test_e2e_replay.py tika raz, na koncu — noc, podsumowanie i
    zamykanie sesji w trakcie dnia nie byly cwiczone na prawdziwym dniu."""
    from datetime import datetime  # noqa: PLC0415

    from kidwatch.classifier import Classifier  # noqa: PLC0415
    from kidwatch.config import Config  # noqa: PLC0415
    from kidwatch.models import DnsEvent  # noqa: PLC0415

    cfg = Config.load(CONFIG)
    store = Store(":memory:")
    engine = Engine(cfg, store, Classifier(cfg.app_map_path))
    rows = [json.loads(line) for line in DAY.read_text().splitlines() if line]
    out = []
    nxt = None
    for r in rows:
        ts = datetime.fromisoformat(r["ts"].replace("Z", "+00:00"))
        nxt = nxt or ts
        while nxt < ts:
            out += engine.tick(nxt)
            nxt += timedelta(seconds=30)
        out += engine.handle(DnsEvent(ts=ts, device_id=r["device"], domain=r["domain"]))
    end = nxt + timedelta(minutes=cfg.engine.idle_minutes + 1)
    while nxt < end:
        out += engine.tick(nxt)
        nxt += timedelta(seconds=30)

    # Start w nocy ma rodzaj NIGHT (alarm), ale to nadal start sesji.
    starts = [n for n in out if n.dedup_key.startswith("start:")]
    ends = [n for n in out if n.kind is NotifyKind.SESSION_END]
    assert len(starts) == len(ends) == 7
    assert len({n.dedup_key for n in out}) == len(out)
    daily = [n for n in out if n.kind is NotifyKind.DAILY]
    assert [n.title for n in daily] == ["Podsumowanie dnia 26.09"]
    store.close()

