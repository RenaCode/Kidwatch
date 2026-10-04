"""Silnik po przeglądzie 04.10: koniec sesji poza limitem (K-9), nadrabianie
podsumowań po przestoju (K-10), urządzenie, które nigdy nie wysłało DNS (K-11)."""

from __future__ import annotations

from datetime import timedelta

from conftest import ev, local, make_config
from kidwatch.engine import LATE_SUFFIX, Engine
from kidwatch.models import NotifyKind
from kidwatch.store import Store


def of(notes, kind):
    return [n for n in notes if n.kind is kind]


def play(eng, start, minutes, domain="www.youtube.com", device="ipad-kuby"):
    for i in range(minutes):
        eng.handle(ev(start + timedelta(minutes=i), domain, device=device))
    eng.tick(start + timedelta(minutes=minutes + 15))   # domknij sesje


# ================================================================== K-9
def test_koniec_sesji_nie_jest_dlawiony_a_zbiorczy_push_ma_nazwy(classifier):
    cfg = make_config(engine={"max_notifications_per_hour": 3, "app_cooldown_minutes": 0})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 10, 0)
    for i, domain in enumerate(
        ["www.youtube.com", "ecsv3.roblox.com", "api.minecraft.net", "www.youtubekids.com"] * 2
    ):
        eng.handle(ev(t + timedelta(minutes=i), domain))
    assert eng.store.count_throttled("iPad Kuby") > 0

    # Limit nadal wyczerpany, a sesja wygasa - koniec MUSI wyjsc.
    notes = eng.tick(t + timedelta(minutes=25))
    assert len(of(notes, NotifyKind.SESSION_END)) == 1
    labels = eng.store.drain_throttled("iPad Kuby")
    assert labels and all("\n" not in label for label in labels)
    assert set(labels) <= {"YouTube", "Roblox", "Minecraft", "YouTube Kids"}


# ================================================================== K-10
def test_podsumowanie_dnia_nadrabiane_po_przestoju(engine):
    play(engine, local(2026, 9, 27, 10, 0), 20)
    # Pod lezal od 20:00 do 00:10 - o 20:30 nic nie wyszlo. W cichych
    # godzinach czekamy do rana.
    assert of(engine.tick(local(2026, 9, 28, 0, 10)), NotifyKind.DAILY) == []
    notes = engine.tick(local(2026, 9, 28, 7, 10))
    daily = of(notes, NotifyKind.DAILY)
    assert len(daily) == 1
    assert daily[0].title == "Podsumowanie dnia 27.09" + LATE_SUFFIX
    assert daily[0].dedup_key == "daily:2026-09-27"
    assert "*Kuba* — 1 sesja" in daily[0].text
    assert engine.store.get_meta("daily_sent:2026-09-27")
    # Drugi tik nic nie wysyla, a zwykle podsumowanie dnia 28.09 wychodzi normalnie.
    assert of(engine.tick(local(2026, 9, 28, 7, 20)), NotifyKind.DAILY) == []
    today = of(engine.tick(local(2026, 9, 28, 20, 31)), NotifyKind.DAILY)
    assert [n.title for n in today] == ["Podsumowanie dnia 28.09"]


def test_bez_sesji_nie_ma_spoznionego_podsumowania(engine):
    assert of(engine.tick(local(2026, 9, 28, 7, 10)), NotifyKind.DAILY) == []


def test_nadrabianie_tylko_jeden_dzien_wstecz(engine):
    play(engine, local(2026, 9, 26, 10, 0), 20)
    # Przestoj dwa dni: 26.09 przepada (swiadomie), 27.09 nie mial sesji.
    assert of(engine.tick(local(2026, 9, 28, 9, 0)), NotifyKind.DAILY) == []


def test_raport_tygodnia_nadrabiany_dzien_po(engine):
    play(engine, local(2026, 9, 29, 15, 0), 30)
    # Niedziela 04.10 19:00 przespana, poniedzialek rano pod wstaje.
    assert of(engine.tick(local(2026, 10, 5, 6, 0)), NotifyKind.WEEKLY) == []   # cisza nocna
    weekly = of(engine.tick(local(2026, 10, 5, 7, 30)), NotifyKind.WEEKLY)
    assert len(weekly) == 1
    assert weekly[0].title.endswith(LATE_SUFFIX)
    assert weekly[0].dedup_key == "weekly:2026-W40"
    assert of(engine.tick(local(2026, 10, 5, 8, 0)), NotifyKind.WEEKLY) == []
    # Wtorek: juz nie nadrabiamy (i nie ma czego).
    assert of(engine.tick(local(2026, 10, 6, 8, 0)), NotifyKind.WEEKLY) == []


def test_raport_tygodnia_bez_sesji_nie_jest_nadrabiany(engine):
    assert of(engine.tick(local(2026, 10, 5, 7, 30)), NotifyKind.WEEKLY) == []


# ================================================================== K-11
def test_urzadzenie_ktore_nigdy_nie_wyslalo_dns(classifier):
    cfg = make_config(watchdog={"device_silence_ignore_quiet_hours": False})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 8, 0)

    def at(minutes):
        """Kuba zyje (DNS co 10 min), Zosia nie pojawila sie ani razu."""
        now = t + timedelta(minutes=minutes)
        eng.handle(ev(now, "gsp-ssl.ls.apple.com"))
        return [n for n in eng.tick(now) if "Zosi" in n.title]

    assert at(0) == []          # pierwszy tik zapisuje alive-since
    assert eng.store.get_meta("alive-since:iPad Zosi")
    assert at(170) == []
    alarm = at(185)
    assert len(alarm) == 1 and alarm[0].kind is NotifyKind.WATCHDOG
    assert "ani razu w DNS" in alarm[0].text and "source_ids" in alarm[0].text
    # Ta sama doba - cisza; nastepna - przypomnienie.
    assert at(290) == []
    assert len(at(24 * 60)) == 1
    # Kuby, ktory wysyla DNS, to nie dotyczy.
    assert eng.store.get_meta("alive-since:iPad Kuby") is None
