"""Kolejka wyjsciowa: wpis znika dopiero po przyjeciu przez kanal (audyt 3).

Wczesniej wpis byl kasowany po wysylce bez wzgledu na wynik, a bramka robila
tylko 3 szybkie proby (1 s, 2 s). Restart bramki przy wdrozeniu albo 502
z Mailguna gubily powiadomienie na zawsze.
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime, timedelta

import httpx

from kidwatch.config import BramkaConfig
from kidwatch.models import Notification, NotifyKind
from kidwatch.notifiers.base import (
    OUTBOX_MAX_AGE,
    OUTBOX_MAX_ATTEMPTS,
    Dispatcher,
    Outbox,
)
from kidwatch.notifiers.bramka import BramkaNotifier
from kidwatch.store import Store

T0 = datetime(2026, 10, 3, 12, 0, tzinfo=UTC)


async def _no_sleep(_):
    return None


class Clock:
    def __init__(self, now: datetime = T0) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now

    def advance(self, **kw) -> None:
        self.now += timedelta(**kw)


class Channel:
    """Kanal, ktory przyjmuje albo odrzuca wedlug `up`."""

    name = "bramka"

    def __init__(self, up: bool = False) -> None:
        self.up = up
        self.calls: list[str] = []

    async def send(self, note):
        self.calls.append(note.dedup_key)
        return self.up

    async def aclose(self):
        return None


def _note(key: str = "start:a") -> Notification:
    return Notification(kind=NotifyKind.SESSION_START, title=f"tytul {key}", text="tresc",
                        dedup_key=key, ts=T0, priority=3)


def _outbox(store: Store, channel, clock: Clock) -> Outbox:
    return Outbox(Dispatcher([channel], store=store), store, now=clock)


def _history(store: Store) -> list[tuple[str, int]]:
    return [
        (r["title"], r["delivered"])
        for r in store.conn.execute("SELECT title, delivered FROM notifications ORDER BY id")
    ]


async def test_bramka_odrzuca_3_razy_wpis_zostaje_i_wychodzi_po_powrocie(store):
    statuses = [502, 502, 502, 200]
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(statuses[len(requests) - 1])

    bramka = BramkaNotifier(
        BramkaConfig(url="http://bramka.test"), key="k",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), sleep=_no_sleep,
    )
    clock = Clock()
    outbox = _outbox(store, bramka, clock)
    await outbox.send_all([_note()])

    assert await outbox.flush() == 0
    assert len(requests) == 3
    [item] = store.outbox_pending()
    assert item.attempts == 1
    assert item.next_at == T0 + timedelta(seconds=30)
    assert "bramka" in item.last_error
    assert _history(store) == []  # w historii panelu tylko wynik koncowy

    clock.advance(seconds=30)
    assert await outbox.flush() == 1
    assert len(requests) == 4
    assert store.outbox_pending() == []
    assert _history(store) == [("tytul start:a", 1)]
    await bramka.aclose()


async def test_wiszacy_wpis_wstrzymuje_kolejne_kolejnosc_zostaje(store):
    channel = Channel(up=False)
    clock = Clock()
    outbox = _outbox(store, channel, clock)
    await outbox.send_all([_note("start:a"), _note("koniec:a")])

    assert await outbox.flush() == 0
    assert channel.calls == ["start:a"]  # "koniec" nie wyprzedza "startu"

    channel.up = True
    clock.advance(seconds=30)
    assert await outbox.flush() == 2
    assert channel.calls == ["start:a", "start:a", "koniec:a"]


async def test_backoff_rosnie_do_15_min_i_nie_porzuca_po_3_probach(store):
    channel = Channel(up=False)
    clock = Clock()
    outbox = _outbox(store, channel, clock)
    await outbox.send_all([_note()])

    gaps = []
    for _ in range(8):
        assert await outbox.flush() == 0
        [item] = store.outbox_pending()
        gap = item.next_at - clock.now
        gaps.append(int(gap.total_seconds()))
        # Przed terminem kolejnej proby kanal nie jest wolany.
        calls = len(channel.calls)
        clock.advance(seconds=gap.total_seconds() - 1)
        assert await outbox.flush() == 0
        assert len(channel.calls) == calls
        clock.advance(seconds=1)

    assert gaps == [30, 60, 120, 300, 600, 900, 900, 900]
    assert store.outbox_pending()[0].attempts == 8


async def test_porzucenie_po_dobie_loguje_i_budzi_czujke(store, caplog):
    channel = Channel(up=False)
    clock = Clock()
    outbox = _outbox(store, channel, clock)
    await outbox.send_all([_note()])
    assert await outbox.flush() == 0

    clock.now = T0 + OUTBOX_MAX_AGE - timedelta(seconds=1)
    await outbox.flush()
    assert [i.note.dedup_key for i in store.outbox_pending()] == ["start:a"]

    clock.now = T0 + OUTBOX_MAX_AGE
    with caplog.at_level(logging.WARNING, logger="kidwatch.notifiers.base"):
        await outbox.flush()
    assert any("porzucam start:a" in r.getMessage() and r.levelno == logging.WARNING
               for r in caplog.records)
    # Panel pokazuje push jako niedostarczony.
    assert _history(store) == [("tytul start:a", 0)]
    [alarm] = store.outbox_pending()
    assert alarm.note.kind is NotifyKind.WATCHDOG
    assert "tytul start:a" in alarm.note.text

    # Alarm wychodzi, gdy kanal wroci.
    channel.up = True
    clock.advance(seconds=30)
    assert await outbox.flush() == 1
    assert channel.calls[-1] == alarm.note.dedup_key


async def test_porzucony_alarm_nie_rodzi_kolejnego(store):
    channel = Channel(up=False)
    clock = Clock()
    outbox = _outbox(store, channel, clock)
    await outbox.send_all([_note()])
    await outbox.flush()
    clock.now = T0 + OUTBOX_MAX_AGE
    await outbox.flush()  # porzuca wpis, kolejkuje alarm
    [alarm] = store.outbox_pending()

    clock.now = T0 + 3 * OUTBOX_MAX_AGE
    await outbox.flush()
    await outbox.flush()
    assert store.outbox_pending() == []
    assert alarm.note.dedup_key.startswith("outbox-lost:")


async def test_porzucenie_po_limicie_prob(store, caplog):
    channel = Channel(up=False)
    clock = Clock()
    outbox = _outbox(store, channel, clock)
    await outbox.send_all([_note()])
    item_id = store.outbox_pending()[0].id
    for _ in range(OUTBOX_MAX_ATTEMPTS - 1):
        store.outbox_attempt(item_id)

    assert await outbox.flush() == 0  # ostatnia dozwolona proba
    assert store.outbox_pending()[0].attempts == OUTBOX_MAX_ATTEMPTS

    clock.advance(minutes=15)
    with caplog.at_level(logging.WARNING, logger="kidwatch.notifiers.base"):
        await outbox.flush()
    assert any("porzucam start:a" in r.getMessage() for r in caplog.records)
    assert [i.note.kind for i in store.outbox_pending()] == [NotifyKind.WATCHDOG]


async def test_restart_z_wiszacym_wpisem(tmp_path):
    db = tmp_path / "k.db"
    clock = Clock()
    store = Store(db)
    outbox = _outbox(store, Channel(up=False), clock)
    await outbox.send_all([_note()])
    await outbox.flush()
    await outbox.flush()  # przed terminem — bez proby
    store.close()  # restart (np. wdrozenie) z wpisem w backoffie

    store = Store(db)
    channel = Channel(up=True)
    outbox = _outbox(store, channel, clock)
    [item] = store.outbox_pending()
    assert item.attempts == 1 and item.last_error is not None

    clock.advance(seconds=10)
    assert await outbox.flush() == 0  # backoff przezyl restart
    assert channel.calls == []

    clock.advance(seconds=20)
    assert await outbox.flush() == 1
    assert channel.calls == ["start:a"]
    assert store.outbox_pending() == []
    store.close()


def test_stara_baza_dostaje_kolumny_kolejki_raz(tmp_path):
    """Produkcja ma tabele outbox bez next_at/last_error; wpis w niej musi
    przezyc aktualizacje i wyjsc od razu."""
    db = tmp_path / "k.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE outbox (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "created_at TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, note TEXT NOT NULL)"
    )
    conn.commit()
    conn.close()
    store = Store(db)
    store.outbox_put([_note()], T0)
    store.close()

    store = Store(db)  # drugi start — migracja nie moze wywalic sie na duplikacie
    cols = {r["name"] for r in store.conn.execute("PRAGMA table_info(outbox)")}
    assert {"next_at", "last_error"} <= cols
    [item] = store.outbox_pending()
    assert item.next_at is None and item.attempts == 0
    store.close()


# ================================================== audyt 2026-10-09: N7
def _bramka(statuses: dict[str, int], requests: list) -> BramkaNotifier:
    """Bramka odpowiadajaca kodem wedlug tytulu powiadomienia."""

    def handler(request: httpx.Request) -> httpx.Response:
        import json  # noqa: PLC0415

        title = json.loads(request.content)["temat"]
        requests.append(title)
        return httpx.Response(next((c for k, c in statuses.items() if k in title), 200))

    return BramkaNotifier(
        BramkaConfig(url="http://bramka.test"), key="k",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)), sleep=_no_sleep,
    )


async def test_trwale_odrzucenie_tresci_nie_blokuje_kolejki(store, caplog):
    """400/413 dotyczy tej jednej wiadomosci — wczesniej wpis stal na czele
    kolejki i wstrzymywal wszystkie kolejne pushe az do OUTBOX_MAX_AGE (doba)."""
    requests: list[str] = []
    bramka = _bramka({"zly": 413}, requests)
    outbox = _outbox(store, bramka, Clock())
    await outbox.send_all([_note("start:zly"), _note("start:dobry")])
    with caplog.at_level(logging.WARNING):
        sent = await outbox.flush()
    assert sent == 1  # "dobry" nie czeka za odrzuconym
    assert await outbox.flush() == 1  # alarm czujki o porzuconym
    assert store.outbox_pending() == []
    assert requests[:2] == ["tytul start:zly", "tytul start:dobry"]
    assert requests.count("tytul start:zly") == 1  # bez ponawiania
    assert ("tytul start:zly", 0) in _history(store)
    assert ("tytul start:dobry", 1) in _history(store)
    assert any("kidwatch nie dostarczyl" in t for t in requests)
    assert "odrzucone trwale" in caplog.text
    await bramka.aclose()


async def test_zly_token_nadal_czeka_w_kolejce(store):
    """401 to blad konfiguracji kanalu, nie tresci — po poprawce tokenu wpis
    ma wyjsc, wiec zostaje w kolejce jak przy awarii."""
    requests: list[str] = []
    bramka = _bramka({"start": 401}, requests)
    outbox = _outbox(store, bramka, Clock())
    await outbox.send_all([_note("start:a")])
    assert await outbox.flush() == 0
    [item] = store.outbox_pending()
    assert item.attempts == 1
    await bramka.aclose()
