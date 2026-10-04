"""Testy przechowalni — szczegolnie sprzatania, ktore kasuje dane."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from kidwatch.store import Store, from_iso, to_iso

NOW = datetime(2026, 9, 27, 12, 0, tzinfo=UTC)


def test_czas_przechodzi_w_obie_strony():
    assert from_iso(to_iso(NOW)) == NOW


def test_naive_datetime_jest_odrzucone(store):
    import pytest  # noqa: PLC0415

    with pytest.raises(ValueError, match="aware"):
        to_iso(datetime(2026, 9, 27, 12, 0))


# =============================================================== idempotencja
def test_klucz_dedupu_mozna_zajac_tylko_raz(store):
    assert store.mark_sent("a", NOW) is True
    assert store.mark_sent("a", NOW) is False
    assert store.already_sent("a") is True
    assert store.already_sent("b") is False


# ====================================================================== sesje
def test_minuty_aplikacji_licza_sie_bez_powtorzen(store):
    sid = store.open_session("iPad Kuby", "Kuba", NOW)
    # Piec zapytan w tej samej minucie to JEDNA minuta.
    for second in (0, 10, 20, 30, 59):
        store.record_app_minute(sid, "YouTube", NOW + timedelta(seconds=second))
    store.record_app_minute(sid, "YouTube", NOW + timedelta(minutes=1))
    store.record_app_minute(sid, "Roblox", NOW + timedelta(minutes=1))
    assert store.session_app_minutes(sid) == [("YouTube", 2), ("Roblox", 1)]


def test_zamknieta_sesja_nie_jest_juz_otwarta(store):
    sid = store.open_session("iPad Kuby", "Kuba", NOW)
    assert store.get_open_session("iPad Kuby") is not None
    store.close_session(sid, NOW + timedelta(minutes=5))
    assert store.get_open_session("iPad Kuby") is None


def test_powtorne_zamkniecie_nie_nadpisuje_czasu(store):
    sid = store.open_session("iPad Kuby", "Kuba", NOW)
    store.close_session(sid, NOW + timedelta(minutes=5))
    store.close_session(sid, NOW + timedelta(hours=5))
    row = store.conn.execute("SELECT ended_at FROM sessions WHERE id=?", (sid,)).fetchone()
    assert from_iso(row["ended_at"]) == NOW + timedelta(minutes=5)


# ============================================================= deduplikacja
def test_seen_before_zapisuje_nowe_i_zglasza_znane(store):
    assert store.seen_before(["a", "b"], NOW) == set()
    assert store.seen_before(["a", "b", "c"], NOW) == {"a", "b"}
    assert store.seen_before(["c"], NOW) == {"c"}


def test_seen_before_znosi_duplikaty_w_jednym_wywolaniu(store):
    assert store.seen_before(["a", "a", "a"], NOW) == set()
    assert store.seen_before(["a"], NOW) == {"a"}


def test_seen_before_na_pustym_wejsciu(store):
    assert store.seen_before([], NOW) == set()


# ================================================================ sprzatanie
def _fill(store: Store, now: datetime) -> None:
    old = now - timedelta(days=40)
    recent = now - timedelta(hours=1)

    store.record_event(old, "iPad Kuby", "k", "stare.pl", "app", "Stare")
    store.record_event(recent, "iPad Kuby", "k", "nowe.pl", "app", "Nowe")

    old_session = store.open_session("iPad Kuby", "Kuba", old)
    store.record_app_minute(old_session, "Stare", old)
    store.close_session(old_session, old)

    new_session = store.open_session("iPad Kuby", "Kuba", recent)
    store.record_app_minute(new_session, "Nowe", recent)

    store.mark_sent("stary-klucz", now - timedelta(days=10))
    store.mark_sent("nowy-klucz", recent)
    store.log_notification("iPad Kuby", now - timedelta(days=10), "app")
    store.log_notification("iPad Kuby", recent, "app")
    store.seen_before(["stary-odcisk"], now - timedelta(days=5))
    store.seen_before(["nowy-odcisk"], recent)


def test_sprzatanie_kasuje_stare_a_zostawia_swieze(store):
    _fill(store, NOW)
    deleted = store.purge(NOW, retention_days=30)

    assert deleted["events"] == 1
    assert deleted["sessions"] == 1
    assert deleted["sent"] == 1
    assert deleted["notify_log"] == 1
    assert deleted["seen_queries"] == 1

    rows = store.conn.execute("SELECT domain FROM events").fetchall()
    assert [r["domain"] for r in rows] == ["nowe.pl"]
    assert store.already_sent("nowy-klucz") is True
    assert store.already_sent("stary-klucz") is False


def test_sprzatanie_nie_zostawia_osieroconych_minut(store):
    """Kasowanie sesji bez jej minut zostawialoby wiersze bez wlasciciela."""
    _fill(store, NOW)
    store.purge(NOW, retention_days=30)
    orphans = store.conn.execute(
        "SELECT COUNT(*) AS n FROM session_apps WHERE session_id NOT IN (SELECT id FROM sessions)"
    ).fetchone()["n"]
    assert orphans == 0


def test_sprzatanie_nie_rusza_otwartej_sesji_nawet_starej(store):
    """Otwarta sesja moze byc dluga; skasowanie jej zgubiloby stan."""
    very_old = NOW - timedelta(days=100)
    sid = store.open_session("iPad Kuby", "Kuba", very_old)
    store.purge(NOW, retention_days=30)
    assert store.get_open_session("iPad Kuby") is not None
    assert int(store.get_open_session("iPad Kuby")["id"]) == sid


def test_retencja_zero_wylacza_kasowanie_zdarzen(store):
    _fill(store, NOW)
    deleted = store.purge(NOW, retention_days=0)
    assert "events" not in deleted
    assert store.conn.execute("SELECT COUNT(*) AS n FROM events").fetchone()["n"] == 2
    # Klucze dedupu i odciski sa krotkotrwale niezaleznie od retencji zdarzen.
    assert deleted["sent"] == 1


# ===================================================================== kursor
def test_kursor_jest_per_zrodlo(store):
    assert store.get_cursor("nextdns") is None
    store.set_cursor("nextdns", "abc")
    store.set_cursor("adguard", "xyz")
    assert store.get_cursor("nextdns") == "abc"
    assert store.get_cursor("adguard") == "xyz"


def test_baza_powstaje_z_katalogiem(tmp_path):
    path = tmp_path / "gdzies" / "gleboko" / "kidwatch.db"
    s = Store(path)
    s.set_meta("a", "b")
    s.close()
    assert path.is_file()
    assert Store(path).get_meta("a") == "b"


# ====================================================== odwiedzone domeny
def test_browsed_since_zwraca_tylko_nierozpoznane_i_tylko_tego_urzadzenia(store):
    later = NOW + timedelta(minutes=5)
    store.record_event(NOW, "iPad Kuby", "k", "forum-o-grach.pl", "unknown", None)
    store.record_event(NOW, "iPad Kuby", "k", "forum-o-grach.pl", "unknown", None)
    store.record_event(NOW, "iPad Kuby", "k", "www.youtube.com", "app", "YouTube")
    store.record_event(NOW, "iPad Kuby", "k", "gsp.apple.com", "noise", None)
    store.record_event(NOW, "iPad Zosi", "z", "inna-strona.pl", "unknown", None)

    got = store.browsed_since("iPad Kuby", NOW - timedelta(minutes=1), later)
    assert got == [("forum-o-grach.pl", 2)]


def test_browsed_since_respektuje_okno_czasowe(store):
    store.record_event(NOW - timedelta(hours=2), "iPad Kuby", "k", "stare.pl", "unknown", None)
    store.record_event(NOW, "iPad Kuby", "k", "nowe.pl", "unknown", None)
    got = store.browsed_since("iPad Kuby", NOW - timedelta(minutes=10))
    assert [d for d, _ in got] == ["nowe.pl"]


def test_stara_baza_dostaje_sessions_child_NULLABLE_bez_utraty_danych(tmp_path):
    """sessions.child bylo NOT NULL; telewizor nie ma dziecka. Migracja
    przebudowuje tabele raz, zachowujac wiersze i ich ID (od nich zaleza
    session_apps i tv_watch)."""
    import sqlite3  # noqa: PLC0415

    from kidwatch.store import SCHEMA  # noqa: PLC0415

    path = tmp_path / "stara.db"
    old = sqlite3.connect(path)
    old.executescript(SCHEMA.replace("    child            TEXT,", "    child  TEXT NOT NULL,"))
    old.execute(
        "INSERT INTO sessions (id, device, child, started_at, last_activity_at) "
        "VALUES (7, 'iPad Kuby', 'Kuba', 'a', 'b')"
    )
    old.commit()
    old.close()

    with Store(path) as s:
        info = {r["name"]: r for r in s.conn.execute("PRAGMA table_info(sessions)")}
        assert info["child"]["notnull"] == 0
        assert s.conn.execute("SELECT id, child FROM sessions").fetchone()[:] == (7, "Kuba")
        s.conn.execute(
            "INSERT INTO sessions (device, child, started_at, last_activity_at) "
            "VALUES ('TV salon', NULL, 'a', 'b')"
        )
        indexes = {r["name"] for r in s.conn.execute("PRAGMA index_list(sessions)")}
        assert {"ix_sessions_open", "ix_sessions_started"} <= indexes
    # Drugi start nic juz nie przebudowuje.
    Store(path).close()
