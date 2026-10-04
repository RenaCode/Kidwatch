"""Testy regul silnika. Kazdy scenariusz jazdy na fałszywym czasie."""

from __future__ import annotations

from datetime import UTC, timedelta

import pytest

from conftest import ev, local, make_config
from kidwatch.classifier import UNKNOWN_LABEL
from kidwatch.engine import Engine, fmt_duration
from kidwatch.models import NotifyKind
from kidwatch.store import Store


# ============================================================== start sesji
def test_pierwsze_zapytanie_aplikacji_otwiera_sesje_jednym_pushem(engine):
    notes = engine.handle(ev(local(2026, 9, 27, 10, 0), "www.youtube.com"))
    assert len(notes) == 1
    n = notes[0]
    assert n.kind is NotifyKind.SESSION_START
    assert n.title == "iPad Kuby aktywny"
    # Start i aplikacja scalone w jeden push, nie dwa.
    assert "10:00" in n.text and "YouTube" in n.text
    assert n.app == "YouTube"


def test_nierozpoznany_ruch_zglasza_start_dopiero_gdy_trwa(engine):
    t = local(2026, 9, 27, 10, 0)
    # Nieznana domena: samo jedno zapytanie to jeszcze nie sesja.
    assert engine.handle(ev(t, "jakas-strona.pl")) == []
    assert engine.tick(t + timedelta(seconds=25)) == []

    # Ruch po ponad minucie potwierdza sesje — start z godzina pierwszego zapytania.
    notes = engine.handle(ev(t + timedelta(seconds=70), "jakas-strona.pl"))
    assert len(notes) == 1
    assert notes[0].kind is NotifyKind.SESSION_START
    assert notes[0].app is None
    assert notes[0].text.startswith("10:00")


def test_aplikacja_w_okienku_scalania_dociaga_sie_do_startu(engine):
    t = local(2026, 9, 27, 10, 0)
    assert engine.handle(ev(t, "jakas-strona.pl")) == []
    notes = engine.handle(ev(t + timedelta(seconds=5), "r1.googlevideo.com"))
    assert len(notes) == 1
    assert notes[0].kind is NotifyKind.SESSION_START
    assert notes[0].app == "YouTube"


def test_szum_nie_budzi_sesji(engine):
    t = local(2026, 9, 27, 3, 0)
    for domain in ("gsp-ssl.ls.apple.com", "p50-content.icloud.com", "settings.crashlytics.com"):
        assert engine.handle(ev(t, domain)) == []
    assert engine.tick(t + timedelta(minutes=5)) == []
    assert engine.store.get_open_session("iPad Kuby") is None


def test_szum_mimo_wszystko_liczy_sie_jako_dowod_zycia(engine):
    """To jest cala wartosc szumu: odroznia spiacy iPad od zdjetego profilu."""
    t = local(2026, 9, 27, 3, 0)
    engine.handle(ev(t, "gsp-ssl.ls.apple.com"))
    assert engine.store.get_meta("alive:iPad Kuby") is not None
    assert engine.store.get_meta("alive:__all__") is not None


def test_nieznane_urzadzenie_jest_ignorowane_ale_podtrzymuje_strumien(engine):
    t = local(2026, 9, 27, 10, 0)
    assert engine.handle(ev(t, "www.youtube.com", device="laptop-taty")) == []
    assert engine.store.get_open_session("iPad Kuby") is None
    assert engine.store.get_meta("alive:__all__") is not None


# ============================================================ cooldown aplikacji
def test_ta_sama_aplikacja_nie_pinguje_w_cooldownie(engine):
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))  # start + YouTube

    # 5 i 14 minut pozniej: wciaz w 15-minutowym cooldownie.
    assert engine.handle(ev(t + timedelta(minutes=5), "r2.googlevideo.com")) == []
    assert engine.handle(ev(t + timedelta(minutes=14), "r3.googlevideo.com")) == []


def test_ta_sama_aplikacja_raz_na_sesje_nie_co_15_min(engine):
    """Audyt 3, S4: YouTube o 16:06, 16:21 i 16:36 w jednej sesji — cooldown
    liczony od ostatniego pusha dawal ~8 maili na dwugodzinny seans."""
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))  # start + YouTube
    later = []
    for minute in range(1, 120):
        later += engine.handle(ev(t + timedelta(minutes=minute), "r2.googlevideo.com"))
    assert [n for n in later if n.kind is NotifyKind.APP] == []

    # Nowa sesja (po ciszy) znow mowi, w co gra.
    engine.tick(t + timedelta(minutes=140))
    t2 = t + timedelta(minutes=150)
    notes = []
    for minute in range(3):
        notes += engine.handle(ev(t2 + timedelta(minutes=minute), "www.youtube.com"))
    assert any(n.app == "YouTube" for n in notes)


def test_powrot_do_aplikacji_w_tej_samej_sesji_bez_pusha(engine):
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))
    for minute in range(1, 5):
        engine.handle(ev(t + timedelta(minutes=minute), "r1.googlevideo.com"))
    roblox = engine.handle(ev(t + timedelta(minutes=5), "ecsv3.roblox.com"))
    assert [n.app for n in roblox] == ["Roblox"]
    for minute in range(6, 25):  # 20 min Robloxa, sesja trwa
        engine.handle(ev(t + timedelta(minutes=minute), "ecsv3.roblox.com"))
    back = []
    for minute in range(25, 30):
        back += engine.handle(ev(t + timedelta(minutes=minute), "www.youtube.com"))
    assert [n for n in back if n.kind is NotifyKind.APP] == []


def test_inna_aplikacja_przechodzi_natychmiast(engine):
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))
    notes = engine.handle(ev(t + timedelta(minutes=1), "ecsv3.roblox.com"))
    assert [n.app for n in notes] == ["Roblox"]


def test_nierozpoznany_ruch_w_trakcie_sesji_trafia_jako_przegladarka(classifier):
    engine = Engine(make_config(engine={"notify_unknown": True}), Store(":memory:"), classifier)
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))
    notes = engine.handle(ev(t + timedelta(minutes=1), "sklep-z-czyms.pl"))
    assert [n.app for n in notes] == [UNKNOWN_LABEL]


# ============================================================== koniec sesji
def test_koniec_sesji_po_bezczynnosci_z_podsumowaniem(engine):
    t = local(2026, 9, 27, 10, 0)
    # Przerwy po 5 minut, wiec przez caly czas to JEDNA sesja (idle_minutes=10).
    engine.handle(ev(t, "www.youtube.com"))
    engine.handle(ev(t + timedelta(minutes=5), "r1.googlevideo.com"))
    engine.handle(ev(t + timedelta(minutes=10), "ecsv3.roblox.com"))
    engine.handle(ev(t + timedelta(minutes=15), "r2.googlevideo.com"))
    engine.handle(ev(t + timedelta(minutes=20), "r3.googlevideo.com"))

    # 10 minut ciszy po ostatniej aktywnosci (10:20) => koniec o 10:30.
    assert [n for n in engine.tick(t + timedelta(minutes=29))
            if n.kind is NotifyKind.SESSION_END] == []
    notes = engine.tick(t + timedelta(minutes=31))

    end = [n for n in notes if n.kind is NotifyKind.SESSION_END]
    assert len(end) == 1
    text = end[0].text
    assert "10:00" in text and "10:20" in text
    assert "20 min" in text
    assert "YouTube" in text and "Roblox" in text
    # Czas MUSI byc opisany jako szacunek — inaczej po miesiacu porownasz to
    # z Czasem przed ekranem i uznasz, ze serwis klamie.
    assert "szacunkowe" in text


def test_szum_nie_przedluza_sesji(engine):
    """Gdyby szum przedluzal sesje, sesja nie skonczylaby sie nigdy."""
    t = local(2026, 9, 27, 10, 0)
    notes = engine.handle(ev(t, "www.youtube.com"))
    for i in range(1, 12):
        notes += engine.handle(ev(t + timedelta(minutes=i), "gsp-ssl.ls.apple.com"))
    notes += engine.tick(t + timedelta(minutes=12))

    ends = [n for n in notes if n.kind is NotifyKind.SESSION_END]
    assert len(ends) == 1
    # Sesja konczy sie na ostatniej NIEszumowej aktywnosci, czyli na 10:00 —
    # jedenascie minut szumu nie przesunelo jej ani o minute.
    assert "10:00\u201310:00" in ends[0].text
    # I nie otworzyla sie zadna druga sesja z samego szumu.
    assert engine.store.get_open_session("iPad Kuby") is None


def test_sesja_bez_zgloszonego_startu_nie_generuje_pushu_o_koncu(engine):
    """Sesja otwarta nieznanym ruchem i zamknieta przed okienkiem scalania
    nie istniala dla uzytkownika — nie moze sie odezwac na pozegnanie."""
    t = local(2026, 9, 27, 10, 0)
    assert engine.handle(ev(t, "jakas-strona.pl")) == []
    engine.store.close_session(1, t)
    engine.store.set_meta("pending_start:iPad Kuby", "null")
    notes = engine.tick(t + timedelta(minutes=30))
    assert [n for n in notes if n.kind is NotifyKind.SESSION_END] == []


# =============================================================== ciche godziny
def test_w_cichych_godzinach_start_sesji_ma_wyzszy_priorytet(engine):
    notes = engine.handle(ev(local(2026, 9, 27, 2, 15), "www.youtube.com"))
    assert len(notes) == 1
    assert notes[0].priority == 5
    # Noc domyslnie = ciche godziny: jeden push w formie nocnej, nie dwa.
    assert notes[0].title == "\U0001F319 Kuba uzywa iPada w nocy"
    assert notes[0].text == "02:15, YouTube"


def test_ciche_godziny_bez_nocy_maja_stary_dopisek(classifier):
    cfg = make_config(engine={"night": {"enabled": False}})
    eng = Engine(cfg, Store(":memory:"), classifier)
    notes = eng.handle(ev(local(2026, 9, 27, 2, 15), "www.youtube.com"))
    assert "CICHYCH" in notes[0].title
    assert notes[0].priority == 5


def test_w_cichych_godzinach_nie_ma_pushy_o_aplikacjach(engine):
    t = local(2026, 9, 27, 2, 15)
    engine.handle(ev(t, "www.youtube.com"))
    # Inna aplikacja, poza cooldownem — w dzien dalaby push. W nocy nie.
    assert engine.handle(ev(t + timedelta(minutes=1), "ecsv3.roblox.com")) == []


def test_poza_cichymi_godzinami_priorytet_jest_zwykly(engine):
    notes = engine.handle(ev(local(2026, 9, 27, 8, 0), "www.youtube.com"))
    assert notes[0].priority == 3
    assert "CICHYCH" not in notes[0].title


def test_ciche_godziny_moga_byc_wylaczone():
    cfg = make_config(engine={"quiet_hours": None})
    import pathlib
    import tempfile  # noqa: E401,PLC0415

    from conftest import APP_MAP  # noqa: PLC0415

    d = pathlib.Path(tempfile.mkdtemp())
    (d / "app_map.yaml").write_text(APP_MAP, encoding="utf-8")
    from kidwatch.classifier import Classifier  # noqa: PLC0415

    eng = Engine(cfg, Store(":memory:"), Classifier(d / "app_map.yaml"))
    t = local(2026, 9, 27, 2, 15)
    eng.handle(ev(t, "www.youtube.com"))
    # Bez cichych godzin apka przechodzi tez noca.
    assert eng.handle(ev(t + timedelta(minutes=1), "ecsv3.roblox.com")) != []


# ============================================================ limit godzinowy
def test_limit_godzinowy_dlawi_apki_i_agreguje_nadmiar(classifier):
    cfg = make_config(engine={"max_notifications_per_hour": 3, "app_cooldown_minutes": 0})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 10, 0)

    sent = []
    for i, domain in enumerate(
        ["www.youtube.com", "ecsv3.roblox.com", "api.minecraft.net", "www.youtubekids.com"] * 2
    ):
        sent += eng.handle(ev(t + timedelta(minutes=i), domain))

    # Limit 3/h: przechodzi start sesji (nigdy nie dlawiony) + 2 apki.
    assert len([n for n in sent if n.kind is NotifyKind.APP]) == 2
    assert eng.store.count_throttled("iPad Kuby") > 0

    # Po godzinie okno limitu sie przesuwa i zaleglosci ida zbiorczo.
    later = eng.tick(t + timedelta(hours=1, minutes=30))
    thr = [n for n in later if n.kind is NotifyKind.THROTTLED]
    assert len(thr) == 1
    assert "pominietych" in thr[0].text
    assert eng.store.count_throttled("iPad Kuby") == 0


def test_start_sesji_nigdy_nie_jest_dlawiony(classifier):
    """Zdlawienie 'iPad wlaczyl sie o 2 w nocy' zniweczylo by sens serwisu."""
    cfg = make_config(engine={"max_notifications_per_hour": 1, "app_cooldown_minutes": 0})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t = local(2026, 9, 27, 10, 0)
    for i in range(6):
        eng.handle(ev(t + timedelta(minutes=i), "ecsv3.roblox.com"))
    # Sesja konczy sie, zaczyna nowa 30 min pozniej — start musi przejsc.
    notes = []
    for i in range(30, 36):
        notes += eng.handle(ev(t + timedelta(minutes=i), "ecsv3.roblox.com"))
    assert any(n.kind is NotifyKind.SESSION_START for n in notes)


# ======================================================== podsumowanie dnia
def test_podsumowanie_dnia_o_wyznaczonej_godzinie_raz(engine):
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))
    engine.handle(ev(t + timedelta(minutes=5), "r1.googlevideo.com"))
    engine.tick(t + timedelta(minutes=30))  # domknij sesje

    # Przed 20:30 nic.
    assert [n for n in engine.tick(local(2026, 9, 27, 20, 0)) if n.kind is NotifyKind.DAILY] == []

    notes = engine.tick(local(2026, 9, 27, 20, 31))
    daily = [n for n in notes if n.kind is NotifyKind.DAILY]
    assert len(daily) == 1
    assert "*Kuba* — 1 sesja" in daily[0].text
    assert "\u2022 YouTube" in daily[0].text
    assert "*Zosia* — brak aktywnosci" in daily[0].text

    # Drugi tik tego samego dnia nie powtarza podsumowania.
    assert [n for n in engine.tick(local(2026, 9, 27, 21, 0)) if n.kind is NotifyKind.DAILY] == []


def test_podsumowanie_liczy_per_dziecko(engine):
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com", device="ipad-kuby"))
    engine.handle(ev(t, "ecsv3.roblox.com", device="ipad-zosi"))
    engine.tick(t + timedelta(minutes=30))
    daily = [n for n in engine.tick(local(2026, 9, 27, 20, 31)) if n.kind is NotifyKind.DAILY]
    assert "*Kuba*" in daily[0].text and "*Zosia*" in daily[0].text
    assert "Roblox" in daily[0].text


# =================================================================== restart
def test_restart_nie_gubi_sesji_ani_nie_dubluje_pushy(tmp_path, classifier):
    db = tmp_path / "state.db"
    cfg = make_config()
    t = local(2026, 9, 27, 10, 0)

    store1 = Store(db)
    eng1 = Engine(cfg, store1, classifier)
    first = eng1.handle(ev(t, "www.youtube.com"))
    assert len(first) == 1
    store1.close()

    # --- restart procesu: nowy Store, nowy Engine, ta sama baza ---
    store2 = Store(db)
    eng2 = Engine(cfg, store2, classifier)

    # Sesja zyje, wiec 2 minuty pozniej NIE ma nowego startu.
    assert eng2.handle(ev(t + timedelta(minutes=2), "r1.googlevideo.com")) == []
    session = store2.get_open_session("iPad Kuby")
    assert session is not None and int(session["start_notified"]) == 1

    # Powtorne przetworzenie tego samego zdarzenia nie generuje drugiego pusha.
    assert eng2.handle(ev(t, "www.youtube.com")) == []

    # Koniec sesji jest zgloszony raz, przez nowy proces. Strumien po
    # restarcie milczy, wiec tik najpierw czeka na nadrobienie zaleglosci
    # (Engine.CATCHUP_MAX), a dopiero potem zamyka sesje.
    assert eng2.tick(t + timedelta(minutes=30)) == []
    later = t + timedelta(minutes=30) + Engine.CATCHUP_MAX
    end = [n for n in eng2.tick(later) if n.kind is NotifyKind.SESSION_END]
    assert len(end) == 1
    store2.close()


def test_dedup_blokuje_dokladnie_ten_sam_klucz(engine):
    t = local(2026, 9, 27, 10, 0)
    assert engine.handle(ev(t, "www.youtube.com")) != []
    # identyczne zdarzenie => identyczny dedup_key => cisza
    assert engine.handle(ev(t, "www.youtube.com")) == []


# ================================================================= formatowanie
@pytest.mark.parametrize(
    ("minutes", "expected"),
    [
        (0, "0 min"),
        (1, "1 min"),
        (59, "59 min"),
        (60, "1 h"),
        (74, "1 h 14 min"),
        (135, "2 h 15 min"),
    ],
)
def test_format_czasu(minutes, expected):
    assert fmt_duration(timedelta(minutes=minutes)) == expected


# ========================================================= ruch wspoldzielony
def _cfg_with_shared(tmp_path):
    """Mapa z sekcja `shared` — CDN-y i SDK reklamowe."""
    from kidwatch.classifier import Classifier  # noqa: PLC0415

    p = tmp_path / "m.yaml"
    p.write_text(
        'noise:\n  - apple.com\n'
        'shared:\n  - cloudfront.net\n  - unity3d.com\n'
        'apps:\n  "Asphalt":\n    - gameloft.com\n  "YouTube":\n    - youtube.com\n',
        encoding="utf-8",
    )
    return Engine(make_config(), Store(":memory:"), Classifier(p))


def test_ruch_wspoldzielony_nie_otwiera_sesji(tmp_path):
    """Gdyby otwieral, reklama dociagnieta w tle budzilaby Cie pushem w nocy."""
    eng = _cfg_with_shared(tmp_path)
    t = local(2026, 9, 27, 3, 0)
    assert eng.handle(ev(t, "d1.cloudfront.net")) == []
    assert eng.handle(ev(t + timedelta(minutes=1), "auction.unity3d.com")) == []
    assert eng.store.get_open_session("iPad Kuby") is None


def test_ruch_wspoldzielony_przedluza_otwarta_sesje(tmp_path):
    """Sedno wykrywania gier: Asphalt gada z wlasnym zapleczem rzadko, a z
    CloudFrontem czesto. Bez tego jego sesja bylaby sztucznie krotka."""
    eng = _cfg_with_shared(tmp_path)
    t = local(2026, 9, 27, 15, 0)
    eng.handle(ev(t, "asphalt.gameloft.com"))  # start sesji

    # Same CDN-y przez 20 minut, co 5 min — sesja ma zyc.
    for i in (5, 10, 15, 20):
        eng.handle(ev(t + timedelta(minutes=i), "d1.cloudfront.net"))

    assert eng.store.get_open_session("iPad Kuby") is not None
    # Ostatnia aktywnosc 15:20, idle_minutes=10, wiec domkniecie dopiero po 15:30.
    assert [n for n in eng.tick(t + timedelta(minutes=25))
            if n.kind is NotifyKind.SESSION_END] == []
    notes = eng.tick(t + timedelta(minutes=31))
    end = [n for n in notes if n.kind is NotifyKind.SESSION_END]
    assert len(end) == 1
    # Sesja trwala do 15:20, nie do 15:00 — CDN ja podtrzymal.
    assert "15:00–15:20" in end[0].text


def test_przedluzanie_jest_OGRANICZONE_a_nie_nieskonczone(tmp_path):
    """NAJWAZNIEJSZY test tej funkcji. Bez ogranicznika odswiezanie aplikacji
    w tle, trafiajace w te same CDN-y, trzymaloby sesje otwarta bez konca —
    sesja nigdy by sie nie skonczyla, a wszystkie czasy byly bez sensu.

    Prog liczy sie od ostatniego ROZPOZNANEGO zdarzenia, nie od ostatniego
    jakiegokolwiek — inaczej sam CDN podtrzymywalby sie w nieskonczonosc.
    """
    from kidwatch.classifier import Classifier  # noqa: PLC0415

    p = tmp_path / "m.yaml"
    p.write_text(
        'noise: []\nshared:\n  - cloudfront.net\napps:\n  "Asphalt":\n    - gameloft.com\n',
        encoding="utf-8",
    )
    cfg = make_config(engine={"shared_extend_minutes": 30})
    eng = Engine(cfg, Store(":memory:"), Classifier(p))

    t = local(2026, 9, 27, 15, 0)
    eng.handle(ev(t, "asphalt.gameloft.com"))  # jedyne rozpoznane zdarzenie

    # Sam CDN co 5 minut przez DWIE GODZINY. Gdyby ogranicznika nie bylo, sesja
    # zylaby caly ten czas.
    for i in range(5, 125, 5):
        eng.handle(ev(t + timedelta(minutes=i), "d1.cloudfront.net"))

    assert eng.store.get_open_session("iPad Kuby") is None, "sesja MUSI byc domknieta"
    closed = eng.store.conn.execute(
        "SELECT started_at, last_activity_at FROM sessions ORDER BY id LIMIT 1"
    ).fetchone()
    from kidwatch.store import from_iso  # noqa: PLC0415

    trwanie = from_iso(closed["last_activity_at"]) - from_iso(closed["started_at"])
    # Najwyzej prog (30 min), a nie dwie godziny.
    assert trwanie <= timedelta(minutes=30), trwanie


def test_prog_zero_wylacza_przedluzanie(tmp_path):
    from kidwatch.classifier import Classifier  # noqa: PLC0415

    p = tmp_path / "m.yaml"
    p.write_text(
        'noise: []\nshared:\n  - cloudfront.net\napps:\n  "Asphalt":\n    - gameloft.com\n',
        encoding="utf-8",
    )
    eng = Engine(make_config(engine={"shared_extend_minutes": 0}), Store(":memory:"), Classifier(p))
    t = local(2026, 9, 27, 15, 0)
    eng.handle(ev(t, "asphalt.gameloft.com"))
    eng.handle(ev(t + timedelta(minutes=5), "d1.cloudfront.net"))
    session = eng.store.get_open_session("iPad Kuby")
    from kidwatch.store import from_iso  # noqa: PLC0415

    assert from_iso(session["last_activity_at"]) == t.astimezone(UTC)


def test_ruch_wspoldzielony_nie_dostaje_pushu_o_aplikacji(tmp_path):
    eng = _cfg_with_shared(tmp_path)
    t = local(2026, 9, 27, 15, 0)
    eng.handle(ev(t, "asphalt.gameloft.com"))
    # CDN w trakcie sesji: zadnego pusha, bo nie wiadomo, co to za apka.
    assert eng.handle(ev(t + timedelta(minutes=2), "d1.cloudfront.net")) == []


def test_ruch_wspoldzielony_liczy_sie_jako_dowod_zycia(tmp_path):
    eng = _cfg_with_shared(tmp_path)
    eng.handle(ev(local(2026, 9, 27, 3, 0), "d1.cloudfront.net"))
    assert eng.store.get_meta("alive:iPad Kuby") is not None


# ============================================== nazywanie odwiedzanych domen
def test_pierwsza_nierozpoznana_domena_jest_nazwana_od_razu(classifier):
    engine = Engine(make_config(engine={"notify_unknown": True}), Store(":memory:"), classifier)
    """Samo "Przegladarka / inne" nic nie mowi. Chcemy wiedziec CO."""
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))  # start sesji
    notes = engine.handle(ev(t + timedelta(seconds=30), "forum-o-grach.pl"))
    assert len(notes) == 1
    assert notes[0].app == UNKNOWN_LABEL
    assert "forum-o-grach.pl" in notes[0].text


def test_kolejne_domeny_ida_ZBIORCZO_po_cooldownie(classifier):
    """Push wychodzi przy pierwszej nierozpoznanej domenie, a nastepne czekaja na
    cooldown i sa wymieniane razem. Inaczej kazde klikniecie w przegladarce
    dawaloby osobne powiadomienie.

    Cooldown krotszy od idle_minutes, bo przy domyslnych progach (15 > 10) sesja
    konczy sie PRZED zbiorczym pushem i domeny wymienia podsumowanie sesji.
    """
    eng = Engine(make_config(
        engine={"app_cooldown_minutes": 5, "notify_unknown": True}
    ), Store(":memory:"), classifier)
    t = local(2026, 9, 27, 10, 0)
    eng.handle(ev(t, "www.youtube.com"))
    first = eng.handle(ev(t + timedelta(seconds=30), "forum-o-grach.pl"))
    assert "forum-o-grach.pl" in first[0].text

    # W cooldownie cisza, mimo kolejnych domen.
    for i, host in enumerate(["www.jakas-gazeta.pl", "sklep-modelarski.pl"], start=1):
        assert eng.handle(ev(t + timedelta(minutes=i), host)) == []

    # Po cooldownie: jeden push wymieniajacy to, co bylo w miedzyczasie.
    notes = eng.handle(ev(t + timedelta(minutes=6), "www.wikipedia.org"))
    apki = [n for n in notes if n.kind is NotifyKind.APP]
    assert len(apki) == 1
    text = apki[0].text
    assert "jakas-gazeta.pl" in text
    assert "sklep-modelarski.pl" in text
    assert "wikipedia.org" in text


def test_domeny_sa_zwijane_do_postaci_czytelnej_dla_czlowieka(classifier):
    """Kilkadziesiat hostow jednej witryny to dla czlowieka jedna nazwa."""
    t = local(2026, 9, 27, 10, 0)
    eng = Engine(make_config(
        engine={"app_cooldown_minutes": 5, "notify_unknown": True}
    ), Store(":memory:"), classifier)
    eng.handle(ev(t, "www.youtube.com"))
    eng.handle(ev(t + timedelta(seconds=10), "start.pl"))  # zuzywa 1. push

    for i, host in enumerate(
        ["a.sklep.pl", "b.sklep.pl", "cdn1.sklep.pl", "cdn2.sklep.pl"], start=1
    ):
        eng.handle(ev(t + timedelta(minutes=i), host))

    notes = [
        n for n in eng.handle(ev(t + timedelta(minutes=6), "inna-strona.pl"))
        if n.kind is NotifyKind.APP
    ]
    assert len(notes) == 1
    # Cztery hosty jednej witryny -> jedna nazwa w tekscie.
    assert notes[0].text.count("sklep.pl") == 1


def test_sesja_otwarta_nierozpoznanym_ruchem_mowi_czym(engine):
    """Zamiast samego "aktywny" chcemy nazwe domeny — to zwykle przegladanie
    albo gra, ktorej nie ma jeszcze w app_map.yaml."""
    t = local(2026, 9, 27, 10, 0)
    assert engine.handle(ev(t, "api.super-gierka-online.com")) == []
    notes = engine.handle(ev(t + timedelta(minutes=2), "api.super-gierka-online.com"))
    assert len(notes) == 1
    assert notes[0].kind is NotifyKind.SESSION_START
    assert "super-gierka-online.com" in notes[0].text


def test_podsumowanie_sesji_wymienia_odwiedzone_strony(engine):
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))
    engine.handle(ev(t + timedelta(minutes=1), "forum-o-grach.pl"))
    engine.handle(ev(t + timedelta(minutes=2), "www.wikipedia.org"))
    notes = engine.tick(t + timedelta(minutes=15))
    end = [n for n in notes if n.kind is NotifyKind.SESSION_END]
    assert len(end) == 1
    assert "strony:" in end[0].text
    assert "forum-o-grach.pl" in end[0].text
    assert "wikipedia.org" in end[0].text


def test_sesja_bez_nierozpoznanego_ruchu_nie_ma_linii_o_stronach(engine):
    t = local(2026, 9, 27, 10, 0)
    engine.handle(ev(t, "www.youtube.com"))
    engine.handle(ev(t + timedelta(minutes=1), "r1.googlevideo.com"))
    notes = engine.tick(t + timedelta(minutes=15))
    end = [n for n in notes if n.kind is NotifyKind.SESSION_END]
    assert "strony:" not in end[0].text


def test_nierozpoznany_ruch_DOMYSLNIE_bez_pusha_ale_zapisany(engine, store):
    """Pierwszy dzien na zywo: "Przegladarka / inne" to bylo zaplecze aplikacji
    (google.com, analityka), nie strony. Domyslnie bez pusha, ale w bazie."""
    t = local(2026, 10, 2, 15, 36)
    engine.handle(ev(t, "www.youtube.com"))
    notes = engine.handle(ev(t + timedelta(seconds=30), "www.google.com"))
    assert [n for n in notes if n.kind is NotifyKind.APP] == []
    assert store.conn.execute("SELECT COUNT(*) FROM events").fetchone()[0] >= 2
