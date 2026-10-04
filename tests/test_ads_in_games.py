"""Reklamy wideo YouTube w grach (Google IMA).

Scenariusz z 2026-10-02 16:07: podczas Asphalt na obu iPadach ruch YouTube
(youtubei.googleapis.com, googlevideo.com, i.ytimg.com, s.youtube.com) w tej
samej sekundzie co SDK reklamowe (unity3d.com, doubleclick.net, fyber,
inner-active). To reklama, nie ogladanie: bez pusha "YouTube", minuty dla gry.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from conftest import ev, local, make_config
from kidwatch.classifier import Classifier
from kidwatch.engine import Engine, is_ad_network
from kidwatch.models import NotifyKind
from kidwatch.store import Store

APP_MAP = """
noise:
  - apple.com
shared:
  - unity3d.com
  - doubleclick.net
  - fyber.com
  - inner-active.mobi
  - cloudfront.net
  - googleapis.com
apps:
  "YouTube":
    - youtube.com
    - googlevideo.com
    - ytimg.com
    - youtubei.googleapis.com
  "Asphalt":
    - gameloft.com
  "Minecraft":
    - minecraft.net
"""

YT = ("youtubei.googleapis.com", "rr2---sn-x.googlevideo.com", "i.ytimg.com", "s.youtube.com")
ADS = ("auction.unityads.unity3d.com", "pubads.g.doubleclick.net", "cdn2.inner-active.mobi")


@pytest.fixture
def engine(tmp_path):
    p = tmp_path / "app_map.yaml"
    p.write_text(APP_MAP, encoding="utf-8")
    store = Store(":memory:")
    yield Engine(make_config(), store, Classifier(p, reload_check_seconds=0.0))
    store.close()


def feed(engine, t, domains, device="ipad-kuby"):
    out = []
    for d in domains:
        out += engine.handle(ev(t, d, device))
    return out


def apps(engine, device="iPad Kuby") -> dict[str, int]:
    sid = int(engine.store.get_open_session(device)["id"])
    return dict(engine.store.session_app_minutes(sid))


def kinds_apps(notes):
    return [(n.kind, n.app) for n in notes]


def test_reklama_w_tej_samej_sekundzie_co_SDK_to_nie_YouTube(engine):
    t = local(2026, 10, 2, 16, 0)
    start = feed(engine, t, ["asphalt.gameloft.com"])
    assert kinds_apps(start) == [(NotifyKind.SESSION_START, "Asphalt")]
    for m in range(1, 7):
        feed(engine, t + timedelta(minutes=m), ["ingame.gameloft.com"])

    t_ad = local(2026, 10, 2, 16, 7)
    notes = feed(engine, t_ad, [*ADS[:2], *YT, ADS[2]])
    notes += feed(engine, t_ad + timedelta(seconds=20), YT)
    notes += engine.tick(t_ad + timedelta(minutes=3))
    assert [n for n in notes if n.app == "YouTube"] == []
    minutes = apps(engine)
    assert "YouTube" not in minutes
    assert minutes["Asphalt"] == 8


def test_YouTube_przed_SDK_tez_jest_reklama_i_minuty_wracaja_do_gry(engine):
    """Kolejnosc zapytan w obrebie tej samej sekundy jest dowolna, a SDK potrafi
    odezwac sie po pobraniu klipu. Okno ±60 s dziala w obie strony."""
    t = local(2026, 10, 2, 16, 0)
    feed(engine, t, ["asphalt.gameloft.com"])
    t_yt = t + timedelta(minutes=2)
    notes = feed(engine, t_yt, YT)
    notes += feed(engine, t_yt + timedelta(minutes=1, seconds=-15), YT)  # 45 s pozniej
    notes += feed(engine, t_yt + timedelta(seconds=50), [ADS[0]])
    notes += engine.tick(t_yt + timedelta(minutes=3))
    assert [n for n in notes if n.app == "YouTube"] == []
    assert "YouTube" not in apps(engine)


def test_YouTube_dluzej_niz_2_min_bez_gry_to_prawdziwe_ogladanie(engine):
    t = local(2026, 10, 2, 16, 0)
    feed(engine, t, ["asphalt.gameloft.com"])
    t_yt = t + timedelta(minutes=1)
    notes = feed(engine, t_yt, [ADS[0], *YT])  # zaczelo sie od reklamy...
    for s in (30, 60, 90, 120, 150, 180, 240):
        notes += feed(engine, t_yt + timedelta(seconds=s), YT[:2])
    # ...ale trwa > 2 min bez jednego zdarzenia Asphalt: dziecko oglada.
    yt = [n for n in notes if n.app == "YouTube"]
    assert len(yt) == 1
    assert yt[0].kind is NotifyKind.APP
    assert yt[0].ts > t_yt + timedelta(minutes=2)
    assert apps(engine)["YouTube"] >= 2


def test_YouTube_po_grze_bez_zadnej_reklamy_to_YouTube_z_pushem_po_minucie(engine):
    """Brak sieci reklamowej w oknie = prawdziwe przelaczenie na YouTube. Push
    czeka 60 s (moze jeszcze przyjsc reklama), minuty od razu sa YouTube."""
    t = local(2026, 10, 2, 16, 0)
    feed(engine, t, ["play.minecraft.net"])
    t_yt = t + timedelta(minutes=5)
    assert feed(engine, t_yt, YT) == []
    assert apps(engine)["YouTube"] == 1
    assert engine.tick(t_yt + timedelta(seconds=30)) == []
    notes = engine.tick(t_yt + timedelta(seconds=61))
    assert kinds_apps(notes) == [(NotifyKind.APP, "YouTube")]


def test_sesja_otwarta_YouTube_nie_ma_kontekstu_gry(engine):
    t = local(2026, 10, 2, 16, 0)
    notes = feed(engine, t, [ADS[0], *YT])
    assert kinds_apps(notes) == [(NotifyKind.SESSION_START, "YouTube")]


def test_reklama_sprzed_ponad_minuty_nie_tlumaczy_YouTube(engine):
    t = local(2026, 10, 2, 16, 0)
    feed(engine, t, ["asphalt.gameloft.com", ADS[0]])
    t_yt = t + timedelta(minutes=3)
    feed(engine, t_yt, YT)
    notes = engine.tick(t_yt + timedelta(seconds=61))
    assert kinds_apps(notes) == [(NotifyKind.APP, "YouTube")]


def test_rozpoznawanie_sieci_reklamowych_po_sufiksie():
    assert is_ad_network("auction.unityads.unity3d.com")
    assert is_ad_network("imasdk.googleapis.com")
    assert not is_ad_network("youtubei.googleapis.com")
    assert not is_ad_network("d2k4q26owzy373.cloudfront.net")


def test_siec_reklamowa_spoza_mapy_tez_jest_dowodem_reklamy(engine):
    """Regresja: mintegral, moloco, pangle, applvn... sa w AD_NETWORK_SUFFIXES,
    ale app_map ich nie zna (UNKNOWN). Liczylo sie tylko AMBIGUOUS, wiec
    reklama przy takim SDK konczyla sie pushem "YouTube"."""
    t = local(2026, 10, 2, 16, 0)
    feed(engine, t, ["asphalt.gameloft.com"])
    t_ad = t + timedelta(minutes=2)
    notes = feed(engine, t_ad, ["analytics.rayjump.com", *YT])
    notes += engine.tick(t_ad + timedelta(minutes=3))
    assert [n for n in notes if n.app == "YouTube"] == []
    assert "YouTube" not in apps(engine)
    assert "Przegladarka / inne" not in apps(engine)


def test_nieznana_siec_reklamowa_nie_otwiera_sesji(engine):
    """SDK reklamowe odpytuje z tla. Jako "Przegladarka / inne" otwieralo
    sesje i budzilo pushem "iPad aktywny" przy spiacym iPadzie."""
    t = local(2026, 10, 2, 3, 0)
    notes = feed(engine, t, ["api.mintegral.com", "cfg.moloco.com"])
    notes += engine.tick(t + timedelta(minutes=1))
    assert engine.store.get_open_session("iPad Kuby") is None
    assert [n for n in notes if n.kind is NotifyKind.SESSION_START] == []
