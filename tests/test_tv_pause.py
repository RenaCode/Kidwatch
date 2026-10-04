"""Pauza monitoringu TV (tvpause.py): wyjazd z dziecmi, w domu ogladaja inni.

W pauzie telewizor nie jest odpytywany, nie powstaja sesje ani pushe TV,
czujka "TV nie odpowiada" milczy, a raporty mowia, ze TV nie byl liczony.
"""

from __future__ import annotations

import http.client
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from conftest import local, make_config, panel_login
from kidwatch.__main__ import main
from kidwatch.config import Config, PanelConfig, StoreConfig, TvConfig
from kidwatch.engine import Engine
from kidwatch.models import NotifyKind
from kidwatch.panel import start_panel
from kidwatch.panel_auth import PanelAuth
from kidwatch.scheduler import device_loop
from kidwatch.sources.tv import TvProbe, TvUnavailable, TvWatcher, parse_snapshot
from kidwatch.store import Store, to_iso
from kidwatch.tvpause import TvPauseRequests, parse_until

FIX = Path(__file__).parent / "fixtures" / "tv"
TZ = local(2026, 10, 3, 0, 0).tzinfo
HASLO = "bardzo-dlugie-haslo-testowe"


def fx(name: str) -> str:
    return (FIX / f"{name}.txt").read_text(encoding="utf-8")


def playing():
    return parse_snapshot(fx("media_youtube_playing"), fx("activity_youtube"), fx("power_awake"))


def tv_config(**kw):
    return make_config(tv=TvConfig(enabled=True, host="192.0.2.10"), **kw)


@pytest.fixture
def rig(tmp_path, classifier):
    """Silnik z kolejka zadan jak w `run` i obserwator TV na tej samej bazie."""
    cfg = tv_config()
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    store = Store(cfg.store.path)
    engine = Engine(cfg, store, classifier)
    requests = TvPauseRequests(cfg.panel_auth_path)
    engine.tv_pause.requests = requests
    watcher = TvWatcher(TvProbe(None), cfg.tv.name, store, tz=TZ, idle_minutes=10)
    yield cfg, store, engine, requests, watcher
    store.close()


def pause_notes(notes):
    return [n for n in notes if n.kind is NotifyKind.TV_PAUSE]


# ================================================================ termin i koniec
def test_pauza_z_terminem_i_automatyczne_wznowienie(rig):
    cfg, store, engine, requests, _ = rig
    t0 = local(2026, 10, 3, 18, 0)
    until = local(2026, 10, 10, 18, 0)
    requests.submit("pause", until, "rodzic")

    notes = pause_notes(engine.tick(t0))
    assert [n.title for n in notes] == ["Monitoring TV wstrzymany do 10.10 18:00"]
    assert notes[0].priority == 2
    assert "Włączone przez: rodzic" in notes[0].text
    latest = requests.latest()
    assert latest["pending"] is False and latest["ok"] is True

    assert store.tv_paused_at(t0 + timedelta(days=3)) is not None
    # Termin dziala od razu, takze zanim tik domknie wiersz.
    assert store.tv_paused_at(until) is None
    assert pause_notes(engine.tick(until - timedelta(minutes=1))) == []

    notes = pause_notes(engine.tick(until + timedelta(seconds=30)))
    assert [n.title for n in notes] == ["Monitoring TV wznowiony"]
    assert notes[0].priority == 2
    row = store.conn.execute("SELECT * FROM tv_pause").fetchone()
    assert row["ended_by"] == "auto"
    assert row["ended_at"] == to_iso(until)
    assert row["started_by"] == "rodzic"
    # Drugi tik nie dubluje pusha.
    assert pause_notes(engine.tick(until + timedelta(minutes=1))) == []


def test_reczne_wznowienie_i_zmiana_terminu(rig):
    _, store, engine, requests, _ = rig
    t0 = local(2026, 10, 3, 18, 0)
    requests.submit("pause", None, "rodzic")
    assert [n.title for n in pause_notes(engine.tick(t0))] == [
        "Monitoring TV wstrzymany do odwołania"
    ]
    # Ponowne "wstrzymaj" w trakcie zmienia termin tej samej pauzy.
    requests.submit("pause", local(2026, 10, 5, 12, 0), "drugi")
    notes = pause_notes(engine.tick(t0 + timedelta(hours=1)))
    assert notes[0].title == "Monitoring TV wstrzymany do 05.10 12:00"
    assert "Zmieniono termin" in notes[0].text
    assert store.conn.execute("SELECT COUNT(*) FROM tv_pause").fetchone()[0] == 1

    requests.submit("resume", None, "drugi")
    notes = pause_notes(engine.tick(t0 + timedelta(hours=2)))
    assert [n.title for n in notes] == ["Monitoring TV wznowiony"]
    assert "ręcznie przez: drugi" in notes[0].text
    row = store.conn.execute("SELECT * FROM tv_pause").fetchone()
    assert row["ended_by"] == "drugi"
    assert store.tv_paused_at(t0 + timedelta(hours=3)) is None


def test_termin_po_czasie_jest_odrzucany(rig):
    _, store, engine, requests, _ = rig
    t0 = local(2026, 10, 3, 18, 0)
    requests.submit("pause", t0 - timedelta(minutes=1), "rodzic")
    assert pause_notes(engine.tick(t0)) == []
    assert requests.latest()["ok"] is False
    assert store.tv_pause_open() is None


def test_parse_until_czas_lokalny_i_granice():
    now = local(2026, 10, 3, 12, 0).astimezone(UTC)
    assert parse_until("2026-10-10T18:00", TZ, now) == local(2026, 10, 10, 18, 0)
    with pytest.raises(ValueError, match="minął"):
        parse_until("2026-10-03T11:00", TZ, now)
    with pytest.raises(ValueError, match="dłuższa"):
        parse_until("2028-10-03T11:00", TZ, now)
    with pytest.raises(ValueError, match="zły termin"):
        parse_until("jutro", TZ, now)


# ============================================================ sesje i pushe TV
def test_w_pauzie_brak_sesji_i_pushy_TV(rig):
    _, store, engine, requests, w = rig
    t0 = local(2026, 10, 3, 17, 0)
    assert [n.kind for n in w.observe(playing(), t0)] == [NotifyKind.TV_START]
    w.observe(playing(), t0 + timedelta(minutes=30))

    # Pauza w trakcie ogladania: sesja konczy sie po cichu na ostatnim odczycie.
    requests.submit("pause", local(2026, 10, 3, 22, 0), "rodzic")
    notes = engine.tick(t0 + timedelta(minutes=31))
    assert NotifyKind.TV_END not in [n.kind for n in notes]
    assert store.get_open_session("TV salon") is None
    assert store.current_tv_segment("TV salon") is None

    for minute in range(35, 240, 5):
        assert w.observe(playing(), t0 + timedelta(minutes=minute)) == []
        assert w.on_unreachable(t0 + timedelta(minutes=minute)) == []
    assert store.conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1

    # Raport dnia liczy tylko ogladanie sprzed pauzy i mowi o pauzie.
    note = engine.summary_for(t0.date(), local(2026, 10, 3, 20, 30))[0]
    assert "*TV salon* — 1 sesja, 30 min" in note.text
    assert "monitoring wstrzymany od 03.10 17:31 do 03.10 22:00" in note.text

    # Po terminie czujnik dziala jak dawniej.
    after = local(2026, 10, 3, 22, 1)
    assert [n.kind for n in w.observe(playing(), after)] == [NotifyKind.TV_START]


class CountingShell:
    def __init__(self, down: bool = False) -> None:
        self.calls: list[str] = []
        self.down = down
        self.usage = ""

    async def shell(self, command: str) -> str:
        self.calls.append(command)
        if self.down:
            raise TvUnavailable("ConnectionRefusedError")
        if "usagestats" in command:
            return self.usage
        if "media_session" in command:
            return fx("media_youtube_playing")
        if "activity" in command:
            return fx("activity_youtube")
        return fx("power_awake")

    async def aclose(self) -> None:
        pass


class Sink:
    def __init__(self) -> None:
        self.notes = []

    async def send_all(self, notes) -> None:
        self.notes.extend(notes)


async def _no_sleep(_):
    return None


async def test_w_pauzie_telewizor_nie_jest_odpytywany(store):
    now = datetime.now(UTC)
    store.start_tv_pause(now - timedelta(hours=1), None, "rodzic")
    shell = CountingShell()
    w = TvWatcher(TvProbe(shell), "TV salon", store)
    sink = Sink()
    await device_loop([w], sink, 30, sleep=_no_sleep, max_iterations=3, store=store)
    assert shell.calls == []
    assert sink.notes == []
    assert store.get_meta("dev-ok:TV salon") is None
    assert await w.poll(now) == []
    assert shell.calls == []


# ===================================================================== czujka
async def test_czujka_TV_milczy_w_pauzie(store):
    now = datetime.now(UTC)
    store.set_meta("dev-ok:TV salon", to_iso(now - timedelta(days=5)))
    store.start_tv_pause(now - timedelta(days=4), now + timedelta(days=3), "rodzic")
    w = TvWatcher(TvProbe(CountingShell(down=True)), "TV salon", store)
    sink = Sink()
    await device_loop([w], sink, 30, sleep=_no_sleep, max_iterations=1, store=store,
                      unreachable_alert_hours=24)
    assert sink.notes == []


async def test_czujka_po_pauzie_liczy_cisze_od_konca_pauzy(store):
    now = datetime.now(UTC)
    store.set_meta("dev-ok:TV salon", to_iso(now - timedelta(days=8)))
    pid = store.start_tv_pause(now - timedelta(days=7), None, "rodzic")
    store.end_tv_pause(pid, now - timedelta(hours=2), "rodzic")
    w = TvWatcher(TvProbe(CountingShell(down=True)), "TV salon", store)
    sink = Sink()
    await device_loop([w], sink, 30, sleep=_no_sleep, max_iterations=1, store=store,
                      unreachable_alert_hours=24)
    assert sink.notes == []

    # Doba ciszy PO pauzie to juz prawdziwa awaria.
    store.conn.execute("UPDATE tv_pause SET ended_at=?", (to_iso(now - timedelta(hours=25)),))
    await device_loop([w], sink, 30, sleep=_no_sleep, max_iterations=1, store=store,
                      unreachable_alert_hours=24)
    assert [n.kind for n in sink.notes] == [NotifyKind.WATCHDOG]


# ================================================================= usagestats
def usage_dump(begin: int, minutes: int, last: datetime) -> str:
    return (
        "user=0\n  In-memory daily stats\n"
        f"    beginTime={begin}\n      packages\n"
        f"        package=com.google.android.youtube.tv totalTimeUsed={minutes * 60_000} "
        f"lastTimeUsed={int(last.timestamp() * 1000)}\n"
    )


async def test_usagestats_po_pauzie_nie_dolicza_czasu_z_pauzy(store):
    shell = CountingShell()
    shell.calls.clear()
    w = TvWatcher(TvProbe(shell), "TV salon", store, tz=TZ, usage_minutes=15)
    t0 = local(2026, 10, 3, 12, 0).astimezone(UTC)
    shell.usage = usage_dump(1, 10, t0)
    await w.poll(t0)
    assert store.tv_usage_between("TV salon", "2026-10-03", "2026-10-03") == [
        ("YouTube", 10 * 60_000)
    ]

    pid = store.start_tv_pause(t0 + timedelta(minutes=5), None, "rodzic")
    calls = len(shell.calls)
    await w.poll(t0 + timedelta(hours=5))
    assert len(shell.calls) == calls  # w pauzie zero odczytow, takze usagestats
    end = local(2026, 10, 4, 12, 0).astimezone(UTC)
    store.end_tv_pause(pid, end, "rodzic")

    # Nowy interwal z 90 min ogladania w pauzie: tylko punkt odniesienia.
    shell.usage = usage_dump(2, 90, end)
    await w.poll(end + timedelta(minutes=1))
    assert store.tv_usage_between("TV salon", "2026-10-04", "2026-10-04") == []
    # Kolejny odczyt liczy juz tylko przyrost po pauzie.
    shell.usage = usage_dump(2, 100, end + timedelta(minutes=16))
    await w.poll(end + timedelta(minutes=17))
    assert store.tv_usage_between("TV salon", "2026-10-04", "2026-10-04") == [
        ("YouTube", 10 * 60_000)
    ]


# ===================================================================== restart
def test_pauza_przezywa_restart(tmp_path, classifier):
    cfg = tv_config()
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    t0 = local(2026, 10, 3, 18, 0)
    until = local(2026, 10, 10, 18, 0)
    with Store(cfg.store.path) as store:
        engine = Engine(cfg, store, classifier)
        engine.tv_pause.requests = TvPauseRequests(cfg.panel_auth_path)
        engine.tv_pause.requests.submit("pause", until, "rodzic")
        assert pause_notes(engine.tick(t0))

    # "Nowy pod": swiezy Store, silnik i obserwator na tym samym pliku.
    with Store(cfg.store.path) as store:
        w = TvWatcher(TvProbe(None), cfg.tv.name, store, tz=TZ)
        assert w.paused(t0 + timedelta(days=1))
        assert w.observe(playing(), t0 + timedelta(days=1)) == []
        engine = Engine(cfg, store, classifier)
        assert pause_notes(engine.tick(t0 + timedelta(days=1))) == []
        notes = pause_notes(engine.tick(until + timedelta(minutes=1)))
        assert [n.title for n in notes] == ["Monitoring TV wznowiony"]


# ===================================================================== raporty
def test_raport_tygodnia_z_dopiskiem_o_pauzie(store, classifier):
    cfg = tv_config()
    engine = Engine(cfg, store, classifier)
    monday = local(2026, 9, 28, 0, 0).date()
    pid = store.start_tv_pause(local(2026, 9, 26, 10, 0), None, "rodzic")
    store.end_tv_pause(pid, local(2026, 10, 2, 18, 0), "auto")
    note = engine.build_weekly(monday, local(2026, 10, 4, 19, 0))
    assert "monitoring wstrzymany od 26.09 10:00 do 02.10 18:00" in note.text
    assert "*TV salon* — nic nie gralo" in note.text

    # Dzien w calosci w pauzie: zamiast "nic nie gralo" — "monitoring wstrzymany".
    day = engine.build_summary(local(2026, 9, 30, 0, 0).date(), local(2026, 9, 30, 21, 0))
    assert "*TV salon* — monitoring wstrzymany" in day.text


def test_raport_bez_pauzy_bez_dopisku(store, classifier):
    engine = Engine(tv_config(), store, classifier)
    note = engine.build_summary(local(2026, 10, 2, 0, 0).date(), local(2026, 10, 2, 21, 0))
    assert "wstrzymany" not in note.text


# ======================================================================= panel
@pytest.fixture
def server(tmp_path):
    cfg = tv_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path / "web")))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", HASLO)
    srv = start_panel(cfg)
    yield srv, cfg
    srv.shutdown()


def call(srv, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.server_address[1], timeout=5)
    hdrs = dict(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        hdrs.setdefault("Content-Type", "application/json")
    conn.request(method, path, body=data, headers=hdrs)
    resp = conn.getresponse()
    raw = resp.read()
    conn.close()
    return resp.status, json.loads(raw) if raw else None


def zaloguj(srv) -> tuple[str, str]:
    cookie = panel_login(srv.server_address[1], "rodzic", HASLO)
    jar = dict(c.split("=", 1) for c in cookie.split("; "))
    return cookie, jar["kidwatch_csrf"]


def test_endpoint_pauzy_wymaga_sesji_i_CSRF(server):
    srv, cfg = server
    later = (datetime.now(TZ) + timedelta(days=7)).strftime("%Y-%m-%dT%H:%M")
    assert call(srv, "GET", "/api/tv/pause")[0] == 401
    assert call(srv, "POST", "/api/tv/pause", {"until": later})[0] == 401
    assert call(srv, "POST", "/api/tv/resume", {})[0] == 401

    cookie, csrf = zaloguj(srv)
    assert call(srv, "POST", "/api/tv/pause", {"until": later}, {"Cookie": cookie})[0] == 403
    assert call(srv, "POST", "/api/tv/pause", {"until": later},
                {"Cookie": cookie, "X-CSRF-Token": "zly"})[0] == 403
    assert call(srv, "POST", "/api/tv/resume", {}, {"Cookie": cookie})[0] == 403
    # Odrzucone POST-y niczego nie zlecily.
    assert TvPauseRequests(cfg.panel_auth_path).pending() == []


def test_endpoint_pauzy_zleca_zadanie_z_loginem(server, classifier):
    srv, cfg = server
    cookie, csrf = zaloguj(srv)
    h = {"Cookie": cookie, "X-CSRF-Token": csrf}
    later = (datetime.now(TZ) + timedelta(days=7)).replace(second=0, microsecond=0)

    for bad in ({}, {"until": "jutro"}, {"until": "2020-01-01T10:00"}, {"until": 5}):
        assert call(srv, "POST", "/api/tv/pause", bad, h)[0] == 400, bad
    status, body = call(srv, "POST", "/api/tv/pause",
                        {"until": later.strftime("%Y-%m-%dT%H:%M")}, h)
    assert status == 202 and body["ok"]
    pending = TvPauseRequests(cfg.panel_auth_path).pending()
    assert [(r["action"], r["login"]) for r in pending] == [("pause", "rodzic")]

    state = call(srv, "GET", "/api/tv/pause", headers={"Cookie": cookie})[1]
    assert state["available"] is True
    assert state["active"] is None
    assert state["request"]["pending"] is True

    # Petla glowna wykonuje zadanie — panel pokazuje aktywna pauze.
    with Store(cfg.store.path) as store:
        engine = Engine(cfg, store, classifier)
        engine.tv_pause.requests = TvPauseRequests(cfg.panel_auth_path)
        assert pause_notes(engine.tick(datetime.now(UTC)))
    state = call(srv, "GET", "/api/tv/pause", headers={"Cookie": cookie})[1]
    assert state["active"]["by"] == "rodzic"
    assert datetime.fromisoformat(state["active"]["until"]) == later
    assert state["request"]["ok"] is True

    assert call(srv, "POST", "/api/tv/resume", {}, h)[0] == 202
    assert call(srv, "POST", "/api/tv/pause", {"until": None}, h)[0] == 202


def test_bez_czujnika_TV_endpoint_pauzy_niedostepny(tmp_path):
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path)))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", HASLO)
    srv = start_panel(cfg)
    try:
        cookie, csrf = zaloguj(srv)
        h = {"Cookie": cookie, "X-CSRF-Token": csrf}
        assert call(srv, "POST", "/api/tv/pause", {"until": None}, h)[0] == 404
        assert call(srv, "GET", "/api/tv/pause", headers={"Cookie": cookie})[1] == {
            "available": False
        }
    finally:
        srv.shutdown()


# ========================================================================= CLI
def test_cli_tv_pauza_zleca_i_pokazuje_stan(tmp_path, capsys, classifier):
    fixture = Path(__file__).parent / "fixtures" / "config.yaml"
    data = yaml.safe_load(fixture.read_text(encoding="utf-8"))
    data["store"]["path"] = str(tmp_path / "k.db")
    data["app_map_path"] = str(Path(__file__).parent.parent / "app_map.yaml")
    data["tv"] = {"enabled": True, "host": "192.0.2.10"}
    cfg_path = tmp_path / "config.yaml"
    cfg_path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    later = (datetime.now(TZ) + timedelta(days=2)).strftime("%Y-%m-%dT%H:%M")

    assert main(["--config", str(cfg_path), "tv-pauza", "--do", "2020-01-01T10:00"]) == 2
    assert main(["--config", str(cfg_path), "tv-pauza", "--do", later]) == 0
    assert "zlecono wstrzymanie" in capsys.readouterr().out

    cfg = Config.load(cfg_path)
    with Store(cfg.store.path) as store:
        engine = Engine(cfg, store, classifier)
        engine.tv_pause.requests = TvPauseRequests(cfg.panel_auth_path)
        assert pause_notes(engine.tick(datetime.now(UTC)))
    assert main(["--config", str(cfg_path), "tv-pauza"]) == 0
    assert "monitoring wstrzymany do" in capsys.readouterr().out

    assert main(["--config", str(cfg_path), "tv-pauza", "--wznow"]) == 0
    assert [r["login"] for r in TvPauseRequests(cfg.panel_auth_path).pending()] == ["cli"]
