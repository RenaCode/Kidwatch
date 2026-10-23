"""Nowa aplikacja na iPadzie: szybkie wykrycie i powiadomienie, ktore nie ginie
przy restarcie (2026-10-23).

Gra zainstalowana z Xcode dziala offline — DNS jej nie widzi, jedynym sygnalem
jest inwentarz MDM. Lista aplikacji szla co `refresh_hours` (6 h), wiec
powiadomienie przyszlo po 5,5 h. Teraz:

  * serwer MDM pyta o sama liste co `apps_refresh_minutes` (domyslnie 15),
    najwyzej jedna oczekujaca komenda na iPada;
  * zdarzenie niesie czas poprzedniej listy — tekst mowi, w jakim oknie
    aplikacja mogla zostac zainstalowana;
  * kazde okno restartu na drodze zdarzenie -> kursor czujki -> outbox ->
    kanal ma test „restart dokladnie tutaj": nowa instancja na tej samej
    bazie, powiadomienie dochodzi raz.

Restart symuluje wyjatek `Zabity` (BaseException, jak SystemExit przy
SIGTERM — petle lapia tylko Exception) rzucony w dokladnym punkcie. SQLite po
zabiciu procesu cofa niezatwierdzona transakcje tak samo jak ROLLBACK.
"""

from __future__ import annotations

import json
import plistlib
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from kidwatch import mdm as kw_mdm
from kidwatch.config import MdmConfig
from kidwatch.mdm import CURSOR_KEY, MdmApi, MdmWatcher, mdm_loop
from kidwatch.notifiers.base import Dispatcher, Outbox
from kidwatch.store import Store
from kidwatch_mdm import server as mdm_server
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import DevicePolicy, Policy
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.store import Store as MdmStore
from kidwatch_mdm.store import iso, now_utc
from test_mdm_kidwatch import TOKEN, UDID
from test_mdm_kidwatch import enroll as enroll_kw
from test_mdm_service import FakePusher, default_responder, enroll, run_commands

TZ = ZoneInfo("Europe/Warsaw")
APPS = "InstalledApplicationList"


class Zabity(BaseException):
    """Proces zabity w tym miejscu (SIGTERM/kill) — nie lapie go `except Exception`."""


def _svc(path, ca, policy) -> MDMService:
    return MDMService(
        store=MdmStore(path),
        ca=ca,
        policy=policy,
        public_url="https://mdm.example.com",
        pusher=FakePusher(),
    )


@pytest.fixture
def ca(tmp_path):
    return CA.create(tmp_path / "ca", org="RenaCode")


@pytest.fixture
def policy():
    return Policy(devices={"dziecko1": DevicePolicy(name="iPad Dziecka")})


@pytest.fixture
def svc(tmp_path, ca, policy):
    return _svc(tmp_path / "mdm.db", ca, policy)


@pytest.fixture
def mdm(tmp_path, ca, policy):
    """Prawdziwy serwer MDM z API admina — droga czujki jak w klastrze."""
    service = _svc(tmp_path / "mdm.db", ca, policy)
    admin = mdm_server.start(mdm_server.make_admin_handler(service, TOKEN), 0, "127.0.0.1")
    yield service, f"http://127.0.0.1:{admin.server_port}"
    admin.shutdown()


def _z_gra(cmd: dict) -> dict:
    if cmd["Command"]["RequestType"] == APPS:
        return {
            "Status": "Acknowledged",
            APPS: [
                {"Identifier": "com.gameloft.asphalt9", "Name": "Asphalt 9"},
                {"Identifier": "com.example.nowagra", "Name": "Nowa Gra"},
            ],
        }
    return default_responder(cmd)


def _pending(svc: MDMService, udid: str, request_type: str) -> int:
    return len(
        svc.store.query(
            "SELECT 1 FROM commands WHERE udid=? AND request_type=? "
            "AND status IN ('queued','sent','not_now')",
            (udid, request_type),
        )
    )


def _gotowy(svc: MDMService):
    """iPad zapisany, z odpowiedziami na wszystko: odswiezenie, profil, DDM."""
    ipad = enroll(svc)
    run_commands(svc, ipad)
    svc.reconcile()
    run_commands(svc, ipad)
    _ddm_pobrane(svc, ipad)
    return ipad


def _ddm_pobrane(svc: MDMService, ipad) -> None:
    """iPad pobral deklaracje (declaration-items) — atrapa tylko potwierdza komende."""
    svc.checkin(*ipad.msg(MessageType="DeclarativeManagement", Endpoint="declaration-items"))


def _installed(svc: MDMService) -> list[dict]:
    return [json.loads(e["detail"]) for e in svc.store.events() if e["kind"] == "apps_installed"]


# ===================================================================== polityka
def test_policy_apps_refresh_defaults_and_bounds():
    assert Policy().apps_refresh_minutes == 15
    assert Policy(apps_refresh_minutes=0).apps_refresh_minutes == 0
    assert Policy(apps_refresh_minutes=360, refresh_hours=6).apps_refresh_minutes == 360
    with pytest.raises(ValidationError, match="apps_refresh_minutes"):
        Policy(apps_refresh_minutes=4)
    with pytest.raises(ValidationError, match="apps_refresh_minutes"):
        Policy(apps_refresh_minutes=361, refresh_hours=6)


# ================================================================ rytm listy
def test_app_list_alone_every_15_minutes(svc):
    ipad = _gotowy(svc)
    t0 = now_utc()
    assert svc.reconcile(now=t0 + timedelta(minutes=10))["pushed"] == 0
    assert _pending(svc, ipad.udid, APPS) == 0

    stats = svc.reconcile(now=t0 + timedelta(minutes=16))
    assert stats["pushed"] == 1 and stats["enqueued"] == 1
    assert _pending(svc, ipad.udid, APPS) == 1
    # Ciezkie zapytania dalej co refresh_hours.
    for heavy in ("DeviceInformation", "SecurityInfo", "ProfileList"):
        assert _pending(svc, ipad.udid, heavy) == 0
    # Nastepny obieg, iPad jeszcze nie odpowiedzial: bez drugiej komendy.
    svc.reconcile(now=t0 + timedelta(minutes=21))
    assert _pending(svc, ipad.udid, APPS) == 1

    seen = run_commands(svc, ipad, _z_gra)
    assert [c["Command"]["RequestType"] for c in seen] == [APPS]
    assert [a["id"] for a in _installed(svc)[-1]["apps"]] == ["com.example.nowagra"]


def test_app_list_off_keeps_old_cadence(tmp_path, ca):
    svc = _svc(tmp_path / "mdm.db", ca, Policy(
        devices={"dziecko1": DevicePolicy(name="iPad")}, apps_refresh_minutes=0))
    ipad = _gotowy(svc)
    t0 = now_utc()
    for minutes in (16, 60, 300):
        svc.reconcile(now=t0 + timedelta(minutes=minutes))
    assert _pending(svc, ipad.udid, APPS) == 0
    svc.reconcile(now=t0 + timedelta(hours=6, minutes=1))
    assert _pending(svc, ipad.udid, APPS) == 1


def test_locked_ipad_gets_one_app_command_and_backed_off_pushes(svc):
    """iPad zablokowany odpowiada NotNow: jedna oczekujaca komenda (zadnej
    lawiny w kolejce), a pushe z rosnacym odstepem jak dla kazdej stojacej
    kolejki — nie co 15 min przez cala noc."""
    ipad = _gotowy(svc)
    t0 = now_utc()
    svc.reconcile(now=t0 + timedelta(minutes=16))
    resp = svc.connect(*ipad.msg(Status="Idle"))
    cmd = plistlib.loads(resp.body)
    assert cmd["Command"]["RequestType"] == APPS
    svc.connect(*ipad.msg(Status="NotNow", CommandUUID=cmd["CommandUUID"]))

    pushes = 0
    for i in range(1, 12 * 12 + 1):  # 12 h obiegow co 5 min (do 6 h przed refresh_hours)
        t = t0 + timedelta(minutes=16 + 5 * i)
        if t - t0 >= timedelta(hours=6):
            break
        pushes += svc.reconcile(now=t)["pushed"]
        assert _pending(svc, ipad.udid, APPS) == 1
    # Polgodziny bez zmian (do 6 pushy), potem co 15 min do 2 h, potem co
    # godzine: ok. 6 + 6 + 4 przez 6 h. Bez odstepu byloby 70.
    assert pushes <= 20, pushes


def test_offline_ipad_does_not_pile_up_commands(svc):
    ipad = _gotowy(svc)
    t0 = now_utc()
    for i in range(1, 60):  # 5 h bez odzewu
        svc.reconcile(now=t0 + timedelta(minutes=16 + 5 * i))
    assert _pending(svc, ipad.udid, APPS) == 1


def test_event_carries_previous_list_time(svc):
    ipad = _gotowy(svc)
    before = svc.store.device(ipad.udid)["apps_at"]
    assert before
    svc.reconcile(now=now_utc() + timedelta(minutes=16))
    run_commands(svc, ipad, _z_gra)
    assert _installed(svc)[-1]["previous_at"] == before


# ==================================================== tekst powiadomienia
def test_new_app_text_says_when_found_and_install_window():
    event = {
        "kind": "apps_installed",
        "at": "2026-10-23T11:36:00+00:00",
        "detail": json.dumps({"apps": [{"id": "g", "name": "Gra"}],
                              "previous_at": "2026-10-23T05:51:00+00:00"}),
    }
    kind, prio, title, text = kw_mdm._describe(event, "iPad Dziecka", "ipad", TZ)
    assert title == "iPad Dziecka: nowa aplikacja" and prio == 3
    assert text == "Gra\nwykryta 13:36, zainstalowana po 07:51"


def test_new_app_text_across_midnight_has_date():
    event = {
        "kind": "apps_installed",
        "at": "2026-10-23T05:00:00+00:00",
        "detail": {"apps": [{"id": "g", "name": "Gra"}],
                   "previous_at": "2026-10-22T20:10:00+00:00"},
    }
    text = kw_mdm._describe(event, "iPad", "ipad", TZ)[3]
    assert text == "Gra\nwykryta 07:00, zainstalowana po 22.10 22:10"


@pytest.mark.parametrize("detail", [
    {"apps": [{"id": "g", "name": "Gra"}]},  # serwer sprzed 2026-10-23
    {"apps": [{"id": "g", "name": "Gra"}], "previous_at": "zle"},
])
def test_new_app_text_without_previous_time_is_unchanged(detail):
    event = {"kind": "apps_installed", "at": "2026-10-23T11:36:00+00:00", "detail": detail}
    assert kw_mdm._describe(event, "iPad", "ipad", TZ)[3] == "Gra"


# ================================== okno (d'): restart w trakcie odpowiedzi iPada
def test_restart_between_event_and_new_list_does_not_double_alarm(tmp_path, ca, policy,
                                                                   monkeypatch):
    """iPad odpowiedzial lista z nowa aplikacja; serwer zapisal zdarzenie i padl
    przed zapisem nowej listy. Po starcie ta sama aplikacja byla znowu „nowa"
    (drugie zdarzenie = drugi push). Teraz odpowiedz idzie jedna transakcja."""
    path = tmp_path / "mdm.db"
    svc = _svc(path, ca, policy)
    ipad = _gotowy(svc)
    svc.reconcile(now=now_utc() + timedelta(minutes=16))

    real = MdmStore.update_device

    def pada_po_zdarzeniu(self, udid, **fields):
        if "apps_json" in fields:
            raise Zabity
        return real(self, udid, **fields)

    monkeypatch.setattr(MdmStore, "update_device", pada_po_zdarzeniu)
    with pytest.raises(Zabity):
        run_commands(svc, ipad, _z_gra)
    monkeypatch.setattr(MdmStore, "update_device", real)

    svc2 = _svc(path, ca, policy)  # restart: ta sama baza
    run_commands(svc2, ipad, _z_gra)  # iPad ponawia; komenda zostala `sent`
    svc2.reconcile(now=now_utc() + timedelta(minutes=40))
    run_commands(svc2, ipad, _z_gra)  # kolejna lista: nic nowego
    assert [[a["id"] for a in d["apps"]] for d in _installed(svc2)] == [["com.example.nowagra"]]


def test_restart_between_ack_and_result_does_not_lose_app(tmp_path, ca, policy, monkeypatch):
    """Komenda zamknieta (acknowledged), a wynik niezapisany: nowa aplikacja
    czekala do nastepnej listy. Teraz restart cofa i zamkniecie — iPad dostaje
    komende ponownie i zdarzenie powstaje od razu."""
    path = tmp_path / "mdm.db"
    svc = _svc(path, ca, policy)
    ipad = _gotowy(svc)
    svc.reconcile(now=now_utc() + timedelta(minutes=16))

    def pada(self, *a, **k):
        raise Zabity

    monkeypatch.setattr(MDMService, "_on_result", pada)
    with pytest.raises(Zabity):
        run_commands(svc, ipad, _z_gra)
    monkeypatch.undo()

    svc2 = _svc(path, ca, policy)
    assert _pending(svc2, ipad.udid, APPS) == 1
    run_commands(svc2, ipad, _z_gra)
    assert len(_installed(svc2)) == 1


# ================================= okno (d): restart, gdy komenda jest `sent`
def test_restart_with_app_command_sent_resends_it(tmp_path, ca, policy):
    path = tmp_path / "mdm.db"
    svc = _svc(path, ca, policy)
    ipad = _gotowy(svc)
    t1 = now_utc() + timedelta(minutes=16)
    svc.reconcile(now=t1)
    sent = plistlib.loads(svc.connect(*ipad.msg(Status="Idle")).body)
    assert sent["Command"]["RequestType"] == APPS  # status `sent`, odpowiedzi brak

    svc2 = _svc(path, ca, policy)  # restart przed odpowiedzia iPada
    stats = svc2.reconcile(now=t1 + timedelta(minutes=5))
    assert stats["pushed"] == 1  # oczekujaca komenda = push mimo restartu
    assert _pending(svc2, ipad.udid, APPS) == 1  # bez duplikatu
    seen = run_commands(svc2, ipad, _z_gra)
    assert [c["CommandUUID"] for c in seen] == [sent["CommandUUID"]]
    assert len(_installed(svc2)) == 1


# =============================================== Kidwatch: kursor -> outbox
class _Kanal:
    name = "atrapa"

    def __init__(self, pada: bool = False):
        self.sent: list[str] = []
        self.pada = pada

    async def send(self, note):
        if self.pada:
            raise Zabity
        self.sent.append(note.text)
        return True


async def _nie_czekaj(_):
    return None


def _outbox_teksty(store: Store) -> list[str]:
    return [i.note.text for i in store.outbox_pending(limit=100)]


async def _czujka(url: str, path, kanal=None, now=None):
    cfg = MdmConfig(enabled=True, url=url)
    store = Store(path)
    outbox = Outbox(Dispatcher([kanal or _Kanal()], store=store), store,
                    now=now or (lambda: datetime.now(UTC)))
    return store, MdmWatcher(MdmApi(cfg, TOKEN), store, cfg, tz=TZ), outbox


def _nowa_aplikacja(svc: MDMService) -> None:
    svc.store.event("apps_installed", UDID, {
        "apps": [{"id": "com.example.nowagra", "name": "Nowa Gra"}],
        "previous_at": iso(now_utc() - timedelta(minutes=15)),
    })


async def test_window_a_event_written_while_kidwatch_down(mdm, tmp_path):
    """(a) Serwer zapisal zdarzenie, Kidwatch lezal: kursor w bazie Kidwatcha,
    zdarzenia w bazie serwera — nowa instancja czyta od kursora."""
    svc, url = mdm
    enroll_kw(svc)
    path = tmp_path / "k.db"
    store, w, outbox = await _czujka(url, path)
    await mdm_loop(w, outbox, 0, sleep=_nie_czekaj, max_iterations=1)
    store.close()
    _nowa_aplikacja(svc)  # Kidwatch nie dziala
    store, w, outbox = await _czujka(url, path)
    await mdm_loop(w, outbox, 0, sleep=_nie_czekaj, max_iterations=2)
    teksty = _outbox_teksty(store)
    assert len(teksty) == 1 and teksty[0].startswith("Nowa Gra\nwykryta ")
    store.close()


async def test_window_b_kill_between_cursor_and_outbox(mdm, tmp_path, monkeypatch):
    """(b) Kursor i klucz dedupu zapisane, notka jeszcze nie w outboxie —
    zabicie procesu w tej chwili gubilo powiadomienie na zawsze."""
    svc, url = mdm
    enroll_kw(svc)
    path = tmp_path / "k.db"
    store, w, outbox = await _czujka(url, path)
    await mdm_loop(w, outbox, 0, sleep=_nie_czekaj, max_iterations=1)
    kursor = store.get_meta(CURSOR_KEY)
    _nowa_aplikacja(svc)

    def zabity(self, notes, at):
        if notes:
            raise Zabity

    monkeypatch.setattr(Store, "outbox_put", zabity)
    with pytest.raises(Zabity):
        await mdm_loop(w, outbox, 0, sleep=_nie_czekaj, max_iterations=1)
    monkeypatch.undo()
    store.close()

    store, w, outbox = await _czujka(url, path)  # restart: ta sama baza
    assert store.get_meta(CURSOR_KEY) == kursor  # kursor nie poszedl bez notki
    await mdm_loop(w, outbox, 0, sleep=_nie_czekaj, max_iterations=3)
    teksty = _outbox_teksty(store)
    assert len(teksty) == 1 and teksty[0].startswith("Nowa Gra"), teksty
    store.close()


async def test_window_c_kill_during_send_delivers_once(mdm, tmp_path):
    """(c) Notka w outboxie, wysylka przerwana przed przyjeciem przez kanal:
    wpis zostaje i wychodzi po restarcie — raz."""
    svc, url = mdm
    enroll_kw(svc)
    path = tmp_path / "k.db"
    t0 = datetime.now(UTC)
    store, w, outbox = await _czujka(url, path, _Kanal(pada=True), now=lambda: t0)
    await mdm_loop(w, outbox, 0, sleep=_nie_czekaj, max_iterations=1)
    _nowa_aplikacja(svc)
    await mdm_loop(w, outbox, 0, sleep=_nie_czekaj, max_iterations=1)
    with pytest.raises(Zabity):
        await outbox.flush()
    store.close()

    kanal = _Kanal()
    later = t0 + timedelta(minutes=2)
    store, w, outbox = await _czujka(url, path, kanal, now=lambda: later)
    await mdm_loop(w, outbox, 0, sleep=lambda _: outbox.flush(), max_iterations=3)
    assert len(kanal.sent) == 1 and kanal.sent[0].startswith("Nowa Gra"), kanal.sent
    assert _outbox_teksty(store) == []
    store.close()


async def test_end_to_end_new_app_through_real_server(mdm, tmp_path):
    """Caly tor: iPad odpowiada lista z nowa gra -> zdarzenie z previous_at ->
    czujka -> outbox -> kanal, tekst z oknem instalacji w strefie domu."""
    svc, url = mdm
    ipad = enroll_kw(svc)
    run_commands(svc, ipad)
    svc.reconcile()
    run_commands(svc, ipad)
    _ddm_pobrane(svc, ipad)
    kanal = _Kanal()
    store, w, outbox = await _czujka(url, tmp_path / "k.db", kanal)
    await mdm_loop(w, outbox, 0, sleep=lambda _: outbox.flush(), max_iterations=1)
    svc.reconcile(now=now_utc() + timedelta(minutes=16))
    run_commands(svc, ipad, _z_gra)
    await mdm_loop(w, outbox, 0, sleep=lambda _: outbox.flush(), max_iterations=2)
    assert len(kanal.sent) == 1
    assert kanal.sent[0].startswith("Nowa Gra\nwykryta "), kanal.sent
    assert ", zainstalowana po " in kanal.sent[0]
    store.close()
