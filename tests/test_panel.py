"""Panel WWW: zapis historii powiadomien i API tylko do odczytu."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta

import pytest

from conftest import local, make_config, panel_login
from kidwatch.config import PanelConfig, StoreConfig, TvConfig
from kidwatch.models import Notification, NotifyKind
from kidwatch.notifiers.base import Dispatcher
from kidwatch.panel import BadRequest, PanelQueries, start_panel
from kidwatch.panel_auth import PanelAuth
from kidwatch.store import Store, to_iso


def note(ts: datetime, title: str = "iPad Kuby aktywny", device: str = "iPad Kuby", **kw):
    return Notification(
        kind=kw.pop("kind", NotifyKind.SESSION_START),
        title=title,
        text=kw.pop("text", "15:12 — Roblox"),
        dedup_key=f"k:{ts.isoformat()}:{title}",
        ts=ts.astimezone(UTC),
        device=device,
        **kw,
    )


class FakeNotifier:
    def __init__(self, name: str, ok: bool) -> None:
        self.name, self.ok = name, ok

    async def send(self, note):
        return self.ok

    async def aclose(self):
        pass


@pytest.fixture
def disk(tmp_path):
    cfg = make_config(
        # Testy chodza po http://, a przegladarka i urllib nie odsylaja
        # ciasteczek Secure po http. W klastrze zostaje domyslne True.
        panel=PanelConfig(
            enabled=True, port=0, static_dir=str(tmp_path / "web"), cookie_secure=False
        ),
    )
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    store = Store(cfg.store.path)
    yield cfg, store
    store.close()


async def test_dispatcher_zapisuje_powiadomienie_z_wynikiem_kanalow(disk):
    cfg, store = disk
    d = Dispatcher([FakeNotifier("ntfy", False), FakeNotifier("ha", True)], store=store)
    await d.send(note(local(2026, 10, 2, 15, 12)))
    row = store.conn.execute("SELECT * FROM notifications").fetchone()
    assert row["title"] == "iPad Kuby aktywny"
    assert json.loads(row["channels"]) == {"ntfy": False, "ha": True}
    assert row["delivered"] == 1


async def test_powiadomienie_ktore_nigdzie_nie_dotarlo_tez_jest_w_historii(disk):
    _, store = disk
    await Dispatcher([FakeNotifier("ntfy", False)], store=store).send(
        note(local(2026, 10, 2, 15, 12))
    )
    assert store.conn.execute("SELECT delivered FROM notifications").fetchone()[0] == 0


async def test_awaria_zapisu_historii_nie_blokuje_wysylki(disk):
    _, store = disk
    store.conn.execute("DROP TABLE notifications")
    results = await Dispatcher([FakeNotifier("ntfy", True)], store=store).send(
        note(local(2026, 10, 2, 15, 12))
    )
    assert results == {"ntfy": True}


def test_filtry_i_stronicowanie(disk):
    cfg, store = disk
    for h in range(10, 15):
        n = note(local(2026, 10, 2, h, 0), f"Kuba {h}")
        store.record_notification(n, {}, datetime.now(UTC))
    store.record_notification(
        note(local(2026, 10, 1, 12, 0), "wczoraj", device="iPad Zosi"), {}, datetime.now(UTC)
    )
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        page = q.notifications(conn, {"day": "2026-10-02", "limit": "3"})
        assert [n["title"] for n in page["items"]] == ["Kuba 14", "Kuba 13", "Kuba 12"]
        assert page["has_more"]
        rest = q.notifications(
            conn, {"day": "2026-10-02", "before": page["items"][-1]["cursor"]}
        )
        assert [n["title"] for n in rest["items"]] == ["Kuba 11", "Kuba 10"]
        zosia = q.notifications(conn, {"device": "iPad Zosi"})
        assert [n["child"] for n in zosia["items"]] == ["Zosia"]


def test_lista_po_czasie_zdarzenia_a_nie_kolejnosci_zapisu(disk):
    cfg, store = disk
    store.record_notification(note(local(2026, 10, 2, 15, 0), "pozniejsze"), {}, datetime.now(UTC))
    store.record_notification(note(local(2026, 10, 2, 9, 0), "wczesniejsze"), {}, datetime.now(UTC))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        page = q.notifications(conn, {"limit": "1"})
        assert [n["title"] for n in page["items"]] == ["pozniejsze"]
        rest = q.notifications(conn, {"before": page["items"][0]["cursor"]})
        assert [n["title"] for n in rest["items"]] == ["wczesniejsze"]


def test_granica_dnia_liczona_w_strefie_lokalnej_nie_w_UTC(disk):
    """00:30 w Warszawie to jeszcze poprzedni dzien w UTC — ma nalezec do dzisiaj."""
    cfg, store = disk
    store.record_notification(note(local(2026, 10, 2, 0, 30), "po polnocy"), {}, datetime.now(UTC))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        assert [n["title"] for n in q.notifications(conn, {"day": "2026-10-02"})["items"]] == [
            "po polnocy"
        ]


def test_podsumowanie_dnia_liczy_sesje_i_aplikacje(disk):
    cfg, store = disk
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 15, 0))
    for m in range(3):
        store.record_app_minute(sid, "Roblox", local(2026, 10, 2, 15, m))
    store.record_app_minute(sid, "YouTube", local(2026, 10, 2, 15, 5))
    store.close_session(sid, local(2026, 10, 2, 15, 47))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        kuba = q.day(conn, {"day": "2026-10-02"})["devices"][0]
    assert kuba["session_minutes"] == 47
    assert kuba["top_apps"] == [{"app": "Roblox", "minutes": 3}, {"app": "YouTube", "minutes": 1}]


def test_panel_otwiera_baze_TYLKO_do_odczytu(disk):
    cfg, _ = disk
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn, pytest.raises(Exception, match="readonly"):
        conn.execute("DELETE FROM notifications")


def test_serwer_http_api_front_i_ochrona_przed_wyjsciem_z_katalogu(disk, tmp_path):
    cfg, store = disk
    web = tmp_path / "web"
    (web / "assets").mkdir(parents=True)
    (web / "index.html").write_text("<html>panel</html>", encoding="utf-8")
    (tmp_path / "sekret.txt").write_text("nie dla panelu", encoding="utf-8")
    store.record_notification(note(local(2026, 10, 2, 15, 12)), {"ntfy": True}, datetime.now(UTC))

    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    base = f"http://127.0.0.1:{server.server_address[1]}"
    try:
        cookie = panel_login(server.server_address[1], "rodzic", "dlugie-haslo-testowe")

        def get(path: str):
            return urllib.request.urlopen(
                urllib.request.Request(f"{base}{path}", headers={"Cookie": cookie})
            )

        with get("/api/notifications") as r:
            assert r.headers["X-Frame-Options"] == "DENY"
            assert r.headers["Strict-Transport-Security"].startswith("max-age=31536000")
            assert json.load(r)["items"][0]["title"] == "iPad Kuby aktywny"
        with get("/api/devices") as r:
            assert [d["child"] for d in json.load(r)] == ["Kuba", "Zosia"]
        # Sciezki SPA i proba wyjscia poza katalog dostaja index.html.
        for path in ("/dzien", "/../sekret.txt", "/%2e%2e/sekret.txt"):
            with urllib.request.urlopen(f"{base}{path}") as r:
                assert r.read() == b"<html>panel</html>"
        with pytest.raises(urllib.error.HTTPError) as err:
            get("/api/day?day=wczoraj")
        assert err.value.code == 400
    finally:
        server.shutdown()


# ================================================ przelacznik dzieci i uzycie
def kuba_i_zosia(store):
    """Kuba: dwie sesje 2.10 (47 + 10 min) i jedna 1.10; Zosia: jedna 2.10."""
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 15, 0))
    for m in range(3):
        store.record_app_minute(sid, "Roblox", local(2026, 10, 2, 15, m))
    store.record_app_minute(sid, "YouTube", local(2026, 10, 2, 15, 5))
    store.close_session(sid, local(2026, 10, 2, 15, 47))
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 18, 0))
    store.record_app_minute(sid, "YouTube", local(2026, 10, 2, 18, 1))
    store.close_session(sid, local(2026, 10, 2, 18, 10))
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 1, 9, 0))
    store.close_session(sid, local(2026, 10, 1, 9, 20))
    sid = store.open_session("iPad Zosi", "Zosia", local(2026, 10, 2, 16, 0))
    store.record_app_minute(sid, "Minecraft", local(2026, 10, 2, 16, 0))
    store.close_session(sid, local(2026, 10, 2, 16, 30))


def test_meta_zawsze_pelna_lista_dzieci_i_urzadzen(disk):
    cfg, _ = disk
    meta = PanelQueries(cfg, cfg.store.path).meta()
    assert meta["children"] == ["Kuba", "Zosia"]
    assert [d["child"] for d in meta["devices"]] == ["Kuba", "Zosia"]


def test_filtr_dziecka_w_kartach_dniu_i_powiadomieniach(disk):
    cfg, store = disk
    kuba_i_zosia(store)
    store.record_notification(note(local(2026, 10, 2, 15, 0)), {}, datetime.now(UTC))
    store.record_notification(
        note(local(2026, 10, 2, 16, 0), "Zosia gra", device="iPad Zosi"), {}, datetime.now(UTC)
    )
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        assert [d["child"] for d in q.devices(conn, {"child": "Zosia"})] == ["Zosia"]
        assert [d["child"] for d in q.devices(conn, {})] == ["Kuba", "Zosia"]
        day = q.day(conn, {"day": "2026-10-02", "child": "Kuba"})
        assert [d["child"] for d in day["devices"]] == ["Kuba"]
        notes = q.notifications(conn, {"child": "Zosia"})["items"]
        assert [n["title"] for n in notes] == ["Zosia gra"]


@pytest.mark.parametrize("method", ["devices", "notifications", "day", "usage"])
def test_nieznane_dziecko_to_400_a_nie_pusta_lista(disk, method):
    """Pusta lista wygladalaby jak "dziecko nic nie robilo"."""
    cfg, _ = disk
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn, pytest.raises(BadRequest, match="Ola"):
        getattr(q, method)(conn, {"child": "Ola"})


def test_uzycie_dzien_po_dniu_per_urzadzenie(disk):
    cfg, store = disk
    kuba_i_zosia(store)
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        u = q.usage(conn, {"days": "3", "until": "2026-10-02"})
    assert [d["day"] for d in u["days"]] == ["2026-09-30", "2026-10-01", "2026-10-02"]
    assert [d["name"] for d in u["devices"]] == ["iPad Kuby", "iPad Zosi"]
    dzis = {d["name"]: d for d in u["days"][2]["devices"]}
    assert dzis["iPad Kuby"]["minutes"] == 57
    assert dzis["iPad Kuby"]["sessions"] == 2
    # YouTube z dwoch sesji sumuje sie w jeden wpis dnia.
    assert dzis["iPad Kuby"]["top_apps"] == [
        {"app": "Roblox", "minutes": 3}, {"app": "YouTube", "minutes": 2},
    ]
    assert dzis["iPad Zosi"]["minutes"] == 30
    assert u["days"][2]["total_minutes"] == 87
    assert u["days"][1]["total_minutes"] == 20
    assert u["days"][0]["total_minutes"] == 0  # dzien bez danych tez jest slupkiem


def test_uzycie_zgadza_sie_z_widokiem_dnia(disk):
    cfg, store = disk
    kuba_i_zosia(store)
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        u = q.usage(conn, {"days": "1", "until": "2026-10-02", "child": "Kuba"})
        d = q.day(conn, {"day": "2026-10-02", "child": "Kuba"})
    assert u["days"][0]["total_minutes"] == d["devices"][0]["session_minutes"]
    assert [x["child"] for x in u["devices"]] == ["Kuba"]


def test_os_dnia_pulpitu_zgadza_sie_z_suma_i_minutami_aplikacji(disk):
    """Odcinki osi dnia na Pulpicie licza sie z tych samych wierszy co suma:
    sesje sumuja sie do `minutes`, ciagi aplikacji — do jej minut dnia."""
    cfg, store = disk
    kuba_i_zosia(store)
    # Druga aplikacja w tej samej minucie co Roblox i dziura w ciagu YouTube.
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 20, 0))
    for m in (0, 1, 2, 5, 6):
        store.record_app_minute(sid, "YouTube", local(2026, 10, 2, 20, m))
    store.record_app_minute(sid, "Roblox", local(2026, 10, 2, 20, 1))
    store.close_session(sid, local(2026, 10, 2, 20, 9))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        u = q.usage(conn, {"days": "1", "until": "2026-10-02", "timeline": "1"})
        bez = q.usage(conn, {"days": "1", "until": "2026-10-02"})
    assert "timeline" not in bez["days"][0]["devices"][0]
    kuba = {d["name"]: d for d in u["days"][0]["devices"]}["iPad Kuby"]
    tl = kuba["timeline"]
    assert sum(s["minutes"] for s in tl["sessions"]) == kuba["minutes"] == 66
    assert [s["started_at"][11:16] for s in tl["sessions"]] == ["15:00", "18:00", "20:00"]
    assert tl["sessions"][0]["ended_at"][11:16] == "15:47"
    per_app: dict[str, int] = {}
    for r in tl["runs"]:
        per_app[r["app"]] = per_app.get(r["app"], 0) + r["minutes"]
    assert per_app == {"Roblox": 4, "YouTube": 7}
    assert {a["app"]: a["minutes"] for a in kuba["top_apps"]} == per_app
    assert [(r["app"], r["started_at"][11:16], r["ended_at"][11:16]) for r in tl["runs"]] == [
        ("Roblox", "15:00", "15:03"), ("YouTube", "15:05", "15:06"),
        ("YouTube", "18:01", "18:02"),
        ("YouTube", "20:00", "20:03"), ("Roblox", "20:01", "20:02"), ("YouTube", "20:05", "20:07"),
    ]
    # Czas lokalny z przesunieciem strefy — front liczy pozycje z daty.
    assert tl["runs"][0]["started_at"].endswith("+02:00")


def test_os_dnia_otwartej_sesji_konczy_sie_na_ostatniej_aktywnosci(disk):
    cfg, store = disk
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 15, 0))
    store.touch_session(sid, local(2026, 10, 2, 15, 12))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        u = q.usage(conn, {"days": "1", "until": "2026-10-02", "timeline": "1"})
    cell = u["days"][0]["devices"][0]
    assert cell["timeline"]["sessions"][0]["ended_at"][11:16] == "15:12"
    assert cell["timeline"]["sessions"][0]["minutes"] == cell["minutes"] == 12


def test_os_dnia_tylko_dla_jednego_dnia(disk):
    cfg, _ = disk
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn, pytest.raises(BadRequest, match="timeline"):
        q.usage(conn, {"days": "7", "timeline": "1"})


def test_uzycie_liczy_dzien_w_strefie_lokalnej(disk):
    """00:30 w Warszawie to jeszcze poprzedni dzien w UTC — ma nalezec do dzisiaj."""
    cfg, store = disk
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 0, 30))
    store.close_session(sid, local(2026, 10, 2, 0, 50))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        u = q.usage(conn, {"days": "2", "until": "2026-10-02"})
    assert [d["total_minutes"] for d in u["days"]] == [0, 20]


@pytest.mark.parametrize("days", ["0", "91", "abc"])
def test_uzycie_odrzuca_zly_zakres(disk, days):
    cfg, _ = disk
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn, pytest.raises(BadRequest):
        q.usage(conn, {"days": days})


def test_telewizor_jest_urzadzeniem_bez_dziecka_tylko_przy_wszyscy(disk):
    """Telewizor oglada cala rodzina: osobna seria przy "Wszyscy", znika przy
    wybranym dziecku. Jego sesje leza w tej samej tabeli co iPadow."""
    cfg, store = disk
    cfg.tv = TvConfig(enabled=True, host="192.0.2.10")
    sid = store.open_session("TV salon", None, local(2026, 10, 2, 19, 0))
    store.open_tv_segment(sid, "TV salon", local(2026, 10, 2, 19, 0),
                          "com.disney.disneyplus", "Disney+", "Bluey", None)
    store.close_session(sid, local(2026, 10, 2, 20, 0))
    store.close_tv_segments("TV salon", local(2026, 10, 2, 20, 0))
    q = PanelQueries(cfg, cfg.store.path)
    assert q.children() == ["Kuba", "Zosia"]
    assert q.meta()["devices"][-1] == {"name": "TV salon", "child": None, "kind": "tv"}
    with q.connect() as conn:
        wszyscy = q.usage(conn, {"days": "1", "until": "2026-10-02"})
        assert wszyscy["devices"][-1] == {"name": "TV salon", "child": None, "kind": "tv"}
        assert wszyscy["days"][0]["total_minutes"] == 60
        kuba = q.usage(conn, {"days": "1", "until": "2026-10-02", "child": "Kuba"})
        assert "TV salon" not in [d["name"] for d in kuba["devices"]]
        karty = q.devices(conn, {})
        assert karty[-1]["kind"] == "tv" and karty[-1]["child"] is None
        dzien = q.day(conn, {"day": "2026-10-02"})["devices"][-1]
        assert [(t["title"], t["minutes"]) for t in dzien["titles"]] == [("Bluey", 60)]


def test_obecnosc_z_UniFi_w_kartach_i_przeterminowanie(disk):
    cfg, store = disk
    teraz = datetime.now(UTC)
    store.set_json("presence:iPad Kuby", {"home": True, "since": to_iso(teraz),
                                          "checked": to_iso(teraz), "essid": "Dom"})
    store.set_json("presence:iPad Zosi", {"home": False, "since": to_iso(teraz),
                                          "checked": to_iso(teraz - timedelta(hours=1))})
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        karty = {d["name"]: d for d in q.devices(conn, {})}
    assert karty["iPad Kuby"]["presence"]["home"] is True
    # Stara informacja to "nie wiadomo", nie "poza domem".
    assert karty["iPad Zosi"]["presence"] is None


def test_api_uzycia_i_filtra_przez_http(disk, tmp_path):
    cfg, store = disk
    kuba_i_zosia(store)
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    try:
        cookie = panel_login(server.server_address[1], "rodzic", "dlugie-haslo-testowe")
        base = f"http://127.0.0.1:{server.server_address[1]}"

        def get(path: str):
            return urllib.request.urlopen(
                urllib.request.Request(f"{base}{path}", headers={"Cookie": cookie})
            )

        with get("/api/meta") as r:
            assert json.load(r)["children"] == ["Kuba", "Zosia"]
        with get("/api/usage?days=2&until=2026-10-02&child=Zosia") as r:
            u = json.load(r)
            assert [d["total_minutes"] for d in u["days"]] == [0, 30]
        with get("/api/devices?child=Kuba") as r:
            assert [d["child"] for d in json.load(r)] == ["Kuba"]
        with pytest.raises(urllib.error.HTTPError) as err:
            get("/api/usage?child=Ola")
        assert err.value.code == 400
        # Bez sesji nowe endpointy tez sa zamkniete.
        for path in ("/api/meta", "/api/usage"):
            with pytest.raises(urllib.error.HTTPError) as err:
                urllib.request.urlopen(f"{base}{path}")
            assert err.value.code == 401
    finally:
        server.shutdown()


# ============================================ spojnosc odczytu i odpornosc HTTP
class _PisarzMiedzyZapytaniami:
    """Polaczenie panelu, przy ktorym petla glowna zapisuje "w polowie" zadania:
    tuz przed zapytaniem o minuty aplikacji otwiera nowa sesje z minuta."""

    def __init__(self, conn, store):
        self._conn, self._store = conn, store

    def execute(self, sql, *args):
        if "FROM session_apps" in sql and self._store is not None:
            sid = self._store.open_session("iPad Kuby", "Kuba", local(2026, 10, 2, 19, 0))
            self._store.record_app_minute(sid, "Roblox", local(2026, 10, 2, 19, 0))
            self._store = None
        return self._conn.execute(sql, *args)


def test_uzycie_nie_pada_gdy_petla_zapisze_sesje_w_trakcie_zadania(disk):
    """Regresja: dwa zapytania /api/usage widzialy rozne stany bazy. Sesja
    otwarta miedzy nimi miala minuty, ale nie miala dnia -> KeyError -> 500.
    Kazde zadanie panelu czyta teraz jedna migawke (transakcja odczytu)."""
    cfg, store = disk
    kuba_i_zosia(store)
    q = PanelQueries(cfg, cfg.store.path)
    conn = q.connect()
    try:
        u = q.usage(_PisarzMiedzyZapytaniami(conn, store), {"days": "1", "until": "2026-10-02"})
    finally:
        conn.close()
    kuba = {d["name"]: d for d in u["days"][0]["devices"]}["iPad Kuby"]
    # Migawka sprzed zapisu: dwie sesje Kuby, bez tej dopisanej w trakcie.
    assert kuba["sessions"] == 2


def test_ujemny_Content_Length_to_400_a_nie_zawieszony_watek(disk, tmp_path):
    """rfile.read(-1) czyta do zamkniecia polaczenia — jeden klient trzymal
    watek panelu tak dlugo, jak chcial."""
    import http.client  # noqa: PLC0415

    cfg, _ = disk
    server = start_panel(cfg)
    try:
        conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=5)
        conn.putrequest("POST", "/api/auth/login")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Content-Length", "-1")
        conn.endheaders()
        r = conn.getresponse()
        assert r.status == 400
        conn.close()
    finally:
        server.shutdown()


def test_limit_logowan_liczy_adres_z_traefika_a_nie_z_naglowka_klienta(disk):
    # Audyt runda 4, pkt 6: limit per adres nie moze dac sie obejsc
    # podmiana pierwszego wpisu X-Forwarded-For.
    import http.client  # noqa: PLC0415

    cfg, _ = disk
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", "dlugie-haslo-testowe")
    server = start_panel(cfg)
    port = server.server_address[1]

    def login(password, fwd):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/api/auth/login",
                     json.dumps({"login": "rodzic", "password": password}),
                     {"Content-Type": "application/json", "X-Forwarded-For": fwd})
        status = conn.getresponse().status
        conn.close()
        return status

    try:
        codes = [login("zle-haslo-xxxx", f"10.0.0.{i}, 203.0.113.7") for i in range(6)]
        assert codes == [401] * 5 + [429]
        # Rodzic z innego adresu loguje sie mimo zgadywania z zewnatrz.
        assert login("dlugie-haslo-testowe", "198.51.100.2") == 200
    finally:
        server.shutdown()


def test_ujemny_limit_nie_zwraca_calej_historii(disk):
    """Audyt 3, N3: SQLite czyta LIMIT -4 jako brak limitu."""
    cfg, store = disk
    for h in range(10, 15):
        store.record_notification(note(local(2026, 10, 2, h, 0), f"n{h}"), {}, datetime.now(UTC))
    q = PanelQueries(cfg, cfg.store.path)
    with q.connect() as conn:
        page = q.notifications(conn, {"limit": "-5"})
    assert len(page["items"]) == 1 and page["has_more"]


@pytest.mark.parametrize("value", ["=1+1", " =1+1", "  @SUM(A1)", "-2"])
def test_csv_nie_przepuszcza_formuly_takze_po_spacjach(value):
    """Audyt 3, N8: sprawdzany byl tylko pierwszy znak."""
    assert PanelQueries._cell(value).startswith("'")


def test_panel_ma_timeout_gniazda(disk):
    """Audyt 3, N7: bez timeoutu wolny klient trzymal watek serwera."""
    cfg, _ = disk
    srv = start_panel(cfg)
    try:
        assert srv.RequestHandlerClass.timeout
    finally:
        srv.shutdown()
