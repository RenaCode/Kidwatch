"""kidwatch-mdm per dom (E3b, docs/architektura-domy.md §4.3, §4.4 p. 4 i 8).

Serwer z dwoma domami: iPad A w Domu 1 (zapisany tokenem instancji, jak przed
E3b), iPad B w Domu 2 (zaproszenie tokenem Domu 2). Token domu nie widzi
i nie steruje obcym urzadzeniem (404 — jak nieistniejace), token instancji
dziala jak dotad. Kanarki: filtr domu wylaczony mutacja -> sprawdzenie
izolacji MUSI to wykryc, inaczej jego cisza nic nie dowodzi.

Dane generyczne: etykiety `dziecko1`, UDID-y z zerami, tokeny z secrets.
"""

from __future__ import annotations

import secrets
import sqlite3

import httpx
import pytest

from kidwatch_mdm import server
from kidwatch_mdm import store as store_mod
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import (
    DevicePolicy,
    DomPolicy,
    Policy,
    dom_etykiety,
    etykieta_w_domu,
    validate,
)
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.store import Store
from test_mdm_service import SCHEMA, TOPIC, FakeIpad, FakePusher

UDID_A = "00008030-000000000000000A"  # Dom 1
UDID_B = "00008030-000000000000000B"  # Dom 2
DOM_2 = 2


def _enroll(svc: MDMService, label: str, udid: str, dom_id: int = 1) -> FakeIpad:
    token = svc.create_enrollment(label, dom_id)["token"]
    ipad = FakeIpad(svc.enrollment_profile(token).body, udid)
    svc.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC))
    svc.checkin(*ipad.msg(MessageType="TokenUpdate", Topic=TOPIC, Token=b"\x01", PushMagic="M"))
    return ipad


@pytest.fixture
def uklad(tmp_path):
    """Serwer HTTP admina z dwoma domami; zwraca (svc, klient, naglowki)."""
    instancja = secrets.token_urlsafe(32)
    svc = MDMService(
        store=Store(tmp_path / "mdm.db"),
        ca=CA.create(tmp_path / "ca", org="RenaCode"),
        policy=Policy(
            devices={
                "dziecko1": DevicePolicy(name="iPad Domu 1", dns_url="https://dns.example/a"),
                "2/dziecko1": DevicePolicy(name="iPad Domu 2", dns_url="https://dns.example/b"),
            }
        ),
        public_url="https://mdm.example.com",
        pusher=FakePusher(),
    )
    _enroll(svc, "dziecko1", UDID_A)
    _enroll(svc, "dziecko1", UDID_B, DOM_2)
    _, token_2 = svc.store.create_home_token(DOM_2)
    _, token_1 = svc.store.create_home_token(1)
    admin = server.start(server.make_admin_handler(svc, instancja), 0, "127.0.0.1")
    klient = httpx.Client(base_url=f"http://127.0.0.1:{admin.server_port}")
    h = {
        "instancja": {"Authorization": f"Bearer {instancja}"},
        1: {"Authorization": f"Bearer {token_1}"},
        DOM_2: {"Authorization": f"Bearer {token_2}"},
    }
    yield svc, klient, h
    admin.shutdown()


def przecieki(klient: httpx.Client, h: dict, dom: int, obcy: str) -> list[str]:
    """Kazda droga, ktora token domu `dom` siega do urzadzenia `obcy` (z innego
    domu). Pusta lista = izolacja dziala. Uzywana przez test i przez kanarka."""
    out = []
    naglowki = h[dom]
    if any(d["udid"] == obcy for d in klient.get("/api/devices", headers=naglowki).json()):
        out.append("lista urzadzen")
    if klient.get(f"/api/devices/{obcy}", headers=naglowki).status_code != 404:
        out.append("szczegoly")
    if klient.post(f"/api/devices/{obcy}/refresh", headers=naglowki).status_code != 404:
        out.append("refresh")
    r = klient.post(
        f"/api/devices/{obcy}/commands", json={"request_type": "DeviceLock"}, headers=naglowki
    )
    if r.status_code != 404:
        out.append(f"komenda ({r.status_code})")
    zdarzenia = klient.get("/api/events?since=0", headers=naglowki).json()
    if any(e.get("udid") == obcy for e in zdarzenia):
        out.append("dziennik")
    ostatnie = klient.get("/api/events?last=500", headers=naglowki).json()
    if any(e.get("udid") == obcy for e in ostatnie):
        out.append("ostatnie zdarzenia")
    return out


# ================================================================ izolacja
@pytest.mark.parametrize(("dom", "obcy"), [(DOM_2, UDID_A), (1, UDID_B)])
def test_token_domu_nie_widzi_i_nie_steruje_obcym(uklad, dom, obcy):
    """§4.4 p. 4, bariera serwera: komenda na UDID z innego domu = 404."""
    svc, klient, h = uklad
    assert przecieki(klient, h, dom, obcy) == []
    # Zadna komenda API nie trafila do kolejki obcego urzadzenia.
    assert all(r["origin"] != "api" for r in svc.store.commands_for(obcy))


def test_token_domu_steruje_wlasnym(uklad):
    svc, klient, h = uklad
    devices = klient.get("/api/devices", headers=h[DOM_2]).json()
    assert [(d["udid"], d["dom_id"], d["name"]) for d in devices] == [
        (UDID_B, DOM_2, "iPad Domu 2")
    ]
    r = klient.post(
        f"/api/devices/{UDID_B}/commands", json={"request_type": "DeviceLock"}, headers=h[DOM_2]
    )
    assert r.status_code == 202
    assert svc.store.command(r.json()["command_uuid"])["udid"] == UDID_B
    assert klient.post(f"/api/devices/{UDID_B}/refresh", headers=h[DOM_2]).status_code == 202
    assert klient.get("/api/whoami", headers=h[DOM_2]).json() == {"zakres": "dom", "dom_id": 2}


def test_token_instancji_bez_zmian(uklad):
    """Pierwszy krok wdrozenia: stary token = instancja, widzi i steruje wszystkim."""
    _, klient, h = uklad
    inst = h["instancja"]
    assert {d["udid"] for d in klient.get("/api/devices", headers=inst).json()} == {
        UDID_A,
        UDID_B,
    }
    for udid in (UDID_A, UDID_B):
        assert klient.post(f"/api/devices/{udid}/refresh", headers=inst).status_code == 202
    assert klient.get("/api/whoami", headers=inst).json() == {"zakres": "instancja"}


def test_zapis_tokenem_domu_wiaze_urzadzenie_z_domem(uklad):
    """Dom z tokenu, nie z ciala: `dom_id` w ciele nic nie zmienia."""
    svc, klient, h = uklad
    r = klient.post(
        "/api/enrollments", json={"label": "dziecko2", "dom_id": 1}, headers=h[DOM_2]
    )
    assert r.status_code == 201
    token = r.json()["url"].rsplit("/", 1)[-1]
    row = svc.store.enrollment(token)
    assert (row["label"], row["dom_id"]) == ("2/dziecko2", DOM_2)
    udid = "00008030-000000000000000C"
    ipad = FakeIpad(svc.enrollment_profile(token).body, udid)
    svc.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC))
    assert svc.store.device(udid)["dom_id"] == DOM_2
    assert udid in {d["udid"] for d in klient.get("/api/devices", headers=h[DOM_2]).json()}
    assert udid not in {d["udid"] for d in klient.get("/api/devices", headers=h[1]).json()}
    # Zdarzenia zapisu naleza do domu urzadzenia.
    kinds = {e["kind"] for e in klient.get("/api/events?since=0", headers=h[DOM_2]).json()
             if e["udid"] == udid}
    assert "authenticate" in kinds


def test_tokeny_tylko_dla_instancji(uklad):
    svc, klient, h = uklad
    for dom in (1, DOM_2):
        assert klient.get("/api/tokens", headers=h[dom]).status_code == 404
        assert klient.post("/api/tokens", json={"dom_id": 3}, headers=h[dom]).status_code == 404
        assert klient.delete("/api/tokens/1", headers=h[dom]).status_code == 404
    inst = h["instancja"]
    assert klient.post("/api/tokens", json={"dom_id": "2"}, headers=inst).status_code == 400
    nowy = klient.post("/api/tokens", json={"dom_id": 3, "opis": "test"}, headers=inst).json()
    assert nowy["dom_id"] == 3 and len(nowy["token"]) >= 32
    lista = klient.get("/api/tokens", headers=inst).json()
    assert all("token" not in t and "hash" not in t for t in lista)
    # W bazie tylko skrot.
    rows = svc.store.query("SELECT hash FROM tokeny_domow")
    assert nowy["token"] not in {r["hash"] for r in rows}
    h3 = {"Authorization": f"Bearer {nowy['token']}"}
    assert klient.get("/api/devices", headers=h3).json() == []
    assert klient.delete(f"/api/tokens/{nowy['id']}", headers=inst).status_code == 200
    assert klient.get("/api/devices", headers=h3).status_code == 401
    assert klient.delete(f"/api/tokens/{nowy['id']}", headers=inst).status_code == 404


def test_os_update_per_dom(uklad):
    svc, klient, h = uklad
    body = {"target_version": "27.1", "deadline": "2026-10-20T20:00:00"}
    assert klient.put("/api/os-update", json=body, headers=h[DOM_2]).status_code == 200
    assert svc.os_update(DOM_2)["target_version"] == "27.1"
    assert svc.os_update(1) is None
    assert klient.get("/api/os-update", headers=h[1]).json()["effective"] is None
    # Dom 1 dalej pod starym kluczem — obraz sprzed E3b go czyta.
    klient.put("/api/os-update", json={"disabled": True}, headers=h["instancja"])
    assert svc.store.setting("os_update") == {}
    # Deklaracje urzadzenia z wersja SWOJEGO domu.
    decl_b = svc.declarations_for(svc.store.device(UDID_B))
    decl_a = svc.declarations_for(svc.store.device(UDID_A))
    assert any("TargetOSVersion" in str(d) for d in decl_b)
    assert not any("TargetOSVersion" in str(d) for d in decl_a)


def test_polityka_bez_wpisow_innych_domow(uklad):
    _, klient, h = uklad
    p2 = klient.get("/api/policy", headers=h[DOM_2]).json()
    assert set(p2["devices"]) == {"2/dziecko1"}
    p1 = klient.get("/api/policy", headers=h[1]).json()
    assert set(p1["devices"]) == {"dziecko1"}
    assert set(klient.get("/api/policy", headers=h["instancja"]).json()["devices"]) == {
        "dziecko1",
        "2/dziecko1",
    }


# ================================================================ kanarki
def test_kanarek_filtr_domu_na_serwerze(uklad, monkeypatch):
    """§4.4 p. 8: bez filtra `dom_id` na serwerze sprawdzenie izolacji MUSI
    znalezc przecieki — inaczej test powyzej niczego nie dowodzi."""
    svc, klient, h = uklad
    monkeypatch.setattr(Store, "device_in", lambda self, udid, dom_id: self.device(udid))
    monkeypatch.setattr(
        Store, "devices", lambda self, dom_id=None: self.query("SELECT * FROM devices")
    )
    assert {"lista urzadzen", "szczegoly", "refresh"} <= set(przecieki(klient, h, DOM_2, UDID_A))


def test_kanarek_dom_z_tokenu(uklad, monkeypatch):
    """Zaproszenie z domem z ciala (mutacja) — test zapisu by to wykryl."""
    svc, klient, h = uklad
    oryginal = svc.create_enrollment
    monkeypatch.setattr(svc, "create_enrollment", lambda label, dom_id=1: oryginal(label, 1))
    r = klient.post("/api/enrollments", json={"label": "dziecko3"}, headers=h[DOM_2])
    assert svc.store.enrollment(r.json()["url"].rsplit("/", 1)[-1])["dom_id"] != DOM_2


# ================================================================ migracja
STARY_SCHEMAT = """
CREATE TABLE enrollments (token TEXT PRIMARY KEY, label TEXT NOT NULL,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, udid TEXT, bound_at TEXT);
CREATE TABLE devices (udid TEXT PRIMARY KEY, label TEXT NOT NULL,
    enrollment_token TEXT NOT NULL, cert_fp TEXT NOT NULL, enrolled_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL);
CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT NOT NULL, udid TEXT,
    kind TEXT NOT NULL, detail TEXT);
INSERT INTO enrollments VALUES ('t', 'dziecko1', 'x', 'x', '00008030-000000000000000A', 'x');
INSERT INTO devices VALUES ('00008030-000000000000000A', 'dziecko1', 't', 'fp', 'x', 'x');
INSERT INTO events (at, udid, kind) VALUES ('x', '00008030-000000000000000A', 'enrolled');
INSERT INTO events (at, udid, kind) VALUES ('x', NULL, 'signature_rejected');
"""


def test_baza_sprzed_e3b_trafia_do_domu_1(tmp_path):
    """Wdrozenie: zapisane iPady w Domu 1 bez zadnej akcji, zdarzenia z domem
    urzadzenia; stary obraz dalej pisze (INSERT bez dom_id) — do Domu 1."""
    path = tmp_path / "mdm.db"
    with sqlite3.connect(path) as conn:
        conn.executescript(STARY_SCHEMAT)
    store = Store(path)
    assert store.device(UDID_A)["dom_id"] == 1
    assert store.enrollment("t")["dom_id"] == 1
    assert [(e["kind"], e["dom_id"]) for e in store.events()] == [
        ("enrolled", 1),
        ("signature_rejected", None),
    ]
    # Zapis „starym obrazem” po wycofaniu: kolumny maja wartosci domyslne.
    store.conn.execute(
        "INSERT INTO devices (udid, label, enrollment_token, cert_fp, enrolled_at, "
        "last_seen_at) VALUES ('00008030-00000000000000FF', 'x', 't', 'f', 'x', 'x')"
    )
    store.conn.execute(
        "INSERT INTO events (at, udid, kind) VALUES ('x', '00008030-00000000000000FF', 'k')"
    )
    store.conn.close()
    again = Store(path)  # ponowny start nowego obrazu: idempotentnie + uzupelnienie
    assert again.device("00008030-00000000000000FF")["dom_id"] == 1
    assert again.events()[-1]["dom_id"] == 1
    cols = {r["name"] for r in again.query("PRAGMA table_info(devices)")}
    assert "dom_id" in cols


# ================================================================ polityka
def test_etykiety_domow():
    assert etykieta_w_domu(1, "dziecko1") == "dziecko1"
    assert etykieta_w_domu(2, "dziecko1") == "2/dziecko1"
    assert dom_etykiety("dziecko1") == 1 and dom_etykiety("2/dziecko1") == 2


def test_nadpisania_domu_w_polityce():
    policy = Policy(
        restrictions={"allowCamera": True},
        blocked_apps=["com.example.wspolna"],
        domy={2: DomPolicy(restrictions={"allowCamera": False}, blocked_apps=[])},
        devices={"2/dziecko1": DevicePolicy(name="x"), "dziecko1": DevicePolicy(name="y")},
    )
    r2 = policy.restrictions_for("2/dziecko1")
    r1 = policy.restrictions_for("dziecko1")
    assert r2["allowCamera"] is False and r1["allowCamera"] is True
    # Pusta lista domu = bez blokowanych aplikacji w tym domu; Dom 1 — wspolne.
    assert "blockedAppBundleIDs" not in r2
    assert r1["blockedAppBundleIDs"] == ["com.example.wspolna"]
    # Nadpisanie domu nie zdejmuje blokad domyslnych.
    assert r2["allowVPNCreation"] is False
    assert validate(policy, SCHEMA) == []
    zla = Policy(domy={2: DomPolicy(restrictions={"allowCamerra": False})})
    assert any("(dom 2)" in e for e in validate(zla, SCHEMA))


def test_profil_zapisu_domu_2_ma_bezpieczna_nazwe_pliku(uklad):
    svc, _, _ = uklad
    token = svc.create_enrollment("dziecko5", DOM_2)["token"]
    disposition = svc.enrollment_profile(token).headers["Content-Disposition"]
    assert "/" not in disposition and "2-dziecko5" in disposition


def test_cli_token_domu(tmp_path, monkeypatch, capsys):
    from kidwatch_mdm.__main__ import main

    monkeypatch.setenv("KIDWATCH_MDM_DATA", str(tmp_path))
    assert main(["token-domu", "1", "--opis", "Dom 1"]) == 0
    token = capsys.readouterr().out.strip()
    store = Store(tmp_path / "kidwatch-mdm.db")
    assert store.home_token_dom(token) == 1
    assert main(["tokeny"]) == 0
    assert token not in capsys.readouterr().out
    assert main(["token-odwolaj", "1"]) == 0
    assert store.home_token_dom(token) is None
    assert main(["token-domu", "0"]) == 1
    assert store_mod.token_hash(token) != token
