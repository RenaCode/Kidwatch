"""kidwatch-mdm i iPhone dziecka (etap E5, docs/iphone.md).

Dwie rzeczy naraz:

1. iPad bajt w bajt jak przed E5. Serwer steruje prawdziwymi iPadami na
   produkcji — profil ograniczen, deklaracje DDM, profil zapisu i teksty
   czujki Kidwatcha porownujemy z migawka zapisana na kodzie sprzed zmiany
   (tests/mdm_migawka_ipada.py, fixtures/mdm_ipad_przed_e5.json).
2. iPhone bez kluczy „tylko pod nadzorem". Liczone ze schematu Apple
   (tools/apple_schema_index.json), nie z listy z pamieci: profile maja
   `supervised_ios`, deklaracje DDM `allowed_enrollments_ios: [supervised]`.
   iOS ignoruje taki klucz bez slowa, wiec w polityce bylby blokada, ktorej nie ma.
"""

from __future__ import annotations

import json
import plistlib
from pathlib import Path

import pytest

from kidwatch_mdm import profiles
from kidwatch_mdm.policy import DEFAULT_RESTRICTIONS, Policy, load, validate
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.store import Store
from mdm_migawka_ipada import IPAD, OS_UPDATE, POLITYKA, migawka, migawka_tekstow, nowe_ca
from test_mdm_service import (
    SCHEMA,
    TOPIC,
    FakeIpad,
    FakePusher,
    run_commands,
    schema_problems,
)

ROOT = Path(__file__).resolve().parents[1]
PRZED = json.loads((ROOT / "tests" / "fixtures" / "mdm_ipad_przed_e5.json").read_text("utf-8"))
UDID_IPHONE = "00008110-000A00000000000B"
DOH = "https://dns.nextdns.io/abc123/iPhone-Dziecka-1"


# ===================================================== iPad: bez zmian
def test_ipad_bajt_w_bajt_jak_przed_e5(tmp_path):
    teraz = migawka(nowe_ca(tmp_path))
    for label, przed in PRZED["mdm"].items():
        assert teraz[label] == przed, f"zmienila sie polityka iPada {label!r}"


def test_ipad_z_rodzajem_w_polityce_tez_bez_zmian(tmp_path):
    """`kind: ipad` wpisane jawnie = brak pola (polityka sprzed iPhone'ow)."""
    raw = json.loads(json.dumps(POLITYKA))
    for dev in raw["devices"].values():
        dev["kind"] = "ipad"
    policy = Policy.model_validate(raw)
    for label in ("dziecko1", "dziecko2", "test"):
        profile, digest = profiles.restrictions_profile(policy, label, "ipad")
        assert digest == PRZED["mdm"][label]["restrictions_hash"]
        decls = profiles.declarations(policy, label, supervised=True, os_update=OS_UPDATE,
                                      kind="ipad")
        assert profiles.declarations_token(decls) == (
            PRZED["mdm"][label]["declarations"]["supervised=True,os_update=True"]["token"]
        )


def test_teksty_czujki_ipada_bez_zmian():
    assert migawka_tekstow(IPAD) == PRZED["teksty"]
    # Serwer po E5 podaje `kind` — dla iPada wynik ten sam.
    assert migawka_tekstow({**IPAD, "kind": "ipad"}) == PRZED["teksty"]


# ===================================================== iPhone: polityka
def _iphone_policy(**dev) -> Policy:
    return Policy.model_validate({
        **POLITYKA,
        "devices": {**POLITYKA["devices"],
                    "iphone1": {"name": "iPhone Dziecka 1", "kind": "iphone",
                                "dns_url": DOH, **dev}},
    })


def _klucze_nadzoru(keys: dict, payload: dict, where: str) -> list[str]:
    """Klucze, ktore wg schematu Apple dzialaja tylko pod nadzorem."""
    found: list[str] = []
    for name, value in payload.items():
        spec = keys.get(name)
        if spec is None:
            continue
        if spec.get("supervised_ios") is True or spec.get("allowed_enrollments_ios") == [
            "supervised"
        ]:
            found.append(f"{where}.{name}")
        sub = spec.get("subkeys") or {}
        if isinstance(value, dict) and sub:
            found += _klucze_nadzoru(sub, value, f"{where}.{name}")
    return found


def _wszystko_dla_iphone_a(policy: Policy, ca, *, supervised: bool) -> list[str]:
    """Klucze nadzoru we WSZYSTKIM, co serwer wysle iPhone'owi."""
    found: list[str] = []
    enroll = plistlib.loads(profiles.enrollment_profile(
        ca=ca, public_url="https://mdm.example.invalid", topic=TOPIC, org=policy.org,
        label="iphone1", device_name="iPhone Dziecka 1", kind="iphone").data)
    restr, _ = profiles.restrictions_profile(policy, "iphone1")
    for profile in (enroll, restr):
        top = {k: v for k, v in profile.items() if k != "PayloadContent"}
        found += _klucze_nadzoru(SCHEMA["profiles"]["TopLevel"]["keys"], top, "profil")
        for p in profile["PayloadContent"]:
            found += _klucze_nadzoru(SCHEMA["profiles"][p["PayloadType"]]["keys"], p,
                                     p["PayloadType"])
    for d in profiles.declarations(policy, "iphone1", supervised=supervised,
                                   os_update=OS_UPDATE):
        if d["Type"] in SCHEMA["declarations"]:
            found += _klucze_nadzoru(SCHEMA["declarations"][d["Type"]]["keys"], d["Payload"],
                                     d["Type"])
    return found


def test_indeks_schematu_zna_wymog_nadzoru_w_deklaracjach():
    """Bez tego test nizej bylby slepy na DDM (detektor sprawdzony na znanym zlu)."""
    su = SCHEMA["declarations"]["com.apple.configuration.softwareupdate.settings"]["keys"]
    dns = SCHEMA["declarations"]["com.apple.configuration.network.dns-settings"]["keys"]
    assert su["AutomaticActions"]["allowed_enrollments_ios"] == ["supervised"]
    assert dns["ProhibitDisablement"]["allowed_enrollments_ios"] == ["supervised"]
    # iPad nadzorowany dostaje te klucze — detektor musi je widziec.
    policy = Policy.model_validate(POLITYKA)
    leaked = []
    for d in profiles.declarations(policy, "dziecko1", supervised=True, os_update=None):
        leaked += _klucze_nadzoru(SCHEMA["declarations"][d["Type"]]["keys"], d["Payload"],
                                  d["Type"])
    assert "com.apple.configuration.softwareupdate.settings.AutomaticActions" in leaked
    assert "com.apple.configuration.network.dns-settings.ProhibitDisablement" in leaked
    restr, _ = profiles.restrictions_profile(policy, "dziecko1")
    assert _klucze_nadzoru(SCHEMA["profiles"]["com.apple.applicationaccess"]["keys"],
                           restr["PayloadContent"][0], "r")


@pytest.mark.parametrize("supervised", [False, True])
def test_polityka_iphone_a_bez_kluczy_nadzoru(tmp_path, supervised):
    """Takze gdy iPhone zglosi IsSupervised: nadzorowany iPhone to osobna decyzja."""
    policy = _iphone_policy(restrictions={"allowCamera": True})
    assert validate(policy, SCHEMA) == []
    leaked = _wszystko_dla_iphone_a(policy, nowe_ca(tmp_path), supervised=supervised)
    assert leaked == [], f"iPhone dostalby klucze nadzoru: {leaked}"


def test_polityka_iphone_a_zgodna_ze_schematem(tmp_path):
    policy = _iphone_policy(restrictions={"allowCamera": True})
    restr, _ = profiles.restrictions_profile(policy, "iphone1")
    payload = restr["PayloadContent"][0]
    assert payload["allowCamera"] is True
    # Ani domyslnych blokad iPada, ani wspolnych nadpisan, ani blokady aplikacji.
    assert not set(DEFAULT_RESTRICTIONS) & set(payload)
    assert "allowDeviceNameModification" not in payload
    assert "blockedAppBundleIDs" not in payload
    problems = schema_problems(SCHEMA["profiles"]["com.apple.applicationaccess"]["keys"],
                               payload, "applicationaccess")
    enroll = plistlib.loads(profiles.enrollment_profile(
        ca=nowe_ca(tmp_path), public_url="https://mdm.example.invalid", topic=TOPIC,
        org="RenaCode", label="iphone1", device_name="iPhone", kind="iphone").data)
    problems += schema_problems(SCHEMA["profiles"]["TopLevel"]["keys"],
                                {k: v for k, v in enroll.items() if k != "PayloadContent"},
                                "profil")
    assert "PayloadRemovalDisallowed" not in enroll
    for d in profiles.declarations(policy, "iphone1", supervised=False, os_update=OS_UPDATE):
        if d["Type"] in SCHEMA["declarations"]:
            problems += schema_problems(SCHEMA["declarations"][d["Type"]]["keys"],
                                        d["Payload"], d["Type"])
    assert problems == [], "\n".join(problems)


def test_iphone_bez_deklaracji_dns_dns_idzie_recznym_profilem():
    """Deklaracja DNS bez nadzoru obejmuje tylko sieci zarzadzane, a moglaby
    wyprzec reczny profil NextDNS — iPhone na komorce zniknalby z wgladu."""
    policy = _iphone_policy()
    for supervised in (False, True):
        types = [d["Type"] for d in profiles.declarations(policy, "iphone1",
                                                          supervised=supervised,
                                                          os_update=OS_UPDATE)]
        assert "com.apple.configuration.network.dns-settings" not in types
        # Wymuszenie wersji i status dzialaja bez nadzoru — zostaja.
        assert "com.apple.configuration.softwareupdate.enforcement.specific" in types
        assert "com.apple.configuration.management.status-subscriptions" in types


@pytest.mark.parametrize(("dev", "blad"), [
    ({"restrictions": {"allowVPNCreation": False}}, "tylko pod nadzorem"),
    ({"restrictions": {"allowExplicitContent": False}}, "tylko pod nadzorem"),
    ({"restrictions": {"allowCamra": False}}, "nieznany klucz"),
    ({"restrictions": {"allowInAppPurchases": False}}, "Popros o zakup"),
    ({"blocked_apps": ["com.example.przegladarka"]}, "wymaga nadzoru"),
])
def test_walidacja_odrzuca_klucze_nadzoru_dla_iphone_a(tmp_path, dev, blad):
    policy = _iphone_policy(**dev)
    errors = validate(policy, SCHEMA)
    assert any("iphone1" in e and blad in e for e in errors), errors
    path = tmp_path / "policy.yaml"
    raw = policy.model_dump()
    # Wpis iPhone'a z dns_url przy bledzie zatrzymuje start (przeglad #53, B1);
    # kwarantanna tylko dla wpisu bez dns_url, jak w docs/iphone.md.
    raw["devices"]["iphone1"]["dns_url"] = None
    path.write_text(json.dumps(raw), encoding="utf-8")
    # Po przegladzie E5 (U2): wpis iPhone'a w kwarantannie, start nie pada.
    loaded = load(path, SCHEMA)
    assert any(blad in e for e in loaded.rejected["iphone1"])
    assert loaded.device("iphone1").restrictions == {}


def test_walidacja_bez_schematu_zna_domyslne_klucze_nadzoru():
    errors = validate(_iphone_policy(restrictions={"allowVPNCreation": False}), None)
    assert errors == ["iphone1: allowVPNCreation dziala tylko pod nadzorem — iPhone go zignoruje"]


def test_rodzaj_z_productname_gdy_polityka_milczy():
    """iPhone zapisany pod etykieta bez `kind: iphone` (albo spoza polityki)
    dostaje polityke iPhone'a, nie blokady iPada."""
    policy = Policy.model_validate(POLITYKA)
    assert policy.kind("dziecko1", "iPad13,18") == "ipad"
    assert policy.kind("dziecko1", None) == "ipad"
    assert policy.kind("dziecko1", "iPhone16,2") == "iphone"
    assert policy.restrictions_for("dziecko1", "iphone") == {}
    assert _iphone_policy().kind("iphone1", None) == "iphone"


# =================================================== iPhone: serwer MDM
@pytest.fixture
def svc(tmp_path):
    return MDMService(
        store=Store(tmp_path / "mdm.db"),
        ca=nowe_ca(tmp_path / "ca"),
        policy=_iphone_policy(),
        public_url="https://mdm.example.invalid",
        pusher=FakePusher(),
    )


def _zapisz_iphone(svc: MDMService, label="iphone1") -> FakeIpad:
    token = svc.create_enrollment(label)["token"]
    data = svc.enrollment_profile(token).body
    profile = plistlib.loads(data)
    if label == "iphone1":
        assert "PayloadRemovalDisallowed" not in profile
    phone = FakeIpad(data, UDID_IPHONE)
    svc.checkin(*phone.msg(MessageType="Authenticate", Topic=TOPIC, SerialNumber="SN-TEST",
                           ProductName="iPhone16,2", OSVersion="27.0", BuildVersion="24A1"))
    svc.checkin(*phone.msg(MessageType="TokenUpdate", Topic=TOPIC, Token=b"\x03\x04",
                           PushMagic="MAGIC"))
    return phone


def _odpowiedz_iphone(cmd: dict) -> dict:
    rt = cmd["Command"]["RequestType"]
    if rt == "DeviceInformation":
        return {"Status": "Acknowledged", "QueryResponses": {
            "DeviceName": "iPhone", "OSVersion": "27.0", "IsSupervised": False,
            "ProductName": "iPhone16,2"}}
    if rt == "InstalledApplicationList":
        return {"Status": "Acknowledged", "InstalledApplicationList": [
            {"Identifier": "com.example.gra", "Name": "Gra", "ShortVersion": "1.0"}]}
    if rt == "ProfileList":
        return {"Status": "Acknowledged", "ProfileList": []}
    return {"Status": "Acknowledged"}


@pytest.mark.parametrize("label", ["iphone1", "spoza-polityki"])
def test_zapis_iphone_a_inwentarz_i_polityka_bez_nadzoru(svc, label):
    phone = _zapisz_iphone(svc, label)
    run_commands(svc, phone, _odpowiedz_iphone)
    svc.reconcile()
    seen = run_commands(svc, phone, _odpowiedz_iphone)
    install = [c for c in seen if c["Command"]["RequestType"] == "InstallProfile"]
    assert len(install) == 1
    profile = plistlib.loads(install[0]["Command"]["Payload"])
    assert _klucze_nadzoru(SCHEMA["profiles"]["com.apple.applicationaccess"]["keys"],
                           profile["PayloadContent"][0], "r") == []
    device = svc.store.device(UDID_IPHONE)
    assert svc.kind_of(device) == "iphone"
    assert json.loads(device["apps_json"])[0]["id"] == "com.example.gra"
    for d in svc.declarations_for(device):
        if d["Type"] in SCHEMA["declarations"]:
            assert _klucze_nadzoru(SCHEMA["declarations"][d["Type"]]["keys"], d["Payload"],
                                   d["Type"]) == []


def test_blokada_ekranu_dziala_na_iphonie_bez_nadzoru(svc):
    phone = _zapisz_iphone(svc)
    run_commands(svc, phone, _odpowiedz_iphone)
    svc.enqueue_api(UDID_IPHONE, "DeviceLock", {"Message": "Czas na sen"})
    seen = [c["Command"]["RequestType"] for c in run_commands(svc, phone, _odpowiedz_iphone)]
    assert seen == ["DeviceLock"]


def test_schemat_restart_wymaga_nadzoru_blokada_nie():
    """Na tym stoja teksty: iPhone bez nadzoru ma blokade, nie restart."""
    from kidwatch_mdm.server import API_COMMANDS, SUPERVISED_COMMANDS  # noqa: PLC0415

    for name in API_COMMANDS:
        assert SCHEMA["commands"][name]["ios"]["supervised"] is (name in SUPERVISED_COMMANDS)


def test_api_podaje_rodzaj(svc):
    """Kidwatch dobiera teksty alarmow po `kind` z /api/devices (petla zwrotna)."""
    import httpx  # noqa: PLC0415

    from kidwatch_mdm import server  # noqa: PLC0415

    _zapisz_iphone(svc)
    token = "t" * 32
    admin = server.start(server.make_admin_handler(svc, token), 0, "127.0.0.1")
    try:
        url = f"http://127.0.0.1:{admin.server_address[1]}/api/devices"
        rows = httpx.get(url, headers={"Authorization": f"Bearer {token}"}).json()
        restart = httpx.post(f"{url}/{UDID_IPHONE}/commands", json={
            "request_type": "RestartDevice"}, headers={"Authorization": f"Bearer {token}"})
        lock = httpx.post(f"{url}/{UDID_IPHONE}/commands", json={
            "request_type": "DeviceLock"}, headers={"Authorization": f"Bearer {token}"})
    finally:
        admin.shutdown()
        admin.server_close()
    assert [(r["udid"], r["kind"]) for r in rows] == [(UDID_IPHONE, "iphone")]
    # iPhone bez nadzoru (supervised jeszcze nieznany = bez): restart odmowiony
    # od razu i zrozumiale, blokada przyjeta.
    assert restart.status_code == 409 and "wymaga nadzoru" in restart.json()["error"]
    assert lock.status_code == 202
    assert [c["request_type"] for c in svc.store.commands_for(UDID_IPHONE)].count(
        "RestartDevice") == 0


# =========================================== czujka Kidwatcha: teksty iPhone'a
def test_teksty_czujki_iphone_a_mowia_o_braku_nadzoru():
    iphone = {"udid": UDID_IPHONE, "name": "iPhone Dziecka 1", "label": "iphone1",
              "product": "iPhone16,2", "kind": "iphone"}
    t = migawka_tekstow(iphone)
    checkout, _, enrolled, _, supervised_on = (z for z in t["zdarzenia"][:5])
    assert "iPhone wypisal sie" in checkout[3] and "usunac profil" in checkout[3]
    assert "Bez nadzoru dzialaja" in enrolled[3] and "blokada ekranu" in enrolled[3]
    assert "Restartu, blokad VPN, DNS" in enrolled[3]
    assert "nie wysyla blokad nadzoru" in supervised_on[3]
    for z in t["zdarzenia"]:
        if z:
            assert "iPad" not in z[2] + z[3], z
    assert "iPhone nie laczy sie" in t["cisza"][0][1]
    assert "iPhone odpowiada" in t["wiszace"]["not_now"][0][1]
    # Serwer sprzed E5 nie podaje `kind` — rozstrzyga ProductName.
    bez_rodzaju = {k: v for k, v in iphone.items() if k != "kind"}
    from kidwatch import mdm  # noqa: PLC0415

    assert mdm._kind(bez_rodzaju) == "iphone"
    assert mdm._kind({"product": "iPad13,18"}) == "ipad"
    assert mdm._kind(None) == "ipad"


def test_przyklad_polityki_z_iphonem_przechodzi_walidacje(tmp_path):
    """Zakomentowany wpis iPhone'a z policy.example.yaml, odkomentowany, startuje."""
    raw = (ROOT / "charts" / "kidwatch-mdm" / "files" / "policy.example.yaml").read_text("utf-8")
    raw = (raw.replace("  # iphone1:", "  iphone1:")
              .replace("  #   name: iPhone Dziecka 1", "    name: iPhone Dziecka 1")
              .replace("  #   kind: iphone", "    kind: iphone"))
    path = tmp_path / "policy.yaml"
    path.write_text(raw, encoding="utf-8")
    policy = load(path, SCHEMA)
    assert policy.device("iphone1").kind == "iphone"
    assert policy.device("dziecko1").kind == "ipad"
