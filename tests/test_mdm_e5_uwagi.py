"""Uwagi z przegladu E5 (audyt3/przeglad-e5.md, U1-U4) — po stronie serwera MDM.

iPady bajt w bajt pilnuje dalej test_mdm_iphone.py (migawka sprzed E5); tu
tylko przypadki, ktorych migawka nie zawiera.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from kidwatch import mdm as kw_mdm
from kidwatch_mdm import profiles
from kidwatch_mdm.policy import (
    SUPERVISED_ONLY_SOFTWARE_UPDATE,
    Policy,
    PolicyError,
    load,
)
from kidwatch_mdm.service import MDMService
from kidwatch_mdm.store import Store
from mdm_migawka_ipada import POLITYKA, nowe_ca
from test_mdm_iphone import _klucze_nadzoru
from test_mdm_service import (
    SCHEMA,
    TOPIC,
    FakeIpad,
    FakePusher,
    default_responder,
    run_commands,
)

ROOT = Path(__file__).resolve().parents[1]
SU = SCHEMA["declarations"]["com.apple.configuration.softwareupdate.settings"]["keys"]
BETA_PELNA = {
    "ProgramEnrollment": "AlwaysOn",
    "RequireProgram": {"Description": "Beta szkolna", "Token": "tok-example"},
    "OfferPrograms": [{"Description": "Beta", "Token": "tok-example"}],
}


# ===================================================================== U1
def _nadzor_ze_schematu(keys: dict) -> dict:
    out = {}
    for name, spec in keys.items():
        sub = _nadzor_ze_schematu(spec.get("subkeys") or {})
        if spec.get("allowed_enrollments_ios") == ["supervised"]:
            out[name] = None
        elif sub:
            out[name] = sub
    return out


def test_lista_kluczy_nadzoru_ddm_zgodna_ze_schematem():
    """Lista w kodzie (bez schematu w czasie dzialania) = to, co mowi Apple.
    Nowy klucz nadzoru po odswiezeniu indeksu wywali ten test."""
    assert _nadzor_ze_schematu(SU) == SUPERVISED_ONLY_SOFTWARE_UPDATE


@pytest.mark.parametrize(("kind", "label"), [("iphone", "iphone1"), ("ipad", "test")])
def test_require_program_nie_trafia_do_urzadzenia_bez_nadzoru(kind, label):
    raw = {**POLITYKA, "software_update": {"Notifications": True, "Beta": dict(BETA_PELNA)},
           "devices": {**POLITYKA["devices"], "iphone1": {"name": "iPhone", "kind": "iphone"}}}
    policy = Policy.model_validate(raw)
    decls = profiles.declarations(policy, label, supervised=False, os_update=None, kind=kind)
    su = next(d for d in decls if d["Type"].endswith("softwareupdate.settings"))
    assert _klucze_nadzoru(SU, su["Payload"], "su") == []
    assert su["Payload"]["Beta"] == {"OfferPrograms": BETA_PELNA["OfferPrograms"]}


def test_ipad_pod_nadzorem_dostaje_require_program_jak_dotad():
    raw = {**POLITYKA, "software_update": {"Beta": dict(BETA_PELNA)}}
    decls = profiles.declarations(Policy.model_validate(raw), "dziecko1", supervised=True,
                                  os_update=None)
    su = next(d for d in decls if d["Type"].endswith("softwareupdate.settings"))
    assert su["Payload"]["Beta"] == BETA_PELNA


# ===================================================================== U2
def _zapisz(tmp_path, raw: dict) -> Path:
    path = tmp_path / "policy.yaml"
    path.write_text(yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
    return path


def _z_iphonem(**dev) -> dict:
    return {**POLITYKA, "devices": {**POLITYKA["devices"],
                                    "iphone1": {"name": "iPhone", "kind": "iphone", **dev}}}


def test_blad_we_wpisie_iphone_a_nie_zatrzymuje_startu(tmp_path):
    """Zly wpis iPhone'a = kwarantanna TEGO wpisu, iPady dalej zarzadzane."""
    policy = load(_zapisz(tmp_path, _z_iphonem(restrictions={"allowVPNCreation": False},
                                               blocked_apps=["com.example.x"])), SCHEMA)
    assert set(policy.rejected) == {"iphone1"}
    assert any("allowVPNCreation" in e for e in policy.rejected["iphone1"])
    dev = policy.device("iphone1")
    assert (dev.kind, dev.restrictions, dev.blocked_apps) == ("iphone", {}, None)
    # iPady bez zmian.
    assert policy.device("dziecko1").dns_url and policy.restrictions_for("dziecko1")


def test_odrzucony_wpis_daje_zdarzenie_i_alarm(tmp_path):
    policy = load(_zapisz(tmp_path, _z_iphonem(restrictions={"allowVPNCreation": False})),
                  SCHEMA)
    svc = MDMService(store=Store(tmp_path / "m.db"), ca=nowe_ca(tmp_path / "ca"),
                     policy=policy, public_url="https://mdm.example.invalid")
    ev = [e for e in svc.store.events() if e["kind"] == "policy_entry_rejected"]
    assert len(ev) == 1 and json.loads(ev[0]["detail"])["label"] == "iphone1"
    described = kw_mdm._describe(dict(ev[0]), "MDM")
    assert described is not None and described[1] >= 4
    assert "iphone1" in described[2] + described[3]


def test_blad_we_wpisie_ipada_dalej_zatrzymuje_start(tmp_path):
    """iPad: zdjecie wpisu po cichu zabraloby nadzorowanemu iPadowi DNS
    i blokady — tu glosny brak startu jest bezpieczniejszy (jak przed E5)."""
    raw = {**POLITYKA, "devices": {**POLITYKA["devices"],
                                   "dziecko1": {"name": "iPad", "restrictions": {"allowCamra": 1}}}}
    with pytest.raises(PolicyError):
        load(_zapisz(tmp_path, raw), SCHEMA)


def test_check_policy_na_sucho(tmp_path):
    ok = _zapisz(tmp_path, POLITYKA)
    bad = tmp_path / "zla.yaml"
    bad.write_text(yaml.safe_dump(_z_iphonem(restrictions={"allowVPNCreation": False})),
                   encoding="utf-8")
    schema = ROOT / "tools" / "apple_schema_index.json"

    def run(path):
        return subprocess.run(
            [sys.executable, "-m", "kidwatch_mdm", "check-policy", str(path),
             "--schema", str(schema)], capture_output=True, text=True, check=False)

    good = run(ok)
    assert good.returncode == 0, good.stderr
    wrong = run(bad)
    assert wrong.returncode == 1
    assert "iphone1" in wrong.stdout and "allowVPNCreation" in wrong.stdout


def test_kind_bez_wzgledu_na_wielkosc_liter():
    assert Policy.model_validate(_z_iphonem(kind="iPhone")).device("iphone1").kind == "iphone"


# ===================================================================== U4
def test_kind_iphone_przy_ipadzie_zostawia_blokady_ipada():
    raw = {**POLITYKA, "devices": {**POLITYKA["devices"],
                                   "dziecko1": {**POLITYKA["devices"]["dziecko1"],
                                                "kind": "iphone"}}}
    policy = Policy.model_validate(raw)
    assert policy.kind("dziecko1", "iPad13,18") == "ipad"
    assert policy.kind_mismatch("dziecko1", "iPad13,18")
    assert not policy.kind_mismatch("dziecko1", "iPhone16,2")
    assert not Policy.model_validate(POLITYKA).kind_mismatch("dziecko1", "iPad13,18")
    restr = policy.restrictions_for("dziecko1", "ipad")
    assert restr["allowVPNCreation"] is False


def test_pomylka_rodzaju_daje_jedno_zdarzenie(tmp_path):
    raw = {**POLITYKA, "devices": {**POLITYKA["devices"],
                                   "dziecko1": {**POLITYKA["devices"]["dziecko1"],
                                                "kind": "iphone"}}}
    svc = MDMService(store=Store(tmp_path / "m.db"), ca=nowe_ca(tmp_path / "ca"),
                     policy=Policy.model_validate(raw),
                     public_url="https://mdm.example.invalid", pusher=FakePusher())
    token = svc.create_enrollment("dziecko1")["token"]
    ipad = FakeIpad(svc.enrollment_profile(token).body, "00000000-0000000000000002")
    svc.checkin(*ipad.msg(MessageType="Authenticate", Topic=TOPIC, ProductName="iPad13,18"))
    svc.checkin(*ipad.msg(MessageType="TokenUpdate", Topic=TOPIC, Token=b"\x01",
                          PushMagic="M"))
    run_commands(svc, ipad, default_responder)
    svc.reconcile()
    svc.reconcile()
    seen = run_commands(svc, ipad, default_responder)
    ev = [e for e in svc.store.events() if e["kind"] == "kind_mismatch"]
    assert len(ev) == 1
    described = kw_mdm._describe(dict(ev[0]), "iPad Dziecka 1")
    assert described[1] >= 4 and "iPad" in described[3]
    device = svc.store.device("00000000-0000000000000002")
    assert svc.kind_of(device) == "ipad"
    install = [c for c in seen if c["Command"]["RequestType"] == "InstallProfile"]
    import plistlib  # noqa: PLC0415

    payload = plistlib.loads(install[0]["Command"]["Payload"])["PayloadContent"][0]
    assert payload["allowVPNCreation"] is False
