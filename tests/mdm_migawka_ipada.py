"""Migawka wszystkiego, co kidwatch-mdm wysyla iPadom — do porownania bajt w bajt.

`tests/fixtures/mdm_ipad_przed_e5.json` zostal zapisany ta funkcja na kodzie
SPRZED etapu E5 (main 7ee717d). Test w test_mdm_iphone.py liczy ja na nowo
i porownuje: obsluga iPhone'a nie moze zmienic ani jednego bajtu profilu
ograniczen, deklaracji DDM ani profilu zapisu iPada (serwer steruje
prawdziwymi iPadami na produkcji).

Odtworzenie fixtury (tylko swiadomie, gdy zmiana polityki iPadow jest celem):
    uv run python tests/mdm_migawka_ipada.py > tests/fixtures/mdm_ipad_przed_e5.json
"""

from __future__ import annotations

import json
import plistlib
import sys
import tempfile
from pathlib import Path

from kidwatch_mdm import profiles
from kidwatch_mdm.pki import CA
from kidwatch_mdm.policy import Policy

TOPIC = "com.apple.mgmt.External.11111111-2222-4333-8444-555555555555"
OS_UPDATE = {"target_version": "27.1", "deadline": "2026-10-20T20:00:00",
             "target_build": "23B1", "details_url": "https://example.invalid/aktualizacja"}

#: Polityka iPadow z kazdym rodzajem nadpisania, ktory dzis istnieje.
POLITYKA = {
    "org": "RenaCode",
    "restrictions": {"allowDeviceNameModification": False},
    "blocked_apps": ["com.example.przegladarka"],
    "devices": {
        "dziecko1": {"name": "iPad Dziecka 1",
                     "dns_url": "https://dns.nextdns.io/abc123/iPad-Dziecka-1"},
        "dziecko2": {"name": "iPad Dziecka 2",
                     "dns_url": "https://dns.nextdns.io/abc123/iPad-Dziecka-2",
                     "restrictions": {"allowCamera": True},
                     "blocked_apps": []},
        "test": {"name": "iPad testowy"},
    },
}
ETYKIETY = ["dziecko1", "dziecko2", "test", "spoza-polityki"]


def _bez_losowych(profile: dict) -> dict:
    """Profil zapisu bez tozsamosci, ktora jest nowa przy kazdym wywolaniu."""
    out = dict(profile)
    content = []
    for payload in profile["PayloadContent"]:
        p = dict(payload)
        for key in ("PayloadContent", "Password", "PayloadUUID", "IdentityCertificateUUID"):
            if key in p and p["PayloadType"] in ("com.apple.security.pkcs12", "com.apple.mdm"):
                if key == "PayloadUUID" and p["PayloadType"] == "com.apple.mdm":
                    continue  # stabilny (uuid5 z etykiety) — porownujemy
                p[key] = "<losowe>"
        content.append(p)
    out["PayloadContent"] = content
    return out


def migawka(ca: CA) -> dict:
    policy = Policy.model_validate(POLITYKA)
    out: dict = {}
    for label in ETYKIETY:
        restr, digest = profiles.restrictions_profile(policy, label)
        entry: dict = {
            "restrictions_plist": plistlib.dumps(restr, fmt=plistlib.FMT_XML,
                                                 sort_keys=True).decode(),
            "restrictions_hash": digest,
            "declarations": {},
        }
        for supervised in (False, True):
            for os_update in (None, OS_UPDATE):
                decls = profiles.declarations(policy, label, supervised=supervised,
                                              os_update=os_update)
                key = f"supervised={supervised},os_update={os_update is not None}"
                entry["declarations"][key] = {
                    "decls": decls,
                    "token": profiles.declarations_token(decls),
                }
        enroll = profiles.enrollment_profile(
            ca=ca, public_url="https://mdm.example.invalid", topic=TOPIC, org=policy.org,
            label=label, device_name=policy.device(label).name,
        )
        entry["enrollment"] = _bez_losowych(plistlib.loads(enroll.data))
        out[label] = entry
    return json.loads(json.dumps(out, sort_keys=True, default=str))


#: Zdarzenia serwera, ktore czujka Kidwatcha zamienia na powiadomienia.
ZDARZENIA = [
    {"kind": "checkout"},
    {"kind": "profile_missing", "detail": {"identifier": "com.example.profil"}},
    {"kind": "enrolled"},
    {"kind": "supervision_changed", "detail": {"supervised": False}},
    {"kind": "supervision_changed", "detail": {"supervised": True}},
    {"kind": "apps_installed", "detail": {"apps": [{"id": "com.example.gra", "name": "Gra"}]}},
    {"kind": "apps_removed", "detail": {"apps": [{"id": "com.example.gra"}]}},
    {"kind": "push_token_dead", "detail": {"reason": "BadDeviceToken"}},
    {"kind": "os_update_failed", "detail": {"count": 1, "reason": "x"}},
    {"kind": "command_error", "detail": {"request_type": "DeviceLock", "chain": [{"c": 1}]}},
    {"kind": "cert_mismatch"},
]


def migawka_tekstow(urzadzenie: dict) -> dict:
    """Teksty czujki MDM Kidwatcha dla jednego urzadzenia z /api/devices."""
    from datetime import UTC, datetime

    from kidwatch import mdm
    from kidwatch.config import MdmConfig

    watcher = mdm.MdmWatcher(None, None, MdmConfig())  # type: ignore[arg-type]
    name = watcher._name(urzadzenie, urzadzenie["udid"])
    now = datetime(2026, 10, 12, 12, 0, tzinfo=UTC)
    zdarzenia = []
    for ev in ZDARZENIA:
        d = mdm._describe(ev, name) if "kind" not in urzadzenie else mdm._describe(
            ev, name, urzadzenie["kind"])
        zdarzenia.append(None if d is None else [d[0].value, d[1], d[2], d[3]])
    cichy = dict(urzadzenie, last_seen_at="2026-10-10T08:00:00+00:00", push_error="410 x")
    wiszacy = dict(urzadzenie, last_seen_at="2026-10-12T11:00:00+00:00", pending_commands=2)
    out = {"zdarzenia": zdarzenia, "cisza": [], "wiszace": {}}
    out["cisza"] = [[n.title, n.text] for n in watcher._silent([cichy], now)]
    for status in ("not_now", "queued", "sent", "inny"):
        wiszacy["oldest_pending"] = {"request_type": "DeviceLock", "status": status,
                                     "created_at": "2026-10-10T08:00:00+00:00"}
        out["wiszace"][status] = [[n.title, n.text] for n in watcher._stuck([wiszacy], now)]
    return out


IPAD = {"udid": "00000000-0000000000000001", "name": "iPad Dziecka 1", "label": "dziecko1",
        "product": "iPad13,18"}


def nowe_ca(directory: Path) -> CA:
    return CA.create(directory, org="Kidwatch test")


if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as tmp:
        json.dump({"mdm": migawka(nowe_ca(Path(tmp))), "teksty": migawka_tekstow(IPAD)},
                  sys.stdout, indent=1, sort_keys=True,
                  ensure_ascii=False)
        sys.stdout.write("\n")
