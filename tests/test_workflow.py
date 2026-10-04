"""Workflow CI: wąskie uprawnienia, piny akcji, front w testach, brak wyścigu
podbicia tagu (przegląd 04.10, K-5, K-6)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
WF = yaml.safe_load((ROOT / ".github/workflows/docker-publish.yml").read_text())


def test_domyslnie_tylko_odczyt():
    assert WF["permissions"] == {"contents": "read"}
    assert WF["jobs"]["obraz"]["permissions"] == {"contents": "read", "packages": "write"}
    assert WF["jobs"]["tag"]["permissions"] == {"contents": "write"}
    assert "permissions" not in WF["jobs"]["testy"]


def test_tag_bez_wyscigu():
    tag = WF["jobs"]["tag"]
    assert tag["concurrency"]["cancel-in-progress"] is False
    script = next(s["run"] for s in tag["steps"] if "run" in s)
    assert 'merge-base --is-ancestor "$GITHUB_SHA" HEAD' in script
    assert 'merge-base --is-ancestor "$GITHUB_SHA" "$CUR_FULL"' in script
    checkout = tag["steps"][0]
    assert checkout["with"]["fetch-depth"] == 0


def test_front_testowany_w_ci():
    runs = [s.get("run", "") for s in WF["jobs"]["testy"]["steps"]]
    assert "npm test" in runs and "npm run build" in runs and "npm ci" in runs


def test_akcje_przypiete_po_sha():
    text = (ROOT / ".github/workflows/docker-publish.yml").read_text()
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref
