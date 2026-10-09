"""Publiczne repo bez prywatnych danych domu (audyt 2026-10-09, N1)."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_repo_bez_adresow_spoza_przykladowych_podsieci():
    """Audyt 2026-10-09 (N1): test TV mial prawdziwy adres telewizora z LAN.
    Repo jest publiczne: w przykladach tylko 192.168.0.x / 192.168.1.x albo
    pule dokumentacyjne (RFC 5737). Prawdziwa podsiec domu to zadna z nich."""
    files = subprocess.run(
        ["git", "ls-files"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.split()
    bad = []
    for name in files:
        path = ROOT / name
        if path.suffix in {".jks", ".png", ".jar", ".ico", ".webp"} or not path.is_file():
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for m in re.finditer(r"\b192\.168\.(\d+)\.\d+", text):
            if m.group(1) not in ("0", "1"):
                bad.append(f"{name}: {m.group(0)}")
    assert bad == []
