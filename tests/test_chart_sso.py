"""SSO z 2FA (Authelia z renacode-infra) przed panelem - `sso` w values.yaml.

Domyślnie wyłączone: scalenie chartu niczego nie zamyka, podpięcie włącza
`valuesObject` w argocd-apps.yaml po rejestracji 2FA. Serwer MDM
(mdm.renacode.com, chart kidwatch-mdm) NIGDY nie stoi za SSO - iPady nie
przejdą logowania w przeglądarce.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

KORZEN = Path(__file__).resolve().parents[1]
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm niedostepny")
SSO = "default-authelia-sso@kubernetescrd"
NAGLOWKI = "default-authelia-naglowki@kubernetescrd"
MW = "traefik.ingress.kubernetes.io/router.middlewares"


def ingressy(chart: str = "kidwatch", *sets: str) -> dict[str, dict]:
    args = [a for kv in sets for a in ("--set", kv)]
    out = subprocess.run(["helm", "template", chart, str(KORZEN / "charts" / chart), *args],
                         capture_output=True, text=True, check=True).stdout
    obiekty = [d for d in yaml.safe_load_all(out) if d]
    return {d["metadata"]["name"]: d for d in obiekty if d["kind"] == "Ingress"}


def middleware(ing: dict) -> list[str]:
    return [m for m in ing["metadata"].get("annotations", {}).get(MW, "").split(",") if m]


def wejscie(ing: dict) -> str:
    return ing["metadata"]["annotations"]["traefik.ingress.kubernetes.io/router.entrypoints"]


def test_domyslnie_BEZ_sso():
    for nazwa, ing in ingressy().items():
        assert SSO not in middleware(ing), nazwa


def test_sso_na_routerze_panelu_po_limitach():
    panel = ingressy("kidwatch", "sso.enabled=true")["kidwatch"]
    assert middleware(panel) == ["default-kidwatch-w-toku@kubernetescrd",
                                 "default-kidwatch-tempo@kubernetescrd", NAGLOWKI, SSO]


def test_sso_bez_limitow():
    panel = ingressy("kidwatch", "sso.enabled=true", "ingress.limity.enabled=false")["kidwatch"]
    assert middleware(panel) == [NAGLOWKI, SSO]


def test_KAZDY_router_do_panelu_ma_sso_albo_tylko_przekierowuje():
    """Router HTTPS bez SSO, który dochodzi do panelu, to obejście Authelii.
    Wolno go mieć tylko routerom z samym przekierowaniem (HTTP, aliasy)."""
    for nazwa, ing in ingressy("kidwatch", "sso.enabled=true").items():
        mw = middleware(ing)
        if SSO in mw:
            continue
        assert len(mw) == 1 and ("redirect" in mw[0]), f"{nazwa}: {mw}"


def test_MDM_nigdy_za_sso():
    for nazwa, ing in ingressy("kidwatch-mdm", "sso.enabled=true").items():
        assert SSO not in middleware(ing), nazwa
        assert "authelia" not in str(ing), nazwa
