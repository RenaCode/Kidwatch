"""Szybki start `docker compose` z README musi wstawać (przegląd 04.10, K-2).

Konfiguracja z config.example.yaml dostaje DOKŁADNIE te zmienne, które
przekazuje docker-compose.yml (puste, jeśli nie ma ich w .env), plus dwie,
które README każe wpisać do .env."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest
import yaml

from kidwatch.config import Config

ROOT = Path(__file__).resolve().parent.parent
#: Tyle wpisuje do .env czytelnik README.
DOTENV = {"NEXTDNS_API_KEY": "klucz-testowy", "NTFY_TOPIC": "kidwatch-test"}


def compose_env() -> dict[str, str]:
    """Środowisko kontenera tak, jak policzy je compose z powyższym .env."""
    service = yaml.safe_load((ROOT / "docker-compose.yml").read_text())["services"]["kidwatch"]
    out = {}
    for name, value in service["environment"].items():
        m = re.fullmatch(r"\$\{(\w+):-(.*)\}", str(value))
        out[name] = DOTENV.get(m.group(1), m.group(2)) if m else str(value)
    return out


def test_compose_przekazuje_zmienne_z_readme():
    env = compose_env()
    assert set(DOTENV) <= set(env), "docker-compose.yml nie przekazuje zmiennej z README"
    assert all(env[k] == v for k, v in DOTENV.items())


def test_config_example_wstaje_w_srodowisku_compose(tmp_path, monkeypatch):
    for name, value in compose_env().items():
        monkeypatch.setenv(name, value)
    # Jak w kontenerze: config.yaml w osobnym katalogu (/config, tylko odczyt).
    conf = tmp_path / "config"
    conf.mkdir()
    shutil.copy(ROOT / "config.example.yaml", conf / "config.yaml")
    cfg = Config.load(conf / "config.yaml")
    assert cfg.store.path == "/data/kidwatch.db"
    assert cfg.panel_auth_path == "/data/panel-auth.db"
    assert cfg.notifiers.ntfy.topic == "kidwatch-test"


def test_bez_nadpisania_sciezka_wzgledem_configu(tmp_path, monkeypatch):
    monkeypatch.delenv("KIDWATCH_STORE_PATH", raising=False)
    monkeypatch.setenv("NTFY_TOPIC", "t")
    shutil.copy(ROOT / "config.example.yaml", tmp_path / "config.yaml")
    cfg = Config.load(tmp_path / "config.yaml")
    assert cfg.store.path == str(tmp_path / "kidwatch.db")


@pytest.mark.skipif(shutil.which("docker") is None, reason="brak dockera")
def test_compose_config_poprawny():
    import subprocess

    r = subprocess.run(["docker", "compose", "-f", str(ROOT / "docker-compose.yml"),
                        "config", "-q"], capture_output=True, text=True, cwd=ROOT)
    assert r.returncode == 0, r.stderr
