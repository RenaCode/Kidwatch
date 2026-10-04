"""Wspolne fixtury. Konfiguracje budujemy w Pythonie, nie z YAML-a — test ma
kontrolowac dokladnie te progi, ktore bada."""

from __future__ import annotations

import base64
import os
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import pytest

from kidwatch.classifier import Classifier
from kidwatch.config import (
    Config,
    DeviceConfig,
    EngineConfig,
    NextDnsConfig,
    NotifiersConfig,
    NtfyConfig,
    QuietHours,
    SourceConfig,
    StoreConfig,
    WatchdogConfig,
)
from kidwatch.engine import Engine
from kidwatch.models import DnsEvent
from kidwatch.store import Store

TZ = ZoneInfo("Europe/Warsaw")

APP_MAP = """
noise:
  - apple.com
  - icloud.com
  - crashlytics.com
apps:
  "YouTube":
    - youtube.com
    - googlevideo.com
  "YouTube Kids":
    - youtubekids.com
  "Roblox":
    - roblox.com
  "Minecraft":
    - minecraft.net
  "Muzyka Apple":
    - music.apple.com
  "Dokladnie ta":
    - "=tylko.example.com"
"""


@pytest.fixture
def app_map(tmp_path):
    p = tmp_path / "app_map.yaml"
    p.write_text(APP_MAP, encoding="utf-8")
    return p


@pytest.fixture
def classifier(app_map):
    # reload_check_seconds=0 => kazde wywolanie sprawdza mtime; testy przeladowania
    # nie musza czekac.
    return Classifier(app_map, reload_check_seconds=0.0)


def make_config(**overrides) -> Config:
    engine_kwargs = {
        "idle_minutes": 10,
        "app_cooldown_minutes": 15,
        "session_start_merge_seconds": 20,
        # Jedna chwila aktywnosci = sesja potwierdzona od razu, jak
        # przed wprowadzeniem potwierdzania. Testy innych regul (cooldown,
        # reklamy, limity) nie musza symulowac minuty aktywnosci; samo
        # potwierdzanie z domyslnymi progami bada test_confirm.py.
        "confirm_moments": 1,
        "daily_summary_time": time(20, 30),
        "max_notifications_per_hour": 12,
        "quiet_hours": QuietHours(start=time(21, 30), end=time(7, 0)),
    }
    engine_kwargs.update(overrides.pop("engine", {}))
    watchdog_kwargs = {
        "enabled": True,
        "stream_silence_minutes": 20,
        "device_silence_minutes": 180,
        "device_silence_ignore_quiet_hours": True,
        "repeat_backoff_max_minutes": 480,
    }
    watchdog_kwargs.update(overrides.pop("watchdog", {}))
    return Config(
        timezone="Europe/Warsaw",
        source=SourceConfig(kind="nextdns", nextdns=NextDnsConfig(profile_id="test")),
        devices=[
            DeviceConfig(display_name="iPad Kuby", child="Kuba", source_ids=["ipad-kuby", "AAA11"]),
            DeviceConfig(display_name="iPad Zosi", child="Zosia", source_ids=["ipad-zosi"]),
        ],
        engine=EngineConfig(**engine_kwargs),
        watchdog=WatchdogConfig(**watchdog_kwargs),
        notifiers=NotifiersConfig(ntfy=NtfyConfig(topic="test-topic")),
        store=StoreConfig(path=":memory:"),
        **overrides,
    )


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    """Argon2id z parametrami produkcji (64 MiB, t=3) to ~0,2 s na hash, a testy
    blokady robia ich kilkanascie. Tu sprawdzamy logike logowania, nie koszt
    hasha — ten jest przypiety w test_panel_auth.py osobno."""
    from argon2 import PasswordHasher  # noqa: PLC0415

    from kidwatch import panel_auth  # noqa: PLC0415

    monkeypatch.setattr(
        panel_auth, "_hasher", PasswordHasher(time_cost=1, memory_cost=8, parallelism=1)
    )
    monkeypatch.setattr(panel_auth, "_dummy_hash", None)
    # Klucz szyfrujacy sekrety TOTP — wylacznie testowy, losowany per test.
    monkeypatch.setenv(panel_auth.TOTP_KEY_ENV, base64.b64encode(os.urandom(32)).decode())


def panel_login(port: int, login: str, password: str, totp_secret: str | None = None) -> str:
    """Pelne logowanie do panelu przez HTTP: haslo, a przy koncie z 2FA takze
    kod. Zwraca naglowek Cookie."""
    import http.client  # noqa: PLC0415
    import json  # noqa: PLC0415

    import pyotp  # noqa: PLC0415

    def post(path, body):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", path, json.dumps(body), {"Content-Type": "application/json"})
        r = conn.getresponse()
        data = json.loads(r.read() or b"null")
        conn.close()
        assert r.status == 200, (path, r.status, data)
        return r, data

    r, data = post("/api/auth/login", {"login": login, "password": password})
    if data["mfa_required"]:
        assert totp_secret, "konto ma 2FA, a test nie podal sekretu"
        # Kod z NASTEPNEGO kroku: biezacy mogl juz zostac zuzyty przy
        # wlaczaniu 2FA (ochrona przed powtorzeniem), a +1 miesci sie w oknie.
        code = pyotp.TOTP(totp_secret).at(datetime.now(UTC).timestamp() + 30)
        r, _ = post("/api/auth/mfa", {"challenge": data["challenge"], "code": code})
    return "; ".join(c.split(";")[0] for c in r.headers.get_all("Set-Cookie"))




@pytest.fixture
def cfg():
    return make_config()


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


@pytest.fixture
def engine(cfg, store, classifier):
    return Engine(cfg, store, classifier)


def local(y, m, d, hh, mm, ss=0) -> datetime:
    """Chwila w strefie Europe/Warsaw — tak myslimy o godzinach w testach."""
    return datetime(y, m, d, hh, mm, ss, tzinfo=TZ)


def ev(ts: datetime, domain: str, device: str = "ipad-kuby") -> DnsEvent:
    return DnsEvent(ts=ts.astimezone(UTC), device_id=device, domain=domain)


def titles(notes) -> list[str]:
    return [n.title for n in notes]


def kinds(notes) -> list[str]:
    return [n.kind.value for n in notes]


__all__ = [
    "TZ",
    "UTC",
    "Engine",
    "Store",
    "timedelta",
    "make_config",
    "local",
    "ev",
    "titles",
    "kinds",
    "panel_login",
]
