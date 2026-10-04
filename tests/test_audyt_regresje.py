"""Regresje z audytu po wprowadzeniu potwierdzania sesji, profilu i trendow.
Kazdy test opisuje blad, ktory naprawil — bez niego test pada."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
from datetime import UTC, date, timedelta

import httpx
import pyotp
import pytest

from conftest import ev, local, make_config, panel_login
from kidwatch import panel as panel_mod
from kidwatch.bramka_admin import BramkaAdmin
from kidwatch.config import BramkaConfig, PanelConfig, StoreConfig
from kidwatch.engine import Engine
from kidwatch.models import DnsEvent, NotifyKind
from kidwatch.panel import start_panel
from kidwatch.panel_auth import AuthError, PanelAuth, SecretBox, Session, csrf_ok, verify_totp
from kidwatch.rollup import refresh_rollups
from kidwatch.scheduler import device_loop
from kidwatch.sources.nextdns import MultiNextDnsSource, parse_log_entry
from kidwatch.sources.tv import TvProbe, TvUnavailable, TvWatcher
from kidwatch.store import Store
from test_profile import HASLO, call
from test_tv import FlakyShell, Sink, _no_sleep


# ================================================ panel: bledy bramki a sesja
def test_odrzucony_klucz_bramki_nie_wylogowuje_z_panelu(tmp_path, monkeypatch):
    """Bramka z 401 (zly BRAMKA_KLUCZ) szla do przegladarki jako 401, a front
    traktuje 401 jak wygasla sesje i wyrzucal rodzica na ekran logowania."""
    cfg = make_config(panel=PanelConfig(enabled=True, port=0, static_dir=str(tmp_path),
                                        cookie_secure=False))
    cfg.store = StoreConfig(path=str(tmp_path / "k.db"))
    Store(cfg.store.path).close()

    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"blad": "zly klucz API"})

    monkeypatch.setattr(panel_mod, "_bramka_admin", lambda cfg: BramkaAdmin(
        BramkaConfig(url="http://bramka"), "k", transport=httpx.MockTransport(handler)))
    PanelAuth(cfg.panel_auth_path).add_user("rodzic", HASLO)
    server = start_panel(cfg)
    try:
        port = server.server_address[1]
        cookie = panel_login(port, "rodzic", HASLO)
        csrf = next(c.split("=", 1)[1] for c in cookie.split("; ")
                    if c.startswith("kidwatch_csrf"))
        h = {"Cookie": cookie, "X-CSRF-Token": csrf}
        status, data = call(port, "POST", "/api/profile/whatsapp/start", {"confirm": HASLO}, h)
        assert status == 502 and "zly klucz" in data["error"]
        assert call(port, "GET", "/api/profile/whatsapp/qr", headers={"Cookie": cookie})[0] == 502
        # Sesja panelu nadal wazna.
        assert call(port, "GET", "/api/auth/me", headers={"Cookie": cookie})[0] == 200
    finally:
        server.shutdown()


# ============================================================ panel_auth
def _session(csrf: str = "token") -> Session:
    return Session(login="x", user_id=1, token_hash="h", csrf=csrf, expires_at=0)


def test_csrf_spoza_ascii_to_odmowa_nie_500():
    assert csrf_ok(_session(), "tokén") is False
    assert csrf_ok(_session(), "token") is True


def test_kod_z_cyframi_spoza_ascii_to_zly_kod_nie_500():
    secret = pyotp.random_base32()
    assert verify_totp(secret, "١٢٣٤٥٦", 1_700_000_000, None) is None


def test_zmiana_hasla_uniewaznia_bilety_mfa(tmp_path):
    """Bilet wydany na STARE haslo pozwalal dokonczyc logowanie kodem po
    zmianie hasla (reset z CLI je kasowal, zmiana z panelu nie)."""
    now = {"t": 1_700_000_000.0}
    auth = PanelAuth(tmp_path / "a.db", box=SecretBox(base64.b64encode(os.urandom(32)).decode()),
                     clock=lambda: now["t"])
    auth.add_user("rodzic", HASLO)
    session = auth.login("rodzic", HASLO).session
    secret = auth.totp_setup(session)["secret"]
    auth.totp_confirm(session, pyotp.TOTP(secret).at(now["t"]))
    challenge = auth.login("rodzic", HASLO).challenge  # ktos zna stare haslo
    auth.change_password(session, HASLO, "zupelnie-nowe-haslo")
    now["t"] += 60
    with pytest.raises(AuthError, match="Bilet"):
        auth.mfa(challenge, pyotp.TOTP(secret).at(now["t"]))


# ================================================================ telewizor
class UsageDown(FlakyShell):
    async def shell(self, command: str) -> str:
        if "usagestats" in command:
            raise TvUnavailable("zerwane polaczenie")
        return await super().shell(command)


async def test_blad_usagestats_nie_gubi_pusha_startu_TV():
    """observe() zajmowal klucz dedupu tv-start, a wyjatek z usagestats
    zaraz po nim wywracal poll() — push startu nie wychodzil nigdy."""
    store = Store(":memory:")
    w = TvWatcher(TvProbe(UsageDown()), "TV salon", store, usage_minutes=15)
    sink = Sink()
    await device_loop([w], sink, 30, sleep=_no_sleep, max_iterations=1, store=store)
    assert [n.kind for n in sink.notes] == [NotifyKind.TV_START]


# ================================================================== NextDNS
def test_wpis_z_polem_nie_tekstowym_jest_pomijany_a_nie_wywraca_zrodla():
    ok = {"timestamp": "2026-10-02T12:00:00Z", "domain": "a.example"}
    assert parse_log_entry(json.dumps(ok | {"domain": 123})) is None
    event = parse_log_entry(json.dumps(ok | {"device": {"name": 7, "id": "abc"}}))
    assert event is not None and event.device_id == "abc"


async def test_zdarzenia_w_kolejce_przezywaja_ponowne_otwarcie_zrodla():
    """Zrodlo z kilku profili padalo z kolejka pelna odebranych zdarzen, a
    kursory strumieni byly juz za nimi — po ponownym otwarciu znikaly."""
    ts = local(2026, 10, 2, 12, 0).astimezone(UTC)

    class Broken:
        profile_id = "zly"

        async def events(self):
            raise ValueError("nieznany format")
            yield  # pragma: no cover

    class Fast:
        profile_id = "szybki"

        async def events(self):
            for i in range(3):
                yield DnsEvent(ts=ts, device_id="d", domain=f"e{i}.example")
            await asyncio.sleep(3600)

    multi = MultiNextDnsSource([Broken(), Fast()])
    # Blad wchodzi do kolejki przed zdarzeniami drugiego profilu.
    with pytest.raises(ValueError):
        async for _ in multi.events():
            pass
    # Ponowne otwarcie (source_loop) oddaje najpierw to, co zostalo w kolejce.
    class Silent:
        profile_id = "cichy"

        async def events(self):
            await asyncio.sleep(3600)
            yield  # pragma: no cover

    multi.sources = [Silent(), Silent()]
    got = []
    async with contextlib.aclosing(multi.events()) as stream:
        async for event in stream:
            got.append(event.domain)
            if len(got) == 3:
                break
    assert got == ["e0.example", "e1.example", "e2.example"]


# ======================================================= potwierdzanie sesji
def test_minuty_sprzed_potwierdzonego_poczatku_nie_licza_sie(classifier):
    """Samotny ping 7 min przed prawdziwa aktywnoscia przesuwal tylko
    poczatek sesji — jego minuta zostawala w aplikacjach i minutach nocnych."""
    cfg = make_config(engine={"confirm_moments": 3, "confirm_minutes": 5},
                      watchdog={"enabled": False})
    eng = Engine(cfg, Store(":memory:"), classifier)
    t0 = local(2026, 10, 2, 14, 0)
    eng.handle(ev(t0, "ecsv3.roblox.com"))
    for s in range(0, 75, 15):
        eng.handle(ev(t0 + timedelta(minutes=7, seconds=s), "minecraft.net"))
    row = eng.store.conn.execute("SELECT * FROM sessions").fetchone()
    assert row["confirmed"] == 1
    apps = dict(eng.store.session_app_minutes(int(row["id"])))
    assert "Roblox" not in apps and apps["Minecraft"] == 2


# ================================================================ agregaty
def test_zmiana_sposobu_liczenia_przelicza_stare_agregaty(tmp_path):
    """Agregaty z wersji, ktora liczyla tez sesje niepotwierdzone, zostawaly
    na zawsze ("starsze dni sa ostateczne") — trend mieszal dwie definicje."""
    cfg = make_config()
    store = Store(tmp_path / "k.db")
    day = date(2026, 9, 28)
    sid = store.open_session("iPad Kuby", "Kuba", local(2026, 9, 28, 3, 0), confirmed=False)
    store.record_app_minute(sid, "YouTube", local(2026, 9, 28, 3, 0))
    store.close_session(sid, local(2026, 9, 28, 3, 0))
    # Agregat policzony "po staremu": samotne zapytanie jako sesja nocna.
    store.upsert_rollup({
        "day": day.isoformat(), "device": "iPad Kuby", "child": "Kuba", "kind": "ipad",
        "minutes": 0, "sessions": 1, "night_minutes": 1, "tv_minutes": None,
        "top_apps": '[["YouTube", 1]]', "tv_apps": None, "computed_at": "x",
    })
    now = local(2026, 10, 3, 12, 0).astimezone(UTC)
    refresh_rollups(cfg, store, now)
    row = store.conn.execute(
        "SELECT sessions, night_minutes FROM daily_rollup WHERE day=? AND device='iPad Kuby'",
        (day.isoformat(),),
    ).fetchone()
    assert (row["sessions"], row["night_minutes"]) == (0, 0)
    # Raz przeliczone — potem znow tylko dzis i wczoraj.
    assert refresh_rollups(cfg, store, now + timedelta(hours=1)) == 2
    store.close()
