"""`user-login` a prawdziwe sciezki kodu (przeglad #63).

1. Detektor kompletnosci z zasiewem przez KOD, nie SQL: kolejka i dedup
   przez `Outbox._rozdziel`/`flush` z profilem konta, historia przez
   `record_notification` (Dispatcher), audyt i `zmienione_przez` przez trasy
   panelu (administrator), pauza TV i czas gry przez ich API. Nowe miejsce,
   w ktorym kod kiedys zapisze login, zostawi po zmianie slad — test padnie.
2. Wyscig z zywym procesem `run`: login zmieniony miedzy rozdzialem kolejki
   a wysylka — wpis ma dojsc (Outbox odswieza profile), nie zginac.

Loginy generyczne, publiczne repo.
"""

from __future__ import annotations

import base64
import os
import sqlite3
from pathlib import Path

from kidwatch import domy as dm
from kidwatch import odbiorcy as o
from kidwatch import zmiana_loginu as zl
from kidwatch.config import Config
from kidwatch.gametime import GameRequests
from kidwatch.notifiers.base import Dispatcher, Outbox
from kidwatch.panel import start_panel
from kidwatch.panel_auth import PanelAuth, box_from_env
from kidwatch.store import Store
from kidwatch.tvpause import TvPauseRequests
from test_domy_e2 import _prosta, _zapisz_konfig
from test_odbiorcy import DZIECKO, NR_A, TZ, Clock, Dom, Konto, note
from test_panel_sso import call, cookie, jar
from test_zmiana_loginu import HASLO, NOWY, STARY, _wszystkie_teksty

DOM_B = 2


def _przygotuj(tmp_path, monkeypatch):
    monkeypatch.setenv("PANEL_TOTP_KEY", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    cfg = Config.load(_zapisz_konfig(tmp_path, _prosta(tmp_path)))
    cfg = cfg.model_copy(update={"panel": cfg.panel.model_copy(
        update={"enabled": True, "port": 0, "static_dir": str(tmp_path / "web")})})
    (tmp_path / "web").mkdir()
    auth = PanelAuth(cfg.panel_auth_path, box=box_from_env())
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj()
    auth.add_user(STARY, HASLO)
    k = o.ProfilePowiadomien(cfg.panel_auth_path)
    k.ustaw_kanaly(STARY, whatsapp=NR_A, email=None)
    k.ustaw_tryb(o.TRYB_KONTA)
    return cfg, auth, rejestr, k


def _kolejka(cfg, k):
    store = Store(cfg.store.path)
    bramka, dom = Konto(), Dom()
    outbox = Outbox(Dispatcher([bramka, dom], store=store), store, now=Clock(),
                    konta=k, dziecko=DZIECKO, tz=TZ)
    return outbox, bramka, store


def _slady(cfg) -> list[str]:
    zle = []
    for path in (cfg.panel_auth_path, cfg.store.path):
        for tabela, kolumna, wartosc in _wszystkie_teksty(path):
            if STARY in wartosc and (tabela, kolumna) != ("audyt", "opis"):
                zle.append(f"{Path(path).name}:{tabela}.{kolumna}")
    return zle


async def _zasiej_kodem(cfg, auth, rejestr, k):
    """Login STARY trafia do baz wylacznie przez prawdziwe sciezki kodu."""
    # Kolejka, dedup i historia: rozdzial i wysylka per konto.
    outbox, bramka, store = _kolejka(cfg, k)
    await outbox.send_all([note(key="s1")])
    await outbox.flush()
    assert bramka.calls == [("s1", NR_A)]
    await outbox.send_all([note(key="s2")])
    await outbox._rozdziel()               # wpis czeka w kolejce konta
    store.start_tv_pause(store_now(), None, STARY)
    store.close()
    # Komenda z WhatsAppa przez bota: dziennik komend i game_requests
    # z loginem 'whatsapp:<login>'.
    await _komenda_whatsapp(cfg)
    # Zlecenia z panelu.
    GameRequests(cfg.panel_auth_path, dom_id=dm.DOM_1).submit("Dziecko A", "block", None, STARY)
    TvPauseRequests(cfg.panel_auth_path, dom_id=dm.DOM_1).submit("pause", None, STARY)
    # Audyt i zmienione_przez: trasy panelu, konto jako administrator instalacji.
    rejestr.ustaw_admin_instancji(auth.user_id(STARY), True)
    assert rejestr.dodaj_dom("Dom B") == DOM_B
    srv = start_panel(cfg)
    try:
        h = {"Remote-User": STARY, "Remote-Groups": "admins"}
        st, headers, _ = call(srv, "GET", "/api/auth/me", headers=h)
        assert st == 200
        j = jar(headers)
        h = {**h, "Cookie": cookie(j), "X-CSRF-Token": j["kidwatch_csrf"]}
        st, _, body = call(srv, "GET", f"/api/domy/{DOM_B}/dziennik", headers=h)
        assert st == 200, body
        st, _, body = call(srv, "POST", f"/api/domy/{DOM_B}/integracje/zapisz",
                           {"typ": "ntfy", "wlaczona": False, "ustawienia": {},
                            "confirm": HASLO}, headers=h)
        assert st == 200, body
    finally:
        srv.shutdown()


class _GryOdRazu(GameRequests):
    """Prawdziwa kolejka; wynik od razu (bez petli czasu gry w tescie)."""

    def result(self, request_id):
        return True, None


async def _komenda_whatsapp(cfg):
    from kidwatch import komendy_baza as kb  # noqa: PLC0415
    from kidwatch.config import LlmKomendConfig, WhatsappKomendyConfig  # noqa: PLC0415
    from kidwatch.komendy_bot import BotKomend, DomKomend  # noqa: PLC0415
    from kidwatch.komendy_llm import Rozpoznawacz  # noqa: PLC0415
    from test_komendy_bot import Kanal, Zapytania, home, kod_z, nic  # noqa: PLC0415

    path = cfg.panel_auth_path
    baza = kb.BazaKomend(path)
    kanal = Kanal()
    dom = DomKomend(dm.DOM_1, "Dom 1", home(), Zapytania(),
                    _GryOdRazu(path, dom_id=dm.DOM_1), None)
    rejestr = dm.RejestrDomow(path)
    profile = o.ProfilePowiadomien(path)
    bot = BotKomend(WhatsappKomendyConfig(enabled=True), baza, kanal,
                    Rozpoznawacz(LlmKomendConfig(), lambda: False, dostawcy=[]),
                    czlonkostwa=rejestr.czlonkostwa, dom={dm.DOM_1: dom}.get,
                    profile=lambda d: profile.dla_domu(d).profile(), sleep=nic)
    for i, tekst in enumerate(("koniec Dziecko A", None)):
        if tekst is None:
            tekst = "TAK " + kod_z(kanal.do(NR_A))
        kanal.skrzynka.append({"id": f"wa-{i}", "numer": NR_A, "tekst": tekst,
                               "ts": store_now().isoformat(), "odpowiedz_na": None})
        await bot.krok()
    assert kanal.do(NR_A)[-1].startswith("Zrobione"), kanal.do(NR_A)


def store_now():
    from datetime import UTC, datetime  # noqa: PLC0415

    return datetime.now(UTC)


async def test_zasiew_przez_kod_i_zero_sladow_po_zmianie(tmp_path, monkeypatch):
    cfg, auth, rejestr, k = _przygotuj(tmp_path, monkeypatch)
    await _zasiej_kodem(cfg, auth, rejestr, k)
    przed = {s.split(":", 1)[1] for s in _slady(cfg)}
    # Kontrola pozytywna: kod naprawde zapisal login w tych miejscach.
    assert przed >= {"users.login", "audyt.login", "integracje.zmienione_przez",
                     "game_requests.login", "tv_pause_requests.login", "outbox.odbiorca",
                     "sent.dedup_key", "notifications.channels", "tv_pause.started_by",
                     "whatsapp_komendy_dziennik.login"}, przed
    with sqlite3.connect(cfg.panel_auth_path) as conn:
        assert conn.execute("SELECT count(*) FROM game_requests WHERE login = ?",
                            (f"whatsapp:{STARY}",)).fetchone()[0] == 1
    zl.zmien_login(cfg.panel_auth_path, STARY, NOWY,
                   bazy=zl.bazy_domow(cfg.panel_auth_path, cfg.store.path), zapisz=True)
    assert _slady(cfg) == []


async def test_kanarek_zasiew_przez_kod_widzi_pominiety_krok(tmp_path, monkeypatch):
    cfg, auth, rejestr, k = _przygotuj(tmp_path, monkeypatch)
    await _zasiej_kodem(cfg, auth, rejestr, k)
    monkeypatch.setattr(zl, "_baza_domu", lambda *a, **kw: None)
    zl.zmien_login(cfg.panel_auth_path, STARY, NOWY,
                   bazy=zl.bazy_domow(cfg.panel_auth_path, cfg.store.path), zapisz=True)
    assert {"kidwatch.db:outbox.odbiorca", "kidwatch.db:sent.dedup_key",
            "kidwatch.db:notifications.channels"} <= set(_slady(cfg))


async def test_kanarek_zasiew_widzi_pominiete_slady_whatsappa(tmp_path, monkeypatch):
    cfg, auth, rejestr, k = _przygotuj(tmp_path, monkeypatch)
    await _zasiej_kodem(cfg, auth, rejestr, k)
    monkeypatch.setattr(zl, "_whatsapp", lambda *a, **kw: None)
    zl.zmien_login(cfg.panel_auth_path, STARY, NOWY,
                   bazy=zl.bazy_domow(cfg.panel_auth_path, cfg.store.path), zapisz=True)
    assert {"panel-auth.db:game_requests.login",
            "panel-auth.db:whatsapp_komendy_dziennik.login"} <= set(_slady(cfg))


# ================================================================ wyscig
async def _wyscig(tmp_path, monkeypatch):
    cfg, _, _, k = _przygotuj(tmp_path, monkeypatch)
    outbox, bramka, store = _kolejka(cfg, k)
    await outbox.send_all([note(key="w1")])
    oryginal = outbox._rozdziel

    async def rozdziel_i_zmiana():
        wynik = await oryginal()  # slownik profili ze STARYM loginem
        zl.zmien_login(cfg.panel_auth_path, STARY, NOWY, bazy={dm.DOM_1: Path(cfg.store.path)},
                       zapisz=True)
        return wynik

    monkeypatch.setattr(outbox, "_rozdziel", rozdziel_i_zmiana)
    await outbox.flush()
    return bramka, store


async def test_zmiana_loginu_miedzy_rozdzialem_a_wysylka_nie_gubi_wpisu(tmp_path, monkeypatch):
    bramka, store = await _wyscig(tmp_path, monkeypatch)
    assert bramka.calls == [("w1", NR_A)]
    assert store.outbox_pending() == []
    store.close()


async def test_kanarek_wyscig_bez_odswiezenia_profili_gubi_wpis(tmp_path, monkeypatch):
    async def bez_odswiezenia(self, profile):
        return False

    monkeypatch.setattr(Outbox, "_odswiez_profile", bez_odswiezenia)
    bramka, store = await _wyscig(tmp_path, monkeypatch)
    assert bramka.calls == []
    store.close()


async def test_konto_naprawde_usuniete_dalej_porzucane(tmp_path, monkeypatch):
    """Odswiezenie nie zatrzymuje wpisu konta, ktorego nie ma: porzucony jak dotad."""
    cfg, auth, _, k = _przygotuj(tmp_path, monkeypatch)
    outbox, bramka, store = _kolejka(cfg, k)
    await outbox.send_all([note(key="u1")])
    await outbox._rozdziel()
    auth.delete_user(STARY)
    await outbox.flush()
    assert bramka.calls == [] and store.outbox_pending() == []
    with sqlite3.connect(cfg.store.path) as conn:
        assert conn.execute("SELECT count(*) FROM outbox").fetchone()[0] == 0
    store.close()
