"""`kidwatch user-login STARY NOWY` — zmiana loginu konta w miejscu.

Na prawdziwych bazach SQLite (panel-auth.db + baza zdarzen Domu 1):
po zmianie haslo + TOTP dzialaja z nowym loginem, starego nie ma,
czlonkostwo i rola zostaja, SSO z `Remote-User=<nowy>` dopasowuje konto.

Test kompletnosci przeszukuje KAZDA kolumne tekstowa obu baz w poszukiwaniu
starego loginu — kanarek (pominiety krok zmiany) musi go tam znalezc.
Loginy generyczne (konto-stare-a), publiczne repo.
"""

from __future__ import annotations

import base64
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path

import pyotp
import pytest

from kidwatch import domy as dm
from kidwatch import zmiana_loginu as zl
from kidwatch.__main__ import main
from kidwatch.config import Config
from kidwatch.gametime import GameRequests
from kidwatch.odbiorcy import ProfilePowiadomien
from kidwatch.panel_auth import AuthError, PanelAuth, box_from_env
from kidwatch.sejf import Sejf
from kidwatch.store import Store
from kidwatch.tvpause import TvPauseRequests
from test_domy_e2 import _prosta, _zapisz_konfig
from test_panel_auth import Clock, next_code

HASLO = "dlugie-haslo-testowe"
STARY, NOWY = "konto-stare-a", "konto-nowe-a"


@pytest.fixture
def inst(tmp_path, monkeypatch):
    """Konto STARY z haslem, 2FA, kanalami, rola w Domu 1 i sladami loginu
    w kazdym miejscu, gdzie login lezy jako tekst; drugie konto obok."""
    monkeypatch.setenv("PANEL_TOTP_KEY", base64.b64encode(os.urandom(32)).decode())
    monkeypatch.setenv("KIDWATCH_KEK", base64.b64encode(os.urandom(32)).decode())
    cfg_path = _zapisz_konfig(tmp_path, _prosta(tmp_path))
    cfg = Config.load(cfg_path)
    clock = Clock(datetime.now(UTC).timestamp())
    auth = PanelAuth(cfg.panel_auth_path, box=box_from_env(), session_seconds=3600, clock=clock)
    rejestr = dm.RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj()
    auth.add_user(STARY, HASLO, "zarzadca")
    auth.add_user("konto-inne-b", HASLO, "podglad")
    uid = auth.user_id(STARY)
    # 2FA
    r = auth.login(STARY, HASLO)
    setup = auth.totp_setup(r.session)
    auth.totp_confirm(r.session, pyotp.TOTP(setup["secret"]).at(clock.t))
    stary_token = r.token
    # Kanaly i flaga administratora (trzymaja id).
    ProfilePowiadomien(cfg.panel_auth_path).ustaw_kanaly(STARY, whatsapp="48600100200",
                                                          email=None)
    # Login jako tekst w panel-auth.db.
    with pytest.raises(AuthError):
        auth.login(STARY, "zle-haslo-zle-haslo", ip="192.0.2.10")
    rejestr.zapisz_audyt(dm.DOM_1, STARY, "test.akcja", "opis bez loginu")
    GameRequests(cfg.panel_auth_path, dom_id=dm.DOM_1).submit("Dziecko A", "block", None, STARY)
    TvPauseRequests(cfg.panel_auth_path, dom_id=dm.DOM_1).submit("pause", None, STARY)
    rejestr.zapisz_integracje(dm.DOM_1, "ntfy", sejf=Sejf.z_srodowiska(), wlaczona=False,
                              ustawienia={}, kto=STARY)
    # Login jako tekst w bazie zdarzen Domu 1.
    store = Store(cfg.store.path)
    store.close()
    with sqlite3.connect(cfg.store.path) as conn:
        conn.execute("INSERT INTO outbox (created_at, note, odbiorca) VALUES ('t', '{}', ?)",
                     (STARY,))
        conn.execute("INSERT INTO outbox (created_at, note, odbiorca) VALUES ('t', '{}', '*')")
        conn.execute("INSERT INTO sent VALUES (?, 't')", (f"zdarzenie-1@{STARY}",))
        conn.execute("INSERT INTO sent VALUES ('zdarzenie-1@konto-inne-b', 't')")
        conn.execute(
            "INSERT INTO notifications (ts, sent_at, kind, title, text, priority, channels, "
            "delivered) VALUES ('t', 't', 'app', 'x', 'x', 3, ?, 1)",
            (json.dumps({f"bramka:{STARY}": True, "bramka:konto-inne-b": False}),))
        conn.execute("INSERT INTO tv_pause (started_at, started_by, ended_by) VALUES "
                     "('t', ?, 'auto')", (STARY,))
    return {"cfg": cfg, "cfg_path": cfg_path, "auth": auth, "rejestr": rejestr, "uid": uid,
            "clock": clock, "secret": setup["secret"], "token": stary_token}


def _wszystkie_teksty(path: str | Path) -> list[tuple[str, str, str]]:
    """(tabela, kolumna, wartosc) kazdej wartosci tekstowej w bazie."""
    out = []
    with sqlite3.connect(str(path)) as conn:
        for (tabela,) in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                                      "AND name NOT LIKE 'sqlite_%'").fetchall():
            kolumny = [r[1] for r in conn.execute(f"PRAGMA table_info({tabela})")]
            for wiersz in conn.execute(f"SELECT * FROM {tabela}"):  # noqa: S608
                out += [(tabela, k, v) for k, v in zip(kolumny, wiersz, strict=True)
                        if isinstance(v, str)]
    return out


def _slady_starego(inst) -> list[str]:
    """Kazde wystapienie starego loginu poza tresciami opisow audytu (wolny
    tekst z chwili zdarzenia — w tym wpis o samej zmianie)."""
    zle = []
    for path in (inst["cfg"].panel_auth_path, inst["cfg"].store.path):
        for tabela, kolumna, wartosc in _wszystkie_teksty(path):
            if STARY in wartosc and (tabela, kolumna) != ("audyt", "opis"):
                zle.append(f"{Path(path).name}:{tabela}.{kolumna}")
    return zle


def _bazy(inst):
    return zl.bazy_domow(inst["cfg"].panel_auth_path, inst["cfg"].store.path)


# ================================================================ zmiana
def test_kontrola_slady_sa_przed_zmiana(inst):
    """Kontrola pozytywna detektora: przed zmiana stary login jest w kazdym
    zasianym miejscu (inaczej test kompletnosci niczego by nie dowodzil)."""
    miejsca = {s.split(":", 1)[1] for s in _slady_starego(inst)}
    assert miejsca >= {"users.login", "login_failures.login", "audyt.login",
                       "game_requests.login", "tv_pause_requests.login",
                       "integracje.zmienione_przez", "outbox.odbiorca", "sent.dedup_key",
                       "notifications.channels", "tv_pause.started_by"}


def test_podglad_niczego_nie_zmienia(inst):
    przed = _wszystkie_teksty(inst["cfg"].panel_auth_path)
    plan = zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst))
    assert not plan.zapisano
    assert dict(plan.zmiany)["users.login"] == 1
    assert dict(plan.zmiany)["dom 1: sent.dedup_key"] == 1
    assert _wszystkie_teksty(inst["cfg"].panel_auth_path) == przed
    assert inst["auth"].user_id(STARY) == inst["uid"]


def test_zmiana_loginu_zachowuje_konto(inst):
    auth, rejestr, uid = inst["auth"], inst["rejestr"], inst["uid"]
    rola_przed = rejestr.czlonkostwo(uid, dm.DOM_1).rola
    plan = zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst),
                          zapisz=True)
    assert plan.zapisano and plan.user_id == uid and plan.domy == [dm.DOM_1]
    # Ani jednego sladu starego loginu w obu bazach.
    assert _slady_starego(inst) == []
    # To samo konto: id, rola w Domu 1, kanaly.
    assert auth.user_id(NOWY) == uid
    assert rejestr.czlonkostwo(uid, dm.DOM_1).rola == rola_przed == "zarzadca"
    assert ProfilePowiadomien(inst["cfg"].panel_auth_path).profil(NOWY).whatsapp == "48600100200"
    # Stary login nie istnieje, sesje zamkniete.
    with pytest.raises(AuthError):
        auth.login(STARY, HASLO)
    assert auth.session(inst["token"]) is None
    # Haslo + TOTP z nowym loginem.
    r = auth.login(NOWY, HASLO)
    assert r.mfa_required
    _, sesja = auth.mfa(r.challenge, next_code(inst["secret"], inst["clock"]))
    assert sesja.user_id == uid and sesja.login == NOWY
    # Blokada nieudanych hasel poszla za kontem.
    with sqlite3.connect(inst["cfg"].panel_auth_path) as conn:
        assert conn.execute("SELECT failures FROM login_failures WHERE login = ?",
                            (NOWY,)).fetchone()[0] >= 1
        wpisy = conn.execute("SELECT dom_id, login, opis FROM audyt WHERE akcja = "
                             "'konto.login' ORDER BY id").fetchall()
    assert wpisy == [(None, NOWY, f"login konta zmieniony: {STARY} -> {NOWY}"),
                     (dm.DOM_1, NOWY, f"login konta zmieniony: {STARY} -> {NOWY}")]
    # Cudze slady nietkniete.
    with sqlite3.connect(inst["cfg"].store.path) as conn:
        assert conn.execute("SELECT count(*) FROM sent WHERE dedup_key = "
                            "'zdarzenie-1@konto-inne-b'").fetchone()[0] == 1
        kanaly = json.loads(conn.execute("SELECT channels FROM notifications").fetchone()[0])
    assert kanaly == {f"bramka:{NOWY}": True, "bramka:konto-inne-b": False}


def test_kanarek_pominiety_krok_zostawia_slady(inst, monkeypatch):
    """Zmiana bez kroku baz domow MUSI zostawic stary login — detektor go widzi."""
    monkeypatch.setattr(zl, "_baza_domu", lambda *a, **k: None)
    zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst), zapisz=True)
    assert {"kidwatch.db:outbox.odbiorca", "kidwatch.db:sent.dedup_key",
            "kidwatch.db:notifications.channels",
            "kidwatch.db:tv_pause.started_by"} <= set(_slady_starego(inst))


def test_sso_remote_user_nowy_dopasowuje_konto(inst, monkeypatch):
    from kidwatch.panel import start_panel  # noqa: PLC0415
    from test_panel_sso import call  # noqa: PLC0415

    zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst), zapisz=True)
    monkeypatch.setenv("SSO_NAGLOWKI", "1")
    (Path(inst["cfg"].panel.static_dir)).mkdir(parents=True, exist_ok=True)
    cfg = inst["cfg"].model_copy(update={"panel": inst["cfg"].panel.model_copy(
        update={"enabled": True, "port": 0})})
    srv = start_panel(cfg)
    try:
        st, _, me = call(srv, "GET", "/api/auth/me",
                         headers={"Remote-User": NOWY, "Remote-Groups": "rodzina"})
        assert st == 200 and me["login"] == NOWY, me
        assert [d["id"] for d in me["domy"]] == [dm.DOM_1]
        st, _, body = call(srv, "GET", "/api/auth/me",
                           headers={"Remote-User": STARY, "Remote-Groups": "rodzina"})
        assert st == 403, body
    finally:
        srv.shutdown()


# ============================================================ walidacja
@pytest.mark.parametrize(("nowy", "powod"), [
    ("Konto-Duze", "niedozwolony"),
    (" konto-spacja", "niedozwolony"),
    ("konto/ukosnik", "niedozwolony"),
    ("", "niedozwolony"),
    ("x" * 65, "niedozwolony"),
    ("konto-inne-b", "zajety"),
    (STARY, "taki sam"),
])
def test_odmowa_zlego_albo_zajetego_loginu(inst, nowy, powod):
    with pytest.raises(zl.BladZmiany, match=powod):
        zl.zmien_login(inst["cfg"].panel_auth_path, STARY, nowy, bazy=_bazy(inst), zapisz=True)
    assert inst["auth"].user_id(STARY) == inst["uid"]


def test_zajety_bez_wzgledu_na_wielkosc_liter(inst):
    """Konto z wielkimi literami (zalozone przed walidacja SSO) blokuje login,
    ktory rozni sie tylko wielkoscia liter."""
    with sqlite3.connect(inst["cfg"].panel_auth_path) as conn:
        conn.execute("UPDATE users SET login = 'Konto-Inne-B' WHERE login = 'konto-inne-b'")
    with pytest.raises(zl.BladZmiany, match="zajety"):
        zl.zmien_login(inst["cfg"].panel_auth_path, STARY, "konto-inne-b", zapisz=True)


def test_brak_konta(inst):
    with pytest.raises(zl.BladZmiany, match="nie ma konta"):
        zl.zmien_login(inst["cfg"].panel_auth_path, "nie-ma-takiego", NOWY, zapisz=True)


# ================================================================== CLI
def test_cli_podglad_potem_zapis(inst, capsys):
    argv = ["--config", str(inst["cfg_path"]), "user-login", STARY, NOWY]
    assert main(argv) == 0
    out = capsys.readouterr().out
    assert "Podglad — nic nie zapisano" in out and "users.login: 1" in out
    assert inst["auth"].user_id(STARY) == inst["uid"]
    assert main([*argv, "--zapisz"]) == 0
    assert "ZAPISANO" in capsys.readouterr().out
    assert inst["auth"].user_id(NOWY) == inst["uid"]
    # Powtorka = dokonczenie (nic do zrobienia), nie blad.
    assert main([*argv, "--zapisz"]) == 0
    assert "DOKONCZENIE" in capsys.readouterr().out


# ======================================================== dokonczenie
def test_czesciowy_stan_ponowne_uruchomienie_dokancza(inst):
    """Przypadek z przegladu: panel-auth.db juz po zmianie, baza domu jeszcze
    nie (WAL = atomowosc per plik albo przerwany przebieg). Ponowne
    uruchomienie tego samego polecenia przepisuje reszte sladow."""
    zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy={}, zapisz=True)
    zostalo = set(_slady_starego(inst))
    assert {"kidwatch.db:sent.dedup_key", "kidwatch.db:notifications.channels",
            "kidwatch.db:outbox.odbiorca", "kidwatch.db:tv_pause.started_by"} <= zostalo
    # Uzytkownik zdazyl sie zalogowac nowym loginem — dokonczenie go nie wyloguje.
    r = inst["auth"].login(NOWY, HASLO)
    token, _ = inst["auth"].mfa(r.challenge, next_code(inst["secret"], inst["clock"]))
    plan = zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst),
                          zapisz=True)
    assert plan.dokonczenie and plan.user_id == inst["uid"]
    assert _slady_starego(inst) == []
    assert inst["auth"].session(token) is not None
    with sqlite3.connect(inst["cfg"].panel_auth_path) as conn:
        assert conn.execute("SELECT count(*) FROM audyt WHERE akcja = 'konto.login' "
                            "AND dom_id IS NULL").fetchone()[0] == 1


def test_dokoncz_jawnie_gdy_stare_konto_istnieje_to_blad(inst):
    with pytest.raises(zl.BladZmiany, match="nadal istnieje"):
        zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst),
                       zapisz=True, dokoncz=True)
    assert inst["auth"].user_id(STARY) == inst["uid"]


def test_kanarek_bez_dokonczenia_slady_zostaja(inst, monkeypatch):
    """Gdyby brak starego konta konczyl sie bledem (stare zachowanie), slady
    zostalyby na zawsze — detektor to widzi."""
    zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy={}, zapisz=True)
    stary_waliduj = zl._waliduj

    def bez_dokonczenia(conn, stary, nowy, dokoncz=False):
        uid, dok = stary_waliduj(conn, stary, nowy, dokoncz)
        if dok:
            raise zl.BladZmiany(f"nie ma konta {stary!r}")
        return uid, dok

    monkeypatch.setattr(zl, "_waliduj", bez_dokonczenia)
    with pytest.raises(zl.BladZmiany):
        zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst), zapisz=True)
    assert _slady_starego(inst)


# ============================= dokonczenie tylko z dowodem przemianowania
def _migawka(inst):
    return (_wszystkie_teksty(inst["cfg"].panel_auth_path),
            _wszystkie_teksty(inst["cfg"].store.path))


@pytest.mark.parametrize("dokoncz", [False, True])
@pytest.mark.parametrize("zapisz", [False, True])
def test_usuniete_konto_nie_dokancza_sie_na_cudze(inst, dokoncz, zapisz):
    """Przypadek z przegladu: STARY usuniety, NOWY to inna osoba. Bez dowodu
    zmiany (konto.login STARY -> NOWY) odmowa — takze z --dokoncz i w podgladzie —
    i zero zmian: slady usunietego konta nie trafiaja do cudzego."""
    inst["auth"].delete_user(STARY)
    przed = _migawka(inst)
    with pytest.raises(zl.BladZmiany, match="nie powstalo przez zmiane"):
        zl.zmien_login(inst["cfg"].panel_auth_path, STARY, "konto-inne-b", bazy=_bazy(inst),
                       zapisz=zapisz, dokoncz=dokoncz)
    assert _migawka(inst) == przed


def test_login_uzyty_ponownie_po_zmianie_nie_jest_dowodem(inst):
    """STARY -> NOWY, potem NOWY usuniete i zalozone od nowa (inna osoba):
    stary wpis konto.login jest starszy niz nowe konto — odmowa."""
    import time  # noqa: PLC0415

    zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy={}, zapisz=True)
    inst["auth"].delete_user(NOWY)
    inst["clock"].t = time.time() + 60
    inst["auth"].add_user(NOWY, HASLO)
    przed = _migawka(inst)
    with pytest.raises(zl.BladZmiany, match="nie powstalo przez zmiane"):
        zl.zmien_login(inst["cfg"].panel_auth_path, STARY, NOWY, bazy=_bazy(inst), zapisz=True)
    assert _migawka(inst) == przed


def test_kanarek_bez_dowodu_dokonczenie_przepisuje_cudze(inst, monkeypatch):
    """Bez sprawdzenia dowodu (stare zachowanie) slady usunietego konta
    laduja na cudzym — test wyzej musi to wylapac."""
    monkeypatch.setattr(zl, "_przemianowane", lambda *a, **k: True)
    inst["auth"].delete_user(STARY)
    przed = _migawka(inst)
    plan = zl.zmien_login(inst["cfg"].panel_auth_path, STARY, "konto-inne-b",
                          bazy=_bazy(inst), zapisz=True)
    assert plan.dokonczenie and _migawka(inst) != przed
