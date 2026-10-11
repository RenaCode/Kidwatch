"""Powiadomienia per konto panelu (odbiorcy.py): routing, cisza, uprawnienia,
dedup, kolejki per odbiorca i migracja z tras bramki.

Zasada migracji: po przelaczeniu na tryb kont KAZDY rodzaj powiadomienia
trafia do dokladnie tych samych numerow, co w trybie tras bramki.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo

import httpx
import pytest

from kidwatch import odbiorcy as o
from kidwatch import uprawnienia as u
from kidwatch.config import BramkaConfig
from kidwatch.models import Notification, NotifyKind
from kidwatch.notifiers.base import Dispatcher, Outbox
from kidwatch.notifiers.bramka import BramkaNotifier
from kidwatch.panel_auth import PanelAuth
from kidwatch.store import Store

TZ = ZoneInfo("Europe/Warsaw")
#: 12:00 czasu lokalnego — poza kazda cisza z testow.
T0 = datetime(2026, 10, 3, 10, 0, tzinfo=UTC)
NR_A, NR_B, NR_C, NR_D = "48500100201", "48500100202", "48500100203", "48500100204"
HASLO = "dlugie-haslo-testowe"
DZIECKO = {"iPad A": "Dziecko A", "iPad B": "Dziecko B"}

WLASC = u.efektywne(u.ROLE_OWNER)
PODGL = u.efektywne(u.ROLE_VIEWER)


def note(kind=NotifyKind.SESSION_START, key="k1", device="iPad A", priority=3, ts=T0):
    return Notification(kind=kind, title=f"t {key}", text="tresc", dedup_key=key, ts=ts,
                        device=device, priority=priority)


def profil(login="rodzic", upr=WLASC, rola=u.ROLE_OWNER, **kw):
    kw.setdefault("whatsapp", NR_A)
    return o.Profil(login=login, rola=rola, uprawnienia=upr, **kw)


def kto(n, profile, now=T0):
    return [a.login for a in o.adresaci(n, profile, dziecko=DZIECKO, tz=TZ, now=now).adresaci]


# ============================================================== routing
def test_kazda_kategoria_ma_wymagane_uprawnienie_i_kazdy_rodzaj_kategorie():
    assert set(o.WYMAGANE) == set(o.KATEGORIE)
    assert all(v in u.OPISY for v in o.WYMAGANE.values())
    for kind in NotifyKind:
        assert o.kategoria(kind) in o.KATEGORIE
    assert o.kategoria("cos_nowego") == o.INNE


def test_wlaczone_i_wylaczone_kategorie():
    p = profil(kategorie=frozenset({o.ALARMY}))
    assert kto(note(NotifyKind.NIGHT), [p]) == ["rodzic"]
    assert kto(note(NotifyKind.SESSION_START), [p]) == []
    assert kto(note(NotifyKind.DAILY), [p]) == []


def test_bez_zapisanych_kategorii_konto_dostaje_wszystko_co_mu_wolno():
    assert kto(note(NotifyKind.MDM), [profil()]) == ["rodzic"]
    assert kto(note(NotifyKind.MDM), [profil("domownik", PODGL, u.ROLE_VIEWER)]) == []
    assert kto(note(NotifyKind.SESSION_START), [profil("domownik", PODGL, u.ROLE_VIEWER)]) \
        == ["domownik"]


def test_podglad_nie_dostaje_mdm_ani_czujki_nawet_z_kategoria_w_bazie():
    """Kategoria zapisana, gdy konto mialo uprawnienie; po odebraniu dziala od razu."""
    p = profil("domownik", PODGL, u.ROLE_VIEWER, kategorie=frozenset(o.KATEGORIE))
    for kind in (NotifyKind.MDM, NotifyKind.WATCHDOG, NotifyKind.DNS_PROFILE,
                 NotifyKind.TV_PAUSE):
        r = o.adresaci(note(kind), [p], dziecko=DZIECKO, tz=TZ, now=T0)
        assert r.adresaci == [] and "uprawnienia" in r.pominieci["domownik"]
    # Pojedyncze nadanie (model uprawnien e5) wlacza MDM bez zmiany roli.
    p2 = profil("domownik", PODGL | {u.MDM_PODGLAD}, u.ROLE_VIEWER)
    assert kto(note(NotifyKind.MDM), [p2]) == ["domownik"]


def test_bez_kanalu_albo_wylaczone_nic():
    assert kto(note(), [profil(whatsapp=None)]) == []
    assert kto(note(), [profil(aktywne=False)]) == []
    # kanal "email" bez adresu = brak kanalu, choc numer jest
    assert kto(note(), [profil(kanal="email")]) == []
    assert kto(note(), [profil(whatsapp=None, email="a@b.pl", kanal="email")]) == ["rodzic"]


def test_dzieci_filtruja_tylko_powiadomienia_o_dziecku():
    p = profil(dzieci=frozenset({"Dziecko B"}))
    assert kto(note(device="iPad A"), [p]) == []
    assert kto(note(device="iPad B"), [p]) == ["rodzic"]
    # telewizor i raport zbiorczy dotycza domu
    assert kto(note(device="Telewizor"), [p]) == ["rodzic"]
    assert kto(note(NotifyKind.DAILY, device=None), [p]) == ["rodzic"]


def test_dedup_raz_na_konto():
    assert kto(note(), [profil(), profil()]) == ["rodzic"]


def test_koniec_ciszy_przez_polnoc():
    od, do = time(22, 0), time(7, 0)
    assert o.koniec_ciszy(od, do, datetime(2026, 10, 3, 23, 0, tzinfo=TZ)) == \
        datetime(2026, 10, 4, 7, 0, tzinfo=TZ)
    assert o.koniec_ciszy(od, do, datetime(2026, 10, 4, 6, 59, tzinfo=TZ)) == \
        datetime(2026, 10, 4, 7, 0, tzinfo=TZ)
    assert o.koniec_ciszy(od, do, datetime(2026, 10, 4, 7, 0, tzinfo=TZ)) is None
    assert o.koniec_ciszy(time(13, 0), time(15, 0), datetime(2026, 10, 4, 14, 0, tzinfo=TZ)) \
        == datetime(2026, 10, 4, 15, 0, tzinfo=TZ)
    assert o.koniec_ciszy(time(8, 0), time(8, 0), datetime(2026, 10, 4, 8, 0, tzinfo=TZ)) is None


def test_cisza_sesje_przepadaja_raport_czeka_alarm_przebija():
    noc = datetime(2026, 10, 3, 22, 30, tzinfo=TZ).astimezone(UTC)
    p = profil(cisza_od=time(22, 0), cisza_do=time(7, 0))
    r = o.adresaci(note(), [p], dziecko=DZIECKO, tz=TZ, now=noc)
    assert r.adresaci == [] and r.pominieci["rodzic"] == "cisza"
    [a] = o.adresaci(note(NotifyKind.DAILY), [p], dziecko=DZIECKO, tz=TZ, now=noc).adresaci
    assert a.po == datetime(2026, 10, 4, 7, 0, tzinfo=TZ)
    [a] = o.adresaci(note(NotifyKind.NIGHT, priority=5), [p], dziecko=DZIECKO, tz=TZ,
                     now=noc).adresaci
    assert a.po is None
    p_bez = profil(cisza_od=time(22, 0), cisza_do=time(7, 0), cisza_alarmy=False)
    [a] = o.adresaci(note(NotifyKind.NIGHT, priority=5), [p_bez], dziecko=DZIECKO, tz=TZ,
                     now=noc).adresaci
    assert a.po is not None


def test_adres_dla_bramki_wg_kanalu():
    p = profil(email="a@b.pl")
    assert p.adres() == {"kanal": "auto", "whatsapp": NR_A, "email": "a@b.pl"}
    assert profil(email="a@b.pl", kanal="whatsapp").adres() == {"kanal": "whatsapp",
                                                                "whatsapp": NR_A}
    pub = p.publiczny()
    assert NR_A not in json.dumps(pub) and pub["whatsapp"].endswith("201")
    assert pub["email"] == "a…@b.pl"


@pytest.mark.parametrize("adres", ["a@b-.pl", "a@-b.pl", "a@" + "x" * 64 + ".pl"])
def test_email_odrzucany_jak_w_bramce(adres):
    """Bramka (charts/bramka: kanaly.EMAIL) odrzuca etykiete domeny z '-' na
    brzegu albo dluzsza niz 63 znaki - 400, czyli porzucenie KAZDEGO
    powiadomienia tego konta. Panel nie moze przyjac takiego adresu."""
    assert o.normalize_email(adres) is None


# =============================================================== baza
@pytest.fixture
def konta(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("rodzic", HASLO)
    auth.add_user("domownik", HASLO, rola=u.ROLE_VIEWER)
    return auth, o.ProfilePowiadomien(path)


def test_profil_domyslny_bez_kanalu(konta):
    _, k = konta
    p = k.profil("domownik")
    assert p.rola == u.ROLE_VIEWER and not p.ma_kanal
    assert p.efektywne_kategorie() == o.dozwolone(PODGL)
    assert k.tryb() == o.TRYB_TRASY


def test_zapis_kanalow_i_preferencji(konta):
    _, k = konta
    assert k.ustaw_kanaly("rodzic", whatsapp="+48 500 100 201", email="Ja@Poczta.PL") == \
        (NR_A, "Ja@poczta.pl")
    k.ustaw_preferencje("rodzic", kategorie=[o.ALARMY, o.MDM], cisza_od="22:00",
                        cisza_do="07:00", dzieci=["Dziecko A"], znane_dzieci=DZIECKO.values())
    p = k.profil("rodzic")
    assert (p.whatsapp, p.email, p.kategorie) == (NR_A, "Ja@poczta.pl",
                                                  frozenset({o.ALARMY, o.MDM}))
    assert (p.cisza_od, p.cisza_do, p.dzieci) == (time(22), time(7), frozenset({"Dziecko A"}))
    # Puste pola kasuja kanal.
    k.ustaw_kanaly("rodzic", whatsapp="", email=None)
    assert not k.profil("rodzic").ma_kanal


@pytest.mark.parametrize(("pole", "wartosc"), [
    ("whatsapp", "123"), ("whatsapp", "48 500 wew. 12"), ("email", "nie-adres"),
    ("email", "a@b"), ("kanal", "sms"),
])
def test_zle_kanaly_odrzucone(konta, pole, wartosc):
    _, k = konta
    kw = {"whatsapp": None, "email": None, "kanal": "auto", pole: wartosc}
    with pytest.raises(ValueError):
        k.ustaw_kanaly("rodzic", **kw)


def test_podglad_nie_wlaczy_sobie_mdm(konta):
    _, k = konta
    with pytest.raises(ValueError, match="uprawnienia"):
        k.ustaw_preferencje("domownik", kategorie=[o.SESJE, o.MDM])
    with pytest.raises(ValueError, match="Nieznana"):
        k.ustaw_preferencje("rodzic", kategorie=["wszystko"])
    with pytest.raises(ValueError, match="obie"):
        k.ustaw_preferencje("rodzic", kategorie=None, cisza_od="22:00")
    with pytest.raises(ValueError, match="dziecko"):
        k.ustaw_preferencje("rodzic", kategorie=None, dzieci=["Obce"],
                            znane_dzieci=DZIECKO.values())


def test_usuniecie_konta_kasuje_kanaly(konta):
    auth, k = konta
    k.ustaw_kanaly("domownik", whatsapp=NR_B, email=None)
    auth.delete_user("domownik")
    assert [p.login for p in k.profile()] == ["rodzic"]
    with k._conn() as conn:
        assert conn.execute("SELECT COUNT(*) FROM user_powiadomienia").fetchone()[0] == 0


def test_baza_bez_kont_to_brak_profili(tmp_path):
    assert o.ProfilePowiadomien(tmp_path / "pusta.db").profile() == []


# ============================================================ migracja
#: Stan bramki po jej migracji tras (2026-10-05): pierwszy numer "*",
#: kolejne "kidwatch"; plus nieaktywny i jeden z dopisana trasa raportow.
BRAMKA = [
    {"numer": NR_A, "etykieta": "Ja", "aktywny": True, "zrodla": ["*"]},
    {"numer": NR_B, "etykieta": "Druga osoba", "aktywny": True, "zrodla": ["kidwatch"]},
    {"numer": NR_C, "etykieta": "Wylaczony", "aktywny": False, "zrodla": ["kidwatch"]},
    {"numer": NR_D, "etykieta": "Raporty", "aktywny": True,
     "zrodla": ["kidwatch", "kidwatch:raport", "trader"]},
]


def test_kategorie_z_tras():
    assert o.kategorie_z_tras(["*"]) == frozenset(o.KATEGORIE)
    assert o.kategorie_z_tras(["kidwatch"]) == {o.SESJE}
    assert o.kategorie_z_tras(["kidwatch:czujka"]) == {o.MDM, o.CZUJKA}
    assert o.kategorie_z_tras(["trader"]) == frozenset()


def _profile_przed():
    return [profil("rodzic", WLASC, whatsapp=None),
            profil("drugi", PODGL, u.ROLE_VIEWER, whatsapp=None),
            profil("trzeci", PODGL, u.ROLE_VIEWER, whatsapp=None),
            profil("czwarty", PODGL, u.ROLE_VIEWER, whatsapp=None)]


def test_migracja_zachowuje_odbiorcow_kazdego_rodzaju():
    przed = _profile_przed()
    kroki = o.plan_migracji(BRAMKA, przed, {2: "drugi", 3: "trzeci", 4: "czwarty"})
    assert [k.login for k in kroki] == ["rodzic", "drugi", "trzeci", "czwarty"]
    po = o.profile_po_migracji(kroki, przed)
    for kind, stare, nowe in o.porownanie(BRAMKA, po, T0):
        assert stare == nowe, kind
        assert stare  # owner z "*" dostaje wszystko — zaden rodzaj nie idzie w proznie


def test_migracja_nadaje_uprawnienie_gdy_podglad_mial_czujke():
    bramka = [{"numer": NR_A, "zrodla": ["*"]},
              {"numer": NR_B, "zrodla": ["kidwatch", "kidwatch:czujka"]}]
    przed = _profile_przed()[:2]
    kroki = o.plan_migracji(bramka, przed, {2: "drugi"})
    assert kroki[1].nadac == {u.MDM_PODGLAD, u.POWIADOMIENIA_TECHNICZNE}
    po = o.profile_po_migracji(kroki, przed)
    assert all(a == b for _, a, b in o.porownanie(bramka, po, T0))
    # Bez nadania (np. uprawnienia odebrane recznie) porownanie pokazuje roznice.
    po_bez = o.profile_po_migracji(
        [o.KrokMigracji(**{**k.__dict__, "nadac": frozenset()}) for k in kroki], przed)
    assert any(a != b for _, a, b in o.porownanie(bramka, po_bez, T0))


def test_migracja_bez_przypisania_nie_jest_rownowazna():
    przed = _profile_przed()
    kroki = o.plan_migracji(BRAMKA, przed, {})
    assert [k.login for k in kroki] == ["rodzic", None, None, None]
    po = o.profile_po_migracji(kroki, przed)
    assert any(a != b for _, a, b in o.porownanie(BRAMKA, po, T0))


def test_migracja_odrzuca_zle_przypisania():
    with pytest.raises(ValueError, match="nie ma konta"):
        o.plan_migracji(BRAMKA, _profile_przed(), {2: "obcy"})
    with pytest.raises(ValueError, match="dwoch"):
        o.plan_migracji(BRAMKA, _profile_przed(), {2: "drugi", 4: "drugi"})


def test_zastosowana_migracja_w_bazie_daje_to_samo(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("rodzic", HASLO)
    for login in ("drugi", "trzeci", "czwarty"):
        auth.add_user(login, HASLO, rola=u.ROLE_VIEWER)
    k = o.ProfilePowiadomien(path)
    kroki = o.plan_migracji(BRAMKA, k.profile(), {2: "drugi", 3: "trzeci", 4: "czwarty"})
    o.zastosuj_migracje(k, kroki, auth)
    for kind, stare, nowe in o.porownanie(BRAMKA, k.profile(), T0):
        assert stare == nowe, kind


def test_zastosowana_migracja_nadaje_uprawnienie_w_bazie(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("rodzic", HASLO)
    auth.add_user("drugi", HASLO, rola=u.ROLE_VIEWER)
    k = o.ProfilePowiadomien(path)
    bramka = [{"numer": NR_A, "zrodla": ["*"]},
              {"numer": NR_B, "zrodla": ["kidwatch", "kidwatch:czujka"]}]
    o.zastosuj_migracje(k, o.plan_migracji(bramka, k.profile(), {2: "drugi"}), auth)
    assert {u.MDM_PODGLAD, u.POWIADOMIENIA_TECHNICZNE} <= k.profil("drugi").uprawnienia
    assert all(a == b for _, a, b in o.porownanie(bramka, k.profile(), T0))


def test_ponowna_migracja_nie_kasuje_adresu_email(tmp_path):
    """Krok 4 wdrozenia: kazdy wpisuje e-mail. Ponowna migracja (np. nowy
    numer w bramce) nie moze go po cichu skasowac — to zapasowy kanal."""
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("rodzic", HASLO)
    auth.add_user("drugi", HASLO, rola=u.ROLE_VIEWER)
    k = o.ProfilePowiadomien(path)
    bramka = [{"numer": NR_A, "zrodla": ["*"]}, {"numer": NR_B, "zrodla": ["kidwatch"]}]
    o.zastosuj_migracje(k, o.plan_migracji(bramka, k.profile(), {2: "drugi"}), auth)
    k.ustaw_kanaly("drugi", whatsapp=NR_B, email="osoba@example.com")
    kroki = o.plan_migracji(bramka, k.profile(), {2: "drugi"})
    po = {p.login: p for p in o.profile_po_migracji(kroki, k.profile())}
    assert po["drugi"].email == "osoba@example.com"
    o.zastosuj_migracje(k, kroki, auth)
    assert k.profil("drugi").email == "osoba@example.com"
    assert k.profil("drugi").whatsapp == NR_B


# ===================================================== kolejka per konto
class Konto:
    """Kanal per konto (jak bramka): zapisuje (klucz, numer)."""

    name = "bramka"
    per_konto = True

    def __init__(self, obsluguje=True, down=()):
        self.obsluguje = obsluguje
        self.down = set(down)
        self.calls: list[tuple[str, str | None]] = []

    async def obsluguje_odbiorcow(self):
        return self.obsluguje

    async def send(self, note, odbiorca=None):
        nr = (odbiorca or {}).get("whatsapp")
        self.calls.append((note.dedup_key, nr))
        return nr not in self.down

    async def aclose(self):
        return None


class Dom:
    name = "ntfy"

    def __init__(self):
        self.calls: list[str] = []

    async def send(self, note):
        self.calls.append(note.dedup_key)
        return True

    async def aclose(self):
        return None


class Clock:
    def __init__(self, now=T0):
        self.now = now

    def __call__(self):
        return self.now


@pytest.fixture
def kolejka(tmp_path):
    path = tmp_path / "panel-auth.db"
    auth = PanelAuth(path)
    auth.add_user("rodzic", HASLO)
    auth.add_user("domownik", HASLO, rola=u.ROLE_VIEWER)
    k = o.ProfilePowiadomien(path)
    k.ustaw_kanaly("rodzic", whatsapp=NR_A, email=None)
    k.ustaw_kanaly("domownik", whatsapp=NR_B, email=None)
    k.ustaw_preferencje("domownik", kategorie=[o.SESJE])
    k.ustaw_tryb(o.TRYB_KONTA)
    store = Store(tmp_path / "k.db")
    bramka, dom, clock = Konto(), Dom(), Clock()
    outbox = Outbox(Dispatcher([bramka, dom], store=store), store, now=clock,
                    konta=k, dziecko=DZIECKO, tz=TZ)
    return outbox, bramka, dom, k, store, clock


def _historia(store):
    return [(r["dedup_key"], json.loads(r["channels"]), r["delivered"])
            for r in store.conn.execute("SELECT * FROM notifications ORDER BY id")]


async def test_tryb_kont_kazdy_dostaje_raz_wg_preferencji(kolejka):
    outbox, bramka, dom, _, store, _ = kolejka
    await outbox.send_all([note(key="s"), note(NotifyKind.MDM, key="m")])
    assert await outbox.flush() == 5  # s: 2 konta + dom; m: wlasciciel + dom
    assert sorted(bramka.calls) == [("m", NR_A), ("s", NR_A), ("s", NR_B)]
    assert dom.calls == ["s", "m"]
    # Jeden wiersz historii na zdarzenie, z wynikiem kazdego odbiorcy.
    hist = dict((k, ch) for k, ch, _ in _historia(store))
    assert hist["s"] == {"bramka:rodzic": True, "bramka:domownik": True, "ntfy": True}
    assert hist["m"] == {"bramka:rodzic": True, "ntfy": True}
    assert store.outbox_pending() == []


async def test_to_samo_zdarzenie_wstawione_dwa_razy_idzie_raz_na_konto(kolejka):
    outbox, bramka, _, _, _, _ = kolejka
    await outbox.send_all([note(key="s")])
    await outbox.send_all([note(key="s")])
    await outbox.flush()
    assert sorted(bramka.calls) == [("s", NR_A), ("s", NR_B)]


async def test_zly_numer_jednego_nie_blokuje_innych(kolejka):
    outbox, bramka, _, _, store, clock = kolejka
    bramka.down = {NR_B}
    await outbox.send_all([note(key="s1"), note(key="s2")])
    await outbox.flush()
    assert [c for c in bramka.calls if c[1] == NR_A] == [("s1", NR_A), ("s2", NR_A)]
    # domownik: s1 czeka (backoff), s2 stoi za nim — kolejnosc w kolejce
    assert [c for c in bramka.calls if c[1] == NR_B] == [("s1", NR_B)]
    assert [i.note.dedup_key for i in store.outbox_pending(odbiorca="domownik")] == ["s1", "s2"]
    bramka.down = set()
    clock.now += timedelta(minutes=5)
    await outbox.flush()
    assert [c for c in bramka.calls if c[1] == NR_B] == [("s1", NR_B), ("s1", NR_B),
                                                         ("s2", NR_B)]
    assert store.outbox_pending() == []


async def test_cisza_wstrzymuje_raport_ale_nie_blokuje_alarmu(kolejka):
    outbox, bramka, _, k, store, clock = kolejka
    k.ustaw_preferencje("rodzic", kategorie=None, cisza_od="22:00", cisza_do="07:00")
    clock.now = datetime(2026, 10, 3, 23, 0, tzinfo=TZ).astimezone(UTC)
    await outbox.send_all([note(NotifyKind.DAILY, key="raport", device=None),
                           note(NotifyKind.NIGHT, key="noc", priority=5)])
    await outbox.flush()
    assert ("noc", NR_A) in bramka.calls and ("raport", NR_A) not in bramka.calls
    clock.now = datetime(2026, 10, 4, 7, 1, tzinfo=TZ).astimezone(UTC)
    await outbox.flush()
    assert ("raport", NR_A) in bramka.calls


async def test_bramka_bez_odbiorcy_jawnego_to_tryb_tras(kolejka):
    """Starsza bramka zignorowalaby `odbiorca` - kazde zadanie do wszystkich.
    Wtedy jedno zadanie bez odbiorcy, jak przed zmiana."""
    outbox, bramka, dom, _, _, _ = kolejka
    bramka.obsluguje = False
    await outbox.send_all([note(key="s")])
    await outbox.flush()
    assert bramka.calls == [("s", None)] and dom.calls == ["s"]


async def test_tryb_tras_dopoki_wlasciciel_nie_wlaczy(kolejka):
    outbox, bramka, _, k, _, _ = kolejka
    k.ustaw_tryb(o.TRYB_TRASY)
    await outbox.send_all([note(key="s")])
    await outbox.flush()
    assert bramka.calls == [("s", None)]


async def test_nikt_nie_chce_zdarzenie_jest_w_historii_i_znika(kolejka):
    outbox, bramka, _, k, store, _ = kolejka
    outbox.dispatcher.notifiers = [bramka]  # bez kanalu domowego
    k.ustaw_preferencje("rodzic", kategorie=[o.SESJE])
    await outbox.send_all([note(NotifyKind.WEEKLY, key="w", device=None)])
    await outbox.flush()
    assert bramka.calls == [] and store.outbox_pending() == []
    assert _historia(store) == [("w", {}, 0)]


async def test_konto_usuniete_po_rozdziale_wpis_porzucony(kolejka, tmp_path):
    outbox, bramka, _, k, store, _ = kolejka
    bramka.down = {NR_B}
    await outbox.send_all([note(key="s")])
    await outbox.flush()
    PanelAuth(k.path).delete_user("domownik")
    outbox._now.now += timedelta(minutes=5)
    await outbox.flush()
    assert store.outbox_pending() == []


async def test_wycofana_bramka_nie_rozsyla_wpisow_kont_do_wszystkich(kolejka):
    """Raport wstrzymany cisza dwoch kont, a bramke wycofano do wersji bez
    `odbiorca`: ta zignorowalaby pole i kazde z dwoch zadan wyslala do
    wszystkich z trasy. Wpisy kont zwijaja sie do jednego wpisu trybu tras."""
    outbox, bramka, _, k, store, clock = kolejka
    for login in ("rodzic", "domownik"):
        k.ustaw_preferencje(login, kategorie=[o.SESJE, o.RAPORTY],
                            cisza_od="22:00", cisza_do="07:00")
    clock.now = datetime(2026, 10, 3, 23, 0, tzinfo=TZ).astimezone(UTC)
    await outbox.send_all([note(NotifyKind.DAILY, key="raport", device=None)])
    await outbox.flush()
    assert bramka.calls == []
    bramka.obsluguje = False
    clock.now = datetime(2026, 10, 4, 7, 1, tzinfo=TZ).astimezone(UTC)
    await outbox.flush()
    assert bramka.calls == [("raport", None)]
    assert store.outbox_pending() == []


async def test_wlasciciel_wrocil_do_tras_wpisy_kont_wychodza_do_kont(kolejka):
    """Przelaczenie na trasy przy bramce z `odbiorca`: wstrzymane wpisy kont
    ida dalej do swoich kont (bramka je rozumie), bez rozsylki do wszystkich."""
    outbox, bramka, _, k, _, clock = kolejka
    k.ustaw_preferencje("rodzic", kategorie=None, cisza_od="22:00", cisza_do="07:00")
    clock.now = datetime(2026, 10, 3, 23, 0, tzinfo=TZ).astimezone(UTC)
    await outbox.send_all([note(NotifyKind.DAILY, key="raport", device=None)])
    await outbox.flush()
    k.ustaw_tryb(o.TRYB_TRASY)
    clock.now = datetime(2026, 10, 4, 7, 1, tzinfo=TZ).astimezone(UTC)
    await outbox.flush()
    assert bramka.calls == [("raport", NR_A)]


@pytest.mark.parametrize("zmiana", ["uprawnienie", "wylaczone", "kategoria"])
async def test_wstrzymany_wpis_nie_wychodzi_po_odebraniu_prawa(kolejka, zmiana):
    """"Odebranie uprawnienia dziala od razu" dotyczy tez wpisow, ktore juz
    czekaja w kolejce konta (raport wstrzymany cisza do rana)."""
    outbox, bramka, _, k, store, clock = kolejka
    k.ustaw_preferencje("domownik", kategorie=[o.SESJE, o.RAPORTY],
                        cisza_od="22:00", cisza_do="07:00")
    clock.now = datetime(2026, 10, 3, 23, 0, tzinfo=TZ).astimezone(UTC)
    await outbox.send_all([note(NotifyKind.DAILY, key="raport", device=None)])
    await outbox.flush()
    if zmiana == "uprawnienie":
        PanelAuth(k.path).set_permissions("domownik", {u.PODGLAD: False})
    elif zmiana == "wylaczone":
        k.ustaw_preferencje("domownik", kategorie=[o.SESJE, o.RAPORTY], aktywne=False)
    else:
        k.ustaw_preferencje("domownik", kategorie=[o.SESJE])
    clock.now = datetime(2026, 10, 4, 7, 1, tzinfo=TZ).astimezone(UTC)
    await outbox.flush()
    assert ("raport", NR_B) not in bramka.calls
    assert store.outbox_pending() == []


# ====================================================== bramka: odbiorca
async def test_bramka_niesie_odbiorce_i_sprawdza_funkcje():
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.url.path == "/v1/stan":
            return httpx.Response(200, json={"kanal": "whatsapp", "funkcje": ["odbiorca"]})
        return httpx.Response(200, json={"ok": True})

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    now = [0.0]
    n = BramkaNotifier(BramkaConfig(url="http://bramka.test"), key="k1", client=client,
                       clock=lambda: now[0])
    assert await n.obsluguje_odbiorcow() is True
    assert await n.obsluguje_odbiorcow() is True
    assert len(seen) == 1  # cache
    adres = {"kanal": "auto", "whatsapp": NR_A}
    assert await n.send(note(), odbiorca=adres)
    body = json.loads(seen[-1].content)
    assert body["odbiorca"] == adres and "kategoria" not in body
    assert await n.send(note())
    assert "odbiorca" not in json.loads(seen[-1].content)


async def test_bramka_stara_albo_niedostepna_to_brak_funkcji():
    responses = [httpx.Response(200, json={"kanal": "email"}), httpx.Response(503)]

    def handler(request):
        return responses.pop(0)

    now = [0.0]
    n = BramkaNotifier(BramkaConfig(url="http://bramka.test"), key="k1",
                       client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                       clock=lambda: now[0])
    assert await n.obsluguje_odbiorcow() is False
    now[0] += 3600
    assert await n.obsluguje_odbiorcow() is False


# ================================================================== CLI
CLI_CONFIG = """
source:
  kind: nextdns
  nextdns:
    profile_id: test
devices:
  - display_name: iPad
    child: Dziecko
    source_ids: [ipad]
store:
  path: k.db
notifiers:
  bramka:
    enabled: true
    url: http://bramka.test
"""


@pytest.fixture
def cli(tmp_path, monkeypatch):
    from kidwatch.__main__ import main
    from kidwatch.bramka_admin import BramkaAdmin
    from kidwatch.config import Config

    cfg = tmp_path / "config.yaml"
    cfg.write_text(CLI_CONFIG, encoding="utf-8")
    monkeypatch.setenv("BRAMKA_KLUCZ_ADMIN", "klucz-admina")
    monkeypatch.setattr(BramkaAdmin, "status", lambda self: {"odbiorcy": BRAMKA[:2]})
    path = Config.load(str(cfg)).panel_auth_path
    auth = PanelAuth(path)
    auth.add_user("rodzic", HASLO)
    auth.add_user("drugi", HASLO, rola=u.ROLE_VIEWER)
    return (lambda *a: main(["--config", str(cfg), *a])), o.ProfilePowiadomien(path)


def test_cli_migracja_bez_zapisu_tylko_plan(cli, capsys):
    run, k = cli
    assert run("konta-migruj") == 0
    out = capsys.readouterr().out
    assert "BRAK KONTA" in out and "ROZ" in out and NR_B not in out and "...202" in out
    assert k.profil("rodzic").whatsapp is None


def test_cli_migracja_nie_wlacza_trybu_z_roznicami(cli, capsys):
    run, k = cli
    assert run("konta-migruj", "--zapisz", "--wlacz") == 1
    assert k.profil("rodzic").whatsapp == NR_A and k.tryb() == o.TRYB_TRASY


def test_cli_migracja_pelna_wlacza_tryb_kont(cli, capsys):
    run, k = cli
    assert run("konta-migruj", "--przypisz", "2=drugi", "--zapisz", "--wlacz") == 0
    assert "ROZ" not in capsys.readouterr().out
    assert k.tryb() == o.TRYB_KONTA
    assert k.profil("drugi").efektywne_kategorie() == {o.SESJE}
    assert run("konta-tryb", "trasy") == 0 and k.tryb() == o.TRYB_TRASY
    assert run("konta-tryb") == 0
    assert "WhatsApp ...201" in capsys.readouterr().out
