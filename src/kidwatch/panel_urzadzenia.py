"""Panel: dzieci i urzadzenia domu (uprawnienie `dom.urzadzenia`).

Trasy /api/domy/<id>/urzadzenia (GET) i .../urzadzenia/zapisz (POST) w
panel.py. Wlasciciel domu i zarzadca sami dodaja, zmieniaja i usuwaja dzieci
i urzadzenia SWOJEGO domu — zamiast administratora z `dom-importuj N --plik`
(konfiguracja_domu.importuj_strukture). Administrator instalacji ma to samo
w kazdym domu (wpis `admin.*` w audycie robi panel._wymaga).
Projekt: renacode-infra: docs/projekty/kidwatch/architektura-domy.md §2.3,
§2.4, §3.6, §4.1.

ZASADY
  - Rola domu zmienia tylko: nazwe, dziecko, rodzaj (ipad, iphone,
    phone-android), `source_ids` i `nextdns_profile`. Pola sieciowe i MDM
    (`udid`, `host`, `unifi_mac`, `unifi_ip`, `mdm`, `ustawienia` z
    `known_apps`) ustawia administrator instalacji; zapis roli domu
    PRZEPISUJE je z bazy bez zmian. Wiersze dopasowujemy po `urzadzenia.id`,
    nie po nazwie — zmiana nazwy nie gubi UDID-u.
  - UDID i adresy to dane techniczne: odpowiedz dla roli domu niesie tylko
    flagi („ustawione przez administratora”), wartosci widzi wylacznie
    aktywny administrator instalacji. Audyt — liczby i nazwy pol, bez
    wartosci.
  - Urzadzenia z polami administratora (UDID, adres, MAC, MDM, lista
    aplikacji) rola domu nie usunie: to odpiecie iPada od MDM i odczytu
    wprost, decyzja administratora.
  - Telewizor (`rodzaj = 'tv'`) nalezy do integracji `tv`: ekran go nie
    pokazuje i nie rusza. Ustawienia domu, strefa, integracje, sekrety
    i `dozwolone_sieci` zostaja nietkniete (sprawdzane po zapisie).
  - Walidacja tymi samymi walidatorami co config.yaml (HomeConfig z
    biezacymi integracjami domu i jego sekretami; dom bez zrodla DNS —
    atrapa zrodla tylko do walidacji, jak importuj_strukture). Zapis ->
    odczyt -> porownanie w JEDNEJ transakcji; blad = 400, baza bez zmian.
  - Ostatnie urzadzenie: zmiana, po ktorej dom, ktory wystartowalby, juz by
    nie wystartowal, jest wycofywana — tak jak w integracjach. Dzialajacy
    dom (takze Dom 1) nie zostanie bez urzadzen: nadzorca uznalby to za
    awarie i wrocil do ostatniej dobrej konfiguracji, czyli dalej pilnowal
    usunietych urzadzen. Dom, ktory i tak nie startuje (swiezy, bez NextDNS
    — „czeka na konfiguracje”, #84), mozna uzupelniac i czyscic dowolnie.
  - Dom w trybie `yaml` — 409, jak integracje.
  - `wersja` jest obowiazkowa: zapis calej listy z nieaktualnego ekranu
    nadpisalby cudza zmiane. Inna niz w bazie = 409 „odswiez”.
"""

from __future__ import annotations

import json
import logging
import re
import sqlite3
import time
from typing import Any

from . import domy as dm
from .konfiguracja_domu import (
    _ADB,
    _ZRODLO_DO_WALIDACJI,
    PORT_LOCKDOWN,
    blad_startu_conn,
    home_z_danych,
    porownaj,
)
from .panel_auth import AuthError, Session
from .panel_integracje import WSKAZOWKA_SIECI, PanelIntegracje, bez_sekretow
from .sejf import Sejf, SejfError
from .straznik import OdmowaSieci, Straznik

log = logging.getLogger(__name__)

#: Rodzaje do wyboru na ekranie (nazwy z bazy, §2.4). Bez `tv`.
RODZAJE = (
    ("ipad", "iPad"),
    ("iphone", "iPhone"),
    ("phone-android", "Telefon z Androidem"),
)
_RODZAJE = {r for r, _ in RODZAJE}
#: Nazwa z konfiguracji (`phone`) przyjmowana jako alias.
_ALIASY_RODZAJU = {"phone": "phone-android"}
#: Pola, ktore ustawia tylko administrator instalacji — wartosci, gdy
#: przyszly od administratora; dla roli domu przepisane z bazy.
POLA_ADMINA = ("udid", "host", "unifi_mac", "unifi_ip")
#: Pola edytowalne przez role domu.
POLA_DOMU = ("nazwa", "dziecko", "rodzaj", "source_ids", "nextdns_profile")
MAX_DZIECI = 30
MAX_URZADZEN = 60
MAX_NAZWA = 64
MAX_SOURCE_IDS = 10
MAX_SOURCE_ID = 128
MAX_POLE_ADMINA = 128
NIE_DLA_YAML_URZADZENIA = (
    "Ten dom ma konfigurację z config.yaml (tryb yaml) — dzieci i urządzenia zmienia się tam. "
    "Ten ekran działa tylko dla domów z konfiguracją w bazie (kidwatch dom-importuj)."
)
NIE_WYSTARTUJE = "Po tej zmianie dom nie wystartuje — zmiana nie została zapisana: "
OSTATNIE = ("Dom musi mieć co najmniej jedno urządzenie dziecka. Dodaj nowe urządzenie w tym "
            "samym zapisie albo poproś administratora o zawieszenie domu.")


def _tekst(v: Any, pole: str, limit: int, *, wymagany: bool = True) -> str | None:
    if v is None or (isinstance(v, str) and not v.strip()):
        if wymagany:
            raise AuthError(400, f"Pole „{pole}” jest wymagane")
        return None
    if not isinstance(v, str) or len(v) > limit:
        raise AuthError(400, f"Niepoprawne pole „{pole}”")
    return v.strip()


def _id(v: Any) -> int | None:
    if v is None:
        return None
    if not isinstance(v, int) or isinstance(v, bool) or v <= 0:
        raise AuthError(400, "Niepoprawny identyfikator wiersza")
    return v


class PanelUrzadzenia(PanelIntegracje):
    """Wspolne z integracjami: sejf, audyt, potwierdzenie, przeladowanie."""

    # ------------------------------------------------------------ dostep
    def _dostep(self, session: Session, ctx) -> dm.Dom:  # noqa: ARG002
        """Uprawnienie `dom.urzadzenia` sprawdzil juz panel._wymaga (podglad
        -> 403, obcy dom -> 404). Tu: dom w trybie `baza`."""
        dom = self.rejestr.dom(ctx.dom_id)
        if dom is None:
            raise AuthError(404, "Nie ma takiego domu")
        if dom.zrodlo_konfiguracji != dm.ZRODLO_BAZA:
            raise AuthError(409, NIE_DLA_YAML_URZADZENIA)
        return dom

    # ------------------------------------------------------------- odczyt
    @staticmethod
    def _wiersze(conn, dom_id: int) -> tuple[list[dict], list[dict]]:
        """(dzieci, urzadzenia) z id wierszy; urzadzenia bez telewizora."""
        dzieci = [{"id": r["id"], "nazwa": r["nazwa"]} for r in conn.execute(
            "SELECT id, nazwa FROM dzieci WHERE dom_id = ? ORDER BY kolejnosc, id", (dom_id,))]
        nazwy = {d["id"]: d["nazwa"] for d in dzieci}
        urzadzenia = []
        for r in conn.execute("SELECT * FROM urzadzenia WHERE dom_id = ? AND rodzaj != 'tv' "
                              "ORDER BY id", (dom_id,)):
            urzadzenia.append({
                "id": r["id"], "nazwa": r["nazwa"], "dziecko": nazwy.get(r["dziecko_id"]),
                "rodzaj": r["rodzaj"], "source_ids": dm._json(r["source_ids"], []),
                "nextdns_profile": r["nextdns_profile"], "unifi_mac": r["unifi_mac"],
                "unifi_ip": r["unifi_ip"], "udid": r["udid"], "host": r["host"],
                "mdm": bool(r["mdm"]), "ustawienia": dm._json(r["ustawienia"], {}),
            })
        return dzieci, urzadzenia

    @staticmethod
    def _chronione(u: dict) -> bool:
        return bool(any(u.get(p) for p in POLA_ADMINA) or u.get("mdm") or u.get("ustawienia"))

    @classmethod
    def _wiersz_ekranu(cls, u: dict, admin: bool) -> dict:
        out = {k: u[k] for k in ("id", "nazwa", "dziecko", "rodzaj", "source_ids",
                                 "nextdns_profile")}
        # Flagi zamiast wartosci: rola domu wie, ze cos jest ustawione, ale
        # nie widzi UDID-u ani adresow (dane techniczne administratora).
        out["administrator"] = {
            "udid": bool(u["udid"]), "host": bool(u["host"]),
            "unifi_mac": bool(u["unifi_mac"]), "unifi_ip": bool(u["unifi_ip"]),
            "mdm": bool(u["mdm"]), "known_apps": bool(u["ustawienia"].get("known_apps")),
        }
        out["chronione"] = cls._chronione(u)
        if admin:
            out["techniczne"] = {p: u[p] for p in POLA_ADMINA}
        return out

    def _profil(self, dom_id: int) -> tuple[str | None, str | None]:
        """(wlaczone zrodlo DNS, ID profilu NextDNS domu) — do podpowiedzi
        hosta Prywatnego DNS. ID profilu nie jest sekretem."""
        integ = {i.typ: i for i in self.rejestr.integracje(dom_id)}
        zrodla = [t for t in ("nextdns", "adguard") if t in integ and integ[t].wlaczona]
        zrodlo = zrodla[0] if len(zrodla) == 1 else None
        profil = integ["nextdns"].ustawienia.get("profile_id") if "nextdns" in integ else None
        return zrodlo, profil if zrodlo == "nextdns" else None

    def _ekran(self, dom: dm.Dom, admin: bool, sejf: Sejf) -> dict:
        with self.rejestr._conn() as conn:
            dzieci, urzadzenia = self._wiersze(conn, dom.id)
            start = blad_startu_conn(conn, dom.id, sejf)
        zrodlo, profil = self._profil(dom.id)
        if not admin:
            start = start and self._bez_technicznych(start, urzadzenia)
        return {
            "dom": {"id": dom.id, "nazwa": dom.nazwa, "wersja": dom.wersja},
            "administrator": admin,
            "dzieci": dzieci,
            "urzadzenia": [self._wiersz_ekranu(u, admin) for u in urzadzenia],
            "rodzaje": [{"rodzaj": r, "nazwa": n} for r, n in RODZAJE],
            "zrodlo": zrodlo,
            "profil_nextdns": profil,
            "start": start,
            "przeladowanie": self.przeladowanie(dom),
        }

    @staticmethod
    def _bez_technicznych(tekst: str, urzadzenia: list[dict]) -> str:
        """Komunikat dla roli domu bez UDID-ow i adresow (walidator potrafi
        powtorzyc wartosc, np. zdublowany UDID)."""
        return bez_sekretow(tekst, [str(u[p]) for u in urzadzenia for p in POLA_ADMINA
                                    if u.get(p)])

    def lista(self, session: Session, ctx) -> dict:
        dom = self._dostep(session, ctx)
        sejf = self._sejf_lub_503()
        try:
            return self._ekran(dom, ctx.admin, sejf)
        except SejfError as exc:
            raise AuthError(503, f"Sekretów domu nie da się odszyfrować: {exc}") from exc

    # -------------------------------------------------------------- zapis
    @staticmethod
    def _dzieci(data: dict) -> list[dict]:
        raw = data.get("dzieci")
        if not isinstance(raw, list) or len(raw) > MAX_DZIECI:
            raise AuthError(400, "Niepoprawne pole „dzieci”")
        out, nazwy = [], set()
        for d in raw:
            if not isinstance(d, dict):
                raise AuthError(400, "Niepoprawne pole „dzieci”")
            nazwa = _tekst(d.get("nazwa"), "imię dziecka", MAX_NAZWA)
            if nazwa in nazwy:
                raise AuthError(400, f"Dziecko „{nazwa}” jest na liście dwa razy")
            nazwy.add(nazwa)
            out.append({"id": _id(d.get("id")), "nazwa": nazwa})
        return out

    @staticmethod
    def _urzadzenia(data: dict, admin: bool) -> list[dict]:
        raw = data.get("urzadzenia")
        if not isinstance(raw, list) or len(raw) > MAX_URZADZEN:
            raise AuthError(400, "Niepoprawne pole „urzadzenia”")
        out, nazwy = [], set()
        for d in raw:
            if not isinstance(d, dict):
                raise AuthError(400, "Niepoprawne pole „urzadzenia”")
            nazwa = _tekst(d.get("nazwa"), "nazwa urządzenia", MAX_NAZWA)
            if nazwa in nazwy:
                raise AuthError(400, f"Urządzenie „{nazwa}” jest na liście dwa razy")
            nazwy.add(nazwa)
            rodzaj = _ALIASY_RODZAJU.get(d.get("rodzaj"), d.get("rodzaj"))
            if rodzaj not in _RODZAJE:
                raise AuthError(400, f"{nazwa}: rodzaj do wyboru: "
                                     f"{', '.join(r for r, _ in RODZAJE)}")
            ids = d.get("source_ids")
            if not isinstance(ids, list) or not 1 <= len(ids) <= MAX_SOURCE_IDS:
                raise AuthError(400, f"{nazwa}: podaj nazwę urządzenia w NextDNS")
            source_ids = [_tekst(s, "nazwa w NextDNS", MAX_SOURCE_ID, wymagany=False)
                          for s in ids]
            source_ids = [s for s in source_ids if s]
            if not source_ids:
                raise AuthError(400, f"{nazwa}: podaj nazwę urządzenia w NextDNS")
            u = {
                "id": _id(d.get("id")), "nazwa": nazwa,
                "dziecko": _tekst(d.get("dziecko"), f"{nazwa}: dziecko", MAX_NAZWA),
                "rodzaj": rodzaj, "source_ids": source_ids,
                "nextdns_profile": _tekst(d.get("nextdns_profile"), "profil NextDNS", 64,
                                          wymagany=False),
            }
            techniczne = [p for p in POLA_ADMINA if p in d]
            if techniczne and not admin:
                raise AuthError(403, "UDID, adres i MAC urządzenia ustawia administrator "
                                     "instalacji.")
            for p in techniczne:
                u[p] = _tekst(d[p], p, MAX_POLE_ADMINA, wymagany=False)
            out.append(u)
        return out

    def zapisz(self, session: Session, data: dict, ctx) -> dict:
        """{dzieci: [{id?, nazwa}], urzadzenia: [{id?, nazwa, dziecko, rodzaj,
        source_ids, nextdns_profile?, (administrator: udid?, host?, unifi_mac?,
        unifi_ip?)}], wersja, confirm}. Pelna lista: wiersza brak = usuniety."""
        dom = self._dostep(session, ctx)
        dzieci = self._dzieci(data)
        urzadzenia = self._urzadzenia(data, ctx.admin)
        wersja = self._wersja(data)
        if wersja is None:
            raise AuthError(400, "Brak pola „wersja” — odśwież ekran.")
        sejf = self._sejf_lub_503()
        self._potwierdz(session, data)
        try:
            opis = self._zapisz_w_transakcji(session, ctx, dom, dzieci, urzadzenia,
                                             wersja, sejf)
        except dm.ZmianaWersji as exc:
            raise AuthError(409, "Dom zmienił się od wczytania ekranu (ktoś inny zapisał "
                                 "zmianę) — odśwież i wpisz zmianę ponownie.") from exc
        except AuthError as exc:
            if exc.status == 400:
                log.warning("panel: %s — dzieci i urzadzenia domu %d odrzucone: %s",
                            session.login, ctx.dom_id, exc.message)
                self._audyt(ctx.dom_id, session.login, "dom.urzadzenia.odmowa",
                            "dzieci i urządzenia: zapis odrzucony (walidacja)")
            raise
        except SejfError as exc:
            raise AuthError(503, f"Sekretów domu nie da się odszyfrować: {exc}") from exc
        log.warning("panel: %s zapisal dzieci i urzadzenia domu %d (%s)", session.login,
                    ctx.dom_id, opis)
        try:
            nowy = self.rejestr.dom(ctx.dom_id)
            assert nowy is not None
            return {"ok": True, **self._ekran(nowy, ctx.admin, sejf)}
        except Exception as exc:
            log.error("panel: dzieci i urzadzenia domu %d zapisane, ale odczyt nieudany: %s",
                      ctx.dom_id, type(exc).__name__)
            return {"ok": True, "ostrzezenie": "Zapisano, ale nie udało się odczytać stanu "
                                               "domu po zapisie — odśwież ekran."}

    # ------------------------------------------------------- transakcja
    def _plan(self, ctx, dzieci_stare: list[dict], urz_stare: list[dict],
              dzieci: list[dict], urzadzenia: list[dict]) -> tuple[list[dict], list[dict]]:
        """Wiersze po zapisie (urzadzenia z `id` albo None dla nowych) i lista
        usunietych. Pola administratora: z zadania administratora albo z bazy."""
        id_dzieci = {d["id"] for d in dzieci_stare}
        for d in dzieci:
            if d["id"] is not None and d["id"] not in id_dzieci:
                raise AuthError(400, "Nieznane dziecko na liście — odśwież ekran.")
        if len({d["id"] for d in dzieci if d["id"] is not None}) != \
                len([d for d in dzieci if d["id"] is not None]):
            raise AuthError(400, "Dziecko na liście dwa razy — odśwież ekran.")
        nazwy_dzieci = {d["nazwa"] for d in dzieci}
        stare = {u["id"]: u for u in urz_stare}
        uzyte: set[int] = set()
        plan = []
        for u in urzadzenia:
            if u["dziecko"] not in nazwy_dzieci:
                raise AuthError(400, f"{u['nazwa']}: dziecko „{u['dziecko']}” nie jest na "
                                     "liście dzieci")
            if u["id"] is None:
                wiersz = {p: None for p in POLA_ADMINA} | {"mdm": False, "ustawienia": {}}
            else:
                if u["id"] not in stare or u["id"] in uzyte:
                    raise AuthError(400, "Nieznane urządzenie na liście — odśwież ekran.")
                uzyte.add(u["id"])
                wiersz = dict(stare[u["id"]])
            wiersz.update({k: v for k, v in u.items() if k == "id" or k in POLA_DOMU})
            if ctx.admin:
                wiersz.update({p: u[p] for p in POLA_ADMINA if p in u})
            plan.append(wiersz)
        # Kolejnosc jak w bazie (po id, nowe na koncu w kolejnosci z ekranu):
        # HomeConfig z planu i z odczytu maja wtedy te same `devices`.
        plan.sort(key=lambda u: (u["id"] is None, u["id"] or 0))
        usuniete = [u for i, u in stare.items() if i not in uzyte]
        if not ctx.admin:
            chronione = [u["nazwa"] for u in usuniete if self._chronione(u)]
            if chronione:
                raise AuthError(400, f"Urządzenie {', '.join(chronione)} ma ustawienia "
                                     "administratora (MDM, odczyt wprost albo UniFi) — usunąć "
                                     "je może administrator instalacji.")
        puste = sorted(nazwy_dzieci - {u["dziecko"] for u in plan})
        if puste:
            raise AuthError(400, f"Dziecko {', '.join(puste)} nie ma żadnego urządzenia — "
                                 "dodaj urządzenie albo usuń dziecko z listy.")
        return plan, usuniete

    def _waliduj(self, dane: dm.DaneDomu, plan: list[dict], sekrety) -> Any:
        """HomeConfig z planowanych urzadzen, biezacych integracji domu i jego
        sekretow — te same walidatory co config.yaml. Dom bez jednego
        wlaczonego zrodla DNS: atrapa zrodla tylko do walidacji. None, gdy
        urzadzen nie ma (to rozstrzyga sprawdzenie startu)."""
        if not plan:
            return None
        integ = dane.integracje
        zrodla = [i for i in integ if i.typ in ("nextdns", "adguard") and i.wlaczona]
        do_walidacji = integ if len(zrodla) == 1 else [
            *(i for i in integ if i.typ not in ("nextdns", "adguard")), _ZRODLO_DO_WALIDACJI]
        try:
            return home_z_danych(dm.DaneDomu(dane.dom, [], plan, do_walidacji), sekrety,
                                 katalog_plikow=_ADB)
        except ValueError as exc:
            tekst = str(exc).split("konfiguracja w bazie niepoprawna: ", 1)[-1]
            # devices.3.source_ids -> nazwa urzadzenia zamiast numeru.
            tekst = re.sub(r"devices\.(\d+)",
                           lambda m: (f"„{plan[int(m[1])]['nazwa']}”"
                                      if int(m[1]) < len(plan) else m[0]), tekst)
            raise AuthError(400, f"Niepoprawne dane: {tekst}") from exc

    def _zapisz_w_transakcji(self, session: Session, ctx, dom: dm.Dom, dzieci: list[dict],
                             urzadzenia: list[dict], wersja: int, sejf: Sejf) -> str:
        teraz = time.time()
        urz_stare: list[dict] = []
        with self.rejestr._conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                if dm._wiersz_domu(conn, dom.id)["wersja"] != wersja:
                    raise dm.ZmianaWersji("dom zmienil sie od wczytania")
                przed_dom = self._wiersz_domu_bez_wersji(conn, dom.id)
                dane = dm.dane_domu_conn(conn, dom.id)
                integracje = [tuple(r) for r in conn.execute(
                    "SELECT * FROM integracje WHERE dom_id = ? ORDER BY typ", (dom.id,))]
                tv = [tuple(r) for r in conn.execute(
                    "SELECT * FROM urzadzenia WHERE dom_id = ? AND rodzaj = 'tv' ORDER BY id",
                    (dom.id,))]
                dzieci_stare, urz_stare = self._wiersze(conn, dom.id)
                przed = blad_startu_conn(conn, dom.id, sejf)
                plan, usuniete = self._plan(ctx, dzieci_stare, urz_stare, dzieci, urzadzenia)
                sekrety = dm.sekrety_domu_conn(conn, dom.id, sejf)
                home = self._waliduj(dane, plan, sekrety)
                if home is not None:
                    self._normalizuj(plan, home, ctx.admin)
                self._sprawdz_adresy(dom, plan, {u["id"]: u for u in urz_stare}, ctx.admin)
                opis = self._zapisz_wiersze(conn, dom.id, dzieci_stare, urz_stare, dzieci,
                                            plan, usuniete)
                # Odczyt i porownanie: wiersze, model, reszta domu nietknieta.
                _, po_urz = self._wiersze(conn, dom.id)
                po_dzieci = [d["nazwa"] for d in self._wiersze(conn, dom.id)[0]]
                roznice = self._roznice(plan, po_urz, [d["nazwa"] for d in dzieci], po_dzieci)
                if home is not None:
                    dane_po = dm.dane_domu_conn(conn, dom.id)
                    z_bazy = self._waliduj(dane_po, [u for u in dane_po.urzadzenia
                                                     if u["rodzaj"] != "tv"], sekrety)
                    roznice += porownaj(home, z_bazy)
                if [tuple(r) for r in conn.execute(
                        "SELECT * FROM integracje WHERE dom_id = ? ORDER BY typ",
                        (dom.id,))] != integracje:
                    roznice.append("integracje zmienione")
                if [tuple(r) for r in conn.execute(
                        "SELECT * FROM urzadzenia WHERE dom_id = ? AND rodzaj = 'tv' "
                        "ORDER BY id", (dom.id,))] != tv:
                    roznice.append("telewizor zmieniony")
                if self._wiersz_domu_bez_wersji(conn, dom.id) != przed_dom:
                    roznice.append("ustawienia domu zmienione")
                if roznice:
                    log.error("panel: zapis dzieci i urzadzen domu %d nie zgadza sie z "
                              "odczytem: %s", dom.id, "; ".join(roznice))
                    raise AuthError(400, "Zapis nie zgadza się z odczytem — nic nie zapisano.")
                po = blad_startu_conn(conn, dom.id, sejf)
                if po is not None and przed is None:
                    if not po_urz:
                        raise AuthError(400, OSTATNIE)
                    raise AuthError(400, NIE_WYSTARTUJE + self._dla_roli(po, urz_stare, ctx))
                dm._audyt(conn, teraz, dom.id, session.login, "dom.urzadzenia.zapis", opis)
                conn.execute("COMMIT")
            except AuthError as exc:
                conn.execute("ROLLBACK")
                exc.message = self._dla_roli(exc.message, urz_stare, ctx)
                raise
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        return opis

    @staticmethod
    def _wiersz_domu_bez_wersji(conn, dom_id: int) -> dict:
        """Wiersz `domy` (ustawienia, strefa, sieci, klucz) bez `wersja`."""
        wiersz = dict(dm._wiersz_domu(conn, dom_id))
        wiersz.pop("wersja")
        return wiersz

    def _dla_roli(self, tekst: str, urz: list[dict], ctx) -> str:
        return tekst if ctx.admin else self._bez_technicznych(tekst, urz)

    @staticmethod
    def _normalizuj(plan: list[dict], home, admin: bool) -> None:
        """Pola edytowane — w postaci po walidatorach (source_ids malymi
        literami, MAC z dwukropkami), zeby zapis == odczyt == model. Pol
        administratora u roli domu nie dotykamy: przechodza z bazy bajt
        w bajt."""
        for u, dev in zip(plan, home.devices, strict=True):
            u["source_ids"] = list(dev.source_ids)
            u["nextdns_profile"] = dev.nextdns_profile
            if admin:
                for p in POLA_ADMINA:
                    u[p] = getattr(dev, p)

    def _sprawdz_adresy(self, dom: dm.Dom, plan: list[dict], stare: dict[int, dict],
                        admin: bool) -> None:
        """Adres iPada (`host`, odczyt wprost) wpisany przez administratora
        przez straznika sieci domu (§3.6), jak adresy integracji."""
        if not admin:
            return
        straznik = Straznik(dom.id, dom.dozwolone_sieci, dom.dozwolone_hosty,
                            resolver=self.resolver)
        for u in plan:
            stary = stare.get(u["id"]) if u["id"] is not None else None
            if u["host"] and (stary is None or stary["host"] != u["host"]):
                try:
                    straznik.sprawdz_host(u["host"], PORT_LOCKDOWN, pole=f"{u['nazwa']}.host")
                except (OdmowaSieci, OSError) as exc:
                    raise AuthError(400, f"{exc} — {WSKAZOWKA_SIECI}") from exc

    @staticmethod
    def _zapisz_wiersze(conn, dom_id: int, dzieci_stare: list[dict], urz_stare: list[dict],
                        dzieci: list[dict], plan: list[dict], usuniete: list[dict]) -> str:
        """UPDATE po id, INSERT nowych, DELETE usunietych. Nazwy sa UNIQUE
        w domu, wiec przy zamianie nazw najpierw nazwy tymczasowe."""
        for u in usuniete:
            conn.execute("DELETE FROM urzadzenia WHERE id = ? AND dom_id = ?", (u["id"], dom_id))
        zostaja = [d for d in dzieci if d["id"] is not None]
        for d in zostaja:
            conn.execute("UPDATE dzieci SET nazwa = ? WHERE id = ? AND dom_id = ?",
                         (f"\x00{d['id']}", d["id"], dom_id))
        id_dziecka = {}
        for i, d in enumerate(dzieci):
            if d["id"] is not None:
                conn.execute("UPDATE dzieci SET nazwa = ?, kolejnosc = ? WHERE id = ? "
                             "AND dom_id = ?", (d["nazwa"], i, d["id"], dom_id))
                id_dziecka[d["nazwa"]] = d["id"]
            else:
                cur = conn.execute("INSERT INTO dzieci (dom_id, nazwa, kolejnosc) "
                                   "VALUES (?, ?, ?)", (dom_id, d["nazwa"], i))
                id_dziecka[d["nazwa"]] = cur.lastrowid
        for u in plan:
            if u["id"] is not None:
                conn.execute("UPDATE urzadzenia SET nazwa = ? WHERE id = ? AND dom_id = ?",
                             (f"\x00{u['id']}", u["id"], dom_id))
        try:
            for u in plan:
                wartosci = (id_dziecka[u["dziecko"]], u["rodzaj"], u["nazwa"],
                            json.dumps(u["source_ids"]), u["nextdns_profile"],
                            u["unifi_mac"], u["unifi_ip"], u["udid"], u["host"],
                            int(bool(u["mdm"])),
                            json.dumps(u["ustawienia"], ensure_ascii=False, sort_keys=True))
                if u["id"] is not None:
                    conn.execute(
                        "UPDATE urzadzenia SET dziecko_id = ?, rodzaj = ?, nazwa = ?, "
                        "source_ids = ?, nextdns_profile = ?, unifi_mac = ?, unifi_ip = ?, "
                        "udid = ?, host = ?, mdm = ?, ustawienia = ? WHERE id = ? AND dom_id = ?",
                        (*wartosci, u["id"], dom_id))
                else:
                    cur = conn.execute(
                        "INSERT INTO urzadzenia (dziecko_id, rodzaj, nazwa, source_ids, "
                        "nextdns_profile, unifi_mac, unifi_ip, udid, host, mdm, ustawienia, "
                        "dom_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (*wartosci, dom_id))
                    u["id"] = cur.lastrowid
        except sqlite3.IntegrityError as exc:
            # Nazwa zajeta przez telewizor albo UDID przypisany w innym domu.
            raise AuthError(400, "Nazwa urządzenia jest już zajęta (np. przez telewizor) albo "
                                 "UDID należy do urządzenia w innym domu.") from exc
        nowe_dzieci = {d["id"] for d in dzieci if d["id"] is not None}
        usuniete_dzieci = [d for d in dzieci_stare if d["id"] not in nowe_dzieci]
        for d in usuniete_dzieci:
            conn.execute("DELETE FROM dzieci WHERE id = ? AND dom_id = ?", (d["id"], dom_id))
        dm._podbij_wersje(conn, dom_id)
        # Audyt: liczby i NAZWY pol, bez wartosci (UDID, adresy).
        stare = {u["id"]: u for u in urz_stare}
        dodane = [u for u in plan if u["id"] not in stare]
        pola: set[str] = set()
        zmienione = 0
        for u in plan:
            if u["id"] in stare:
                rozne = {p for p in (*POLA_DOMU, *POLA_ADMINA) if stare[u["id"]][p] != u[p]}
                pola |= rozne
                zmienione += bool(rozne)
        stare_dzieci = {d["id"]: d["nazwa"] for d in dzieci_stare}
        dzieci_zmienione = sum(1 for d in dzieci if d["id"] is not None
                               and stare_dzieci[d["id"]] != d["nazwa"])
        return (f"urzadzenia: dodane {len(dodane)}, zmienione {zmienione}, usuniete "
                f"{len(usuniete)}; dzieci: dodane {sum(d['id'] is None for d in dzieci)}, "
                f"zmienione {dzieci_zmienione}, usuniete {len(usuniete_dzieci)}; pola: "
                f"{', '.join(sorted(pola)) or '-'}")

    @staticmethod
    def _roznice(plan: list[dict], po: list[dict], dzieci: list[str],
                 po_dzieci: list[str]) -> list[str]:
        out = []
        if dzieci != po_dzieci:
            out.append("dzieci: rozne")
        oczekiwane = {u["id"]: u for u in plan}
        if set(oczekiwane) != {u["id"] for u in po}:
            out.append("urzadzenia: inny zestaw wierszy")
        for u in po:
            o = oczekiwane.get(u["id"])
            if o is None:
                continue
            rozne = [k for k in u if k != "id" and o.get(k) != u[k]]
            if rozne:
                out.append(f"urzadzenie {u['id']}: {', '.join(rozne)}")
        return out
