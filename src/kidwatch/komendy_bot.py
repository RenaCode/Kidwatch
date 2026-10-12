"""Bot komend z WhatsAppa: skrzynka bramki -> konto -> dom -> potwierdzenie
kodem -> wykonanie -> odpowiedz, kopia do drugiego opiekuna i dziennik.

DROGA WIADOMOSCI (sekcja 10 przekazania, decyzje 2026-10-11):

  rodzic --WhatsApp--> bramka (W1: webhook WAHA, HMAC, deduplikacja)
        --GET /v1/whatsapp/skrzynka (klucz Kidwatcha)--> ten modul
        --POST /v1/whatsapp/skrzynka/potwierdz--> (po przetworzeniu, takze
          odrzucone; ponowna dostawa jest odsiewana po id wiadomosci)

  1. numer -> konto (kanal WhatsApp osoby w `user_powiadomienia`). Nieznany
     numer: CISZA — zadnej odpowiedzi (nie zdradzamy, ze bot przyjmuje
     komendy, i nie ryzykujemy blokady numeru za spam), wpis w dzienniku;
  2. limit wiadomosci na numer, blokada po zlych kodach, wylacznik
     administratora; domy, w ktorych konto ma `whatsapp.komendy`;
  3. rozpoznanie: dokladna komenda (komendy.parsuj) albo LLM
     (komendy_llm.py) — w obu przypadkach wynik z ZAMKNIETEJ listy akcji.
     Odpowiedz-cytat na powiadomienie Kidwatcha wyznacza dom i dziecko;
  4. uprawnienie akcji w domu (to samo `uprawnienia.efektywne` co panel),
     dostepnosc (czas gry, MDM), dzienny limit luzowania;
  5. "Zrozumialem: ...? Odpowiedz TAK 1234" — kod jednorazowy, 2 min,
     przypisany do numeru i tej jednej akcji. Odczyt (`stan`, `pomoc`)
     odpowiada od razu: niczego nie zmienia;
  6. po kodzie — te same sprawdzenia JESZCZE RAZ (uprawnienie moglo zniknac
     w ciagu 2 min), wykonanie przez istniejace kolejki (game_requests, API
     serwera MDM), odpowiedz, kopia do pozostalych opiekunow domu.

Bot dziala w procesie `run` obok srodowisk domow i siega tylko do domow,
ktore w tym procesie chodza (dzis Dom 1; kolejne — etap E3b).
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import Any

import httpx

from . import komendy as k
from . import komendy_baza as kb
from . import uprawnienia as upr
from .bramka_admin import mask, normalize_number
from .config import BramkaConfig, DeviceConfig, HomeConfig, WhatsappKomendyConfig
from .komendy_llm import AWARIA, OK, Rozpoznawacz
from .notifiers.base import with_retry
from .notifiers.bramka import BramkaNotifier

log = logging.getLogger(__name__)

#: Tekst na ekranie zablokowanego iPada (DeviceLock `Message`).
KOMUNIKAT_BLOKADY = "Blokada od rodzica (Kidwatch)"
#: Rodzaje urzadzen, ktore MDM umie zablokowac.
IOS = ("ipad", "iphone")
#: Jak dlugo bot czeka na wynik zadania czasu gry (petla gry co ~3 s).
CZEKAJ_NA_GRE = 20.0
#: Alarm o padnietym LLM: od razu, potem co 1 h, 2 h, 4 h... najwyzej co dobe.
ALARM_PIERWSZY_ODSTEP = 3600.0
ALARM_MAX_ODSTEP = 24 * 3600.0


# ================================================================= dom
@dataclass
class DomKomend:
    """To, czego bot potrzebuje od JEDNEGO domu: konfiguracja (dzieci,
    urzadzenia), odczyt stanu (PanelQueries na bazie domu, tylko do odczytu),
    kolejka czasu gry i API serwera MDM. None = funkcja w domu wylaczona."""

    dom_id: int
    nazwa: str
    home: HomeConfig
    queries: Any = None
    gry: Any = None
    mdm: Any = None

    @property
    def dzieci(self) -> list[str]:
        return list(dict.fromkeys(d.child for d in self.home.devices))

    @property
    def urzadzenia(self) -> dict[str, str | None]:
        out: dict[str, str | None] = {d.display_name: d.child for d in self.home.devices}
        if self.home.tv.enabled:
            out[self.home.tv.name] = None
        return out

    def ios(self, dziecko: str | None, urzadzenie: str | None) -> list[DeviceConfig]:
        return [d for d in self.home.devices if d.kind in IOS
                and (urzadzenie is None or d.display_name == urzadzenie)
                and (dziecko is None or d.child == dziecko)]

    def stan_gry(self, dziecko: str) -> dict:
        """Stan czasu gry dziecka z bazy domu (meta `game:<profil>`)."""
        if self.queries is None or not self.home.game_time.enabled:
            return {}
        conn = self.queries.connect()
        try:
            return self.queries._game(conn, dziecko) or {}
        finally:
            conn.close()


# ======================================================== kanal do bramki
class KanalBota:
    """Skrzynka i odpowiedzi przez bramke, kluczem wysylkowym Kidwatcha.
    Odpowiedz idzie TYLKO do jawnego odbiorcy (tryb `odbiorca` bramki);
    bramka bez niego wyslalaby ja trasami do wszystkich — wtedy bot nie
    przetwarza skrzynki wcale (`gotowy`)."""

    def __init__(self, cfg: BramkaConfig, key: str,
                 client: httpx.AsyncClient | None = None, sleep=None) -> None:
        self.cfg = cfg
        self._key = key
        self._owns = client is None
        self._client = client or httpx.AsyncClient(timeout=cfg.timeout_seconds)
        self._wysylka = BramkaNotifier(cfg, key, client=self._client, sleep=sleep)
        self._sleep_kwargs = {"sleep": sleep} if sleep is not None else {}
        self._brak_skrzynki = False

    def _url(self, sciezka: str) -> str:
        return self.cfg.url.rstrip("/") + sciezka

    async def gotowy(self) -> bool:
        return await self._wysylka.obsluguje_odbiorcow()

    async def pobierz(self) -> list[dict]:
        r = await self._client.get(self._url("/v1/whatsapp/skrzynka"),
                                   headers={"X-Api-Key": self._key})
        if r.status_code == 404:
            # Bramka bez W1: nic do zrobienia, raz w logu.
            if not self._brak_skrzynki:
                log.info("komendy: bramka nie ma skrzynki WhatsApp (404) - czekam")
                self._brak_skrzynki = True
            return []
        r.raise_for_status()
        self._brak_skrzynki = False
        data = r.json()
        lista = data.get("wiadomosci") if isinstance(data, dict) else None
        return [w for w in lista or [] if isinstance(w, dict)][:50]

    async def potwierdz(self, ids: Sequence[str]) -> None:
        if not ids:
            return
        r = await self._client.post(self._url("/v1/whatsapp/skrzynka/potwierdz"),
                                    json={"id": list(ids)}, headers={"X-Api-Key": self._key})
        r.raise_for_status()

    async def wyslij(self, odbiorca: dict, tekst: str) -> bool:
        payload = {
            "temat": "Kidwatch",
            "tresc": tekst,
            "zrodlo": self.cfg.zrodlo,
            "priorytet": 4,
            "rodzaj": "komenda",
            "format": "markdown-lite",
            "kategoria": "komendy",
            "odbiorca": odbiorca,
        }
        return await with_retry(
            lambda: self._client.post(self._url("/v1/wyslij"), json=payload,
                                      headers={"X-Api-Key": self._key}),
            what="komendy: odpowiedz", **self._sleep_kwargs,
        )

    async def aclose(self) -> None:
        if self._owns:
            await self._client.aclose()


# ================================================================ bot
class Odpowiedz(Exception):  # noqa: N818 - sterowanie przeplywem, nie blad
    """Koniec obslugi wiadomosci: odpowiedz nadawcy + wpis w dzienniku."""

    def __init__(self, tekst: str, wynik: str, *, dom_id: int | None = None,
                 komenda: k.Komenda | None = None, szczegol: str | None = None,
                 llm: bool = False) -> None:
        super().__init__(wynik)
        self.tekst, self.wynik, self.dom_id = tekst, wynik, dom_id
        self.komenda, self.szczegol, self.llm = komenda, szczegol, llm


@dataclass
class Kontekst:
    wiadomosc_id: str
    numer: str
    konto: kb.Konto
    #: (dom, uprawnienia konta w nim) — tylko domy z `whatsapp.komendy`.
    domy: list[tuple[DomKomend, frozenset[str]]] = field(default_factory=list)

    def dom(self, dom_id: int | None) -> tuple[DomKomend, frozenset[str]] | None:
        return next(((d, u) for d, u in self.domy if d.dom_id == dom_id), None)


class BotKomend:
    def __init__(
        self,
        cfg: WhatsappKomendyConfig,
        baza: kb.BazaKomend,
        kanal: KanalBota,
        llm: Rozpoznawacz,
        *,
        czlonkostwa: Callable[[int], list],
        dom: Callable[[int], DomKomend | None],
        profile: Callable[[int], list],
        alarm: Callable[[str, str], Awaitable[None]] | None = None,
        clock: Callable[[], float] = time.time,
        sleep=asyncio.sleep,
    ) -> None:
        self.cfg = cfg
        self.baza = baza
        self.kanal = kanal
        self.llm = llm
        #: user_id -> domy.Czlonkostwo (z `uprawnienia` w domu).
        self.czlonkostwa = czlonkostwa
        #: dom_id -> DomKomend albo None (dom nie chodzi w tym procesie).
        self.dom = dom
        #: dom_id -> odbiorcy.Profil czlonkow domu (kopie do opiekunow).
        self.profile = profile
        self.alarm = alarm
        self.clock = clock
        self.sleep = sleep
        self._alarm_llm: tuple[float, float] | None = None
        self._gotowy_log: bool | None = None

    # ---------------------------------------------------------- petla
    async def krok(self) -> int:
        """Jedno pobranie skrzynki. Zwraca liczbe obsluzonych wiadomosci."""
        gotowy = await self.kanal.gotowy()
        if gotowy != self._gotowy_log:
            (log.info if gotowy else log.error)(
                "komendy: %s", "bramka obsluguje odbiorce - przyjmuje komendy" if gotowy
                else "bramka NIE obsluguje jawnego odbiorcy - komend nie przetwarzam")
            self._gotowy_log = gotowy
        if not gotowy:
            return 0
        wiadomosci = await self.kanal.pobierz()
        ids: list[str] = []
        for w in wiadomosci:
            wid = w.get("id")
            if not isinstance(wid, str) or not wid:
                continue
            try:
                await self.obsluz(w)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Jedna wiadomosc nie zatrzyma reszty; potwierdzamy ja mimo to —
                # inaczej wracalaby w kolko (i tak jest juz w `przetworzone`).
                log.exception("komendy: blad przy wiadomosci %s", wid)
            ids.append(wid)
        try:
            await self.kanal.potwierdz(ids)
        except Exception as exc:  # noqa: BLE001 - bramka odda je znowu, odsiejemy po id
            log.warning("komendy: nie potwierdzilem %d wiadomosci w bramce: %s", len(ids), exc)
        return len(ids)

    # -------------------------------------------------------- wiadomosc
    async def obsluz(self, w: dict) -> None:
        wid = str(w["id"])
        if not self.baza.oznacz_przetworzona(wid):
            return
        surowy = str(w.get("numer") or "")
        numer = normalize_number(surowy)
        tekst = w.get("tekst") if isinstance(w.get("tekst"), str) else ""
        if numer is None:
            self.baza.zapisz(numer="...???", wynik=kb.NIEZNANY_NUMER, wiadomosc_id=wid,
                             szczegol="niepoprawny numer")
            return
        konto = self.baza.konto_po_numerze(numer)
        if not isinstance(konto, kb.Konto):
            # CISZA: obcy numer nie dostaje zadnej odpowiedzi.
            self.baza.zapisz(numer=numer, wynik=kb.NIEZNANY_NUMER, wiadomosc_id=wid,
                             szczegol=None if konto is None else "numer przy kilku kontach")
            log.info("komendy: wiadomosc z nieznanego numeru %s - bez odpowiedzi", mask(numer))
            return
        ctx = Kontekst(wid, numer, konto)
        try:
            await self._obsluz_konto(ctx, w, tekst)
        except Odpowiedz as o:
            await self._odpowiedz(ctx, o.tekst)
            k_ = o.komenda
            self.baza.zapisz(
                numer=numer, wynik=o.wynik, wiadomosc_id=wid, login=konto.login,
                dom_id=o.dom_id, akcja=k_.akcja if k_ else None,
                cel=(k_.urzadzenie or k_.dziecko) if k_ else None,
                minuty=k_.minuty if k_ else None, szczegol=o.szczegol, llm=o.llm)

    async def _obsluz_konto(self, ctx: Kontekst, w: dict, tekst: str) -> None:
        p = k.parsuj(tekst)
        lim = self.baza.licz_wiadomosc(ctx.numer, self.cfg.na_godzine,
                                       licz=not isinstance(p, k.Potwierdzenie))
        if not lim.ok:
            wynik = kb.ZABLOKOWANY if lim.blokada_do else kb.LIMIT
            if lim.zglos:
                raise Odpowiedz("Za dużo wiadomości — kolejne komendy przyjmę za godzinę.", wynik)
            self.baza.zapisz(numer=ctx.numer, wynik=wynik, wiadomosc_id=ctx.wiadomosc_id,
                             login=ctx.konto.login)
            return
        wiek = self._wiek(w.get("ts"))
        if wiek is not None and wiek > self.cfg.max_wiek_sekund:
            raise Odpowiedz(
                f"Ta wiadomość dotarła do mnie po {int(wiek // 60)} min — starych komend nie "
                "wykonuję. Wyślij ją jeszcze raz.", kb.PRZETERMINOWANA)
        if self.baza.wylaczone():
            raise Odpowiedz("Komendy z WhatsAppa są teraz wyłączone przez administratora. "
                            "Użyj panelu Kidwatcha.", kb.WYLACZONE)
        ctx.domy = self._domy(ctx.konto)
        if not ctx.domy:
            raise Odpowiedz("To konto nie może wydawać komend Kidwatcha z WhatsAppa.",
                            kb.BEZ_UPRAWNIEN)
        if isinstance(p, k.Potwierdzenie):
            await self._potwierdz(ctx, p.kod)
            return
        cytat = self._cytat(ctx, w.get("odpowiedz_na"))
        dom: DomKomend | None = None
        komenda: k.Komenda | None = None
        if isinstance(p, k.Surowa):
            dom, komenda = self._z_parsera(ctx, p, cytat)
        llm = komenda is None
        if llm:
            dom = self._dom_dla_llm(ctx, cytat, tekst)
            komenda = await self._z_llm(ctx, dom, tekst)
        assert komenda is not None
        await self._przyjmij(ctx, dom, komenda, cytat, llm)

    def _wiek(self, ts: object) -> float | None:
        if not isinstance(ts, str):
            return None
        try:
            chwila = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            return None
        if chwila.tzinfo is None:
            chwila = chwila.replace(tzinfo=UTC)
        return max(0.0, self.clock() - chwila.timestamp())

    def _domy(self, konto: kb.Konto) -> list[tuple[DomKomend, frozenset[str]]]:
        out = []
        for c in self.czlonkostwa(konto.user_id):
            uprawnienia = c.uprawnienia
            if upr.WHATSAPP_KOMENDY not in uprawnienia:
                continue
            dom = self.dom(c.dom_id)
            if dom is not None:
                out.append((dom, uprawnienia))
        return out

    def _cytat(self, ctx: Kontekst, odpowiedz_na: object) -> kb.Wyslane | None:
        """Powiadomienie, na ktore rodzic odpowiedzial — tylko z domu, w ktorym
        moze wydawac komendy, i wyslane do NIEGO (w trybie kont)."""
        if not isinstance(odpowiedz_na, str) or not odpowiedz_na:
            return None
        w = self.baza.wyslane(odpowiedz_na)
        if w is None or ctx.dom(w.dom_id) is None:
            return None
        if w.numer is not None and w.numer != ctx.numer:
            return None
        return w

    # ------------------------------------------------------ rozpoznanie
    def _dom_z_nazwy(self, ctx: Kontekst, nazwa: str) -> DomKomend:
        for d, _ in ctx.domy:
            if nazwa in (str(d.dom_id), k.norm(d.nazwa), k.norm(d.nazwa).removeprefix("dom ")):
                return d
        raise Odpowiedz(f"Nie znam domu „{nazwa}”. {self._lista_domow(ctx)}", kb.DOPYTANIE)

    @staticmethod
    def _lista_domow(ctx: Kontekst) -> str:
        return "Twoje domy: " + ", ".join(f"{d.dom_id} — {d.nazwa}" for d, _ in ctx.domy) + "."

    def _pytaj_o_dom(self, ctx: Kontekst) -> Odpowiedz:
        return Odpowiedz("Należysz do kilku domów — dopisz na końcu „dom <numer>”. "
                         + self._lista_domow(ctx), kb.DOPYTANIE)

    def _z_parsera(self, ctx: Kontekst, s: k.Surowa, cytat: kb.Wyslane | None
                   ) -> tuple[DomKomend | None, k.Komenda | None]:
        """Dokladna komenda -> (dom, Komenda). (dom, None) = cel nie pasuje
        dokladnie do zadnej nazwy: rozpozna go LLM."""
        if s.akcja in (k.POMOC, k.CISZA):
            dom = self._dom_z_nazwy(ctx, s.dom) if s.dom else (
                ctx.dom(cytat.dom_id)[0] if cytat else ctx.domy[0][0])
            return dom, k.Komenda(s.akcja, godziny=s.godziny)
        if s.dom:
            kandydaci = [self._dom_z_nazwy(ctx, s.dom)]
        elif cytat is not None:
            kandydaci = [ctx.dom(cytat.dom_id)[0]]
        else:
            kandydaci = [d for d, _ in ctx.domy]
        if s.cel is None:
            if len(kandydaci) > 1:
                raise self._pytaj_o_dom(ctx)
            dom = kandydaci[0]
            return dom, k.Komenda(s.akcja, minuty=s.minuty)
        trafione = []
        for d in kandydaci:
            with contextlib.suppress(k.NieZnamCelu):
                trafione.append((d, k.dopasuj(s.cel, d.dzieci, d.urzadzenia)))
        if not trafione:
            return (kandydaci[0] if len(kandydaci) == 1 else None), None
        if len(trafione) > 1:
            raise self._pytaj_o_dom(ctx)
        dom, (dziecko, urzadzenie) = trafione[0]
        return dom, k.Komenda(s.akcja, dziecko, urzadzenie, minuty=s.minuty)

    def _dom_dla_llm(self, ctx: Kontekst, cytat: kb.Wyslane | None, tekst: str) -> DomKomend:
        if cytat is not None:
            return ctx.dom(cytat.dom_id)[0]
        if len(ctx.domy) == 1:
            return ctx.domy[0][0]
        t = k.norm(tekst)
        if m := k._DOM.fullmatch(t):
            return self._dom_z_nazwy(ctx, m["dom"].strip())
        raise self._pytaj_o_dom(ctx)

    async def _z_llm(self, ctx: Kontekst, dom: DomKomend, tekst: str) -> k.Komenda:
        bez = k.BEZ_LLM.format(dziecko=dom.dzieci[0] if dom.dzieci else "Dziecko")
        if not self.llm.dostepny:
            raise Odpowiedz(bez, kb.BEZ_LLM, dom_id=dom.dom_id, szczegol="brak kluczy LLM")
        wynik = await self.llm.rozpoznaj(tekst, dom.dzieci, dom.urzadzenia)
        if wynik.status != OK:
            if wynik.status == AWARIA:
                await self._alarm_llm_awaria(wynik.bledy)
            raise Odpowiedz(bez, kb.BEZ_LLM, dom_id=dom.dom_id,
                            szczegol="; ".join(wynik.bledy) or "limit wywolan")
        self._alarm_llm_ok()
        komenda = k.z_llm(wynik.dane, dom.dzieci, dom.urzadzenia)
        if komenda is None or komenda.akcja == k.NIEZNANA:
            raise Odpowiedz("Nie zrozumiałem. Napisz „pomoc”, żeby zobaczyć komendy, albo np. "
                            f"„koniec {dom.dzieci[0] if dom.dzieci else 'Dziecko'}”.",
                            kb.NIE_ROZUMIEM, dom_id=dom.dom_id, llm=True,
                            szczegol=f"wynik {wynik.dostawca} poza lista")
        return komenda

    # --------------------------------------------------- przyjecie akcji
    def _uzupelnij(self, dom: DomKomend, km: k.Komenda, cytat: kb.Wyslane | None,
                   llm: bool) -> k.Komenda:
        if (cytat is not None and cytat.dom_id == dom.dom_id
                and km.dziecko is None and km.urzadzenie is None):
            km = replace(km, dziecko=cytat.dziecko,
                         urzadzenie=cytat.urzadzenie if cytat.urzadzenie in dom.urzadzenia
                         else None)
        if km.urzadzenie is not None and km.dziecko is None:
            km = replace(km, dziecko=dom.urzadzenia.get(km.urzadzenie))
        potrzebne = km.akcja in k.Z_DZIECKIEM or (km.akcja == k.ZABLOKUJ and km.urzadzenie is None)
        if potrzebne and km.dziecko is None:
            if len(dom.dzieci) == 1:
                km = replace(km, dziecko=dom.dzieci[0])
            else:
                raise Odpowiedz(
                    f"Którego dziecka? Napisz np. „{km.akcja} {dom.dzieci[0]}”. Dzieci: "
                    + ", ".join(dom.dzieci) + ".",
                    kb.DOPYTANIE, dom_id=dom.dom_id, komenda=km, llm=llm)
        return km

    def _sprawdz(self, dom: DomKomend, uprawnienia: frozenset[str], km: k.Komenda,
                 llm: bool) -> list[DeviceConfig]:
        """Uprawnienie, dostepnosc i limity — przed pytaniem o kod i drugi raz
        przed wykonaniem. Zwraca urzadzenia do blokady ekranu."""
        def nie(tekst: str, wynik: str = kb.ODMOWA) -> Odpowiedz:
            return Odpowiedz(tekst, wynik, dom_id=dom.dom_id, komenda=km, llm=llm)

        brak = k.WYMAGA[km.akcja] - uprawnienia
        if brak:
            u = sorted(brak)[0]
            raise nie(f"Twoje konto nie ma uprawnienia „{u}” ({upr.OPISY.get(u, '?')}).")
        ekrany: list[DeviceConfig] = []
        blokada_ekranu = km.akcja == k.ZABLOKUJ or (
            km.akcja == k.KONIEC and upr.MDM_KOMENDY in uprawnienia)
        if blokada_ekranu and dom.mdm is not None:
            ekrany = dom.ios(km.dziecko, km.urzadzenie)
        if km.akcja == k.ZABLOKUJ:
            if dom.mdm is None:
                raise nie("Blokada ekranu jest niedostępna: MDM w tym domu jest wyłączony.")
            if not ekrany:
                raise nie("Blokada ekranu działa tylko na iPadzie i iPhonie — "
                          f"{km.urzadzenie or km.dziecko} takiego nie ma.")
        # `koniec` bez czasu gry, ale z MDM — sama blokada ekranu.
        if (km.akcja in (k.KONIEC, k.ODEJMIJ, k.DODAJ, k.ODBLOKUJ) and dom.gry is None
                and (km.akcja != k.KONIEC or not ekrany)):
            raise nie("Czas gry jest w tym domu wyłączony.")
        if km.akcja == k.DODAJ:
            limit = self.cfg.luzowanie_minut
            if not limit:
                raise nie("Dodawanie czasu z WhatsAppa jest wyłączone — użyj panelu.")
            juz = self.baza.luzowanie_dzis(dom.dom_id, km.dziecko, k.DODAJ, dom.home.tz)
            if juz + (km.minuty or 0) > limit:
                raise nie(f"Dzienny limit z WhatsAppa to {limit} min dla {km.dziecko}; dziś "
                          f"zostało {max(0, limit - juz)} min. Więcej doda się w panelu.")
        if km.akcja == k.ODBLOKUJ:
            limit = self.cfg.odblokowania
            if not limit:
                raise nie("Odblokowanie z WhatsAppa jest wyłączone — użyj panelu.")
            if self.baza.luzowanie_dzis(dom.dom_id, km.dziecko, k.ODBLOKUJ,
                                        dom.home.tz) >= limit:
                raise nie(f"Dzienny limit odblokowań z WhatsAppa ({limit}) dla {km.dziecko} "
                          "wyczerpany. Odblokujesz w panelu.")
        if km.akcja == k.ODEJMIJ and dom.stan_gry(km.dziecko).get("mode") != "bonus":
            raise nie(f"{km.dziecko} nie ma teraz dodanego czasu — nie ma czego skracać. "
                      f"Napisz „koniec {km.dziecko}”, żeby zablokować gry.")
        if km.akcja == k.CISZA and (km.godziny or 0) > self.cfg.cisza_max_godzin:
            raise nie(f"Najdłuższa cisza to {self.cfg.cisza_max_godzin} h.")
        return ekrany

    async def _przyjmij(self, ctx: Kontekst, dom: DomKomend | None, km: k.Komenda,
                        cytat: kb.Wyslane | None, llm: bool) -> None:
        assert dom is not None
        if km.akcja == k.POMOC:
            dzieci = list(dict.fromkeys(c for d, _ in ctx.domy for c in d.dzieci))
            raise Odpowiedz(k.pomoc(dzieci, limit_minut=self.cfg.luzowanie_minut),
                            kb.ODPOWIEDZ, dom_id=dom.dom_id, komenda=km, llm=llm)
        _, uprawnienia = ctx.dom(dom.dom_id)
        km = self._uzupelnij(dom, km, cytat, llm)
        ekrany = self._sprawdz(dom, uprawnienia, km, llm)
        if km.akcja == k.STAN:
            tekst = await asyncio.to_thread(self._stan, dom, km.dziecko)
            raise Odpowiedz(tekst, kb.ODPOWIEDZ, dom_id=dom.dom_id, komenda=km, llm=llm)
        kod = self.baza.nowy_kod(ctx.numer, ctx.konto, dom.dom_id, km, llm=llm,
                                 wiadomosc_id=ctx.wiadomosc_id, waznosc=self.cfg.kod_sekundy)
        gdzie = f" ({dom.nazwa})" if len(ctx.domy) > 1 else ""
        dopisek = " Kopię dostanie drugi opiekun." if km.akcja in k.LUZUJACE else ""
        minuty = max(1, self.cfg.kod_sekundy // 60)
        raise Odpowiedz(
            f"Zrozumiałem: {k.opis(km, [e.display_name for e in ekrany])}{gdzie}? "
            f"Odpowiedz TAK {kod} (ważne {minuty} min).{dopisek}",
            kb.POTWIERDZENIE, dom_id=dom.dom_id, komenda=km, llm=llm)

    # ----------------------------------------------------- potwierdzenie
    async def _potwierdz(self, ctx: Kontekst, kod: str) -> None:
        o = self.baza.uzyj_kodu(ctx.numer, kod)
        if o == kb.KOD_WYGASL:
            raise Odpowiedz("Kod wygasł — wyślij komendę jeszcze raz.", kb.KOD_WYGASL)
        if not isinstance(o, kb.Oczekujacy) or o.user_id != ctx.konto.user_id:
            do = self.baza.zly_kod(ctx.numer, prog=self.cfg.zle_kody,
                                   blokada=self.cfg.blokada_minut * 60)
            tekst = "Nieprawidłowy albo już użyty kod."
            if do is not None:
                godz = datetime.fromtimestamp(do, UTC).astimezone(
                    ctx.domy[0][0].home.tz).strftime("%H:%M")
                tekst += f" Za dużo błędnych kodów — komendy z tego numeru wstrzymane do {godz}."
            raise Odpowiedz(tekst, kb.ZLY_KOD)
        self.baza.dobry_kod(ctx.numer)
        km = o.komenda
        para = ctx.dom(o.dom_id)
        if para is None:
            raise Odpowiedz("Nie możesz już wydawać komend w tym domu.", kb.ODMOWA,
                            dom_id=o.dom_id, komenda=km, llm=o.llm)
        dom, uprawnienia = para
        ekrany = self._sprawdz(dom, uprawnienia, km, o.llm)
        ok, tekst = await self._wykonaj(ctx, dom, uprawnienia, km, ekrany)
        await self._odpowiedz(ctx, tekst)
        self.baza.zapisz(numer=ctx.numer, wynik=kb.WYKONANE if ok else kb.BLAD,
                         wiadomosc_id=ctx.wiadomosc_id, login=ctx.konto.login, dom_id=dom.dom_id,
                         akcja=km.akcja, cel=km.dziecko or km.urzadzenie, minuty=km.minuty,
                         szczegol=None if ok else tekst, llm=o.llm)
        await self._kopia(ctx, dom, km, ekrany, tekst)

    # ---------------------------------------------------------- wykonanie
    async def _wykonaj(self, ctx: Kontekst, dom: DomKomend, uprawnienia: frozenset[str],
                       km: k.Komenda, ekrany: list[DeviceConfig]) -> tuple[bool, str]:
        if km.akcja == k.CISZA:
            do = self.clock() + (km.godziny or 1) * 3600
            self.baza.ustaw_cisze(ctx.konto.user_id, do)
            godz = datetime.fromtimestamp(do, UTC).astimezone(dom.home.tz).strftime("%H:%M")
            return True, (f"Wyciszone do {godz} — tylko Twoje powiadomienia; pilne alarmy "
                          "nadal przyjdą.")
        czesci: list[str] = []
        ok = True
        if km.akcja in (k.KONIEC, k.ODEJMIJ, k.DODAJ, k.ODBLOKUJ) and dom.gry is not None:
            akcja = {k.KONIEC: "block", k.ODEJMIJ: "shorten", k.DODAJ: "bonus",
                     k.ODBLOKUJ: "allow"}[km.akcja]
            gry_ok, opis = await self._gra(ctx, dom, km.dziecko, akcja, km.minuty)
            ok &= gry_ok
            czesci.append(opis)
        if ekrany:
            wyniki = await asyncio.to_thread(self._zablokuj, dom, ekrany)
            for nazwa, e_ok, blad in wyniki:
                ok &= e_ok
                czesci.append(f"{nazwa}: ekran zablokowany" if e_ok
                              else f"{nazwa}: blokada NIE wyszła ({blad})")
        return ok, ("Zrobione: " if ok else "Nie wszystko się udało: ") + "; ".join(czesci) + "."

    async def _gra(self, ctx: Kontekst, dom: DomKomend, dziecko: str, akcja: str,
                   minuty: int | None) -> tuple[bool, str]:
        from .gametime import WHATSAPP_PREFIKS, TooManyRequests  # noqa: PLC0415

        nazwy = {"block": "gry zablokowane", "allow": "gry odblokowane",
                 "bonus": f"+{minuty} min czasu gry", "shorten": f"-{minuty} min czasu gry"}
        try:
            req = await asyncio.to_thread(dom.gry.submit, dziecko, akcja, minuty,
                                          WHATSAPP_PREFIKS + ctx.konto.login)
        except TooManyRequests:
            return False, "czas gry: za dużo oczekujących zmian, spróbuj za chwilę"
        koniec = time.monotonic() + CZEKAJ_NA_GRE
        while time.monotonic() < koniec:
            wynik = await asyncio.to_thread(dom.gry.result, req)
            if wynik is not None:
                ok, blad = wynik
                return ok, f"{dziecko}: {nazwy[akcja]}" if ok else \
                    f"{dziecko}: {nazwy[akcja]} — NIE wyszło ({blad})"
            await self.sleep(0.5)
        return True, f"{dziecko}: {nazwy[akcja]} — zlecone, potwierdzi powiadomienie o czasie gry"

    def _zablokuj(self, dom: DomKomend, ekrany: list[DeviceConfig]
                  ) -> list[tuple[str, bool, str | None]]:
        """DeviceLock (a pod nadzorem i z `lost_mode` — EnableLostMode) przez
        API serwera MDM. Urzadzenie po UDID z konfiguracji, inaczej po nazwie
        z polityki MDM (= display_name, jak w alarmach MDM)."""
        from .mdm import MdmError  # noqa: PLC0415

        try:
            zapisane = [d for d in dom.mdm.devices() if not d.get("checked_out_at")]
        except MdmError as exc:
            return [(e.display_name, False, str(exc)) for e in ekrany]
        out = []
        for e in ekrany:
            d = next((d for d in zapisane if e.udid and d.get("udid") == e.udid), None) or \
                next((d for d in zapisane if d.get("name") == e.display_name), None)
            if d is None:
                out.append((e.display_name, False, "nie jest zapisany w MDM"))
                continue
            body = {"request_type": "DeviceLock", "Message": KOMUNIKAT_BLOKADY}
            if self.cfg.lost_mode and d.get("supervised"):
                # Gałąź na czas po nadzorze (W5): serwer MDM musi dostać
                # EnableLostMode w API_COMMANDS; do tego czasu odrzuci ją 400.
                body = {"request_type": "EnableLostMode", "Message": KOMUNIKAT_BLOKADY}
            try:
                dom.mdm.request("POST", f"/api/devices/{d['udid']}/commands", body)
                out.append((e.display_name, True, None))
            except MdmError as exc:
                out.append((e.display_name, False, str(exc)))
        return out

    # --------------------------------------------------------------- stan
    def _stan(self, dom: DomKomend, dziecko: str | None) -> str:
        if dom.queries is None:
            return "Stan jest teraz niedostępny."
        conn = dom.queries.connect()
        try:
            urzadzenia = dom.queries.devices(conn, {"child": dziecko} if dziecko else {})
        finally:
            conn.close()
        tz = dom.home.tz
        teraz = datetime.fromtimestamp(self.clock(), UTC).astimezone(tz)

        def hhmm(iso: str | None) -> str:
            return datetime.fromisoformat(iso).astimezone(tz).strftime("%H:%M") if iso else "?"

        linie = [f"Stan — {dom.nazwa}, {teraz:%H:%M}:"]
        gry: set[str] = set()
        for d in urzadzenia:
            if d["kind"] == "tv":
                np = d.get("now_playing")
                co = (f"{np.get('app') or np.get('title') or 'coś'} od {hhmm(np.get('since'))}"
                      if np else ("włączony" if d.get("session") else "nic nie leci"))
                linie.append(f"• {d['name']}: {co}")
                continue
            s = d.get("session")
            dzis = d.get("today") or {}
            top = dzis.get("top_app")
            linie.append(
                f"• {d['name']} ({d['child']}): "
                + (f"aktywny od {hhmm(s.get('started_at'))}" if s else "nieaktywny")
                + f"; dziś {dzis.get('minutes', 0)} min"
                + (f", najczęściej {top['app']}" if top else ""))
            g = d.get("game")
            if g and d["child"] not in gry:
                gry.add(d["child"])
                linie.append(f"  gry {d['child']}: {self._opis_gry(g, teraz)}")
        if len(linie) == 1:
            linie.append("brak urządzeń")
        return "\n".join(linie)

    @staticmethod
    def _opis_gry(g: dict, teraz: datetime) -> str:
        tryb = g.get("mode")
        if tryb == "bonus" and g.get("bonus_until"):
            do = datetime.fromisoformat(g["bonus_until"])
            zostalo = max(0, int((do - teraz).total_seconds() // 60))
            opis = f"dodany czas do {do.astimezone(teraz.tzinfo):%H:%M} (zostało {zostalo} min)"
        else:
            opis = {"blocked": "zablokowane", "allowed": "dozwolone",
                    "mixed": "częściowo zablokowane"}.get(tryb, "brak danych")
        return opis + (" — ponawiam zapis" if g.get("retrying") else "")

    # ------------------------------------------------- odpowiedzi i kopie
    async def _odpowiedz(self, ctx: Kontekst, tekst: str) -> None:
        if not await self.kanal.wyslij({"kanal": "whatsapp", "whatsapp": ctx.numer}, tekst):
            log.error("komendy: odpowiedz do %s nie wyszla", mask(ctx.numer))

    async def _kopia(self, ctx: Kontekst, dom: DomKomend, km: k.Komenda,
                     ekrany: list[DeviceConfig], wynik: str) -> None:
        """Kopia KAZDEJ wykonanej komendy do pozostalych opiekunow domu
        (konta z `whatsapp.komendy`), ich kanalem, niezaleznie od ich ciszy
        i kategorii — to zabezpieczenie, nie informacja."""
        try:
            profile = await asyncio.to_thread(self.profile, dom.dom_id)
        except Exception:
            log.exception("komendy: nie odczytalem opiekunow domu %d do kopii", dom.dom_id)
            return
        naglowek = "LUZOWANIE z WhatsAppa" if km.akcja in k.LUZUJACE else "Komenda z WhatsAppa"
        tekst = (f"Kidwatch — {naglowek} od {ctx.konto.login}: "
                 f"{k.opis(km, [e.display_name for e in ekrany])}.\n{wynik}")
        adresaci = [p for p in profile if p.login != ctx.konto.login and p.ma_kanal
                    and upr.WHATSAPP_KOMENDY in p.uprawnienia]
        if not adresaci:
            log.info("komendy: dom %d bez drugiego opiekuna z kanalem - kopii brak", dom.dom_id)
        for p in adresaci:
            if not await self.kanal.wyslij(p.adres(), tekst):
                log.error("komendy: kopia do %s nie wyszla", p.login)

    # -------------------------------------------------------- alarm LLM
    async def _alarm_llm_awaria(self, bledy: Sequence[str]) -> None:
        teraz = self.clock()
        if self._alarm_llm is not None and teraz < self._alarm_llm[0]:
            return
        odstep = ALARM_PIERWSZY_ODSTEP if self._alarm_llm is None else \
            min(self._alarm_llm[1] * 2, ALARM_MAX_ODSTEP)
        self._alarm_llm = (teraz + odstep, odstep)
        tytul = "Kidwatch: komendy z WhatsAppa bez LLM"
        tresc = ("Żaden dostawca LLM nie odpowiada (" + "; ".join(bledy) + "). Dokładne "
                 "komendy działają; wolny tekst dostaje prośbę o dokładną komendę. "
                 "Sprawdź klucze i środki (KIDWATCH_LLM_GEMINI_KEY, KIDWATCH_LLM_ANTHROPIC_KEY).")
        log.error("komendy: %s — %s", tytul, tresc)
        if self.alarm is None:
            return
        try:
            await self.alarm(tytul, tresc)
        except Exception:
            log.exception("komendy: alarm o LLM nie wyszedl")

    def _alarm_llm_ok(self) -> None:
        if self._alarm_llm is not None:
            log.info("komendy: LLM znowu odpowiada")
            self._alarm_llm = None


async def petla_komend(bot: BotKomend, poll_seconds: float, sleep=asyncio.sleep,
                       max_iterations: int | None = None) -> None:
    """Petla instancji. Blad bramki, bazy albo LLM nie konczy jej — loguje
    raz na rodzaj bledu, jak czujki."""
    iteration = 0
    ostatni: str | None = None
    sprzatanie = 0.0
    while max_iterations is None or iteration < max_iterations:
        iteration += 1
        try:
            await bot.krok()
            if ostatni is not None:
                log.info("komendy: bramka znowu odpowiada")
                ostatni = None
            if time.time() - sprzatanie > 3600:
                await asyncio.to_thread(bot.baza.sprzataj)
                sprzatanie = time.time()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            rodzaj = type(exc).__name__
            if rodzaj != ostatni:
                log.warning("komendy: blad pobierania skrzynki (%s): %s", rodzaj, exc)
                ostatni = rodzaj
        await sleep(poll_seconds)


# ============================================================ skladanie
def zapis_wyslanych(auth_path: str, dom_id: int, home: HomeConfig):
    """`BramkaNotifier.po_wysylce` dla kolejki domu: id wiadomosci ->
    dom, urzadzenie, dziecko, adresat. Blad zapisu tylko w logu."""
    baza = kb.BazaKomend(auth_path)
    dziecko = {d.display_name: d.child for d in home.devices}

    def zapisz(note, odbiorca: dict | None, wid: str) -> None:
        numer = (odbiorca or {}).get("whatsapp")
        baza.zapisz_wyslane(wid, note.dom_id or dom_id, note.device,
                            dziecko.get(note.device or ""), numer)

    return zapisz


def zbuduj_bota(cfg, rejestr, konfiguracje: dict, alarm=None) -> BotKomend | None:
    """Bot dla `run`: Config (instancja), rejestr domow i konfiguracje
    DZIALAJACYCH srodowisk domow (`konfiguracje`, podmieniane przy
    przeladowaniu). None = bramka wylaczona albo bez klucza."""
    from .config import MissingSecretError  # noqa: PLC0415
    from .mdm import build_api  # noqa: PLC0415
    from .odbiorcy import ProfilePowiadomien  # noqa: PLC0415
    from .panel import queries_domow  # noqa: PLC0415

    wk = cfg.whatsapp_komendy
    bc = cfg.notifiers.bramka
    if bc is None or not bc.enabled:
        log.error("whatsapp_komendy.enabled, ale bramka wylaczona - komendy nie ruszaja")
        return None
    try:
        klucz = bc.key()
    except MissingSecretError as exc:
        log.error("whatsapp_komendy.enabled, ale %s - komendy nie ruszaja", exc)
        return None
    auth_path = cfg.panel_auth_path
    baza = kb.BazaKomend(auth_path)
    llm = Rozpoznawacz(wk.llm, lambda: baza.wywolanie_llm(wk.llm.wywolan_na_dobe))
    if not llm.dostepny:
        log.warning("komendy: brak kluczy LLM - tylko dokladne komendy")
    zapytania = queries_domow(cfg, lambda dom: konfiguracje.get(dom.id))
    mdm_instancji = build_api(cfg.mdm)
    pamiec: dict[int, tuple[int, DomKomend]] = {}

    def dom(dom_id: int) -> DomKomend | None:
        home = konfiguracje.get(dom_id)
        d = rejestr.dom(dom_id)
        if home is None or d is None or d.zawieszony:
            return None
        zapis = pamiec.get(dom_id)
        if zapis is not None and zapis[0] == id(home):
            return zapis[1]
        if zapis is not None and zapis[1].mdm not in (None, mdm_instancji):
            # Klient MDM z sejfu poprzedniej konfiguracji domu (przeladowanie).
            with contextlib.suppress(Exception):
                zapis[1].mdm.close()
        q = zapytania(d)
        # Jak panel (`_mdm_domu`): MDM ma dzis tylko Dom 1 — z sejfu domu
        # w trybie `baza`, inaczej token instancji (MDM_ADMIN_TOKEN).
        mdm = None
        if dom_id == 1:
            mdm = q.mdm if q.mdm_z_bazy else mdm_instancji
        wynik = DomKomend(dom_id, d.nazwa, home, q, q.requests, mdm)
        pamiec[dom_id] = (id(home), wynik)
        return wynik

    profile = ProfilePowiadomien(auth_path)
    return BotKomend(
        wk, baza, KanalBota(bc, klucz), llm,
        czlonkostwa=rejestr.czlonkostwa, dom=dom,
        profile=lambda dom_id: profile.dla_domu(dom_id).profile(), alarm=alarm,
    )
