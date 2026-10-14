"""Integracja z wlasnym serwerem MDM (kidwatch-mdm, osobny pod).

Dwie rzeczy:
  1. `MdmApi` — klient API admina serwera MDM. Uzywa go panel (zakladka MDM)
     i czujka. Synchroniczny, bo panel chodzi w watkach; czujka wola go przez
     asyncio.to_thread.
  2. `MdmWatcher` — zamienia dziennik zdarzen serwera i stan iPadow na
     powiadomienia: profil zdjety, iPad cichy, nowa aplikacja, certyfikat
     APNs przed wygasnieciem.

Serwer MDM ma WLASNA baze i jest jedynym jej pisarzem. Kidwatch pamieta tylko
kursor dziennika (meta `mdm:events`) i znaczniki wyslanych alarmow.

Domy (docs/architektura-domy.md §4.3, etap E3b). Serwer zna dom kazdego
urzadzenia i rozroznia token INSTANCJI (`MDM_ADMIN_TOKEN`, wszystko) od tokenu
DOMU (tylko jego urzadzenia). Czujka ma wiec trzy zakresy (`zakres_tokenu`):

  * ZAKRES_INSTANCJA — dom trzyma token instancji. Dozwolone wylacznie Domu 1
    i dziala dokladnie jak przed E3b (iPady, dziennik, alarmy serwera) —
    pierwszy krok wdrozenia nie zmienia nic;
  * ZAKRES_DOM — dom ma wlasny token: iPady i zdarzenia domu, bez alarmow
    calego serwera (certyfikat APNs, uzgadnianie, pushe);
  * ZAKRES_SERWER — czujka instancji z tokenem instancji: tylko alarmy serwera
    i zdarzenia bez domu, do administratora (alarm instancji), aktywna, gdy
    zaden dom nie trzyma tokenu instancji.

Dom inny niz Dom 1 z tokenem instancji nie dostaje MDM wcale (fail-closed):
widzialby iPady Domu 1. Druga bariera w panelu: `udid_w_domie`.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import logging
import os
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .config import SEKRETY_ZE_SRODOWISKA, MdmConfig
from .models import Notification, NotifyKind
from .store import Store

log = logging.getLogger(__name__)

CURSOR_KEY = "mdm:events"

#: Dom wlasciciela — jedyny, ktoremu wolno trzymac token instancji.
DOM_1 = 1
ZAKRES_INSTANCJA = "instancja"
ZAKRES_DOM = "dom"
ZAKRES_SERWER = "serwer"


def token_instancji() -> str | None:
    """Token instancji serwera MDM (Sekret kidwatch-mdm-admin) z env."""
    return os.environ.get(SEKRETY_ZE_SRODOWISKA[("mdm", "token")], "").strip() or None


def zakres_tokenu(dom_id: int, token: str | None) -> str | None:
    """Zakres czujki i posrednika panelu dla tokenu domu: ZAKRES_INSTANCJA
    (Dom 1 z tokenem instancji — zachowanie sprzed E3b), ZAKRES_DOM albo
    None — brak tokenu albo token instancji w innym domu (odmowa)."""
    if not token:
        return None
    inst = token_instancji()
    if inst is not None and hmac.compare_digest(token.encode(), inst.encode()):
        if dom_id != DOM_1:
            log.error("dom %d: token MDM to token instancji — widzialby iPady innych domow; "
                      "MDM tego domu wylaczone (wydaj token domu: kidwatch-mdm token-domu %d)",
                      dom_id, dom_id)
            return None
        return ZAKRES_INSTANCJA
    return ZAKRES_DOM


def udid_w_domie(udid: str, dom_id: int, home, dom_udidu: Callable[[str], int | None]) -> bool:
    """Druga bariera panelu (§4.3): czy UDID nalezy do domu, ZANIM panel
    zawola serwer MDM. Niezalezna od filtra serwera — liczy z danych Kidwatcha.

    `dom_udidu(udid)` — dom z tabeli `urzadzenia` (UDID jest tam globalnie
    jednoznaczny) albo None. UDID przypisany innemu domowi = obcy zawsze.
    Poza tym nalezy do domu, gdy jest w urzadzeniach jego konfiguracji.
    Wyjatek Domu 1: iPady zapisane do MDM przed domami nie musza miec
    `udid` w config.yaml — UDID, ktorego nie ma zaden dom, Dom 1 dalej
    obsluguje (inaczej blad w tym filtrze odcialby Dom 1 od komend)."""
    u = udid.strip().upper()
    wlasciciel = dom_udidu(u)
    if wlasciciel is not None:
        return wlasciciel == dom_id
    if any((getattr(d, "udid", None) or "").upper() == u for d in getattr(home, "devices", ())):
        return True
    return dom_id == DOM_1
#: Identyfikator bazy serwera MDM, do ktorej odnosi sie kursor.
INSTANCE_KEY = "mdm:instance"


class MdmError(RuntimeError):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class MdmApi:
    def __init__(self, cfg: MdmConfig, token: str, client: httpx.Client | None = None) -> None:
        self.cfg = cfg
        self._client = client or httpx.Client(
            base_url=cfg.url.rstrip("/"),
            timeout=cfg.timeout_seconds,
            headers={"Authorization": f"Bearer {token}"},
        )

    def request(self, method: str, path: str, body: dict | None = None) -> Any:
        try:
            resp = self._client.request(method, path, json=body)
        except httpx.HTTPError as exc:
            raise MdmError(503, f"serwer MDM nieosiagalny: {exc}") from exc
        try:
            data = resp.json()
        except ValueError:
            data = {"error": resp.text[:200]}
        if resp.status_code >= 400:
            message = data.get("error") if isinstance(data, dict) else None
            raise MdmError(resp.status_code, str(message or f"HTTP {resp.status_code}"))
        return data

    def health(self) -> dict:
        return self.request("GET", "/api/health")

    def devices(self) -> list[dict]:
        return self.request("GET", "/api/devices")

    def events(self, since: int) -> list[dict]:
        return self.request("GET", f"/api/events?since={int(since)}")

    def last_event_id(self) -> int:
        """Najwyzszy numer zdarzenia — dla serwera bez `last_event_id` w health."""
        rows = self.request("GET", "/api/events?last=1")
        return max((int(r["id"]) for r in rows), default=0)

    def close(self) -> None:
        self._client.close()


def config_domu(home_mdm, url: str) -> MdmConfig:
    """MdmConfig domu: ustawienia i dostawca sekretow z konfiguracji domu
    (tryb `baza`: token z sejfu), adres serwera z instancji."""
    cfg = MdmConfig.model_validate({**home_mdm.model_dump(), "url": url})
    cfg._sekrety = home_mdm._sekrety
    return cfg


def build_api(cfg: MdmConfig) -> MdmApi | None:
    if not cfg.enabled:
        return None
    token = cfg.token()
    if not token:
        log.error("mdm.enabled, ale brak MDM_ADMIN_TOKEN — integracja MDM wylaczona")
        return None
    return MdmApi(cfg, token)


# ================================================================= czujka
#: Co iPhone bez nadzoru daje przez MDM — powtarzane w tekstach, zeby alarm
#: nie obiecywal blokad, ktorych iOS nie wykona (docs/iphone.md). Bez restartu:
#: RestartDevice wymaga nadzoru (mdm/commands/device.restart.yaml).
_IPHONE_MOZE = "lista aplikacji, blokada ekranu i aktualizacje"


def _kind(device: dict | None) -> str:
    """"iphone" | "ipad" z /api/devices. Serwer sprzed iPhone'ow nie podaje
    `kind` — wtedy rozstrzyga ProductName, jak w kidwatch_mdm.policy."""
    if not device:
        return "ipad"
    if device.get("kind"):
        return str(device["kind"])
    return "iphone" if str(device.get("product") or "").startswith("iPhone") else "ipad"


#: Zdarzenie serwera -> (rodzaj, priorytet, tytul). None = nie powiadamiamy.
#: Klucze to `kind` z tabeli events w kidwatch_mdm/store.py.
def _describe(
    event: dict, name: str, device_kind: str = "ipad"
) -> tuple[NotifyKind, int, str, str] | None:
    kind = event["kind"]
    iphone = device_kind == "iphone"
    noun = "iPhone" if iphone else "iPad"
    detail: Any = event.get("detail")
    if isinstance(detail, str):
        with contextlib.suppress(ValueError):
            detail = json.loads(detail)
    if kind == "checkout":
        return (
            NotifyKind.MDM,
            5,
            f"{name}: profil MDM zdjety",
            "iPhone wypisal sie z zarzadzania — bez nadzoru wystarczy usunac profil "
            f"w Ustawieniach. Przestaly dzialac: {_IPHONE_MOZE}. DNS idzie osobnym "
            "profilem NextDNS; jego zdjecie pokaze czujka ciszy."
            if iphone
            else "iPad wypisal sie z zarzadzania. Blokady VPN i DNS juz nie dzialaja. "
            "Na nadzorowanym iPadzie to mozliwe tylko po resecie z komputera.",
        )
    if kind == "profile_missing":
        return (
            NotifyKind.MDM,
            4,
            f"{name}: zniknal profil ograniczen",
            f"Brak profilu {detail.get('identifier') if isinstance(detail, dict) else ''}. "
            "Serwer MDM wgra go ponownie przy najblizszym polaczeniu.",
        )
    if kind == "enrolled":
        return (
            NotifyKind.MDM,
            3,
            f"{name}: zapisany do MDM",
            f"iPhone polaczyl sie z serwerem MDM. Bez nadzoru dzialaja: {_IPHONE_MOZE}. "
            "Restartu, blokad VPN, DNS ani usuwania profilu nie bedzie — DNS idzie "
            "recznym profilem NextDNS."
            if iphone
            else "iPad polaczyl sie z serwerem MDM. Ograniczenia i DNS zostana wgrane "
            "automatycznie.",
        )
    if kind == "supervision_changed":
        supervised = isinstance(detail, dict) and detail.get("supervised")
        return (
            NotifyKind.MDM,
            5 if not supervised else 3,
            f"{name}: {'wlaczony' if supervised else 'UTRACONY'} nadzor",
            "Bez nadzoru iOS ignoruje blokady VPN, DNS i usuwania profilu."
            if not supervised
            else (
                "iPhone jest nadzorowany, ale polityka iPhone'a nie wysyla blokad "
                "nadzoru — to osobna decyzja (docs/iphone.md)."
                if iphone
                else "iPad jest nadzorowany — blokady dzialaja."
            ),
        )
    if kind in ("apps_installed", "apps_removed"):
        apps = detail.get("apps", []) if isinstance(detail, dict) else []
        names = ", ".join(a.get("name") or a.get("id") for a in apps) or "?"
        added = kind == "apps_installed"
        return (
            NotifyKind.DEVICE_INVENTORY,
            3 if added else 2,
            f"{name}: {'nowa aplikacja' if added else 'usunieta aplikacja'}",
            names,
        )
    if kind == "push_token_dead":
        return (
            NotifyKind.MDM,
            4,
            f"{name}: {noun} nie przyjmuje pushy",
            "APNs odrzucil token urzadzenia. Pomoze ponowny zapis do MDM.",
        )
    if kind == "os_update_failed":
        # Stare zdarzenia z serwera sprzed poprawki niosa {"count": 0} — to
        # brak awarii, nie awaria. Kidwatch nadrabia dziennik, wiec filtr tez tu.
        if isinstance(detail, dict) and not (detail.get("count") or 0) > 0:
            return None
        return (
            NotifyKind.MDM,
            3,
            f"{name}: aktualizacja systemu nieudana",
            json.dumps(detail, ensure_ascii=False) if detail else "",
        )
    if kind == "command_error":
        rtype = detail.get("request_type") if isinstance(detail, dict) else "?"
        if rtype in (
            "DeviceInformation",
            "SecurityInfo",
            "ProfileList",
            "InstalledApplicationList",
        ):
            return None  # odczyty: ponowione przy nastepnym odswiezeniu
        return (
            NotifyKind.MDM,
            3,
            f"{name}: {noun} odrzucil komende {rtype}",
            json.dumps(detail.get("chain"), ensure_ascii=False)[:500]
            if isinstance(detail, dict)
            else "",
        )
    if kind == "policy_entry_rejected":
        label = detail.get("label") if isinstance(detail, dict) else "?"
        errors = detail.get("errors") if isinstance(detail, dict) else None
        return (
            NotifyKind.MDM,
            4,
            f"MDM: wpis {label} w polityce odrzucony",
            "Serwer MDM wystartowal, ale ten wpis iPhone'a dostal kwarantanne (bez "
            "wlasnych ograniczen): " + "; ".join(errors or [])[:400]
            + ". Popraw polityke (kidwatch-mdm check-policy) i zrestartuj serwer.",
        )
    if kind == "kind_mismatch":
        product = detail.get("product") if isinstance(detail, dict) else "?"
        label = detail.get("label") if isinstance(detail, dict) else "?"
        quarantined = isinstance(detail, dict) and detail.get("quarantined")
        return (
            NotifyKind.MDM,
            5 if quarantined else 4,
            f"{name}: pomylka rodzaju w polityce MDM",
            f"Etykieta {label} ma kind: iphone, a urzadzenie to iPad ({product}). "
            + (
                "Wpis jest w kwarantannie (bledy iPhone'a), wiec iPad NIE dostaje "
                "wlasnych ograniczen z tego wpisu — usun `kind: iphone` i zrestartuj "
                "serwer. "
                if quarantined
                else "Serwer traktuje je jako iPada i zostawia blokady, ale popraw "
                "polityke; "
            )
            + "profil zapisu mogl powstac bez blokady usuniecia — zapisz iPada ponownie.",
        )
    if kind in ("cert_mismatch", "enrollment_reuse", "unknown_identity"):
        return (
            NotifyKind.MDM,
            4,
            "MDM: odrzucona proba podszycia",
            f"Zdarzenie {kind}: wiadomosc z poprawnym podpisem, ale nie od tego urzadzenia.",
        )
    return None


#: Podpowiedz do alarmu wiszacej komendy, wg jej stanu w kolejce serwera.
_STUCK_HINT = {
    "not_now": "iPad odpowiada „nie teraz” (np. zablokowany ekran) — wykona ja po odblokowaniu.",
    "queued": "iPad laczy sie z MDM, ale jej nie pobral — sprawdz pushe.",
    "sent": "iPad ja pobral, ale nie odpowiedzial.",
}


def _stuck_hint(status: str, device_kind: str) -> str:
    hint = _STUCK_HINT.get(status, "")
    return hint.replace("iPad", "iPhone", 1) if device_kind == "iphone" else hint


class MdmWatcher:
    def __init__(
        self, api: MdmApi, store: Store, cfg: MdmConfig, zakres: str = ZAKRES_INSTANCJA
    ) -> None:
        self.api = api
        self.store = store
        self.cfg = cfg
        #: ZAKRES_INSTANCJA (jak przed E3b), ZAKRES_DOM albo ZAKRES_SERWER.
        self.zakres = zakres

    # Podzial na fetch (tylko HTTP) i process (baza): mdm_loop wola fetch
    # w watku pomocniczym, zeby wolny serwer MDM nie trzymal petli asyncio,
    # a baze Kidwatch dotyka WYLACZNIE z watku petli. Polaczenie SQLite nie
    # wolno uzyc w innym watku niz ten, ktory je otworzyl — pierwsza wersja
    # robila wszystko w to_thread i padala przy kazdym odczycie (2026-10-09).
    def cursor(self) -> int | None:
        """Kursor dziennika; None = Kidwatch jeszcze nigdy nie czytal serwera."""
        raw = self.store.get_meta(CURSOR_KEY)
        return None if raw is None else int(raw)

    def fetch(self, since: int | None, instance: str | None = None) -> dict:
        health = self.api.health()
        head = health.get("last_event_id")
        server = health.get("instance")
        # Kiedy kursor nic nie znaczy i trzeba zaczac od biezacego konca:
        #   first    — pierwsze uruchomienie: historia serwera to nie alarmy,
        #              a pominiecie tylko pierwszej porcji (200) puszczalo reszte;
        #   instance — nowa baza serwera (nowy PVC, ponowny init): numeracja
        #              od 1, stary kursor wyciszalby wszystko na tygodnie;
        #   rewind   — ta sama baza odtworzona z kopii: max(id) ponizej kursora.
        reset = None
        if since is None:
            reset = "first"
        elif instance and server and server != instance:
            reset = "instance"
        elif head is not None and int(head) < since:
            reset = "rewind"
        if reset and head is None:
            head = self.api.last_event_id()
        return {
            "devices": self.api.devices(),
            "events": [] if reset else self.api.events(since),
            "health": health,
            "since": since or 0,
            "reset": reset,
            "head": int(head or 0),
        }

    def process(self, data: dict, now: datetime) -> list[Notification]:
        devices = data["devices"]
        by_udid = {d["udid"]: d for d in devices}
        out = self._reset(data, now)
        events = data["events"]
        if self.zakres == ZAKRES_SERWER:
            # Zdarzenia z domem ida do czujek domow; serwer bez `dom_id` w
            # zdarzeniach (sprzed E3b) — nic, zeby nie dublowac alarmow domu.
            events = [e for e in events if "dom_id" in e and e["dom_id"] is None]
        out += self._events(by_udid, events, data["since"], now, last_id=_max_id(data))
        if self.zakres != ZAKRES_SERWER:
            out += self._silent(devices, now)
            out += self._stuck(devices, now)
        if self.zakres != ZAKRES_DOM:
            # Stan calego serwera: certyfikat, uzgadnianie, pushe. Z tokenem
            # domu robi to czujka instancji — inaczej kazdy dom dostalby alarm
            # o certyfikacie, ktorego nie odnowi.
            out += self._certificate(data["health"], now)
            out += self._reconcile(data["health"], now)
            out += self._push(data["health"], devices, now)
        server = data["health"].get("instance")
        if server and server != self.store.get_meta(INSTANCE_KEY):
            self.store.set_meta(INSTANCE_KEY, server)
        # Klucze z data ("raz na dobe") nic nie dawaly bez zapisu: mdm_loop
        # wysyla przez Outbox, ktory kluczy nie sprawdza, wiec stan trwajacy
        # (iPad wylaczony, uzgadnianie stoi) dawal ten sam push co obieg,
        # czyli co minute (audyt 2026-10-10, W1). Zapis tu, w watku petli.
        return [n for n in out if self.store.mark_sent(n.dedup_key, now)]

    def poll(self, now: datetime) -> list[Notification]:
        """Wszystko w biezacym watku (CLI, testy)."""
        return self.process(self.fetch(self.cursor(), self.store.get_meta(INSTANCE_KEY)), now)

    async def poll_async(self, now: datetime) -> list[Notification]:
        data = await asyncio.to_thread(
            self.fetch, self.cursor(), self.store.get_meta(INSTANCE_KEY)
        )
        return self.process(data, now)

    def _reset(self, data: dict, now: datetime) -> list[Notification]:
        reset = data.get("reset")
        if not reset:
            return []
        self.store.set_meta(CURSOR_KEY, str(data["head"]))
        if reset == "first" or self.zakres == ZAKRES_SERWER:
            # Nowa baza serwera — alarm daje czujka domu (zakladka MDM domu).
            return []
        log.warning(
            "mdm: %s bazy serwera — kursor %s -> %s",
            "nowa instancja" if reset == "instance" else "cofniecie",
            data["since"],
            data["head"],
        )
        return [
            Notification(
                kind=NotifyKind.MDM,
                title="MDM: baza serwera " + ("nowa" if reset == "instance" else "odtworzona"),
                text=(
                    "Serwer MDM ma inna baze niz przy ostatnim odczycie (nowy wolumen, "
                    "ponowna instalacja albo kopia zapasowa). Zdarzenia sprzed tej chwili "
                    "pominiete — sprawdz w zakladce MDM, czy iPady sa zapisane."
                ),
                dedup_key=f"mdm-reset:{data['health'].get('instance')}:{data['head']}",
                ts=now,
                priority=4,
                tags=("mdm",),
            )
        ]

    def _name(self, device: dict | None, udid: str | None) -> str:
        if device:
            return device.get("name") or device.get("label") or udid or "iPad"
        return udid or "MDM"

    def _events(
        self,
        by_udid: dict[str, dict],
        events: list[dict],
        since: int,
        now: datetime,
        last_id: int | None = None,
    ) -> list[Notification]:
        out: list[Notification] = []
        last = max(since, last_id or 0)
        for event in events:
            last = max(last, int(event["id"]))
            device = by_udid.get(event.get("udid"))
            described = _describe(event, self._name(device, event.get("udid")), _kind(device))
            if described is None:
                continue
            kind, priority, title, text = described
            out.append(
                Notification(
                    kind=kind,
                    title=title,
                    text=text,
                    dedup_key=f"mdm-ev:{event['id']}",
                    # Serwer MDM pisze ISO 8601 bez ulamkow sekund — store.from_iso
                    # Kidwatch wymaga ich, wiec tu zwykly fromisoformat.
                    ts=datetime.fromisoformat(event["at"]) if event.get("at") else now,
                    device=self._name(by_udid.get(event.get("udid")), event.get("udid")),
                    priority=priority,
                    tags=("mdm",),
                )
            )
        if last != since:
            self.store.set_meta(CURSOR_KEY, str(last))
        return out

    def _silent(self, devices: list[dict], now: datetime) -> list[Notification]:
        limit = timedelta(hours=self.cfg.silent_alert_hours)
        out: list[Notification] = []
        for d in devices:
            if d.get("checked_out_at") or not d.get("last_seen_at"):
                continue
            seen = datetime.fromisoformat(d["last_seen_at"])
            if now - seen < limit:
                continue
            hours = int((now - seen).total_seconds() // 3600)
            name = self._name(d, d["udid"])
            out.append(
                Notification(
                    kind=NotifyKind.MDM,
                    title=f"{name}: brak kontaktu z MDM od {hours} h",
                    text=(
                        f"{'iPhone' if _kind(d) == 'iphone' else 'iPad'} nie laczy sie "
                        "z serwerem MDM. Mozliwe: wylaczony, bez sieci, "
                        "reset w trybie odzyskiwania albo blad pushy"
                        + (f" ({d['push_error']})" if d.get("push_error") else "")
                        + "."
                    ),
                    # Raz na dobe na iPada — dedup po dacie, nie po godzinie.
                    dedup_key=f"mdm-silent:{d['udid']}:{now.date().isoformat()}",
                    ts=now,
                    device=name,
                    priority=4,
                    tags=("mdm",),
                )
            )
        return out

    def _certificate(self, health: dict, now: datetime) -> list[Notification]:
        apns = health.get("apns") or {}
        if not apns.get("configured"):
            return []
        days = apns.get("days_left")
        if days is None or days > self.cfg.cert_warn_days:
            return []
        # Co tydzien, a w ostatnim tygodniu codziennie.
        year, week, _ = now.isocalendar()
        bucket = now.date().isoformat() if days <= 7 else f"{year}-w{week}"
        return [
            Notification(
                kind=NotifyKind.MDM,
                title=f"Certyfikat APNs MDM wygasa za {days} dni",
                text=(
                    "Odnow go na identity.apple.com TYM SAMYM Apple ID (Renew, nie nowy "
                    "certyfikat), potem podmien Sekret kidwatch-mdm-apns. Po wygasnieciu "
                    "zaden iPad nie dostanie komendy."
                ),
                dedup_key=f"mdm-cert:{bucket}",
                ts=now,
                priority=5 if days <= 7 else 4,
                tags=("mdm",),
            )
        ]


    def _reconcile(self, health: dict, now: datetime) -> list[Notification]:
        """Uzgadnianie serwera padajace przy kazdym obiegu: pod zdrowy, a nikt
        nie wgrywa profili, DDM ani nie budzi iPadow."""
        if "last_reconcile_ok_at" not in health:
            return []  # serwer sprzed tego pola
        ok = health.get("last_reconcile_ok_at") or health.get("started_at")
        if not ok:
            return []
        stalled = now - datetime.fromisoformat(ok)
        if stalled < timedelta(minutes=self.cfg.reconcile_alert_minutes):
            return []
        minutes = int(stalled.total_seconds() // 60)
        since = f"{minutes // 60} h" if minutes >= 60 else f"{minutes} min"
        error = health.get("last_reconcile_error")
        return [
            Notification(
                kind=NotifyKind.MDM,
                title=f"MDM: uzgadnianie nie dziala od {since}",
                text=(
                    "Serwer MDM odpowiada, ale nie uzgadnia stanu iPadow: profile, DDM i "
                    "pushe stoja. "
                    + (f"Ostatni blad: {error}" if error else "Sprawdz log kidwatch-mdm.")
                ),
                # Raz na dobe — trwaly blad nie moze dawac alarmu co minute.
                dedup_key=f"mdm-reconcile:{now.date().isoformat()}",
                ts=now,
                priority=4,
                tags=("mdm",),
            )
        ]

    def _push(self, health: dict, devices: list[dict], now: datetime) -> list[Notification]:
        """Komendy czekaja, a pushe do APNs padaja: uzgadnianie wyglada na
        zdrowe, a zaden iPad nie przychodzi po blokade, profil ani DDM."""
        since = health.get("push_failing_since")
        if not since:
            return []
        pending = sum(
            d.get("pending_commands") or 0 for d in devices if not d.get("checked_out_at")
        )
        stalled = now - datetime.fromisoformat(since)
        if not pending or stalled < timedelta(minutes=self.cfg.push_alert_minutes):
            return []
        hours = int(stalled.total_seconds() // 3600)
        return [
            Notification(
                kind=NotifyKind.MDM,
                title=f"MDM: pushe do iPadow nie wychodza od {hours} h",
                text=(
                    f"Czeka komend: {pending}. APNs odrzuca albo jest nieosiagalny "
                    f"({health.get('push_failures') or '?'} nieudanych z rzedu, ostatni "
                    f"blad: {health.get('last_push_error') or '?'}). Sprawdz egress "
                    "kidwatch-mdm do api.push.apple.com:443 i certyfikat APNs."
                ),
                dedup_key=f"mdm-push:{now.date().isoformat()}",
                ts=now,
                priority=4,
                tags=("mdm",),
            )
        ]

    def _stuck(self, devices: list[dict], now: datetime) -> list[Notification]:
        """Komenda wiszaca dobami na iPadzie, ktory sie odzywa (NotNow bez
        konca, zgubiony push). iPad milczacy ma juz alarm ciszy."""
        limit = timedelta(hours=self.cfg.stuck_alert_hours)
        silent = timedelta(hours=self.cfg.silent_alert_hours)
        out: list[Notification] = []
        for d in devices:
            oldest = d.get("oldest_pending")
            if d.get("checked_out_at") or not oldest or not d.get("last_seen_at"):
                continue
            if now - datetime.fromisoformat(d["last_seen_at"]) >= silent:
                continue
            waiting = now - datetime.fromisoformat(oldest["created_at"])
            if waiting < limit:
                continue
            name = self._name(d, d["udid"])
            hours = int(waiting.total_seconds() // 3600)
            out.append(
                Notification(
                    kind=NotifyKind.MDM,
                    title=f"{name}: komenda {oldest['request_type']} czeka od {hours} h",
                    text=(
                        f"Czeka komend: {d.get('pending_commands') or 1}, najstarsza w stanie "
                        f"{oldest['status']}. "
                        + _stuck_hint(oldest["status"], _kind(d))
                    ),
                    dedup_key=f"mdm-stuck:{d['udid']}:{now.date().isoformat()}",
                    ts=now,
                    device=name,
                    priority=3,
                    tags=("mdm",),
                )
            )
        return out


def _max_id(data: dict) -> int | None:
    """Najwyzszy numer w porcji zdarzen PRZED filtrem czujki serwera — kursor
    przesuwa sie takze po zdarzeniach domow, ktorych ta czujka nie zglasza."""
    ids = [int(e["id"]) for e in data.get("events") or []]
    return max(ids) if ids else None


class AlarmyInstancji:
    """Dispatcher czujki serwera (ZAKRES_SERWER): kazda notka jako alarm
    instancji (`__main__.alarm_instancji`, do administratora). Bez kanalu —
    sam log."""

    def __init__(self, alarm) -> None:
        self.alarm = alarm

    async def send_all(self, notes) -> None:
        for note in notes:
            if self.alarm is None:
                log.error("alarm MDM instancji (tylko log): %s — %s", note.title, note.text)
                continue
            try:
                await self.alarm(note.title, note.text)
            except Exception:
                log.exception("alarm MDM instancji nie wyszedl: %s", note.title)


async def mdm_loop(
    watcher: MdmWatcher,
    dispatcher,
    interval_seconds: float,
    sleep=asyncio.sleep,
    max_iterations: int | None = None,
    aktywny: Callable[[], bool] | None = None,
) -> None:
    """Odpytuje serwer MDM. Blad logujemy raz na rodzaj, jak czujka UniFi.
    `aktywny()` False = obieg pominiety (czujka instancji, gdy alarmy serwera
    daje dom z tokenem instancji)."""
    last_error: str | None = None
    iteration = 0
    while max_iterations is None or iteration < max_iterations:
        iteration += 1
        if aktywny is not None and not aktywny():
            await sleep(interval_seconds)
            continue
        try:
            notes = await watcher.poll_async(datetime.now(UTC))
            if last_error is not None:
                log.info("mdm: serwer znowu odpowiada")
                last_error = None
            await dispatcher.send_all(notes)
        except asyncio.CancelledError:
            raise
        except MdmError as exc:
            kind = f"{exc.status}"
            if kind != last_error:
                log.log(
                    logging.ERROR if exc.status in (401, 403) else logging.WARNING, "mdm: %s", exc
                )
                last_error = kind
        except Exception:
            log.exception("mdm: nieoczekiwany blad")
        await sleep(interval_seconds)
