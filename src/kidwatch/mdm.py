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
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from .config import MdmConfig
from .models import Notification, NotifyKind
from .store import Store

log = logging.getLogger(__name__)

CURSOR_KEY = "mdm:events"
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


def build_api(cfg: MdmConfig) -> MdmApi | None:
    if not cfg.enabled:
        return None
    token = cfg.token()
    if not token:
        log.error("mdm.enabled, ale brak MDM_ADMIN_TOKEN — integracja MDM wylaczona")
        return None
    return MdmApi(cfg, token)


# ================================================================= czujka
#: Zdarzenie serwera -> (rodzaj, priorytet, tytul). None = nie powiadamiamy.
#: Klucze to `kind` z tabeli events w kidwatch_mdm/store.py.
def _describe(event: dict, name: str) -> tuple[NotifyKind, int, str, str] | None:
    kind = event["kind"]
    detail: Any = event.get("detail")
    if isinstance(detail, str):
        with contextlib.suppress(ValueError):
            detail = json.loads(detail)
    if kind == "checkout":
        return (
            NotifyKind.MDM,
            5,
            f"{name}: profil MDM zdjety",
            "iPad wypisal sie z zarzadzania. Blokady VPN i DNS juz nie dzialaja. "
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
            "iPad polaczyl sie z serwerem MDM. Ograniczenia i DNS zostana wgrane automatycznie.",
        )
    if kind == "supervision_changed":
        supervised = isinstance(detail, dict) and detail.get("supervised")
        return (
            NotifyKind.MDM,
            5 if not supervised else 3,
            f"{name}: {'wlaczony' if supervised else 'UTRACONY'} nadzor",
            "Bez nadzoru iOS ignoruje blokady VPN, DNS i usuwania profilu."
            if not supervised
            else "iPad jest nadzorowany — blokady dzialaja.",
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
            f"{name}: iPad nie przyjmuje pushy",
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
            f"{name}: iPad odrzucil komende {rtype}",
            json.dumps(detail.get("chain"), ensure_ascii=False)[:500]
            if isinstance(detail, dict)
            else "",
        )
    if kind in ("cert_mismatch", "enrollment_reuse", "unknown_identity"):
        return (
            NotifyKind.MDM,
            4,
            "MDM: odrzucona proba podszycia",
            f"Zdarzenie {kind}: wiadomosc z poprawnym podpisem, ale nie od tego urzadzenia.",
        )
    return None


class MdmWatcher:
    def __init__(self, api: MdmApi, store: Store, cfg: MdmConfig) -> None:
        self.api = api
        self.store = store
        self.cfg = cfg

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
        out += self._events(by_udid, data["events"], data["since"], now)
        out += self._silent(devices, now)
        out += self._certificate(data["health"], now)
        out += self._reconcile(data["health"], now)
        server = data["health"].get("instance")
        if server and server != self.store.get_meta(INSTANCE_KEY):
            self.store.set_meta(INSTANCE_KEY, server)
        return out

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
        if reset == "first":
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
        self, by_udid: dict[str, dict], events: list[dict], since: int, now: datetime
    ) -> list[Notification]:
        out: list[Notification] = []
        last = since
        for event in events:
            last = max(last, int(event["id"]))
            described = _describe(
                event, self._name(by_udid.get(event.get("udid")), event.get("udid"))
            )
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
                        "iPad nie laczy sie z serwerem MDM. Mozliwe: wylaczony, bez sieci, "
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


async def mdm_loop(
    watcher: MdmWatcher,
    dispatcher,
    interval_seconds: float,
    sleep=asyncio.sleep,
    max_iterations: int | None = None,
) -> None:
    """Odpytuje serwer MDM. Blad logujemy raz na rodzaj, jak czujka UniFi."""
    last_error: str | None = None
    iteration = 0
    while max_iterations is None or iteration < max_iterations:
        iteration += 1
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
