"""Zrodlo AdGuard Home — odpytywanie /control/querylog.

Zweryfikowane w openapi.yaml AdGuard Home (AdguardTeam/AdGuardHome) 2026-09-27:
  * `GET /control/querylog`, Basic Auth;
  * parametry: `older_than`, `offset`, `limit`, `search`, `reason` (tablica);
  * UWAGA — `response_status` jest w schemacie oznaczony jako **deprecated**,
    zastapiony przez `reason`. Nie wysylamy zadnego z nich: bez filtra endpoint
    zwraca wszystkie zapytania, a to dokladnie to, czego chcemy;
  * odpowiedz: {"oldest": str, "data": [QueryLogItem]};
  * QueryLogItem: `time`, `question.{name,type,class,unicode_name}`, `client`,
    `client_id`, `reason`, `status`, `elapsedMs` (jedyne pole w camelCase),
    `upstream`, `answer`, `cached`.

Endpoint nie ma parametru "nowsze niz", tylko `older_than`. Dlatego odpytujemy
najnowsza strone i odsiewamy to, co juz widzielismy, po odcisku zapytania.
"""

from __future__ import annotations

import asyncio
import base64
import logging
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta

import httpx

from ..config import AdGuardConfig
from ..models import DnsEvent
from ..store import Store

log = logging.getLogger(__name__)


def fingerprint(time_raw: str, client: str, name: str) -> str:
    """Odcisk jednego zapytania. `time` z AdGuarda ma rozdzielczosc
    mikrosekundowa, wiec trojka (czas, klient, domena) jest praktycznie unikalna."""
    return f"{time_raw}|{client}|{name.lower()}"


def parse_item(raw: dict) -> tuple[DnsEvent, str] | None:
    """Zamienia QueryLogItem w (DnsEvent, odcisk). None, gdy wpis jest bezuzyteczny."""
    if not isinstance(raw, dict):
        return None
    question = raw.get("question") or {}
    if not isinstance(question, dict):
        return None
    domain = (question.get("name") or "").strip()
    time_raw = raw.get("time")
    if not domain or not time_raw:
        return None
    try:
        ts = datetime.fromisoformat(str(time_raw).replace("Z", "+00:00"))
    except ValueError:
        log.warning("nieparsowalny czas AdGuarda: %r", time_raw)
        return None
    if ts.tzinfo is None:
        return None

    client = (raw.get("client") or "").strip()
    client_id = (raw.get("client_id") or "").strip()
    # ClientID jest stabilny (ustawiony w profilu DoH), IP moze sie zmienic przy
    # odnowieniu DHCP — wiec ClientID jest glownym tropem, a IP zapasowym.
    primary = client_id or client or "__UNKNOWN__"
    alt = client if client_id else None

    return (
        DnsEvent(ts=ts, device_id=primary, domain=domain, device_alt=alt),
        fingerprint(str(time_raw), client, domain),
    )


class AdGuardSource:
    name = "adguard"

    def __init__(
        self,
        cfg: AdGuardConfig,
        password: str,
        store: Store,
        client: httpx.AsyncClient | None = None,
        sleep=asyncio.sleep,
        now=lambda: datetime.now(UTC),
    ) -> None:
        self.cfg = cfg
        self.store = store
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=cfg.poll_interval_seconds + 10)
        self._sleep = sleep
        self._now = now
        token = base64.b64encode(f"{cfg.username}:{password}".encode()).decode()
        self._headers = {"Authorization": f"Basic {token}"}
        self._first_poll = True

    @property
    def url(self) -> str:
        return f"{self.cfg.base_url.rstrip('/')}/control/querylog"

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def events(self) -> AsyncIterator[DnsEvent]:
        backoff = 1.0
        while True:
            try:
                for event in await self.poll_once():
                    yield event
                backoff = 1.0
            except asyncio.CancelledError:
                raise
            except httpx.HTTPStatusError as exc:
                log.error("AdGuard odpowiedzial %s", exc.response.status_code)
                await self._sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            except (httpx.HTTPError, ValueError) as exc:
                # ValueError = odpowiedz, ktora nie jest JSON-em (strona bledu
                # proxy z kodem 200). Bez tego wyjatek konczyl generator.
                log.warning("blad odpytania AdGuarda: %s", exc)
                await self._sleep(backoff)
                backoff = min(backoff * 2, 60.0)
                continue
            await self._sleep(self.cfg.poll_interval_seconds)

    async def poll_once(self) -> list[DnsEvent]:
        response = await self._client.get(
            self.url, params={"limit": self.cfg.page_limit}, headers=self._headers
        )
        response.raise_for_status()
        payload = response.json()
        items = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(items, list):
            log.warning("odpowiedz AdGuarda bez tablicy 'data' — pomijam przebieg")
            return []

        parsed: list[tuple[DnsEvent, str]] = []
        for raw in items:
            hit = parse_item(raw)
            if hit is not None:
                parsed.append(hit)

        now = self._now()
        known = self.store.seen_before((fp for _, fp in parsed), now)

        # Po restarcie querylog zawiera cala historie. Bez tego progu dostalbys
        # lawine pushy o aktywnosci, ktora dawno minela.
        cutoff: datetime | None = None
        if self._first_poll and self.cfg.max_backfill_minutes > 0:
            cutoff = now - timedelta(minutes=self.cfg.max_backfill_minutes)
        self._first_poll = False

        fresh = [
            event
            for event, fp in parsed
            if fp not in known and (cutoff is None or event.ts >= cutoff)
        ]
        # AdGuard zwraca najnowsze najpierw; silnik oczekuje porzadku rosnacego.
        fresh.sort(key=lambda e: e.ts)
        return fresh
