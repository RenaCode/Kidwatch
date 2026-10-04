"""Kanal Home Assistant — webhook, zeby dalo sie budowac automatyzacje.

Wysylamy pola strukturalne (device, event, app, text), a nie gotowy napis, bo
automatyzacja w HA ma warunkowac na `event` i `device`, nie parsowac tekstu.
"""

from __future__ import annotations

import logging

import httpx

from ..config import HomeAssistantConfig
from ..models import Notification
from .base import with_retry

log = logging.getLogger(__name__)


class HomeAssistantNotifier:
    name = "homeassistant"

    def __init__(
        self,
        cfg: HomeAssistantConfig,
        webhook_id: str,
        client: httpx.AsyncClient | None = None,
        sleep=None,
    ) -> None:
        self.cfg = cfg
        self._webhook_id = webhook_id
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=cfg.timeout_seconds)
        self._sleep_kwargs = {"sleep": sleep} if sleep is not None else {}

    @property
    def url(self) -> str:
        return f"{self.cfg.base_url.rstrip('/')}/api/webhook/{self._webhook_id}"

    def payload(self, note: Notification) -> dict:
        return {
            "device": note.device,
            "event": note.kind.value,
            "app": note.app,
            "text": note.text,
            "title": note.title,
            "priority": note.priority,
            "ts": note.ts.isoformat(),
        }

    async def send(self, note: Notification) -> bool:
        return await with_retry(
            lambda: self._client.post(self.url, json=self.payload(note)),
            what="home assistant",
            **self._sleep_kwargs,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
