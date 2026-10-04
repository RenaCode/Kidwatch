"""Kanal ntfy.

ODEJSCIE OD PIERWOTNEGO PLANU, swiadome: publikujemy **postacia JSON** (POST na
korzen serwera z polem `topic`), a nie `POST /{topic}` z naglowkami `Title`,
`Priority`, `Tags`.

Powod jest konkretny i sprawdzony w tym repo (test_notifiers.py):
naglowki HTTP nie przenosza UTF-8. httpx koduje je kodekiem **ascii**, wiec tytul
z polskim znakiem wywala cala wysylke wyjatkiem UnicodeEncodeError:

    UnicodeEncodeError: 'ascii' codec can't encode character '\u0142'

Imiona dzieci i nazwy urzadzen to dokladnie te napisy, ktore wchodza do tytulu,
wiec "Michal" przez l z kreska zamieniloby kazdy push w blad. Postac JSON jest
w UTF-8 i tego ograniczenia nie ma. Dokumentacja ntfy wymienia oba sposoby jako
rownowazne (docs.ntfy.sh/publish).
"""

from __future__ import annotations

import logging

import httpx

from ..config import NtfyConfig
from ..models import Notification
from .base import with_retry

log = logging.getLogger(__name__)


class NtfyNotifier:
    name = "ntfy"

    def __init__(
        self,
        cfg: NtfyConfig,
        token: str | None = None,
        client: httpx.AsyncClient | None = None,
        sleep=None,
    ) -> None:
        self.cfg = cfg
        self._token = token
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=cfg.timeout_seconds)
        self._sleep_kwargs = {"sleep": sleep} if sleep is not None else {}

    @property
    def url(self) -> str:
        return self.cfg.server.rstrip("/") + "/"

    def payload(self, note: Notification) -> dict:
        body = {
            "topic": self.cfg.topic,
            "title": note.title,
            "message": note.text,
            "priority": note.priority or self.cfg.default_priority,
        }
        if note.tags:
            body["tags"] = list(note.tags)
        return body

    def headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        return headers

    async def send(self, note: Notification) -> bool:
        return await with_retry(
            lambda: self._client.post(self.url, json=self.payload(note), headers=self.headers()),
            what=f"ntfy[{self.cfg.topic}]",
            **self._sleep_kwargs,
        )

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
