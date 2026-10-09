"""Wspolna warstwa wysylki: ponawianie i izolacja bledow.

Zasada nadrzedna: **nieudane powiadomienie nie moze zatrzymac przetwarzania.**
Jesli ntfy jest chwilowo niedostepny, sesje i tak musza byc liczone dalej,
inaczej jedna usterka sieci zafalszowuje caly dzien.
"""

from __future__ import annotations

import asyncio
import contextlib
import contextvars
import logging
from collections.abc import Awaitable, Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol

import httpx

from ..models import Notification, NotifyKind

if TYPE_CHECKING:
    from ..store import OutboxItem, Store

log = logging.getLogger(__name__)

MAX_ATTEMPTS = 3

#: Odrzucenia, ktore dotycza TEJ wiadomosci, nie kanalu: zla tresc (400),
#: za duze cialo (413), niepoprawne pola (422). Ten sam wpis nie przejdzie
#: nigdy, wiec kolejka porzuca go od razu zamiast wstrzymywac wszystko za nim
#: na dobe. 401/403/404 (zly token, zly adres) to blad konfiguracji kanalu —
#: po poprawce wpis wyjdzie, wiec czeka w kolejce jak przy awarii.
PERMANENT_STATUSES = frozenset({400, 413, 422})

#: Dispatcher ustawia tu liste przed wywolaniem kanalu; with_retry dopisuje
#: kod trwalego odrzucenia. Kanaly dalej zwracaja zwykle bool.
_REJECTED: contextvars.ContextVar[list[int] | None] = contextvars.ContextVar(
    "kidwatch_rejected", default=None
)


class Notifier(Protocol):
    name: str

    async def send(self, note: Notification) -> bool: ...
    async def aclose(self) -> None: ...


async def with_retry(
    action: Callable[[], Awaitable[httpx.Response]],
    *,
    what: str,
    attempts: int = MAX_ATTEMPTS,
    sleep=asyncio.sleep,
) -> bool:
    """Wykonuje `action` ponawiajac przy bledzie. Zwraca, czy sie udalo.

    Nie podnosi wyjatku: wywolujacy ma isc dalej niezaleznie od wyniku.
    """
    delay = 1.0
    for attempt in range(1, attempts + 1):
        try:
            response = await action()
            response.raise_for_status()
            return True
        except asyncio.CancelledError:
            raise
        except httpx.HTTPStatusError as exc:
            status = exc.response.status_code
            # 4xx poza 408 i 429 nie naprawi sie przez powtorzenie — zly token,
            # zla nazwa tematu. Ponawianie tylko zjadaloby limity.
            if 400 <= status < 500 and status not in (408, 429):
                log.error("%s: odrzucone z kodem %s — nie ponawiam", what, status)
                rejected = _REJECTED.get()
                if rejected is not None and status in PERMANENT_STATUSES:
                    rejected.append(status)
                return False
            log.warning("%s: kod %s (proba %d/%d)", what, status, attempt, attempts)
        except httpx.HTTPError as exc:
            log.warning("%s: %s (proba %d/%d)", what, exc, attempt, attempts)
        except Exception:
            log.exception("%s: nieoczekiwany blad (proba %d/%d)", what, attempt, attempts)

        if attempt < attempts:
            await sleep(delay)
            delay *= 2

    log.error("%s: nie udalo sie po %d probach — ide dalej", what, attempts)
    return False


class Dispatcher:
    """Rozsyla powiadomienie do wszystkich wlaczonych kanalow.

    Z `store` kazde powiadomienie trafia tez do historii panelu — razem z tym,
    ktore kanaly je przyjely.
    """

    def __init__(self, notifiers: Sequence[Notifier], store: Store | None = None) -> None:
        self.notifiers = list(notifiers)
        self.store = store

    async def send(self, note: Notification, *, record: bool = True) -> dict[str, bool]:
        """`record=False` pomija historie panelu — Outbox zapisuje tam tylko
        wynik koncowy, nie kazda nieudana probe."""
        results, _ = await self.send_detailed(note, record=record)
        return results

    async def send_detailed(
        self, note: Notification, *, record: bool = True
    ) -> tuple[dict[str, bool], set[str]]:
        """Jak `send`, plus kanaly, ktore odrzucily TE wiadomosc trwale."""
        results: dict[str, bool] = {}
        rejected: set[str] = set()
        for notifier in self.notifiers:
            codes: list[int] = []
            token = _REJECTED.set(codes)
            try:
                results[notifier.name] = await notifier.send(note)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Kanal nie moze wywrocic petli glownej ani zablokowac pozostalych.
                log.exception("kanal %s wysypal sie na powiadomieniu", notifier.name)
                results[notifier.name] = False
            finally:
                _REJECTED.reset(token)
            if codes and not results[notifier.name]:
                rejected.add(notifier.name)
        if record:
            self.record(note, results)
        return results, rejected

    def record(self, note: Notification, results: dict[str, bool]) -> None:
        if self.store is None:
            return
        try:
            self.store.record_notification(note, results, datetime.now(UTC))
        except Exception:
            # Historia to dodatek — jej awaria nie moze zatrzymac powiadomien.
            log.exception("nie zapisalem powiadomienia do historii")

    async def send_all(self, notes: Sequence[Notification]) -> None:
        for note in notes:
            await self.send(note)

    async def aclose(self) -> None:
        for notifier in self.notifiers:
            try:
                await notifier.aclose()
            except Exception:
                log.exception("blad przy zamykaniu kanalu %s", notifier.name)


#: Odstepy miedzy kolejnymi probami wyslania wpisu z kolejki (s). Po ostatnim
#: — co OUTBOX_BACKOFF_MAX. Krotkie ponawianie (1 s, 2 s) robi sam kanal
#: w `with_retry`; to tutaj przetrzymuje restart bramki przy wdrozeniu czy
#: kilkugodzinna awarie Mailguna.
OUTBOX_BACKOFF = (30, 60, 120, 300, 600)
OUTBOX_BACKOFF_MAX = 900

#: Wpis starszy niz to albo po tylu probach jest porzucany (WARNING w logu
#: i alarm czujki). Doba to dosc, zeby przeczekac awarie; push sprzed doby
#: o starcie sesji nic juz nie znaczy. Limit prob jest bezpiecznikiem na
#: wypadek, gdyby zegar stal — przy backoffie wiek konczy sie pierwszy.
OUTBOX_MAX_AGE = timedelta(hours=24)
OUTBOX_MAX_ATTEMPTS = 100

#: Prefiks klucza alarmu o porzuconych wpisach. Porzucenie samego alarmu nie
#: rodzi nastepnego — inaczej trwala awaria krecilaby alarmy w kolko.
OUTBOX_LOST_KEY = "outbox-lost:"


def outbox_backoff(attempt: int) -> timedelta:
    """Odstep po `attempt`-tej (liczonej od 1) probie."""
    idx = attempt - 1
    seconds = OUTBOX_BACKOFF[idx] if 0 <= idx < len(OUTBOX_BACKOFF) else OUTBOX_BACKOFF_MAX
    return timedelta(seconds=seconds)


class Outbox:
    """Kolejka wyjsciowa w kidwatch.db przed Dispatcherem.

    `send_all` tylko zapisuje do tabeli outbox — petle (tik, strumien DNS,
    telewizor, czas gry) nie czekaja na siec. Wysyla `run`, jedno zadanie,
    po kolei.

    Wpis znika DOPIERO, gdy przyjal go co najmniej jeden kanal (bramka 2xx).
    Nieudany zostaje z licznikiem prob, `last_error` i `next_at` (backoff
    OUTBOX_BACKOFF) i wyjdzie, gdy kanal wroci — takze po restarcie procesu.
    Kolejnosc: wszystkie powiadomienia ida do tych samych odbiorcow, wiec
    czekajacy wpis wstrzymuje kolejne za nim; inaczej po awarii "koniec
    sesji" przyszedlby przed "startem". Nie blokuje to tiku ani tetna — one
    tylko dopisuja do tabeli.

    Duplikaty: proba jest liczona przed wysylka, a wpis kasowany po niej.
    Gdy kanal przyjmie push, a proces padnie przed skasowaniem (Recreate,
    liveness, OOM), po starcie ten sam push pojdzie drugi raz. Swiadomie:
    zgubiony jest gorszy niz zdublowany (README: "Restart nie gubi pushy").
    Klucz dedupu tego nie zatrzyma — chroni przed ponownym WYGENEROWANIEM
    powiadomienia, nie przed ponowna wysylka gotowego.
    """

    def __init__(
        self,
        dispatcher: Dispatcher,
        store: Store,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.store = store
        self._now = now or (lambda: datetime.now(UTC))
        self._wake = asyncio.Event()

    @property
    def notifiers(self) -> list[Notifier]:
        return self.dispatcher.notifiers

    async def send_all(self, notes: Sequence[Notification]) -> None:
        if not notes:
            return
        self.store.outbox_put(notes, self._now())
        self._wake.set()

    async def flush(self) -> int:
        """Wysyla to, co czeka i juz moze isc. Zwraca liczbe wyslanych wpisow.

        Konczy na pierwszym wpisie, ktory nie wyszedl albo czeka na swoja
        kolej (`next_at`) — kolejne stoja za nim.
        """
        done = 0
        lost: list[OutboxItem] = []
        while (item := self.store.outbox_head()) is not None:
            now = self._now()
            if self._expired(item, now):
                self._abandon(item)
                lost.append(item)
                continue
            if item.next_at is not None and item.next_at > now:
                break
            attempt = item.attempts + 1
            self.store.outbox_attempt(item.id, next_at=now + outbox_backoff(attempt))
            results, rejected = await self.dispatcher.send_detailed(item.note, record=False)
            # Bez zadnego kanalu nie ma na co czekac (start ostrzega w logu).
            if not results or any(results.values()):
                self.dispatcher.record(item.note, results)
                self.store.outbox_done(item.id)
                done += 1
                continue
            failed = ", ".join(sorted(results))
            if rejected == set(results):
                # Kazdy kanal odrzucil TRESC (400/413/422): ponawianie nic nie da,
                # a czekajacy wpis wstrzymywalby cala kolejke na dobe (audyt
                # 2026-10-09, N7). Porzucamy od razu, z alarmem czujki.
                self._abandon(item, reason=f"odrzucone trwale ({failed})")
                lost.append(item)
                continue
            self.store.outbox_failed(item.id, f"zaden kanal nie przyjal ({failed})")
            log.warning(
                "kolejka: %s nie wyszlo (proba %d, kanaly: %s) — ponowie za %s",
                item.note.dedup_key, attempt, failed, outbox_backoff(attempt),
            )
            break
        self._alarm_lost(lost)
        return done

    @staticmethod
    def _expired(item: OutboxItem, now: datetime) -> bool:
        return (
            now - item.created_at >= OUTBOX_MAX_AGE
            or item.attempts >= OUTBOX_MAX_ATTEMPTS
        )

    def _abandon(self, item: OutboxItem, reason: str | None = None) -> None:
        log.warning(
            "kolejka: porzucam %s po %d probach (w kolejce od %s, ostatni blad: %s)",
            item.note.dedup_key, item.attempts, item.created_at.isoformat(),
            reason or item.last_error,
        )
        # Panel ma pokazac, ze tego push nie dostal nikt.
        self.dispatcher.record(item.note, {n.name: False for n in self.notifiers})
        self.store.outbox_done(item.id)

    def _alarm_lost(self, lost: Sequence[OutboxItem]) -> None:
        """Alarm czujki: porzucone powiadomienie to cichy blad, jak cisza DNS.

        Idzie ta sama kolejka — dojdzie, gdy kanal wroci. Najwyzej raz na dobe
        (klucz w `sent`), bo dluga awaria porzuca wpisy jeden po drugim.
        """
        lost = [i for i in lost if not i.note.dedup_key.startswith(OUTBOX_LOST_KEY)]
        if not lost:
            return
        now = self._now()
        key = f"{OUTBOX_LOST_KEY}{now:%Y%m%d}"
        if not self.store.mark_sent(key, now):
            return
        titles = "\n".join(f"- {i.note.title}" for i in lost[:5])
        more = f"\n(i {len(lost) - 5} wiecej)" if len(lost) > 5 else ""
        self.store.outbox_put(
            [
                Notification(
                    kind=NotifyKind.WATCHDOG,
                    title="kidwatch nie dostarczyl powiadomien",
                    text=(
                        f"Nie doszly (po dobie ponawiania albo odrzucone przez "
                        f"bramke): {len(lost)}.\n"
                        f"{titles}{more}\n"
                        f"Sprawdz bramke i kanaly; szczegoly w logu kidwatch."
                    ),
                    dedup_key=key,
                    ts=now,
                    priority=4,
                    tags=("rotating_light",),
                )
            ],
            now,
        )
        self._wake.set()

    async def run(self, idle_seconds: float = 5.0, max_iterations: int | None = None) -> None:
        iteration = 0
        while max_iterations is None or iteration < max_iterations:
            iteration += 1
            self._wake.clear()
            try:
                await self.flush()
            except asyncio.CancelledError:
                raise
            except Exception:
                # Jak w innych petlach: blad bazy albo kanalu nie konczy wysylki.
                log.exception("kolejka: blad wysylki — ponowie")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._wake.wait(), timeout=idle_seconds)

    async def aclose(self) -> None:
        await self.dispatcher.aclose()
