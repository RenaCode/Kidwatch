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
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol

import httpx

from ..models import Notification, NotifyKind
from ..odbiorcy import TRYB_KONTA, Profil, adresaci

if TYPE_CHECKING:
    from zoneinfo import ZoneInfo

    from ..odbiorcy import ProfilePowiadomien
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

    @property
    def domowe(self) -> list[Notifier]:
        """Kanaly domu (ntfy, Home Assistant) - w trybie kont dostaja kazde
        powiadomienie raz, bez odbiorcy."""
        return [n for n in self.notifiers if not getattr(n, "per_konto", False)]

    @property
    def per_konto(self) -> list[Notifier]:
        return [n for n in self.notifiers if getattr(n, "per_konto", False)]

    async def send_detailed(
        self, note: Notification, *, record: bool = True,
        cel: Profil | str | None = None,
    ) -> tuple[dict[str, bool], set[str]]:
        """Jak `send`, plus kanaly, ktore odrzucily TE wiadomosc trwale.

        `cel`: None - wszystkie kanaly (tryb tras); "" - tylko domowe;
        Profil - tylko kanaly per konto, z jawnym odbiorca (wynik pod
        kluczem "kanal:login")."""
        results: dict[str, bool] = {}
        rejected: set[str] = set()
        if cel is None:
            targets = self.notifiers
        elif isinstance(cel, str):
            targets = self.domowe
        else:
            targets = self.per_konto
        for notifier in targets:
            name = notifier.name if not isinstance(cel, Profil) \
                else f"{notifier.name}:{cel.login}"
            codes: list[int] = []
            token = _REJECTED.set(codes)
            try:
                if isinstance(cel, Profil):
                    results[name] = await notifier.send(note, odbiorca=cel.adres())
                else:
                    results[name] = await notifier.send(note)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Kanal nie moze wywrocic petli glownej ani zablokowac pozostalych.
                log.exception("kanal %s wysypal sie na powiadomieniu", name)
                results[name] = False
            finally:
                _REJECTED.reset(token)
            if codes and not results[name]:
                rejected.add(name)
        if record:
            self.record(note, results)
        return results, rejected

    def record(self, note: Notification, results: dict[str, bool], *, merge: bool = False) -> None:
        if self.store is None:
            return
        try:
            self.store.record_notification(note, results, datetime.now(UTC), merge=merge)
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

    KOLEJKI ODBIORCOW. Nowy wpis jest najpierw rozdzielany (`_rozdziel`):
    w trybie tras trafia do jednej kolejki '*' (wszystkie kanaly, jak przed
    kontami), w trybie kont (odbiorcy.py) — do kolejki kazdego konta, ktore
    go chce i moze dostac, plus '' dla kanalow domowych. Kolejnosc obowiazuje
    W KOLEJCE: czekajacy wpis wstrzymuje kolejne za nim tego samego odbiorcy
    (inaczej po awarii "koniec sesji" przyszedlby przed "startem"), ale nie
    wstrzymuje innych odbiorcow — zly numer jednej osoby nie blokuje
    powiadomien reszty domu. Wpis wstrzymany cisza konta (attempts == 0,
    next_at w przyszlosci) nie blokuje kolejki — alarm w ciszy wychodzi
    przed raportem czekajacym na rano.

    Duplikaty: proba jest liczona przed wysylka, a wpis kasowany po niej.
    Gdy kanal przyjmie push, a proces padnie przed skasowaniem (Recreate,
    liveness, OOM), po starcie ten sam push pojdzie drugi raz. Swiadomie:
    zgubiony jest gorszy niz zdublowany (README: "Restart nie gubi pushy").
    Klucz dedupu tego nie zatrzyma — chroni przed ponownym WYGENEROWANIEM
    powiadomienia, nie przed ponowna wysylka gotowego. Per konto dochodzi
    klucz "<dedup>@<login>" w `sent`: to samo zdarzenie nie trafi do jednej
    osoby dwa razy, nawet gdy zostanie wstawione ponownie.
    """

    def __init__(
        self,
        dispatcher: Dispatcher,
        store: Store,
        now: Callable[[], datetime] | None = None,
        *,
        konta: ProfilePowiadomien | None = None,
        dziecko: Mapping[str, str] | None = None,
        tz: ZoneInfo | None = None,
    ) -> None:
        self.dispatcher = dispatcher
        self.store = store
        self._now = now or (lambda: datetime.now(UTC))
        self._wake = asyncio.Event()
        self.konta = konta
        self.dziecko = dict(dziecko or {})
        self.tz = tz or UTC
        self._tryb_log: str | None = None

    @property
    def notifiers(self) -> list[Notifier]:
        return self.dispatcher.notifiers

    async def send_all(self, notes: Sequence[Notification]) -> None:
        if not notes:
            return
        self.store.outbox_put(notes, self._now())
        self._wake.set()

    async def profile_kont(self) -> list[Profil] | None:
        """Profile kont, gdy tryb kont jest wlaczony i mozliwy; None = tryb
        tras. Zmiana trybu idzie do logu raz, przy przejsciu."""
        powod = None
        profile: list[Profil] | None = None
        if self.konta is None or not self.dispatcher.per_konto:
            powod = "tryb tras (brak kont albo kanalu per konto)"
        elif self.konta.tryb() != TRYB_KONTA:
            powod = "tryb tras (wlasciciel nie wlaczyl trybu kont)"
        elif not all([await n.obsluguje_odbiorcow() for n in self.dispatcher.per_konto]):
            powod = "TRYB TRAS: wlaczony tryb kont, ale bramka nie obsluguje jawnego odbiorcy"
        else:
            profile = self.konta.profile()
            powod = f"tryb kont ({sum(p.ma_kanal and p.aktywne for p in profile)} z kanalem)"
        if powod != self._tryb_log:
            (log.error if powod.startswith("TRYB TRAS") else log.info)("kolejka: %s", powod)
            self._tryb_log = powod
        return profile

    async def _rozdziel(self) -> dict[str, Profil]:
        """Nierozdzielone wpisy -> kolejki odbiorcow. Zwraca profile kont
        (login -> Profil) do wysylki; pusty slownik w trybie tras."""
        pending = self.store.outbox_pending(odbiorca=None, limit=500)
        try:
            profile = await self.profile_kont()
        except Exception:
            # Baza kont niedostepna: nie zgadujemy odbiorcow — wpisy czekaja
            # nierozdzielone, a nastepny flush sprobuje znowu.
            log.exception("kolejka: nie odczytalem kont — wstrzymuje rozdzial")
            return {}
        if profile is None:
            for item in pending:
                self.store.outbox_route(item.id, [("*", item.next_at)])
            return {}
        by_login = {p.login: p for p in profile}
        now = self._now()
        for item in pending:
            rozdzial = adresaci(item.note, profile, dziecko=self.dziecko, tz=self.tz, now=now)
            targets: list[tuple[str, datetime | None]] = []
            for a in rozdzial.adresaci:
                if self.store.mark_sent(f"{item.note.dedup_key}@{a.login}", now):
                    targets.append((a.login, a.po))
            if self.dispatcher.domowe:
                targets.append(("", None))
            if not targets:
                log.info("kolejka: %s - nikt nie chce tego dostac (%s)", item.note.dedup_key,
                         ", ".join(f"{k}: {v}" for k, v in rozdzial.pominieci.items()) or "-")
                self.dispatcher.record(item.note, {}, merge=True)
            self.store.outbox_route(item.id, targets)
        return by_login

    async def flush(self) -> int:
        """Wysyla to, co czeka i juz moze isc. Zwraca liczbe wyslanych wpisow.

        W kazdej kolejce konczy na pierwszym wpisie, ktory nie wyszedl albo
        czeka na swoja kolej (`next_at`) — kolejne tego odbiorcy stoja za nim.
        """
        profile = await self._rozdziel()
        if not profile and self.konta is not None and any(
            q not in ("*", "") for q in self.store.outbox_queues()
        ):
            # Wpisy kont z poprzedniego flusha, a tryb kont wlasnie wypadl
            # (bramka wycofana): wysylamy je dalej na zapisane kanaly kont.
            with contextlib.suppress(Exception):
                profile = {p.login: p for p in self.konta.profile()}
        done = 0
        lost: list[OutboxItem] = []
        for queue in self.store.outbox_queues():
            done += await self._flush_queue(queue, profile, lost)
        self._alarm_lost(lost)
        return done

    async def _flush_queue(
        self, queue: str, profile: Mapping[str, Profil], lost: list[OutboxItem]
    ) -> int:
        done = 0
        merge = queue != "*"
        while True:
            now = self._now()
            item = self._head(queue, now)
            if item is None:
                break
            if self._expired(item, now):
                self._abandon(item)
                lost.append(item)
                continue
            if item.next_at is not None and item.next_at > now:
                break
            cel: Profil | str | None = None
            if queue == "":
                cel = ""
            elif queue != "*":
                cel = profile.get(queue)
                if cel is None or not cel.ma_kanal:
                    # Konto usuniete albo bez kanalu od chwili rozdzialu.
                    log.warning("kolejka: %s dla %r - konto bez kanalu, porzucam",
                                item.note.dedup_key, queue)
                    self.store.outbox_done(item.id)
                    continue
            attempt = item.attempts + 1
            self.store.outbox_attempt(item.id, next_at=now + outbox_backoff(attempt))
            results, rejected = await self.dispatcher.send_detailed(
                item.note, record=False, cel=cel
            )
            # Bez zadnego kanalu nie ma na co czekac (start ostrzega w logu).
            if not results or any(results.values()):
                self.dispatcher.record(item.note, results, merge=merge)
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
        return done

    def _head(self, queue: str, now: datetime) -> OutboxItem | None:
        """Pierwszy wpis kolejki, z pominieciem wstrzymanych cisza (attempts 0,
        next_at w przyszlosci) — te nie blokuja kolejnych."""
        for item in self.store.outbox_pending(odbiorca=queue, limit=200):
            held = item.attempts == 0 and item.next_at is not None and item.next_at > now
            if not held or self._expired(item, now):
                return item
        return None

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
        # Panel ma pokazac, ze tego push nie dostal nikt (ten odbiorca).
        queue = item.odbiorca
        if queue in (None, "*"):
            self.dispatcher.record(item.note, {n.name: False for n in self.notifiers})
        elif queue == "":
            self.dispatcher.record(item.note, {n.name: False for n in self.dispatcher.domowe},
                                   merge=True)
        else:
            self.dispatcher.record(
                item.note, {f"{n.name}:{queue}": False for n in self.dispatcher.per_konto},
                merge=True,
            )
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
