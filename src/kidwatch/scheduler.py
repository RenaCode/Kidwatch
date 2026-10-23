"""Petla cykliczna: domykanie sesji, podsumowanie dnia, czujka, sprzatanie.

Sama petla nie zawiera zadnej logiki decyzyjnej — pyta silnik, co teraz wyslac,
i przekazuje to do wysylki. Dzieki temu wszystkie reguly pozostaja w jednym
miejscu i sa testowalne bez czekania.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

from .engine import Engine
from .notifiers.base import Dispatcher
from .store import Store, from_iso, to_iso

log = logging.getLogger(__name__)

#: Tik co 30 s wystarcza: najkrotszy istotny prog (okienko scalania) liczy sie
#: w sekundach, ale jego minicie wykrywa tez kolejne zdarzenie DNS.
DEFAULT_TICK_SECONDS = 30.0

#: Plik tetna dotykany po kazdym tiku.
#:
#: Czujka w silniku wykrywa cisze w danych, ale nie potrafi zglosic wlasnej
#: smierci: jesli caly proces zawisnie, nie wysle zadnego alarmu, bo alarm
#: wysyla ten sam proces. Tetno to warstwa NIZEJ — czyta je orkiestrator
#: (sonda liveness w k8s, healthcheck w Dockerze) i restartuje kontener.
HEARTBEAT_PATH = Path(os.environ.get("KIDWATCH_HEARTBEAT", "/tmp/kidwatch-heartbeat"))  # noqa: S108


def touch_heartbeat(path: Path | None = None) -> None:
    """Zapisuje czas ostatniego udanego tiku. Blad zapisu nie moze zabic petli.
    Bez `path` — biezace HEARTBEAT_PATH (nadzorca domow, E3b)."""
    path = HEARTBEAT_PATH if path is None else path
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(str(int(time.time())), encoding="utf-8")
    except OSError as exc:
        log.warning("nie moge zapisac tetna do %s: %s", path, exc)


async def tick_loop(
    engine: Engine,
    dispatcher: Dispatcher,
    store: Store,
    retention_days: int = 30,
    notifications_retention_days: int = 0,
    rollup_retention_days: int = 0,
    interval_seconds: float = DEFAULT_TICK_SECONDS,
    sleep=asyncio.sleep,
    max_iterations: int | None = None,
    heartbeat_path: Path | None = HEARTBEAT_PATH,
    tetno=None,
) -> None:
    """Woła `engine.tick()` w petli. `max_iterations` istnieje dla testow.

    `tetno()` — tetno domu (domy.HomeRuntime.dotknij_tetna) po udanym tiku.
    `heartbeat_path=None` — plik tetna procesu dotyka kto inny (nadzorca
    domow z izolacja awarii, E3b): tik jednego domu nie decyduje o liveness."""
    iteration = 0
    while max_iterations is None or iteration < max_iterations:
        iteration += 1
        try:
            notes = engine.tick()
            if notes:
                log.info("tik wygenerowal %d powiadomien", len(notes))
            await dispatcher.send_all(notes)
            _maybe_purge(
                store,
                retention_days,
                notifications_days=notifications_retention_days,
                rollup_days=rollup_retention_days,
            )
            # Dotykamy tetna DOPIERO po udanym tiku — inaczej zglaszalibysmy
            # zdrowie procesu, ktory w kazdym obiegu wywala wyjatek.
            if heartbeat_path is not None:
                touch_heartbeat(heartbeat_path)
            if tetno is not None:
                tetno()
        except asyncio.CancelledError:
            raise
        except Exception:
            # Wyjatek w tiku nie moze zabic petli, bo wtedy przestaje dzialac
            # takze czujka — czyli stracilibysmy jedyny sygnal, ze cos nie gra.
            log.exception("blad w tiku — kontynuuje")
        await sleep(interval_seconds)


def _maybe_purge(
    store: Store,
    retention_days: int,
    now: datetime | None = None,
    notifications_days: int = 0,
    rollup_days: int = 0,
) -> None:
    """Sprzata raz na dobe. Bez tego baza rosnie bez konca."""
    now = now or datetime.now(UTC)
    last = store.get_meta("last_purge")
    if last is not None and now - from_iso(last) < timedelta(days=1):
        return
    store.set_meta("last_purge", to_iso(now))
    deleted = store.purge(now, retention_days, notifications_days, rollup_days)
    removed = {k: v for k, v in deleted.items() if v}
    if removed:
        log.info("sprzatanie bazy: %s", removed)


#: Pauza przed ponownym otwarciem zrodla po bledzie, ktorego samo nie obsluzylo.
SOURCE_RESTART_SECONDS = 30.0


async def source_loop(
    source,
    engine: Engine,
    dispatcher: Dispatcher,
    store: Store,
    sleep=asyncio.sleep,
    restart_seconds: float = SOURCE_RESTART_SECONDS,
) -> None:
    """Czyta zdarzenia ze zrodla i przekazuje je silnikowi.

    Zrodlo samo ponawia polaczenia. Wyjatek, ktorego NIE przewidzialo, nie
    moze jednak konczyc tej petli: cmd_run zamyka proces po pierwszym
    zakonczonym zadaniu, wiec jeden nieznany format odpowiedzi zabijal tez
    TV, UniFi i panel. Otwieramy wtedy zrodlo od nowa — NextDNS wznawia od
    kursora w pamieci, AdGuard od odciskow w bazie. Normalny koniec strumienia
    (tylko w testach — prawdziwe zrodla sa nieskonczone) konczy petle.
    """
    while True:
        try:
            async for event in source.events():
                try:
                    notes = engine.handle(event)
                    await dispatcher.send_all(notes)
                    if event.cursor:
                        store.set_cursor(event.cursor_key or source.name, event.cursor)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    # Jedno zle zdarzenie nie moze zatrzymac strumienia.
                    log.exception("blad przy obsludze zdarzenia %r", event)
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception(
                "zrodlo %s padlo nieprzewidzianym bledem — otwieram je ponownie za %.0f s",
                source.name,
                restart_seconds,
            )
        await sleep(restart_seconds)


# ============================================== odczyt wprost z iPadow
#: Przypomnienie o procesach bez dopasowania (sama liczba na INFO) co tyle.
UNMATCHED_SUMMARY_EVERY = timedelta(hours=1)


class UnmatchedLog:
    """Log „procesy bez dopasowania” bez powtarzania tego samego co obieg.

    Bez listy aplikacji iPada (lockdown nie podal, brak katalogu MDM) KAZDY
    proces systemowy wyglada na nieznana aplikacje — ~150 nazw w jednej linii
    INFO co minute. Teraz:
      * INFO tylko z NOWYMI nazwami (nigdy dotad nie zgloszonymi),
      * DEBUG z pelna lista, gdy zbior sie zmienil,
      * INFO z sama liczba raz na UNMATCHED_SUMMARY_EVERY.
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self.reported: set[str] = set()
        self.last: frozenset[str] = frozenset()
        self.summary_at: datetime | None = None

    def report(self, names: set[str], now: datetime) -> None:
        current = frozenset(names)
        new = current - self.reported
        if new:
            log.info(
                "%s: nowe procesy bez dopasowania do aplikacji (%d z %d): %s",
                self.name, len(new), len(current), ", ".join(sorted(new)),
            )
            self.reported |= new
        if current != self.last:
            log.debug(
                "%s: procesy bez dopasowania do aplikacji (%d): %s",
                self.name, len(current), ", ".join(sorted(current)),
            )
        self.last = current
        if self.summary_at is None or now - self.summary_at >= UNMATCHED_SUMMARY_EVERY:
            if not new:
                log.info(
                    "%s: %d procesow bez dopasowania do aplikacji (pelna lista na DEBUG)",
                    self.name, len(current),
                )
            self.summary_at = now


async def device_loop(
    watchers,
    dispatcher: Dispatcher,
    interval_seconds: float,
    sleep=asyncio.sleep,
    max_iterations: int | None = None,
    unreachable_alert_hours: float = 24.0,
    store: Store | None = None,
) -> None:
    """Odpytuje iPady i wysyla roznice.

    NIEOSIAGALNY iPAD TO NORMALNY STAN, NIE AWARIA. iPad odpada od Wi-Fi, gdy
    zasnie, a spi wiekszosc doby — logowanie tego jako bledu zasypaloby logi i
    zniweczylo ich wartosc diagnostyczna. Dlatego pierwsza niedostepnosc danego
    urzadzenia jest na poziomie INFO, a powtorzenia schodza na DEBUG.

    ALE jest granica. Warstwa, ktora nie zadzialala ANI RAZU — bo zly adres,
    bo odczyt chodzi spoza sieci lokalnej iPada, bo brak rekordu parowania —
    wyglada DOKLADNIE tak samo jak spiacy iPad. Dlatego po
    `unreachable_alert_hours` bez jednego udanego odczytu zglaszamy to jako
    awarie. To ta sama logika, co sonda liveness dla samego procesu.
    """
    from .sources.base import Unreachable  # noqa: PLC0415

    unreachable: dict[str, int] = {}
    unmatched_logs: dict[str, UnmatchedLog] = {}
    iteration = 0
    while max_iterations is None or iteration < max_iterations:
        iteration += 1
        for watcher in watchers:
            name = watcher.device_name
            paused = getattr(watcher, "paused", None)
            if paused is not None and paused(datetime.now(UTC)):
                # Pauza monitoringu TV (tvpause.py): bez odczytu, bez
                # liczenia nieudanych prob.
                unreachable.pop(name, None)
                continue
            try:
                notes = await watcher.poll(datetime.now(UTC))
            except Unreachable as exc:
                misses = unreachable.get(name, 0) + 1
                unreachable[name] = misses
                if misses == 1:
                    log.info("%s nieosiagalny (spi albo poza siecia): %s", name, exc)
                else:
                    log.debug("%s nieosiagalny od %d prob", name, misses)
                # Telewizor wyjety z pradu w trakcie ogladania: sesje trzeba
                # domknac takze bez odpowiedzi (iPady tego haka nie maja —
                # ich sesje domyka warstwa DNS).
                on_unreachable = getattr(watcher, "on_unreachable", None)
                if on_unreachable is not None:
                    await dispatcher.send_all(on_unreachable(datetime.now(UTC)))
                continue
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("%s: nieoczekiwany blad odczytu", name)
                continue

            if unreachable.pop(name, 0):
                log.info("%s znowu odpowiada", name)
            if store is not None:
                store.set_meta(f"dev-ok:{name}", to_iso(datetime.now(UTC)))
            if notes:
                log.info("%s: %d zmian", name, len(notes))
            await dispatcher.send_all(notes)
            if watcher.unmatched:
                # Jak nieznane domeny w app_map.yaml — chcemy wiedziec, czego
                # brakuje w process_aliases, zeby nazwac apke po imieniu.
                unmatched_logs.setdefault(name, UnmatchedLog(name)).report(
                    watcher.unmatched, datetime.now(UTC)
                )
                watcher.unmatched.clear()

        if store is not None:
            await dispatcher.send_all(
                _unreachable_alerts(watchers, store, unreachable_alert_hours)
            )
        await sleep(interval_seconds)


def _unreachable_alerts(watchers, store: Store, alert_hours: float) -> list:
    """Zglasza urzadzenia, z ktorych nie udalo sie odczytac NIC przez zbyt dlugo.

    Bez tego blad konfiguracji (zly adres, odczyt spoza sieci lokalnej iPada,
    brak rekordu parowania) byl nieodrozialny od spiacego iPada —
    a cisza jest tu normalna, wiec nikt by tego nie zauwazyl.
    """
    from .models import Notification, NotifyKind  # noqa: PLC0415

    now = datetime.now(UTC)
    out = []
    for watcher in watchers:
        name = watcher.device_name
        paused = getattr(watcher, "paused", None)
        if paused is not None and paused(now):
            # W pauzie telewizora nie odpytujemy, wiec brak odczytu to norma.
            continue
        resumed_at = getattr(watcher, "resumed_at", None)
        resumed = resumed_at() if resumed_at is not None else None
        last = store.get_meta(f"dev-ok:{name}")
        first_seen_key = f"dev-since:{name}"
        if last is None:
            since = store.get_meta(first_seen_key)
            if since is None:
                store.set_meta(first_seen_key, to_iso(now))
                continue
            ref = from_iso(since)
            reason = "ANI RAZU nie udalo sie odczytac"
        else:
            ref = from_iso(last)
            reason = "brak udanego odczytu"
        # Po pauzie cisza liczy sie od jej konca: tydzien bez odczytu, bo
        # nikt nie pytal, to nie tydzien awarii.
        silent_for = now - (max(ref, resumed) if resumed is not None else ref)
        if silent_for < timedelta(hours=alert_hours):
            continue
        key = f"dev-unreachable:{name}:{now:%Y%m%d}"
        if not store.mark_sent(key, now):
            continue
        out.append(
            Notification(
                kind=NotifyKind.WATCHDOG,
                title=f"{name} — odczyt z urzadzenia nie dziala",
                text=(
                    f"{reason} od {int(silent_for.total_seconds() // 3600)} h.\n"
                    + getattr(
                        watcher,
                        "unreachable_hint",
                        "Sprawdz: adres iPada w konfiguracji (IPv4 w domowym LAN), "
                        "czy odczyt chodzi w tej samej sieci lokalnej co iPad "
                        "(iOS odrzuca lockdown przez VPN) i rekord parowania.",
                    )
                ),
                dedup_key=key,
                ts=now,
                device=name,
                priority=4,
                tags=("rotating_light",),
            )
        )
    return out
