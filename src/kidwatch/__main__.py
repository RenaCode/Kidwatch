"""CLI: run | replay | test-notify | summary | weekly | tv | tv-pauza | unifi | user-add | ..."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from .classifier import Classifier, registrable
from .config import Config, MissingSecretError
from .engine import Engine
from .models import DnsEvent, Notification, NotifyKind
from .notifiers.base import Dispatcher, Notifier, Outbox
from .notifiers.bramka import BramkaNotifier
from .notifiers.homeassistant import HomeAssistantNotifier
from .notifiers.ntfy import NtfyNotifier
from .scheduler import device_loop, source_loop, tick_loop
from .store import Store, from_iso

log = logging.getLogger("kidwatch")


# ======================================================================= montaz
def build_notifiers(cfg: Config) -> list[Notifier]:
    notifiers: list[Notifier] = []
    ntfy = cfg.notifiers.ntfy
    if ntfy and ntfy.enabled:
        notifiers.append(NtfyNotifier(ntfy, token=ntfy.token()))
    ha = cfg.notifiers.homeassistant
    if ha and ha.enabled:
        notifiers.append(HomeAssistantNotifier(ha, webhook_id=ha.webhook_id()))
    bramka = cfg.notifiers.bramka
    if bramka and bramka.enabled:
        notifiers.append(BramkaNotifier(bramka, key=bramka.key()))
    return notifiers


def nextdns_cursor(store: Store, profile: str, primary: str) -> str | None:
    """Kursor profilu. Profil glowny czytal dotad klucz `cursor:nextdns` —
    bez tej sciezki pierwszy start po aktualizacji zaczynalby od "teraz"
    i gubil zdarzenia z czasu restartu."""
    cursor = store.get_cursor(f"nextdns:{profile}")
    if cursor is None and profile == primary:
        cursor = store.get_cursor("nextdns")
    return cursor


def build_source(cfg: Config, store: Store):
    if cfg.source.kind == "nextdns":
        from .sources.nextdns import (  # noqa: PLC0415
            ConnectGate,
            MultiNextDnsSource,
            NextDnsSource,
        )

        nx = cfg.source.nextdns
        assert nx is not None
        profiles = cfg.nextdns_profiles
        device_filter = None
        if nx.server_side_device_filter and len(cfg.devices) == 1 and len(profiles) == 1:
            # Filtr po stronie API dziala po device.ID. Przy wielu urzadzeniach
            # przyjmuje jedna wartosc, wiec filtrujemy lokalnie.
            device_filter = cfg.devices[0].source_ids[0]
        key = nx.api_key()
        gate = ConnectGate(nx.connect_spacing_seconds)
        return MultiNextDnsSource([
            NextDnsSource(
                cfg=nx,
                api_key=key,
                cursor=nextdns_cursor(store, profile, nx.profile_id),
                device_filter=device_filter,
                profile_id=profile,
                cursor_key=f"nextdns:{profile}",
                gate=gate,
            )
            for profile in profiles
        ])

    from .sources.adguard import AdGuardSource  # noqa: PLC0415

    ag = cfg.source.adguard
    assert ag is not None
    return AdGuardSource(cfg=ag, password=ag.password(), store=store)


def load_parts(config_path: str) -> tuple[Config, Store, Engine]:
    cfg = Config.load(config_path)
    store = Store(cfg.store.path)
    classifier = Classifier(cfg.app_map_path)
    return cfg, store, Engine(cfg, store, classifier)


# ======================================================================= wydruk
def render(note: Notification) -> str:
    icon = {
        NotifyKind.SESSION_START: "[START] ",
        NotifyKind.APP: "[APKA]  ",
        NotifyKind.SESSION_END: "[KONIEC]",
        NotifyKind.DAILY: "[DZIEN] ",
        NotifyKind.THROTTLED: "[ZBIOR] ",
        NotifyKind.WATCHDOG: "[CZUJKA]",
        NotifyKind.NIGHT: "[NOC]   ",
        NotifyKind.WEEKLY: "[TYDZ]  ",
        NotifyKind.GAME: "[GRA]   ",
        NotifyKind.TV_PAUSE: "[PAUZA] ",
    }.get(note.kind, f"[{note.kind}]")
    body = note.text.replace("\n", "\n          ")
    return f"{icon} {note.title}\n          {body}"


# ========================================================================== run
OUTBOX_FLUSH_ON_STOP_SECONDS = 10.0


async def cmd_run(args) -> int:
    cfg, store, engine = load_parts(args.config)
    if cfg.tv.enabled:
        from .tvpause import TvPauseRequests  # noqa: PLC0415

        # Zadania pauzy TV z panelu i z `tv-pauza` wykonuje tik silnika.
        engine.tv_pause.requests = TvPauseRequests(cfg.panel_auth_path)
    # Petle oddaja powiadomienia do kolejki w bazie; wysyla je osobne zadanie
    # "outbox". Wiszacy kanal nie trzyma tiku (tetno, liveness) ani strumienia.
    dispatcher = Outbox(Dispatcher(build_notifiers(cfg), store=store), store)
    source = build_source(cfg, store)

    log.info(
        "start: zrodlo=%s urzadzenia=%s kanaly=%s",
        source.name,
        [d.display_name for d in cfg.devices],
        [n.name for n in dispatcher.notifiers],
    )
    if not dispatcher.notifiers:
        log.warning("zaden kanal powiadomien nie jest wlaczony — nic nie dotrze")

    panel = None
    if cfg.panel.enabled:
        from .panel import start_panel  # noqa: PLC0415

        panel = start_panel(cfg)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # pragma: no cover
            loop.add_signal_handler(sig, stop.set)

    tasks = [
        asyncio.create_task(source_loop(source, engine, dispatcher, store), name="source"),
        asyncio.create_task(
            tick_loop(
                engine,
                dispatcher,
                store,
                retention_days=cfg.store.retention_days,
                notifications_retention_days=cfg.store.notifications_retention_days,
                rollup_retention_days=cfg.store.rollup_retention_days,
            ),
            name="tick",
        ),
        asyncio.create_task(dispatcher.run(), name="outbox"),
        asyncio.create_task(stop.wait(), name="stop"),
    ]

    # Odczyt z iPadow jedzie w TYM SAMYM procesie, nie w osobnym kontenerze.
    # SQLite ma jednego pisarza — dwa procesy na jednej bazie rozjechalyby stan
    # i zdublowaly powiadomienia. Ten sam powod, dla ktorego Deployment ma
    # replicas:1 i strategie Recreate.
    watchers = build_watchers(cfg, store) if cfg.device_read.enabled else []
    if watchers:
        log.info(
            "odczyt z iPadow wlaczony: %s, co %.0f s",
            [w.device_name for w in watchers],
            cfg.device_read.poll_seconds,
        )
        tasks.insert(
            2,
            asyncio.create_task(
                device_loop(
                    watchers,
                    dispatcher,
                    cfg.device_read.poll_seconds,
                    unreachable_alert_hours=cfg.device_read.unreachable_alert_hours,
                    store=store,
                ),
                name="device",
            ),
        )
    elif cfg.device_read.enabled:
        log.warning("device_read.enabled=true, ale zadne urzadzenie nie ma udid i host")

    # Telewizor: ta sama petla co iPady (nieosiagalny = normalny stan, alarm
    # po wielu godzinach), z wlasnym rytmem i progiem.
    tv = build_tv_watcher(cfg, store) if cfg.tv.enabled else None
    if tv is not None:
        log.info("czujnik TV wlaczony: %s (%s), co %.0f s",
                 cfg.tv.name, cfg.tv.host, cfg.tv.poll_seconds)
        tasks.insert(2, asyncio.create_task(
            device_loop(
                [tv],
                dispatcher,
                cfg.tv.poll_seconds,
                unreachable_alert_hours=cfg.tv.unreachable_alert_hours,
                store=store,
            ),
            name="tv",
        ))

    unifi = build_unifi_watcher(cfg, store) if cfg.unifi.enabled else None
    if unifi is not None:
        from .sources.unifi import unifi_loop  # noqa: PLC0415

        log.info("czujka UniFi wlaczona: %s, iPady: %s",
                 cfg.unifi.url, [d[0] for d in unifi.devices])
        tasks.insert(2, asyncio.create_task(
            unifi_loop(unifi, dispatcher, cfg.unifi.poll_seconds), name="unifi"
        ))

    game = build_game_time(cfg, store, dispatcher) if cfg.game_time.enabled else None
    if game is not None:
        from .gametime import game_loop  # noqa: PLC0415

        log.info("czas gry wlaczony: profile %s, uslugi %s, kategorie %s",
                 sorted(set(game.profiles.values())), cfg.game_time.services,
                 cfg.game_time.categories)
        tasks.insert(2, asyncio.create_task(
            game_loop(game, cfg.game_time.poll_seconds), name="game"
        ))

    done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    # Kazde zadanie poza "stop" jest nieskonczone, wiec jego koniec — z bledem
    # czy bez — to awaria. Kod 0 udawal w k8s czyste zatrzymanie i ginal
    # w statystyce restartow; niezerowy widac w `kubectl describe` jako Error.
    failed = [task for task in done if task.get_name() != "stop"]
    for task in failed:
        if task.exception() is not None:
            log.error(
                "zadanie %s zakonczylo sie bledem",
                task.get_name(),
                exc_info=task.exception(),
            )
        else:
            log.error("zadanie %s zakonczylo sie bez bledu, a nie powinno", task.get_name())

    if panel is not None:
        panel.shutdown()
    for watcher in [*watchers, *([tv] if tv else [])]:
        await watcher.probe.aclose()
    if game is not None:
        await game.client.aclose()
    # Co zostalo w kolejce, probujemy wyslac przed zamknieciem — reszta i tak
    # wyjdzie po starcie. Krocej niz terminationGracePeriodSeconds (30 s).
    with contextlib.suppress(Exception):
        await asyncio.wait_for(dispatcher.flush(), timeout=OUTBOX_FLUSH_ON_STOP_SECONDS)
    await dispatcher.aclose()
    await source.aclose()
    store.close()
    log.info("zatrzymano")
    return 1 if failed else 0


# ======================================================================= replay
def read_jsonl(path: Path):
    """Czyta zapis dnia. Kazda linia: {"ts": ISO8601, "device": str, "domain": str}."""
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            raw = json.loads(line)
            ts = datetime.fromisoformat(str(raw["ts"]).replace("Z", "+00:00"))
            if ts.tzinfo is None:
                raise ValueError("ts bez strefy czasowej")
            yield DnsEvent(ts=ts, device_id=str(raw["device"]), domain=str(raw["domain"]))
        except (KeyError, ValueError, json.JSONDecodeError) as exc:
            raise SystemExit(f"{path}:{number}: niepoprawna linia ({exc})") from exc


async def cmd_replay(args) -> int:
    cfg = Config.load(args.config)
    # Odtwarzanie NIGDY nie dotyka prawdziwej bazy: inaczej jeden przebieg testowy
    # zapisalby klucze dedupu i zablokowal prawdziwe powiadomienia.
    store = Store(":memory:")
    engine = Engine(cfg, store, Classifier(cfg.app_map_path))

    notifiers = [] if args.dry_run else build_notifiers(cfg)
    dispatcher = Dispatcher(notifiers)

    events = list(read_jsonl(Path(args.file)))
    if not events:
        print("plik nie zawiera zdarzen")
        return 1

    produced: list[Notification] = []
    for event in events:
        notes = engine.handle(event)
        produced += notes
        await dispatcher.send_all(notes)

    # Domknij sesje, ktore zostaly otwarte na koncu zapisu, i wypchnij
    # podsumowanie dnia — inaczej ostatnia sesja nigdy by sie nie zamknela.
    last = events[-1].ts
    tail = engine.tick(last + timedelta(minutes=cfg.engine.idle_minutes + 1))
    produced += tail
    await dispatcher.send_all(tail)

    for note in produced:
        print(render(note))

    print(f"\n--- {len(events)} zdarzen -> {len(produced)} powiadomien ---")
    store.close()
    await dispatcher.aclose()
    return 0


# ================================================================== test-notify
async def cmd_test_notify(args) -> int:
    cfg = Config.load(args.config)
    dispatcher = Dispatcher(build_notifiers(cfg))
    if not dispatcher.notifiers:
        print("zaden kanal nie jest wlaczony w konfiguracji", file=sys.stderr)
        return 1

    note = Notification(
        kind=NotifyKind.SESSION_START,
        title="kidwatch — próbny push",
        text=(
            "Jeśli to widzisz, kanał działa.\n"
            "Zażółć gęślą jaźń — sprawdzenie polskich znaków."
        ),
        dedup_key=f"test:{datetime.now(UTC).isoformat()}",
        ts=datetime.now(UTC),
        device="test",
        priority=3,
        tags=("white_check_mark",),
    )
    results = await dispatcher.send(note)
    await dispatcher.aclose()
    for name, ok in results.items():
        print(f"{name}: {'wyslano' if ok else 'NIE UDALO SIE'}")
    return 0 if all(results.values()) else 1


# ====================================================================== domains
async def cmd_domains(args) -> int:
    """Wypisuje najczestsze domeny z bazy — do uzupelniania app_map.yaml.

    Bez tego rozszerzanie mapy jest zgadywaniem. Gry sa tu najtrudniejszym
    przypadkiem: gadaja malo i glownie przez wspoldzielone CDN-y, a wydawcy
    zmieniaja zaplecze. Jedyne wiarygodne zrodlo to wlasne logi.
    """
    cfg, store, _ = load_parts(args.config)
    since = datetime.now(UTC) - timedelta(days=args.days)

    kinds = ("unknown",) if args.unknown_only else None
    rows = store.top_domains(since, kinds=kinds, limit=args.limit)
    if not rows:
        scope = " w kategorii 'unknown'" if args.unknown_only else ""
        print(f"brak zdarzen z ostatnich {args.days} dni{scope}.")
        print("Uruchom `kidwatch run`, zeby zebrac dane.")
        store.close()
        return 0

    # Zwijamy poddomeny, bo do app_map.yaml wpisujesz domene, nie kazdy host.
    grouped: dict[tuple[str, str, str | None], dict] = {}
    for row in rows:
        key = (registrable(row["domain"]), row["kind"], row["app"])
        entry = grouped.setdefault(key, {"n": 0, "devices": 0, "hosts": set()})
        entry["n"] += row["n"]
        entry["devices"] = max(entry["devices"], row["devices"])
        entry["hosts"].add(row["domain"])

    # Nierozpoznane na gorze: to one wymagaja Twojej decyzji.
    order = {"unknown": 0, "ambiguous": 1, "app": 2, "noise": 3}
    items = sorted(grouped.items(), key=lambda kv: (order.get(kv[0][1], 9), -kv[1]["n"]))

    print(f"Domeny z ostatnich {args.days} dni (zwiniete do domeny rejestrowalnej):")
    print()
    print(f"{'domena':38} {'kategoria':10} {'zapytan':>8} {'hostow':>7}  aplikacja")
    print("-" * 88)
    for (domain, kind, app), data in items:
        print(f"{domain:38} {kind:10} {data['n']:8} {len(data['hosts']):7}  {app or ''}")

    unknown = [i for i in items if i[0][1] == "unknown"]
    if unknown:
        print()
        print(f"{len(unknown)} nierozpoznanych domen. Te z gory listy warto dopisac do")
        print(f"{cfg.app_map_path} — lokalnie przeladowuje sie na goraco; w klastrze")
        print("zmiana w charcie restartuje poda (checksum/app-map).")
        print()
        print("Przyklad wpisu:")
        print()
        print("  apps:")
        print('    "Nazwa gry":')
        print(f"      - {unknown[0][0][0]}")
    store.close()
    return 0


# ========================================================================== web
#: Nazwy dni po polsku. Nie polegamy na locale procesu — w kontenerze jest C,
#: a w terminalu uzytkownika co innego, i raport wygladalby inaczej w kazdym
#: miejscu uruchomienia.
DNI = ("poniedzialek", "wtorek", "sroda", "czwartek", "piatek", "sobota", "niedziela")


async def cmd_web(args) -> int:
    """Raport odwiedzonych domen per dziecko per dzien.

    To jest granica tego, co DNS wie o przegladaniu: domena, liczba zapytan,
    kiedy. Adresu strony ani tresci nie widzi nic poza proxy z wlasnym CA.
    """
    cfg, store, engine = load_parts(args.config)
    today = datetime.now(cfg.tz).date()
    days = [today - timedelta(days=i) for i in range(args.days)]

    only = args.device.strip().lower() if args.device else None
    devices = [d for d in cfg.devices if only is None or d.display_name.lower() == only]
    if not devices:
        print(f"nie znam urzadzenia {args.device!r}. Znane: "
              + ", ".join(d.display_name for d in cfg.devices))
        store.close()
        return 1

    printed = False
    for day in days:
        start = datetime.combine(day, datetime.min.time(), tzinfo=cfg.tz)
        end = start + timedelta(days=1)
        header_done = False
        for dev in devices:
            browsed = store.browsed_since(dev.display_name, start, end)
            sessions = [
                r for r in store.sessions_between(start, end)
                if r["device"] == dev.display_name and int(r["start_notified"])
            ]
            apps: dict[str, int] = {}
            for row in sessions:
                for app, n in store.session_app_minutes(int(row["id"])):
                    apps[app] = apps.get(app, 0) + n
            if not browsed and not apps:
                continue
            if not header_done:
                print(f"\n=== {DNI[day.weekday()]} {day:%d.%m.%Y} ===")
                header_done = True
            printed = True
            print(f"\n{dev.display_name} ({dev.child})")
            if apps:
                top = sorted(apps.items(), key=lambda kv: (-kv[1], kv[0]))
                print("  aplikacje: " + ", ".join(f"{a} ~{n} min" for a, n in top[:8]))
            if browsed:
                # Zwijamy hosty do domen, bo kilkadziesiat hostow jednej witryny
                # to dla czlowieka jedna nazwa.
                counts: dict[str, int] = {}
                for host, n in browsed:
                    counts[registrable(host)] = counts.get(registrable(host), 0) + n
                print(f"  strony ({len(counts)} domen):")
                for name, n in sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[: args.limit]:
                    print(f"    {n:5}x  {name}")
            else:
                print("  strony: brak nierozpoznanego ruchu")

    if not printed:
        print(f"brak danych z ostatnich {args.days} dni. Uruchom `kidwatch run`.")
    else:
        print(
            "\nDNS widzi DOMENY, nie adresy stron ani tresc. Domeny nieznanych\n"
            "aplikacji i gier mozesz nazwac: kidwatch domains --unknown-only"
        )
    store.close()
    return 0


# ======================================================================= device
def build_tv_watcher(cfg, store):
    """Obserwator telewizora albo None (z bledem w logu), gdy brak klucza ADB.

    Brak klucza nie zabija procesu — jak przy rekordach parowania iPadow:
    klucz zaklada sie recznie PO wdrozeniu, a DNS ma dzialac od razu.
    """
    from .sources.tv import AdbTcpShell, TvProbe, TvWatcher  # noqa: PLC0415

    try:
        shell = AdbTcpShell(cfg.tv.host, cfg.tv.port, cfg.tv.adb_key_dir, cfg.tv.timeout_seconds)
    except (FileNotFoundError, ValueError) as exc:
        log.error("%s: czujnik TV wylaczony — %s", cfg.tv.name, exc)
        return None
    probe = TvProbe(shell)
    hybryda = build_tv_traffic(cfg, store, probe)
    return TvWatcher(
        hybryda or probe,
        cfg.tv.name,
        store,
        tz=cfg.tz,
        idle_minutes=cfg.tv.idle_minutes,
        apps=cfg.tv.apps,
        quiet_hours=cfg.engine.quiet_hours,
        usage_minutes=cfg.tv.usage_poll_minutes,
        adb_alert_minutes=cfg.tv.adb_alert_minutes,
    )


def build_tv_traffic(cfg, store, probe):
    """Hybryda ADB + ruch sieci (sources/tv_siec.py) albo None, gdy UniFi nie
    jest skonfigurowane - wtedy telewizor czytany jest jak dotad, samym ADB."""
    from .sources.tv_siec import HybridProbe, LicznikRuchu  # noqa: PLC0415
    from .sources.unifi import UnifiClient  # noqa: PLC0415

    if not cfg.tv.traffic:
        return None
    key = cfg.unifi.api_key() if cfg.unifi.enabled else None
    if not key or not cfg.unifi.cert_sha256:
        log.info("%s: zapas z ruchu sieci wylaczony — brak skonfigurowanego UniFi",
                 cfg.tv.name)
        return None
    client = UnifiClient(cfg.unifi.url, cfg.unifi.site, key, cfg.unifi.cert_sha256,
                         cfg.unifi.timeout_seconds)
    licznik = LicznikRuchu(client, cfg.tv.host, cfg.tv.unifi_mac,
                           okno_min=cfg.tv.traffic_window_minutes,
                           odswiez_s=cfg.unifi.poll_seconds)
    log.info("%s: zapas z ruchu sieci wlaczony (UniFi, prog %.0f MB / %.0f min%s)",
             cfg.tv.name, cfg.tv.traffic_min_mb, cfg.tv.traffic_window_minutes,
             ", serwis z NextDNS" if cfg.tv.nextdns_ids else "")
    return HybridProbe(probe, licznik, store, prog_mb=cfg.tv.traffic_min_mb,
                       nextdns_ids=cfg.tv.nextdns_ids, device_name=cfg.tv.name)


def build_game_time(cfg: Config, store: Store, dispatcher):
    """Sterownik czasu gry. Id uslug spoza znanej listy tylko ostrzegaja —
    NextDNS doklada uslugi, a nieistniejace id odrzuci samo API przy zapisie
    (blad widac w panelu, w logu i w pushu)."""
    from .gametime import GameRequests, GameTime, ParentalControlClient  # noqa: PLC0415

    unknown = cfg.game_time.unknown_services()
    if unknown:
        log.warning(
            "game_time.services: %s nie ma na znanej liscie uslug NextDNS — jesli to "
            "literowka, NextDNS odrzuci zapis; jesli nowa usluga, zignoruj", unknown
        )
    nx = cfg.source.nextdns
    assert nx is not None
    client = ParentalControlClient(nx.base_url, nx.api_key(), timeout=cfg.game_time.timeout_seconds)
    return GameTime(cfg, store, GameRequests(cfg.panel_auth_path), client, dispatcher)


def build_unifi_watcher(cfg, store):
    """Czujka UniFi albo None z ostrzezeniem — bez klucza, bez odcisku
    certyfikatu albo bez zadnego MAC-a nie ma czego uruchamiac."""
    from .sources.unifi import UnifiClient, UnifiWatcher  # noqa: PLC0415

    key = cfg.unifi.api_key()
    devices = [
        (d.display_name, d.unifi_mac, d.unifi_ip) for d in cfg.devices if d.unifi_mac or d.unifi_ip
    ]
    why = None
    if not key:
        why = "brak UNIFI_API_KEY w srodowisku (Sekret kidwatch-secrets)"
    elif not cfg.unifi.cert_sha256:
        why = ("brak unifi.cert_sha256 — bez przypietego certyfikatu klucz API "
               "nie zostanie wyslany (odczyt: python -m kidwatch unifi --fingerprint)")
    elif not devices:
        why = "zadne urzadzenie nie ma unifi_mac ani unifi_ip"
    if why:
        log.warning("czujka UniFi wylaczona: %s", why)
        return None
    client = UnifiClient(cfg.unifi.url, cfg.unifi.site, key, cfg.unifi.cert_sha256,
                         cfg.unifi.timeout_seconds)
    return UnifiWatcher(
        client,
        devices,
        store,
        window_minutes=cfg.unifi.window_minutes,
        alarm_mb=cfg.unifi.alarm_mb,
        repeat_backoff_max_minutes=cfg.unifi.repeat_backoff_max_minutes,
    )


def build_watchers(cfg, store):
    """Buduje obserwatorow dla urzadzen, ktore maja udid i host.

    Brak rekordu parowania POJEDYNCZEGO urzadzenia pomija tylko je. Wczesniej
    wyjatek leciał az do main() i zabijal caly proces — razem z warstwa DNS,
    ktora z parowaniem nie ma nic wspolnego. A rekordy zakladasz recznie PO
    wdrozeniu, wiec pod wpadalby w petle restartow dokladnie w tym okienku.
    """
    from .sources.device import (  # noqa: PLC0415
        DeviceProbe,
        DeviceTarget,
        DeviceUnavailable,
        DeviceWatcher,
    )

    out = []
    for dev in cfg.devices:
        if not dev.reads_device:
            continue
        try:
            probe = DeviceProbe.over_tcp(
                DeviceTarget(udid=dev.udid, host=dev.host),
                cfg.device_read.records_path,
                timeout=cfg.device_read.timeout_seconds,
            )
        except DeviceUnavailable as exc:
            log.error("%s: pomijam odczyt z urzadzenia — %s", dev.display_name, exc)
            continue
        out.append(
            DeviceWatcher(
                probe,
                device_name=dev.display_name,
                child=dev.child,
                store=store,
                tz=cfg.tz,
                aliases=cfg.device_read.process_aliases,
                max_per_hour=cfg.device_read.max_notifications_per_hour,
                quiet_hours=cfg.engine.quiet_hours,
                fallback_apps=dev.known_apps,
            )
        )
    return out


async def cmd_device(args) -> int:
    """Jednorazowy odczyt stanu iPadow — do sprawdzenia konfiguracji."""
    from .sources.device import DeviceUnavailable  # noqa: PLC0415

    cfg, store, _ = load_parts(args.config)
    watchers = build_watchers(cfg, store)
    if not watchers:
        print(
            "Zadne urzadzenie nie ma 'udid' i 'host' w konfiguracji.\n"
            "Adresy i UDID-y znajdziesz komenda:  pymobiledevice3 bonjour mobdev2"
        )
        store.close()
        return 1

    rc = 0
    for w in watchers:
        print(f"\n=== {w.device_name} ({w.child}) — {w.probe.target.host} ===")
        try:
            snap = await w.probe.snapshot()
        except DeviceUnavailable as exc:
            print(f"  NIEOSIAGALNY: {exc}")
            print("  To normalne, gdy iPad spi — odpada wtedy od Wi-Fi.")
            rc = 1
            continue
        finally:
            await w.probe.aclose()

        print(f"  aplikacje uzytkownika ({len(snap.apps)}):")
        for bid, app in sorted(snap.apps.items(), key=lambda kv: kv[1].label.lower()):
            print(f"    {app.label[:32]:32} {bid}")
        from .sources.device import looks_like_app  # noqa: PLC0415

        running = {
            pid: label
            for pid, proc in snap.running.items()
            if (label := looks_like_app(proc, snap.apps, cfg.device_read.process_aliases))
        }
        print(f"  odpalone ({len(running)} z {len(snap.running)} procesow):")
        for pid, label in sorted(running.items()):
            print(f"    pid {pid:<6} {label}")
        state = {True: "WLACZONY", False: "WYGASZONY", None: "nieznany"}[snap.screen_on]
        print(f"  ekran: {state}")
    store.close()
    return rc


async def cmd_device_watch(args) -> int:
    """Petla: odpytuje iPady i wysyla powiadomienia o zmianach."""
    cfg, store, _ = load_parts(args.config)
    watchers = build_watchers(cfg, store)
    if not watchers:
        print("Zadne urzadzenie nie ma 'udid' i 'host' — nie ma czego odpytywac.", file=sys.stderr)
        store.close()
        return 1

    dispatcher = Dispatcher(build_notifiers(cfg), store=store)
    log.info(
        "odczyt z iPadow: %s, co %.0f s",
        [w.device_name for w in watchers],
        cfg.device_read.poll_seconds,
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # pragma: no cover
            loop.add_signal_handler(sig, stop.set)

    task = asyncio.create_task(
        device_loop(
            watchers,
            dispatcher,
            cfg.device_read.poll_seconds,
            unreachable_alert_hours=cfg.device_read.unreachable_alert_hours,
            store=store,
        ),
        name="device",
    )
    await asyncio.wait(
        [task, asyncio.create_task(stop.wait())], return_when=asyncio.FIRST_COMPLETED
    )
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    for w in watchers:
        await w.probe.aclose()
    await dispatcher.aclose()
    store.close()
    return 0


# =========================================================================== tv
async def cmd_tv(args) -> int:
    """Jednorazowy odczyt telewizora — do sprawdzenia klucza ADB i tunelu.

    `--raw` wypisuje surowe odpowiedzi dumpsys. Tak nagrywa sie probki do
    tests/fixtures/tv/ po aktualizacji systemu TV albo nowej aplikacji.
    """
    from .sources.tv import AdbTcpShell, TvProbe, TvUnavailable, parse_snapshot  # noqa: PLC0415

    cfg = Config.load(args.config)
    try:
        shell = AdbTcpShell(cfg.tv.host, cfg.tv.port, cfg.tv.adb_key_dir, cfg.tv.timeout_seconds)
    except FileNotFoundError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2
    probe = TvProbe(shell)
    try:
        raw = await probe.raw()
        raw["usage"] = await probe.usage()
    except TvUnavailable as exc:
        print(f"{cfg.tv.name} ({cfg.tv.host}:{cfg.tv.port}) NIEOSIAGALNY: {exc}")
        return 1
    finally:
        await probe.aclose()
    if args.raw:
        for key, text in raw.items():
            print(f"===== {key} =====\n{text}")
        return 0
    from .sources.tv import parse_usagestats  # noqa: PLC0415

    usage = parse_usagestats(raw["usage"])
    if usage is None:
        print("usagestats: brak bloku daily (inny format? sprawdz --raw)")
    else:
        top = sorted(usage.packages.items(), key=lambda kv: -kv[1][0])[:8]
        print("usagestats (biezacy interwal dzienny): " + ", ".join(
            f"{pkg} {ms // 60000} min" for pkg, (ms, _) in top if ms
        ))
    snap = parse_snapshot(raw["media"], raw["activity"], raw["power"])
    print(f"{cfg.tv.name}: ekran {'WLACZONY' if snap.awake else 'uspiony'}, "
          f"na pierwszym planie: {snap.foreground or '-'}")
    for sess in snap.sessions:
        print(f"  sesja {sess.package}: active={sess.active} state={sess.state} "
              f"tytul={sess.title!r} kanal={sess.channel!r}")
    playing = snap.playing(cfg.tv.apps)
    print(f"gra: {playing.label if playing else 'nic'}")
    return 0


# ======================================================================== unifi
async def cmd_tv_pause(args) -> int:
    """Pauza monitoringu TV z wiersza polecen — to samo co przycisk w panelu.
    Zleca zadanie w panel-auth.db; wykonuje je (i wysyla push) dzialajacy
    `run`, wiec baza ma dalej jednego pisarza."""
    from .tvpause import (  # noqa: PLC0415
        TooManyRequests,
        TvPauseRequests,
        fmt_until,
        parse_until,
    )

    cfg = Config.load(args.config)
    if not cfg.tv.enabled:
        print("czujnik TV jest wylaczony (tv.enabled: false)", file=sys.stderr)
        return 2
    now = datetime.now(UTC)
    if args.do is None and not args.do_odwolania and not args.wznow:
        with Store(cfg.store.path) as store:
            row = store.tv_paused_at(now)
        if row is None:
            print(f"{cfg.tv.name}: monitoring dziala")
        else:
            until = from_iso(row["until"]) if row["until"] else None
            print(f"{cfg.tv.name}: monitoring wstrzymany {fmt_until(until, cfg.tz)} "
                  f"(od {from_iso(row['started_at']).astimezone(cfg.tz):%d.%m %H:%M}, "
                  f"wlaczone przez: {row['started_by'] or '?'})")
        return 0
    if args.wznow:
        action, until = "resume", None
    else:
        action = "pause"
        try:
            until = None if args.do_odwolania else parse_until(args.do, cfg.tz, now)
        except ValueError as exc:
            print(f"--do: {exc}", file=sys.stderr)
            return 2
    try:
        TvPauseRequests(cfg.panel_auth_path).submit(action, until, "cli")
    except TooManyRequests:
        print("za duzo oczekujacych zadan — czy `run` dziala?", file=sys.stderr)
        return 1
    what = "wznowienie" if action == "resume" else f"wstrzymanie {fmt_until(until, cfg.tz)}"
    print(f"zlecono {what} monitoringu {cfg.tv.name}; wykona je `run` w ciagu ~30 s")
    return 0


async def cmd_unifi(args) -> int:
    """`--fingerprint`: odcisk certyfikatu kontrolera (nic nie wysyla). Bez
    opcji: kto z `devices[].unifi_mac` jest teraz w domowym Wi-Fi."""
    from .sources.unifi import UnifiClient, UnifiError, server_fingerprint  # noqa: PLC0415

    cfg = Config.load(args.config)
    if args.fingerprint:
        got = server_fingerprint(cfg.unifi.url, cfg.unifi.timeout_seconds)
        print(":".join(got[i:i + 2] for i in range(0, 64, 2)).upper())
        print("Porownaj z odczytem z sieci domowej (openssl s_client), zanim wpiszesz "
              "go do unifi.cert_sha256.", file=sys.stderr)
        return 0
    key = cfg.unifi.api_key()
    if not key or not cfg.unifi.cert_sha256:
        print("potrzebne UNIFI_API_KEY w srodowisku i unifi.cert_sha256 w konfiguracji",
              file=sys.stderr)
        return 2
    client = UnifiClient(cfg.unifi.url, cfg.unifi.site, key, cfg.unifi.cert_sha256,
                         cfg.unifi.timeout_seconds)
    try:
        stations = await client.stations()
    except UnifiError as exc:
        print(f"UniFi: {exc}", file=sys.stderr)
        return 1
    by_mac = {str(s.get("mac", "")).lower(): s for s in stations}
    by_ip = {str(s.get("ip", "")): s for s in stations if s.get("ip")}
    print(f"klientow w sieci: {len(stations)}")
    for dev in cfg.devices:
        if not dev.unifi_mac and not dev.unifi_ip:
            print(f"  {dev.display_name:20} brak unifi_mac i unifi_ip")
            continue
        sta = (by_mac.get(dev.unifi_mac) if dev.unifi_mac else None) or (
            by_ip.get(dev.unifi_ip) if dev.unifi_ip else None
        )
        if sta is None:
            print(f"  {dev.display_name:20} POZA DOMEM (albo inny, prywatny MAC)")
        else:
            mb = (int(sta.get("tx_bytes") or 0) + int(sta.get("rx_bytes") or 0)) / 1e6
            print(f"  {dev.display_name:20} w domu: {sta.get('essid')}, {sta.get('ip')}, "
                  f"{mb:.0f} MB od polaczenia")
    return 0


# ====================================================================== summary
async def cmd_summary(args) -> int:
    cfg, store, engine = load_parts(args.config)
    day = date.fromisoformat(args.date) if args.date else datetime.now(cfg.tz).date()
    # Nie zajmujemy klucza dedupu: `summary` ma dawac sie wolac wielokrotnie,
    # a zajety klucz `daily:<dzien>` wylaczylby prawdziwe podsumowanie o 20:30.
    print(render(engine.build_summary(day, datetime.now(UTC))))
    store.close()
    return 0


# ======================================================================= weekly
def parse_week(raw: str) -> date:
    """"2026-W40" -> poniedzialek tego tygodnia ISO."""
    import re  # noqa: PLC0415

    m = re.fullmatch(r"(\d{4})-W(\d{1,2})", raw.strip(), flags=re.IGNORECASE)
    if not m:
        raise SystemExit(f"--week {raw!r}: oczekuje YYYY-Www, np. 2026-W40")
    try:
        return date.fromisocalendar(int(m.group(1)), int(m.group(2)), 1)
    except ValueError as exc:
        raise SystemExit(f"--week {raw!r}: {exc}") from exc


async def cmd_weekly(args) -> int:
    """Raport tygodniowy. Tak jak `summary` NIE zajmuje klucza dedupu
    (weekly:<tydzien>) — inaczej prawdziwy raport w niedziele przepadlby.
    Bez --dry-run wysyla go kanalami (proba kanalu na prawdziwej tresci)."""
    from .engine import report_week  # noqa: PLC0415

    cfg, store, engine = load_parts(args.config)
    now = datetime.now(UTC)
    monday = parse_week(args.week) if args.week else report_week(now.astimezone(cfg.tz).date())
    note = engine.build_weekly(monday, now)
    print(render(note))
    rc = 0
    if not args.dry_run:
        dispatcher = Dispatcher(build_notifiers(cfg))
        if not dispatcher.notifiers:
            print("zaden kanal nie jest wlaczony — tylko wydruk", file=sys.stderr)
        results = await dispatcher.send(note)
        await dispatcher.aclose()
        for name, ok in results.items():
            print(f"{name}: {'wyslano' if ok else 'NIE UDALO SIE'}", file=sys.stderr)
        rc = 0 if all(results.values()) else 1
    store.close()
    return rc


# ======================================================================== konta
def _auth(cfg: Config):
    from .panel_auth import PanelAuth  # noqa: PLC0415

    return PanelAuth(cfg.panel_auth_path)


def _new_password(args) -> tuple[str, bool]:
    """(haslo, czy_wygenerowane). Haslo NIGDY z argumentu wiersza polecen:
    trafiloby do historii powloki i do `ps` kazdego, kto patrzy na wezel."""
    from .panel_auth import generate_password  # noqa: PLC0415

    if args.password_stdin:
        password = sys.stdin.readline().rstrip("\r\n")
        if not password:
            raise SystemExit("--password-stdin: na stdin nie ma hasla")
        return password, False
    return generate_password(), True


def _print_generated(login: str, password: str) -> None:
    # Wypisane RAZ. W bazie jest tylko hash, wiec drugiej okazji nie bedzie.
    print(f"login: {login}")
    print(f"haslo: {password}")
    print("Zapisz je teraz — nie da sie go odczytac ponownie, tylko zresetowac.")


async def cmd_user_add(args) -> int:
    from .panel_auth import UserExists  # noqa: PLC0415

    cfg = Config.load(args.config)
    password, generated = _new_password(args)
    try:
        _auth(cfg).add_user(args.login, password)
    except UserExists:
        print(f"konto {args.login!r} juz istnieje — uzyj user-reset", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    print(f"zalozono konto panelu {args.login!r} ({cfg.panel_auth_path})")
    if generated:
        _print_generated(args.login, password)
    print("Weryfikacje dwuetapowa (TOTP) wlaczysz po zalogowaniu: menu konta -> Wlacz 2FA.")
    return 0


async def cmd_user_reset(args) -> int:
    from .panel_auth import UnknownUser  # noqa: PLC0415

    cfg = Config.load(args.config)
    if args.totp:
        # Osobno od hasla: zgubiony telefon to nie zapomniane haslo, a reset
        # obu naraz bylby dla kogos, kto zna tylko jedno z nich, prezentem.
        if args.password_stdin:
            print("--totp nie zmienia hasla; --password-stdin pomin", file=sys.stderr)
            return 2
        try:
            n = _auth(cfg).reset_totp(args.login)
        except UnknownUser:
            print(f"nie ma konta {args.login!r}", file=sys.stderr)
            return 1
        print(f"drugi skladnik {args.login!r} wylaczony, kody zapasowe skasowane, "
              f"blokada zdjeta, wylogowano sesji: {n}")
        print("Konto loguje sie teraz samym haslem; 2FA mozna wlaczyc od nowa w panelu.")
        return 0
    password, generated = _new_password(args)
    try:
        n = _auth(cfg).reset_user(args.login, password)
    except UnknownUser:
        print(f"nie ma konta {args.login!r}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    print(f"nowe haslo dla {args.login!r}, blokada zdjeta, wylogowano sesji: {n}")
    if generated:
        _print_generated(args.login, password)
    return 0


async def cmd_user_del(args) -> int:
    from .panel_auth import UnknownUser  # noqa: PLC0415

    cfg = Config.load(args.config)
    try:
        _auth(cfg).delete_user(args.login)
    except UnknownUser:
        print(f"nie ma konta {args.login!r}", file=sys.stderr)
        return 1
    print(f"usunieto konto {args.login!r} razem z jego sesjami")
    return 0


async def cmd_user_list(args) -> int:
    cfg = Config.load(args.config)
    users = _auth(cfg).list_users()
    if not users:
        print("brak kont. Zaloz: python -m kidwatch user-add <login>")
        return 0
    now = datetime.now(UTC).timestamp()
    for u in users:
        last = (
            datetime.fromtimestamp(u["last_login_at"], cfg.tz).strftime("%Y-%m-%d %H:%M")
            if u["last_login_at"] else "nigdy"
        )
        lock = (
            f", ZABLOKOWANE jeszcze {int(u['locked_until'] - now)} s"
            if u["locked_until"] and u["locked_until"] > now else ""
        )
        totp = (
            f"2FA wlaczone, kodow zapasowych: {u['backup_codes_left']}"
            if u["totp"] else "bez 2FA"
        )
        print(f"{u['login']:24} ostatnie logowanie: {last}, {totp}, "
              f"nieudane proby: {u['failed_logins']}{lock}")
    return 0


# ========================================================================= main
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="kidwatch", description=__doc__)
    parser.add_argument("--config", default=os.environ.get("KIDWATCH_CONFIG", "config.yaml"))
    parser.add_argument("--verbose", "-v", action="store_true", help="logi na poziomie DEBUG")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="nasluchuj zrodla i wysylaj powiadomienia")

    replay = sub.add_parser("replay", help="odtworz zapis dnia z pliku .jsonl")
    replay.add_argument("file")
    replay.add_argument(
        "--dry-run", action="store_true", help="tylko wypisz, nie wysylaj nigdzie"
    )

    sub.add_parser("test-notify", help="wyslij probny push")

    domains = sub.add_parser(
        "domains", help="najczestsze domeny z bazy — do uzupelniania app_map.yaml"
    )
    domains.add_argument("--days", type=int, default=7, help="ile dni wstecz (domyslnie 7)")
    domains.add_argument("--limit", type=int, default=40, help="ile hostow pobrac (domyslnie 40)")
    domains.add_argument(
        "--unknown-only",
        action="store_true",
        help="tylko domeny NIEROZPOZNANE — to one wymagaja dopisania do mapy",
    )

    device = sub.add_parser(
        "device", help="jednorazowy odczyt stanu iPadow (sprawdzenie konfiguracji)"
    )
    device.set_defaults(_handler="device")

    device_watch = sub.add_parser(
        "device-watch", help="petla: odpytuj iPady i wysylaj powiadomienia o zmianach"
    )
    device_watch.set_defaults(_handler="device-watch")

    web = sub.add_parser("web", help="raport odwiedzonych domen per dziecko per dzien")
    web.add_argument("--days", type=int, default=1, help="ile dni wstecz (domyslnie 1)")
    web.add_argument("--device", help="tylko to urzadzenie (nazwa wyswietlana)")
    web.add_argument("--limit", type=int, default=25, help="ile domen na dzien (domyslnie 25)")

    summary = sub.add_parser("summary", help="wypisz podsumowanie doby")
    summary.add_argument("--date", help="YYYY-MM-DD, domyslnie dzisiaj")

    weekly = sub.add_parser("weekly", help="raport tygodniowy (drukuje; bez --dry-run wysyla)")
    weekly.add_argument("--week", help="YYYY-Www (tydzien ISO), domyslnie tydzien do raportu")
    weekly.add_argument("--dry-run", action="store_true", help="tylko wypisz, nie wysylaj")

    tv = sub.add_parser("tv", help="jednorazowy odczyt telewizora (ADB)")
    tv.add_argument("--raw", action="store_true",
                    help="surowe odpowiedzi dumpsys — do nagrywania probek testowych")

    tv_pause = sub.add_parser(
        "tv-pauza", help="wstrzymaj albo wznow monitoring TV (bez opcji: stan pauzy)"
    )
    when = tv_pause.add_mutually_exclusive_group()
    when.add_argument("--do", metavar="RRRR-MM-DDTGG:MM",
                      help="wstrzymaj do tej chwili (czas lokalny z konfiguracji)")
    when.add_argument("--do-odwolania", action="store_true", help="wstrzymaj bez terminu")
    when.add_argument("--wznow", action="store_true", help="wznow monitoring teraz")

    unifi = sub.add_parser("unifi", help="obecnosc iPadow w Wi-Fi wg kontrolera UniFi")
    unifi.add_argument("--fingerprint", action="store_true",
                       help="tylko odcisk SHA-256 certyfikatu kontrolera (nic nie wysyla)")

    # Konta panelu WWW. W klastrze przez:
    #   kubectl -n default exec deploy/kidwatch -c kidwatch -- python -m kidwatch user-add <login>
    users: dict[str, argparse.ArgumentParser] = {}
    for name, help_ in (
        ("user-add", "zaloz konto panelu WWW (haslo losowe albo z --password-stdin)"),
        ("user-reset", "nowe haslo (albo z --totp: zdjecie 2FA), zdjecie blokady "
                       "i wylogowanie wszystkich sesji konta"),
    ):
        p = users[name] = sub.add_parser(name, help=help_)
        p.add_argument("login")
        p.add_argument(
            "--password-stdin",
            action="store_true",
            help="wczytaj haslo z pierwszej linii stdin (min. 12 znakow); "
            "bez tej opcji haslo jest losowane i wypisane RAZ",
        )
    users["user-reset"].add_argument(
        "--totp",
        action="store_true",
        help="zamiast hasla zdejmij drugi skladnik (zgubiony telefon, zmiana "
        "PANEL_TOTP_KEY); haslo zostaje, 2FA mozna wlaczyc od nowa w panelu",
    )
    user_del = sub.add_parser("user-del", help="usun konto panelu WWW razem z sesjami")
    user_del.add_argument("login")
    sub.add_parser("user-list", help="konta panelu WWW, ostatnie logowanie i blokady")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )
    handlers = {
        "run": cmd_run,
        "replay": cmd_replay,
        "test-notify": cmd_test_notify,
        "domains": cmd_domains,
        "device": cmd_device,
        "device-watch": cmd_device_watch,
        "web": cmd_web,
        "summary": cmd_summary,
        "weekly": cmd_weekly,
        "tv": cmd_tv,
        "tv-pauza": cmd_tv_pause,
        "unifi": cmd_unifi,
        "user-add": cmd_user_add,
        "user-reset": cmd_user_reset,
        "user-del": cmd_user_del,
        "user-list": cmd_user_list,
    }
    try:
        return asyncio.run(handlers[args.command](args))
    except MissingSecretError as exc:
        print(f"\nBRAK SEKRETU: {exc}\n", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    sys.exit(main())
