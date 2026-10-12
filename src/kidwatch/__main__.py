"""CLI: run | replay | test-notify | summary | weekly | tv | tv-pauza | user-add | domy |
dom-importuj | dom-zrodlo | dom-sieci | klucze-rotuj | klucze-potwierdz | dom-klucz-rotuj |
..."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import logging
import os
import signal
import sqlite3
import sys
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from . import uprawnienia
from .classifier import Classifier, registrable
from .config import BramkaConfig, Config, HomeConfig, InstanceConfig, MissingSecretError
from .engine import Engine
from .models import DnsEvent, Notification, NotifyKind
from .notifiers.base import Dispatcher, Notifier, Outbox
from .notifiers.bramka import BramkaNotifier
from .notifiers.homeassistant import HomeAssistantNotifier
from .notifiers.ntfy import NtfyNotifier
from .scheduler import device_loop
from .store import Store, from_iso

log = logging.getLogger("kidwatch")


# ======================================================================= montaz
def _transport(cfg: HomeConfig):
    """Transport ze straznikiem sieci domu (straznik.py) albo None — Dom 1
    z config.yaml laczy sie jak przed domami."""
    from .straznik import transport  # noqa: PLC0415

    return transport(cfg.straznik)


def build_notifiers(cfg: HomeConfig, bramka: BramkaConfig | None) -> list[Notifier]:
    """Kanaly domu (ntfy, Home Assistant) i wspolna bramka instancji."""
    notifiers: list[Notifier] = []
    ntfy = cfg.notifiers.ntfy
    if ntfy and ntfy.enabled:
        notifiers.append(NtfyNotifier(ntfy, token=ntfy.token(), transport=_transport(cfg)))
    ha = cfg.notifiers.homeassistant
    if ha and ha.enabled:
        notifiers.append(HomeAssistantNotifier(ha, webhook_id=ha.webhook_id(),
                                               transport=_transport(cfg)))
    if bramka and bramka.enabled:
        notifiers.append(BramkaNotifier(bramka, key=bramka.key()))
    return notifiers


def build_outbox(
    cfg: HomeConfig, store: Store, *, bramka: BramkaConfig | None, auth_path: str,
    dom_id: int | None = None,
) -> Outbox:
    """Kolejka z routingiem per konto (odbiorcy.py), gdy bramka na to
    pozwala w konfiguracji. Tryb (trasy/konta) Outbox ustala przy kazdym
    rozdziale — wlasciciel przelacza go bez restartu."""
    from zoneinfo import ZoneInfo  # noqa: PLC0415

    dispatcher = Dispatcher(build_notifiers(cfg, bramka), store=store)
    konta = None
    if bramka is not None and bramka.enabled and bramka.per_konto:
        from .odbiorcy import ProfilePowiadomien  # noqa: PLC0415

        # Odbiorcy, preferencje i tryb TEGO domu (czlonkowie domu).
        konta = ProfilePowiadomien(auth_path, dom_id=1 if dom_id is None else dom_id)
    return Outbox(
        dispatcher, store, konta=konta,
        dziecko={d.display_name: d.child for d in cfg.devices}, tz=ZoneInfo(cfg.timezone),
        dom_id=dom_id,
    )


def nextdns_cursor(store: Store, profile: str, primary: str) -> str | None:
    """Kursor profilu. Profil glowny czytal dotad klucz `cursor:nextdns` —
    bez tej sciezki pierwszy start po aktualizacji zaczynalby od "teraz"
    i gubil zdarzenia z czasu restartu."""
    cursor = store.get_cursor(f"nextdns:{profile}")
    if cursor is None and profile == primary:
        cursor = store.get_cursor("nextdns")
    return cursor


def build_source(cfg: HomeConfig, store: Store):
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
        # Bramka per klucz API (konto NextDNS, §5.2): dwa domy na jednym koncie
        # dziela limit 429, domy z osobnymi kontami — nie.
        gate = ConnectGate.dla_klucza(key, nx.connect_spacing_seconds)
        return MultiNextDnsSource([
            NextDnsSource(
                cfg=nx,
                api_key=key,
                cursor=nextdns_cursor(store, profile, nx.profile_id),
                device_filter=device_filter,
                profile_id=profile,
                cursor_key=f"nextdns:{profile}",
                gate=gate,
                transport=_transport(cfg),
            )
            for profile in profiles
        ])

    from .sources.adguard import AdGuardSource  # noqa: PLC0415

    ag = cfg.source.adguard
    assert ag is not None
    return AdGuardSource(cfg=ag, password=ag.password(), store=store, transport=_transport(cfg))


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
        NotifyKind.MDM: "[MDM]   ",
    }.get(note.kind, f"[{note.kind}]")
    body = note.text.replace("\n", "\n          ")
    return f"{icon} {note.title}\n          {body}"


# ========================================================================== run
OUTBOX_FLUSH_ON_STOP_SECONDS = 10.0


def build_home_runtime(dom_id: int, inst: InstanceConfig, home: HomeConfig,
                       classifier: Classifier):
    """Srodowisko domu (domy.HomeRuntime): baza domu, silnik, kolejka z `dom_id`,
    zrodlo DNS i petle wlaczone w konfiguracji domu. Kolejnosc budowy jak
    przed domami — brak sekretu zrodla przerywa start, zanim ruszy panel."""
    from .domy import (  # noqa: PLC0415
        HomeRuntime,
        katalog_domu,
        katalog_sekretow_domu,
        sciezka_bazy_domu,
    )
    from .scheduler import device_loop, source_loop, tick_loop  # noqa: PLC0415

    auth_path = inst.panel_auth_path
    store = Store(str(sciezka_bazy_domu(dom_id, inst.store.path)))
    engine = Engine(home, store, classifier)
    if home.tv.enabled:
        from .tvpause import TvPauseRequests  # noqa: PLC0415

        # Zadania pauzy TV z panelu i z `tv-pauza` wykonuje tik silnika.
        engine.tv_pause.requests = TvPauseRequests(auth_path, dom_id=dom_id)
    # Petle oddaja powiadomienia do kolejki w bazie; wysyla je osobne zadanie
    # "outbox". Wiszacy kanal nie trzyma tiku (tetno, liveness) ani strumienia.
    dispatcher = build_outbox(home, store, bramka=inst.notifiers.bramka, auth_path=auth_path,
                              dom_id=dom_id)
    source = build_source(home, store)
    rt = HomeRuntime(dom_id, home, store, engine, dispatcher, source)
    rt.dodaj_petle("source", lambda: source_loop(source, engine, dispatcher, store))
    rt.dodaj_petle("tick", lambda: tick_loop(
        engine,
        dispatcher,
        store,
        retention_days=home.store.retention_days,
        notifications_retention_days=home.store.notifications_retention_days,
        rollup_retention_days=home.store.rollup_retention_days,
    ))
    rt.dodaj_petle("outbox", dispatcher.run)

    # Odczyt z iPadow jedzie w TYM SAMYM procesie, nie w osobnym kontenerze.
    # SQLite ma jednego pisarza — dwa procesy na jednej bazie rozjechalyby stan
    # i zdublowaly powiadomienia. Ten sam powod, dla ktorego Deployment ma
    # replicas:1 i strategie Recreate.
    watchers = (build_watchers(home, store, inst.device_read.records_path)
                if home.device_read.enabled else [])
    if watchers:
        log.info(
            "odczyt z iPadow wlaczony: %s, co %.0f s",
            [w.device_name for w in watchers],
            home.device_read.poll_seconds,
        )
        rt.dodaj_petle("device", lambda: device_loop(
            watchers,
            dispatcher,
            home.device_read.poll_seconds,
            unreachable_alert_hours=home.device_read.unreachable_alert_hours,
            store=store,
        ))
    elif home.device_read.enabled:
        log.warning("device_read.enabled=true, ale zadne urzadzenie nie ma udid i host")

    # Telewizor: ta sama petla co iPady (nieosiagalny = normalny stan, alarm
    # po wielu godzinach), z wlasnym rytmem i progiem.
    # Dom z konfiguracja w bazie trzyma token aplikacji TV w pamieci poda
    # (zapisany przez konfiguracja_domu.zbuduj_dom), nie na wolumenie.
    katalog = (katalog_sekretow_domu(dom_id) if home.sekrety is not None
               else katalog_domu(dom_id, inst.store.path))
    tv = build_tv_watcher(home, store, katalog) if home.tv.enabled else None
    if tv is not None:
        log.info("czujnik TV wlaczony: %s (%s), co %.0f s",
                 home.tv.name, home.tv.host, home.tv.poll_seconds)
        rt.dodaj_petle("tv", lambda: device_loop(
            [tv],
            dispatcher,
            home.tv.poll_seconds,
            unreachable_alert_hours=home.tv.unreachable_alert_hours,
            store=store,
        ))
    for watcher in [*watchers, *([tv] if tv else [])]:
        rt.dodaj_sprzatanie(watcher.probe.aclose)

    unifi = build_unifi_watcher(home, store) if home.unifi.enabled else None
    if unifi is not None:
        from .sources.unifi import unifi_loop  # noqa: PLC0415

        log.info("czujka UniFi wlaczona: %s, iPady: %s",
                 home.unifi.url, [d[0] for d in unifi.devices])
        rt.dodaj_petle("unifi", lambda: unifi_loop(unifi, dispatcher, home.unifi.poll_seconds))

    # Serwer MDM to osobny pod z wlasna baza — tu tylko czujka po jego API.
    from .config import MdmConfig  # noqa: PLC0415
    from .mdm import MdmWatcher, build_api, mdm_loop  # noqa: PLC0415

    mdm_cfg = MdmConfig.model_validate({**home.mdm.model_dump(), "url": inst.mdm.url})
    mdm_cfg._sekrety = home.mdm._sekrety  # token z sekretow domu (tryb `baza`)
    mdm_api = build_api(mdm_cfg)
    if mdm_api is not None:
        log.info("czujka MDM wlaczona: %s, co %.0f s", mdm_cfg.url, mdm_cfg.poll_seconds)
        rt.dodaj_petle("mdm", lambda: mdm_loop(
            MdmWatcher(mdm_api, store, mdm_cfg), dispatcher, mdm_cfg.poll_seconds
        ))

    game = (build_game_time(home, store, dispatcher, auth_path, dom_id)
            if home.game_time.enabled else None)
    if game is not None:
        from .gametime import game_loop  # noqa: PLC0415

        log.info("czas gry wlaczony: profile %s, uslugi %s, kategorie %s",
                 sorted(set(game.profiles.values())), home.game_time.services,
                 home.game_time.categories)
        rt.dodaj_petle("game", lambda: game_loop(game, home.game_time.poll_seconds))
        rt.dodaj_sprzatanie(game.client.aclose)
    return rt


#: Klucz Sekretu wymuszajacy config.yaml dla Domu 1 (docs/sejf-domow.md, §4).
WYMUSZENIE_DOMU_1_ENV = "KIDWATCH_DOM_1_ZRODLO"


def home_domu_z_bazy(rejestr, dom_id: int) -> HomeConfig:
    """Konfiguracja domu w trybie `baza` (E2): sekrety z sejfu (KIDWATCH_KEK),
    straznik sieci, pliki z sekretow w pamieci poda."""
    from .konfiguracja_domu import zbuduj_dom  # noqa: PLC0415
    from .sejf import Sejf  # noqa: PLC0415

    return zbuduj_dom(rejestr, dom_id, Sejf.z_srodowiska())


async def cmd_run(args) -> int:
    from .domy import DOM_1, ZRODLO_BAZA, ZRODLO_YAML, Nadzorca, RejestrDomow  # noqa: PLC0415
    from .sejf import SejfError  # noqa: PLC0415
    from .straznik import OdmowaSieci  # noqa: PLC0415

    cfg = Config.load(args.config)
    inst, home = cfg.split()
    rejestr = RejestrDomow(inst.panel_auth_path)
    # Dom 1 i czlonkostwa w panel-auth.db (docs/architektura-domy.md §6).
    # W trybie `yaml` monitoring od nich nie zalezy, wiec blad bazy panelu
    # go nie zatrzyma (jak w E1).
    w_bazie: list[int] = []
    try:
        raport = rejestr.migruj(strefa=home.timezone)
        if raport.zmiany:
            log.info("domy: Dom 1 %s, uzgodnione czlonkostwa: %d, nowe kolumny: %s",
                     "zalozony" if raport.dom_1_zalozony else "bez zmian",
                     len(raport.uzgodnione), list(raport.kolumny) or "-")
        w_bazie = [d.id for d in rejestr.domy() if d.zrodlo_konfiguracji == ZRODLO_BAZA]
    except sqlite3.Error:
        log.exception("domy: migracja panel-auth.db nie powiodla sie")
    wymuszone = os.environ.get(WYMUSZENIE_DOMU_1_ENV, "")
    if wymuszone.strip().lower() == ZRODLO_YAML:
        # Droga powrotu BEZ `kubectl exec` (pod w CrashLoop nie przyjmie exec):
        # klucz w Sekrecie + restart. Baza zostaje bez zmian.
        if DOM_1 in w_bazie:
            log.warning("%s=yaml: Dom 1 z config.yaml mimo trybu `baza` w panel-auth.db "
                        "(wymuszenie z Sekretu; usun klucz po naprawie)", WYMUSZENIE_DOMU_1_ENV)
            w_bazie.remove(DOM_1)
    elif wymuszone.strip():
        log.warning("%s=%r nieznane — jedyna wartosc to `yaml`; ignoruje",
                    WYMUSZENIE_DOMU_1_ENV, wymuszone)
    inne = [d for d in w_bazie if d != DOM_1]
    if inne:
        # Kolejne domy wymagaja izolacji powiadomien i awarii (E3a/E3b).
        log.warning("domy %s maja konfiguracje w bazie — ich uruchamianie to etap E3b, "
                    "na razie chodzi tylko Dom 1", inne)
    if DOM_1 in w_bazie:
        # KEK, szyfrogram albo adres spoza sieci domu — Dom 1 nie startuje
        # z polowa konfiguracji. Brak KEK nie dotyczy trybu `yaml`.
        try:
            home = home_domu_z_bazy(rejestr, DOM_1)
        except (SejfError, OdmowaSieci, ValueError, LookupError, OSError,
                sqlite3.Error) as exc:
            log.error("Dom 1: konfiguracja z bazy nie wystartowala — %s. Powrot do "
                      "config.yaml bez exec: klucz %s=yaml w kidwatch-secrets + restart; "
                      "z dzialajacym podem: kidwatch dom-zrodlo 1 yaml (docs/sejf-domow.md)",
                      exc, WYMUSZENIE_DOMU_1_ENV)
            return 2
        log.info("Dom 1: konfiguracja z bazy (sekrety: %s, sieci: %s)",
                 home.sekrety, [str(n) for n in home.straznik.sieci])
    runtime = build_home_runtime(DOM_1, inst, home, Classifier(inst.app_map_path))

    log.info(
        "start: zrodlo=%s urzadzenia=%s kanaly=%s",
        runtime.source.name,
        [d.display_name for d in home.devices],
        [n.name for n in runtime.outbox.notifiers],
    )
    if not runtime.outbox.notifiers:
        log.warning("zaden kanal powiadomien nie jest wlaczony — nic nie dotrze")

    panel = None
    if cfg.panel.enabled:
        from .panel import start_panel  # noqa: PLC0415

        # Panel Domu 1 z TEJ SAMEJ konfiguracji co jego srodowisko — przy
        # `baza` (E2) nie z config.yaml, inaczej panel pokazalby pusty dom
        # (przeglad E3a, B-1). Kolejne domy: E3b.
        panel = start_panel(cfg, konfiguracja_domu=lambda dom: home if dom.id == DOM_1 else None)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):  # pragma: no cover
            loop.add_signal_handler(sig, stop.set)

    nadzorca = Nadzorca([runtime])
    rc = await nadzorca.run(stop)
    if panel is not None:
        panel.shutdown()
    await nadzorca.zamknij(OUTBOX_FLUSH_ON_STOP_SECONDS)
    log.info("zatrzymano")
    return rc


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

    notifiers = [] if args.dry_run else build_notifiers(cfg, cfg.notifiers.bramka)
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
    dispatcher = Dispatcher(build_notifiers(cfg, cfg.notifiers.bramka))
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
def build_tv_watcher(cfg: HomeConfig, store: Store, katalog: Path):
    """Obserwator telewizora albo None (z bledem w logu), gdy brak klucza ADB.

    Brak klucza nie zabija procesu — jak przy rekordach parowania iPadow:
    klucz zaklada sie recznie PO wdrozeniu, a DNS ma dzialac od razu.
    """
    from .sources.tv import (  # noqa: PLC0415
        AdbTcpShell,
        BrakAdb,  # noqa: PLC0415
        TvProbe,
        TvWatcher,
    )

    try:
        shell = AdbTcpShell(cfg.tv.host, cfg.tv.port, cfg.tv.adb_key_dir, cfg.tv.timeout_seconds,
                            straznik=cfg.straznik)
    except (FileNotFoundError, ValueError) as exc:
        if not cfg.tv.aplikacja:
            log.error("%s: czujnik TV wylaczony — %s", cfg.tv.name, exc)
            return None
        # Aplikacja Kidwatch TV i zapasy dzialaja bez ADB.
        log.warning("%s: bez ADB — %s", cfg.tv.name, exc)
        shell = BrakAdb(str(exc))
    aplikacja = build_tv_app(cfg, shell, katalog)
    probe = TvProbe(shell)
    hybryda = build_tv_traffic(cfg, store, probe, aplikacja)
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


def build_tv_app(cfg: HomeConfig, shell, katalog_domu: Path):
    """Aplikacja Kidwatch TV (sources/tv_app.py) albo None (tv.aplikacja: false).
    Rejestrowana w `tv_app.AKTYWNA` dla panelu (instalacja, parowanie). Token
    w `tv-app/` w katalogu domu (domy.katalog_domu)."""
    from .sources import tv_app  # noqa: PLC0415
    from .sources.tv import AdbTcpShell  # noqa: PLC0415

    if not cfg.tv.aplikacja:
        return None
    katalog = katalog_domu / "tv-app"
    app = tv_app.AplikacjaTv(cfg.tv.host, katalog, timeout=cfg.tv.timeout_seconds,
                             transport=_transport(cfg))
    app.adb = shell if isinstance(shell, AdbTcpShell) else None
    sekrety = cfg.sekrety
    if sekrety is not None and hasattr(sekrety, "zapisz"):
        # Tryb `baza`: plik tokenu jest w pamieci poda — trwala kopia w bazie.
        app.po_sparowaniu = lambda token: sekrety.zapisz("tv", "app_token", token)
    tv_app.AKTYWNA = app
    log.info("%s: aplikacja Kidwatch TV (%s:%d) - %s", cfg.tv.name, cfg.tv.host, tv_app.PORT,
             "sparowana" if app.sparowana else "do instalacji/parowania w panelu")
    return app


def build_tv_traffic(cfg: HomeConfig, store: Store, probe, aplikacja=None):
    """Hybryda ADB + Sony REST + ruch sieci (sources/tv_siec.py, sony.py) albo
    None, gdy oba zapasy sa wylaczone - wtedy telewizor czyta samo ADB."""
    from .sources.sony import SonyClient  # noqa: PLC0415
    from .sources.tv_siec import HybridProbe, LicznikRuchu  # noqa: PLC0415
    from .sources.unifi import UnifiClient  # noqa: PLC0415

    licznik = None
    key = cfg.unifi.api_key() if cfg.unifi.enabled else None
    if cfg.tv.traffic and key and cfg.unifi.cert_sha256:
        client = UnifiClient(cfg.unifi.url, cfg.unifi.site, key, cfg.unifi.cert_sha256,
                             cfg.unifi.timeout_seconds, straznik=cfg.straznik)
        licznik = LicznikRuchu(client, cfg.tv.host, cfg.tv.unifi_mac,
                               okno_min=cfg.tv.traffic_window_minutes,
                               odswiez_s=cfg.unifi.poll_seconds)
    sony = None
    if cfg.tv.sony:
        sony = SonyClient(cfg.tv.host, cfg.tv.sony_psk(), timeout=cfg.tv.timeout_seconds,
                          transport=_transport(cfg))
    if licznik is None and sony is None and aplikacja is None:
        log.info("%s: odczyt zapasowy wylaczony (brak UniFi i tv.sony: false)", cfg.tv.name)
        return None
    czesci = []
    if sony:
        czesci.append("Sony REST z kluczem PSK" if sony.psk
                      else "Sony REST (tylko zasilanie, brak TV_SONY_PSK)")
    if aplikacja is not None:
        czesci.insert(0, "aplikacja Kidwatch TV")
    if licznik:
        czesci.append(f"ruch UniFi (prog {cfg.tv.traffic_min_mb:.0f} MB / "
                      f"{cfg.tv.traffic_window_minutes:.0f} min)")
        if cfg.tv.nextdns_ids:
            czesci.append("serwis z NextDNS")
    log.info("%s: odczyt zapasowy: %s", cfg.tv.name, ", ".join(czesci))
    return HybridProbe(probe, licznik, store, prog_mb=cfg.tv.traffic_min_mb,
                       nextdns_ids=cfg.tv.nextdns_ids, device_name=cfg.tv.name, sony=sony,
                       apps=cfg.tv.apps, aplikacja=aplikacja)


def build_game_time(cfg: HomeConfig, store: Store, dispatcher, auth_path: str, dom_id: int):
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
    client = ParentalControlClient(nx.base_url, nx.api_key(), timeout=cfg.game_time.timeout_seconds,
                                   transport=_transport(cfg))
    return GameTime(cfg, store, GameRequests(auth_path, dom_id=dom_id), client, dispatcher)


def build_unifi_watcher(cfg: HomeConfig, store: Store):
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
                         cfg.unifi.timeout_seconds, straznik=cfg.straznik)
    return UnifiWatcher(
        client,
        devices,
        store,
        window_minutes=cfg.unifi.window_minutes,
        alarm_mb=cfg.unifi.alarm_mb,
        repeat_backoff_max_minutes=cfg.unifi.repeat_backoff_max_minutes,
        kinds={d.display_name: d.kind for d in cfg.devices},
    )


def build_watchers(cfg: HomeConfig, store: Store, records_path: Path):
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
    from .straznik import OdmowaSieci, adres_literalny  # noqa: PLC0415

    out = []
    for dev in cfg.devices:
        if not dev.reads_device:
            continue
        if cfg.straznik is not None:
            # pymobiledevice3 sam rozwiazuje nazwe — w domu z konfiguracja w bazie
            # tylko adres IP sprawdzony przez straznika (bez DNS rebinding).
            try:
                if adres_literalny(dev.host or "") is None:
                    raise OdmowaSieci(f"host {dev.host} to nie adres IP")
                cfg.straznik.sprawdz_ip(adres_literalny(dev.host or ""), dev.host)
            except OdmowaSieci as exc:
                log.error("%s: pomijam odczyt z urzadzenia — %s", dev.display_name, exc)
                continue
        try:
            probe = DeviceProbe.over_tcp(
                DeviceTarget(udid=dev.udid, host=dev.host),
                records_path,
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
    watchers = build_watchers(cfg, store, cfg.device_read.records_path)
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
    watchers = build_watchers(cfg, store, cfg.device_read.records_path)
    if not watchers:
        print("Zadne urzadzenie nie ma 'udid' i 'host' — nie ma czego odpytywac.", file=sys.stderr)
        store.close()
        return 1

    dispatcher = Dispatcher(build_notifiers(cfg, cfg.notifiers.bramka), store=store)
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
        dispatcher = Dispatcher(build_notifiers(cfg, cfg.notifiers.bramka))
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
    return _auth_path(cfg.panel_auth_path)


def _auth_path(path: str):
    from .panel_auth import PanelAuth  # noqa: PLC0415

    return PanelAuth(path)


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
        _auth(cfg).add_user(args.login, password, args.rola,
                            dom_id=None if args.bez_domu else 1)
    except UserExists:
        print(f"konto {args.login!r} juz istnieje — uzyj user-reset", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    gdzie = "bez domu" if args.bez_domu else f"rola {args.rola} w Domu 1"
    print(f"zalozono konto panelu {args.login!r}, {gdzie} ({cfg.panel_auth_path})")
    from .panel_sso import login_ok  # noqa: PLC0415

    if not login_ok(args.login.strip()):
        # Konto dziala z haslem, ale logowanie przez SSO (Remote-User z Authelii,
        # zawsze malymi literami) nigdy go nie znajdzie.
        print(f"UWAGA: login {args.login!r} nie dopasuje sie do konta w Authelii (SSO) — "
              "dozwolone tylko a-z, 0-9, '.', '_', '-'. Usun: user-del, zaloz z malym loginem.",
              file=sys.stderr)
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


async def cmd_user_rola(args) -> int:
    from .panel_auth import UnknownUser  # noqa: PLC0415

    cfg = Config.load(args.config)
    try:
        n = _auth(cfg).set_role(args.login, args.rola)
    except UnknownUser:
        print(f"nie ma konta {args.login!r}", file=sys.stderr)
        return 1
    except ValueError as exc:  # m.in. ostatnie konto z zarzadzaniem kontami w domu
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    print(f"konto {args.login!r}: rola {args.rola}, wylogowano sesji: {n}")
    return 0


async def cmd_user_uprawnienia(args) -> int:
    from .panel_auth import UnknownUser  # noqa: PLC0415

    cfg = Config.load(args.config)
    if not args.zmiany:
        # Samo `user-uprawnienia <login>`: podglad stanu, bez zmian.
        u = next((u for u in _auth(cfg).list_users() if u["login"] == args.login.strip()), None)
        if u is None:
            print(f"nie ma konta {args.login!r}", file=sys.stderr)
            return 1
        print(f"konto {u['login']!r}, rola {u['rola']}, odstepstwa: "
              f"{' '.join(u['odstepstwa']) or 'brak'}")
        for nazwa, opis in uprawnienia.OPISY.items():
            print(f"  [{'x' if nazwa in u['uprawnienia'] else ' '}] {nazwa:24} {opis}")
        return 0
    try:
        zmiany = uprawnienia.parsuj_zmiany(args.zmiany)
        n = _auth(cfg).set_permissions(args.login, zmiany)
    except ValueError as exc:
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    except UnknownUser:
        print(f"nie ma konta {args.login!r}", file=sys.stderr)
        return 1
    print(f"konto {args.login!r}: {' '.join(args.zmiany)}, wylogowano sesji: {n}")
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
        odst = f" ({' '.join(u['odstepstwa'])})" if u["odstepstwa"] else ""
        print(f"{u['login']:24} rola: {u['rola']}{odst}, ostatnie logowanie: {last}, {totp}, "
              f"nieudane proby: {u['failed_logins']}{lock}")
    return 0


# ============================================================ powiadomienia kont
def _konta(cfg: Config):
    from .odbiorcy import ProfilePowiadomien  # noqa: PLC0415

    return ProfilePowiadomien(cfg.panel_auth_path)


def _przypisania(raw: list[str]) -> dict[int, str]:
    wynik: dict[int, str] = {}
    for item in raw:
        poz, sep, login = item.partition("=")
        if not sep or not poz.isdigit() or not login.strip():
            raise SystemExit(f"--przypisz {item!r}: oczekuje POZYCJA=login, np. 2=konto2")
        wynik[int(poz)] = login.strip()
    return wynik


async def cmd_konta_migruj(args) -> int:
    """Odbiorcy z bramki -> kanaly i kategorie kont panelu. Bez --zapisz
    tylko pokazuje plan i porownanie "przed / po" dla kazdego rodzaju."""
    from . import odbiorcy as o  # noqa: PLC0415
    from .bramka_admin import BramkaAdmin, BramkaError, mask  # noqa: PLC0415

    cfg = Config.load(args.config)
    bc = cfg.notifiers.bramka
    if bc is None or not bc.enabled:
        print("bramka wylaczona w konfiguracji — nie ma czego migrowac", file=sys.stderr)
        return 1
    key, _ = bc.admin_key()
    try:
        lista = BramkaAdmin(bc, key).status().get("odbiorcy") or []
    except BramkaError as exc:
        print(f"bramka: {exc.message}", file=sys.stderr)
        return 1
    konta = _konta(cfg)
    profile = konta.profile()
    try:
        kroki = o.plan_migracji(lista, profile, _przypisania(args.przypisz))
    except ValueError as exc:
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    print("Odbiorcy bramki -> konta panelu:")
    for k in kroki:
        kat = ", ".join(sorted(k.kategorie, key=o.KATEGORIE.index)) or "nic z kidwatch"
        extra = f", nada: {', '.join(sorted(k.nadac))}" if k.nadac else ""
        stan = "" if k.aktywny else " (nieaktywny)"
        print(f"  {k.pozycja}. {mask(k.numer)} [{k.etykieta or '-'}]{stan} -> "
              f"{k.login or 'BRAK KONTA'}: {kat}{extra}")
    bez_konta = [k for k in kroki if k.login is None and k.aktywny and k.kategorie]
    po = o.profile_po_migracji(kroki, profile)
    rozne = 0
    print("\nPrzed (trasy bramki) / po (konta), numery WhatsApp:")
    for kind, przed, teraz in o.porownanie(lista, po, datetime.now(UTC)):
        same = przed == teraz
        rozne += not same
        print(f"  {'ok ' if same else 'ROZ'} {kind.value:18} "
              f"{', '.join(sorted(mask(n) for n in przed)) or '-':30} "
              f"{', '.join(sorted(mask(n) for n in teraz)) or '-'}")
    if bez_konta:
        print(f"\n{len(bez_konta)} aktywnych odbiorcow bez konta — przypisz ich "
              "(--przypisz POZYCJA=login; konto zaloz: user-add LOGIN --rola podglad).")
    if not args.zapisz:
        print("\nNic nie zapisano. Zapis: dodaj --zapisz (i --wlacz, by od razu "
              "przelaczyc na tryb kont).")
        return 0
    o.zastosuj_migracje(konta, kroki, _auth(cfg))
    print("\nZapisano kanaly i kategorie kont.")
    if args.wlacz:
        if bez_konta or rozne:
            print("NIE wlaczam trybu kont: sa odbiorcy bez konta albo roznice wyzej. "
                  "Popraw i uruchom ponownie, albo: konta-tryb konta.", file=sys.stderr)
            return 1
        konta.ustaw_tryb(o.TRYB_KONTA)
        print("Tryb kont wlaczony (dziala, gdy bramka obsluguje jawnego odbiorce).")
    print("Adres e-mail kont (zapasowy kanal) uzupelnia kazdy w panelu: Profil -> Powiadomienia.")
    return 0


async def cmd_konta_tryb(args) -> int:
    from . import odbiorcy as o  # noqa: PLC0415

    cfg = Config.load(args.config)
    konta = _konta(cfg)
    if args.tryb:
        konta.ustaw_tryb(args.tryb)
    print(f"tryb powiadomien: {konta.tryb()}")
    bc = cfg.notifiers.bramka
    if bc is not None and not bc.per_konto:
        print("UWAGA: notifiers.bramka.per_konto=false w konfiguracji — zawsze tryb tras")
    for p in konta.profile():
        kat = ", ".join(sorted(p.efektywne_kategorie(), key=o.KATEGORIE.index)) or "-"
        kanaly = ", ".join(x for x in (
            p.publiczny()["whatsapp"] and f"WhatsApp {p.publiczny()['whatsapp']}",
            p.publiczny()["email"] and f"e-mail {p.publiczny()['email']}",
        ) if x) or "BRAK KANALU"
        print(f"  {p.login:24} {kanaly}; {kat}{'' if p.aktywne else ' (wylaczone)'}")
    return 0


# ========================================================================= domy
async def cmd_domy(args) -> int:
    """Domy z panel-auth.db i ich czlonkowie (docs/architektura-domy.md).
    Uruchamia migracje (idempotentna), wiec dziala tez przed pierwszym `run`.
    `--sprawdz`: odszyfrowanie wszystkich integracji (test kopii, §3.3)."""
    from .domy import ZRODLO_YAML, RejestrDomow  # noqa: PLC0415

    # --baza: kopia panel-auth.db (test odtworzenia, §3.3) — bez config.yaml.
    baza = getattr(args, "baza", None)
    cfg = None if baza else Config.load(args.config)
    rejestr = RejestrDomow(baza or cfg.panel_auth_path)
    raport = rejestr.migruj(strefa=cfg.timezone if cfg else None)
    if raport.zmiany:
        print(f"migracja: Dom 1 {'zalozony' if raport.dom_1_zalozony else 'bez zmian'}, "
              f"uzgodnione czlonkostwa: {', '.join(raport.uzgodnione) or '-'}")
    for dom in rejestr.domy():
        zrodlo = ("config.yaml" if dom.zrodlo_konfiguracji == ZRODLO_YAML
                  else dom.zrodlo_konfiguracji)
        strefa = (cfg.timezone if cfg and dom.zrodlo_konfiguracji == ZRODLO_YAML
                  else dom.strefa)
        print(f"{dom.id}. {dom.nazwa} — konfiguracja: {zrodlo}, strefa: {strefa}, "
              f"wersja: {dom.wersja}{', ZAWIESZONY' if dom.zawieszony else ''}")
        czlonkowie = rejestr.czlonkowie(dom.id)
        if not czlonkowie:
            print("   brak czlonkow")
        for c in czlonkowie:
            odst = " ".join([f"+{n}" for n in sorted(c.nadane)]
                            + [f"-{n}" for n in sorted(c.odebrane)])
            print(f"   {c.login:24} {c.rola}{f' ({odst})' if odst else ''}")
        for i in rejestr.integracje(dom.id):
            print(f"   integracja {i.typ:14} {'wlaczona ' if i.wlaczona else 'wylaczona'} "
                  f"sekrety: {', '.join(i.sekrety_pola) or '-'}")
        if dom.dozwolone_sieci or dom.dozwolone_hosty:
            print(f"   sieci: {', '.join(dom.dozwolone_sieci) or '-'}; "
                  f"hosty: {', '.join(dom.dozwolone_hosty) or '-'}")
    bez = rejestr.konta_bez_domu()
    if bez:
        print(f"konta bez zadnego domu: {', '.join(bez)}")
    admini = [u["login"] for u in _auth_path(rejestr.path).list_users() if u["admin_instancji"]]
    if admini:
        print(f"administratorzy instalacji: {', '.join(admini)}")
    if getattr(args, "sprawdz", False):
        from .konfiguracja_domu import zbuduj_dom  # noqa: PLC0415
        from .sejf import SejfError  # noqa: PLC0415
        from .straznik import OdmowaSieci  # noqa: PLC0415

        sejf = _sejf()
        raport = rejestr.sprawdz_raport(sejf)
        bledy = raport.bledy
        for dom in rejestr.domy():
            if dom.zrodlo_konfiguracji == ZRODLO_YAML or any(b[0] == dom.id for b in bledy):
                continue
            try:
                zbuduj_dom(rejestr, dom.id, sejf, materializuj=False)
            except (SejfError, OdmowaSieci, ValueError) as exc:
                bledy.append((dom.id, "konfiguracja", str(exc)))
        for dom_id, typ, blad in bledy:
            print(f"BLAD: Dom {dom_id} {typ or 'DEK'}: {blad}")
        print(f"sprawdzono kluczem {sejf.kek_id}: kluczy domow: {raport.klucze_domow}, "
              f"integracji: {raport.integracje}")
        if bledy:
            print(f"WYNIK: {len(bledy)} bledow")
            return 1
        if raport.klucze_domow == 0:
            # Baza bez DEK „odszyfrowuje sie” kazdym kluczem — to nie jest dowod.
            print("WYNIK: nic nie potwierdzono — w bazie nie ma zadnego klucza domu, wiec "
                  "TO NIE JEST test KIDWATCH_KEK (kopia sprzed importu albo zly plik?)")
            return 1
        print("WYNIK: wszystko sie odszyfrowuje")
        return 0
    return 0


def _sejf():
    from .sejf import Sejf  # noqa: PLC0415

    return Sejf.z_srodowiska()


def _rejestr(cfg: Config):
    from .domy import RejestrDomow  # noqa: PLC0415

    rejestr = RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj(strefa=cfg.timezone)
    return rejestr


async def cmd_dom_importuj(args) -> int:
    """Dom 1: config.yaml + sekrety z env/plikow -> baza (§6 p. 4)."""
    from .domy import DOM_1, katalog_domu  # noqa: PLC0415
    from .konfiguracja_domu import importuj, sekrety_z_yaml  # noqa: PLC0415

    if args.dom != DOM_1:
        print("Konfiguracje w config.yaml ma tylko Dom 1.", file=sys.stderr)
        return 2
    cfg = Config.load(args.config)
    inst, home = cfg.split()
    rejestr = _rejestr(cfg)
    sekrety = sekrety_z_yaml(home, katalog_domu(DOM_1, inst.store.path))
    raport = importuj(rejestr, DOM_1, home, sekrety, sejf=_sejf(), zapisz=args.zapisz,
                      kto="cli",
                      plik_tokenu_tv=katalog_domu(DOM_1, inst.store.path) / "tv-app" / "token")
    print(f"Dom {raport.dom_id}: strefa {raport.strefa}")
    print(f"  dzieci: {', '.join(raport.dzieci)}")
    print(f"  urzadzenia: {', '.join(raport.urzadzenia)}")
    for typ, (wlaczona, maski) in raport.integracje.items():
        pola = ", ".join(f"{p}={m}" for p, m in maski.items()) or "bez sekretow"
        print(f"  {typ:14} {'wlaczona ' if wlaczona else 'wylaczona'}  {pola}")
    print(f"  dozwolone_sieci: {', '.join(raport.dozwolone_sieci) or '-'}")
    print(f"  dozwolone_hosty: {', '.join(raport.dozwolone_hosty) or '-'}")
    for o in raport.ostrzezenia:
        print(f"  UWAGA: {o}")
    if raport.roznice:
        print("ROZNICE config.yaml <-> baza (nic nie zapisano):")
        for r in raport.roznice:
            print(f"  - {r}")
        return 1
    print("Porownanie: konfiguracja z bazy identyczna z config.yaml, sekrety identyczne.")
    if raport.zapisano:
        print("ZAPISANO. Dom 1 ma teraz konfiguracje z bazy — dziala po restarcie poda.\n"
              "Powrot: kidwatch dom-zrodlo 1 yaml (+ restart).")
    else:
        print("Podglad — nic nie zapisano. Zapis: dom-importuj 1 --zapisz")
    return 0


async def cmd_dom_zrodlo(args) -> int:
    from .domy import ZRODLO_BAZA  # noqa: PLC0415
    from .konfiguracja_domu import zbuduj_dom  # noqa: PLC0415
    from .straznik import OdmowaSieci  # noqa: PLC0415

    cfg = Config.load(args.config)
    rejestr = _rejestr(cfg)
    try:
        if args.zrodlo == ZRODLO_BAZA:
            # Przelaczenie tylko na konfiguracje, ktora sie buduje i odszyfrowuje.
            zbuduj_dom(rejestr, args.dom, _sejf(), materializuj=False)
        rejestr.ustaw_zrodlo(args.dom, args.zrodlo, kto="cli")
    except (ValueError, LookupError, OdmowaSieci) as exc:
        print(str(exc), file=sys.stderr)
        return 2
    print(f"Dom {args.dom}: konfiguracja z {args.zrodlo}. Dziala po restarcie poda.")
    return 0


async def cmd_dom_sieci(args) -> int:
    """Sieci i hosty domu (§3.6) — wylacznie administrator instancji (CLI)."""
    cfg = Config.load(args.config)
    rejestr = _rejestr(cfg)
    dom = rejestr.dom(args.dom)
    if dom is None:
        print(f"nie ma domu {args.dom}", file=sys.stderr)
        return 2
    sieci = list(dom.dozwolone_sieci)
    hosty = list(dom.dozwolone_hosty)
    zmiana = bool(args.dodaj or args.usun or args.host or args.bez_hosta or args.wyczysc)
    if args.wyczysc:
        sieci, hosty = [], []
    sieci = [s for s in [*sieci, *args.dodaj] if s not in args.usun]
    bez_hosta = {h.strip().lower() for h in args.bez_hosta}
    hosty = [h for h in [*hosty, *args.host] if h.strip().lower() not in bez_hosta]
    if zmiana:
        try:
            dom = rejestr.ustaw_sieci(args.dom, sieci=sieci, hosty=hosty, kto="cli")
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
    print(f"Dom {dom.id}: dozwolone_sieci: {', '.join(dom.dozwolone_sieci) or '-'}")
    print(f"        dozwolone_hosty: {', '.join(dom.dozwolone_hosty) or '-'}")
    if zmiana:
        print("Dziala po restarcie poda (albo przeladowaniu domu w E3b).")
    return 0


async def cmd_klucze_rotuj(args) -> int:
    from .sejf import KEK_POPRZEDNI_ENV  # noqa: PLC0415

    cfg = Config.load(args.config)
    sejf = _sejf()
    zmienione = _rejestr(cfg).rotuj_kek(sejf, kto="cli")
    print(f"DEK-i przepakowane kluczem {sejf.kek_id}: "
          f"{', '.join(f'Dom {d}' for d in zmienione) or 'brak (wszystkie juz na nim)'}")
    print(f"Teraz usun {KEK_POPRZEDNI_ENV} z Sekretu i zrestartuj poda "
          f"(docs/sejf-domow.md).")
    return 0


async def cmd_klucze_potwierdz(args) -> int:
    """Dowod, ze klucz z menedzera hasel (stdin) jest BIEZACYM kluczem bazy:
    otwiera kazdy klucz domu i kazda integracje. Bez tego dowodu polecenie
    ODMAWIA — runbook nie pozwala wtedy usunac KIDWATCH_KEK_POPRZEDNI ani
    starego wpisu w menedzerze hasel (docs/sejf-domow.md, §7)."""
    from .domy import RejestrDomow  # noqa: PLC0415
    from .sejf import BrakKek, Sejf, _klucz_z_base64  # noqa: PLC0415

    klucz = Sejf(_klucz_z_base64(sys.stdin.readline(), "klucz z menedzera hasel"))
    rejestr = RejestrDomow(args.baza) if args.baza else _rejestr(Config.load(args.config))
    raport = rejestr.sprawdz_raport(klucz)
    problemy = []
    if raport.bledy:
        problemy.append(f"{len(raport.bledy)} kluczy domow/integracji nie otwiera sie tym "
                        f"kluczem (DEK-i na innym kluczu? najpierw kidwatch klucze-rotuj)")
    if raport.klucze_domow == 0 and not raport.bledy:
        problemy.append("w bazie nie ma zadnego klucza domu — nic nie potwierdzono")
    if not args.baza:
        try:
            biezacy = Sejf.z_srodowiska()
        except BrakKek:
            biezacy = None
        if biezacy is not None and biezacy.kek_id != klucz.kek_id:
            problemy.append(f"to nie jest biezacy KIDWATCH_KEK procesu ({biezacy.kek_id})")
    if problemy:
        print(f"ODMOWA: klucz {klucz.kek_id} NIE jest potwierdzony:")
        for p in problemy:
            print(f"  - {p}")
        print("NIE usuwaj KIDWATCH_KEK_POPRZEDNI z Sekretu ani zadnego klucza z menedzera "
              "hasel.")
        return 1
    rotacje = rejestr.ostatnia_rotacja_kek()
    if not args.baza:
        rejestr.zapisz_potwierdzenie_kek(klucz.kek_id, raport.klucze_domow, raport.integracje,
                                         kto="cli")
    print(f"POTWIERDZONO: klucz {klucz.kek_id} z menedzera hasel otwiera "
          f"{raport.klucze_domow} kluczy domow i {raport.integracje} integracji.")
    print("Wolno usunac KIDWATCH_KEK_POPRZEDNI z Sekretu (jesli jest).")
    if rotacje is not None:
        print(f"Stary klucz w menedzerze hasel: NIE usuwaj, dopoki istnieja kopie bazy sprzed "
              f"{rotacje} — kopie sprzed rotacji otwiera tylko stary klucz.")
    else:
        print("Brak rotacji w historii bazy — nie ma starszego klucza do przechowania.")
    return 0


async def cmd_dom_klucz_rotuj(args) -> int:
    cfg = Config.load(args.config)
    typy = _rejestr(cfg).rotuj_dek(args.dom, _sejf(), kto="cli")
    print(f"Dom {args.dom}: nowy klucz danych, przeszyfrowane: {', '.join(typy) or '-'}")
    return 0


async def cmd_user_admin(args) -> int:
    """Administrator instalacji (§2.3, decyzja 5): flaga w panel-auth.db,
    wylacznie z CLI. `on` wypisuje konto ze wszystkich domow (konto
    administracyjne bez czlonkostw — widzi domy przez role, z wpisem w
    dzienniku, i nie dostaje ich powiadomien), chyba ze --zostaw-domy."""
    from .domy import OstatniZarzadzajacy, RejestrDomow  # noqa: PLC0415
    from .panel_auth import UnknownUser  # noqa: PLC0415

    cfg = Config.load(args.config)
    auth = _auth(cfg)
    rejestr = RejestrDomow(cfg.panel_auth_path)
    try:
        uid = auth.user_id(args.login)
    except UnknownUser:
        print(f"nie ma konta {args.login!r}", file=sys.stderr)
        return 1
    wlacz = args.stan == "on"
    if wlacz and not args.zostaw_domy:
        czlonkostwa = rejestr.czlonkostwa(uid)
        # Najpierw sprawdzenie wszystkich domow, potem zmiany — bez polowicznego
        # wypisania, gdy w drugim domu to ostatni zarzadzajacy.
        for c in czlonkostwa:
            if uprawnienia.KONTA in c.uprawnienia and not any(
                    uprawnienia.KONTA in x.uprawnienia
                    for x in rejestr.czlonkowie(c.dom_id) if x.user_id != uid):
                print(f"odrzucone: {args.login!r} to jedyne konto zarzadzajace domem "
                      f"{c.dom_id} — najpierw daj te role komus innemu (konto prywatne "
                      "zostaw jako zwykle konto, administratorem zrob osobne).",
                      file=sys.stderr)
                return 1
        for c in czlonkostwa:
            try:
                auth.remove_membership(args.login, c.dom_id)
            except OstatniZarzadzajacy as exc:
                print(f"odrzucone: {exc}", file=sys.stderr)
                return 1
            print(f"wypisano z domu {c.dom_id} (byla rola: {c.rola})")
    zmiana = rejestr.ustaw_admin_instancji(uid, wlacz)
    n = auth.revoke_sessions(args.login)
    print(f"konto {args.login!r}: administrator instalacji "
          f"{'TAK' if wlacz else 'nie'}{'' if zmiana else ' (bez zmian)'}, "
          f"wylogowano sesji: {n}")
    if wlacz:
        print("Rola dziala tylko przy logowaniu przez Authelie z grupa 'admins' "
              "albo haslem z wlaczonym 2FA. Kazde wejscie do cudzego domu trafia do dziennika.")
    return 0


async def cmd_dom_dodaj(args) -> int:
    """Nowy dom (konfiguracja z bazy) z pusta baza zdarzen."""
    from .domy import RejestrDomow, sciezka_bazy_domu  # noqa: PLC0415

    cfg = Config.load(args.config)
    rejestr = RejestrDomow(cfg.panel_auth_path)
    rejestr.migruj(strefa=cfg.timezone)
    try:
        dom_id = rejestr.dodaj_dom(args.nazwa, strefa=args.strefa or cfg.timezone)
    except ValueError as exc:
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    # Pusta baza zdarzen domu: panel czyta ja tylko do odczytu, wiec musi
    # istniec. Pisze do niej potem wylacznie srodowisko domu.
    Store(str(sciezka_bazy_domu(dom_id, cfg.store.path))).close()
    print(f"zalozono dom {dom_id}: {args.nazwa}. Czlonkow dodasz: dom-czlonek {dom_id} <login> "
          "<rola>; integracje — po etapie E2.")
    return 0


async def cmd_dom_czlonek(args) -> int:
    """Rola konta w domu albo wypisanie (--usun)."""
    from .panel_auth import UnknownUser  # noqa: PLC0415

    cfg = Config.load(args.config)
    auth = _auth(cfg)
    try:
        if args.usun:
            n = auth.remove_membership(args.login, args.dom)
            print(f"konto {args.login!r} wypisane z domu {args.dom}, wylogowano sesji: {n}")
        else:
            if not args.rola:
                print("podaj role (wlasciciel-domu, zarzadca, podglad) albo --usun",
                      file=sys.stderr)
                return 2
            n = auth.set_role(args.login, args.rola, dom_id=args.dom)
            print(f"konto {args.login!r}: rola {args.rola} w domu {args.dom}, "
                  f"wylogowano sesji: {n}")
    except UnknownUser:
        print(f"nie ma konta {args.login!r}", file=sys.stderr)
        return 1
    except (ValueError, LookupError) as exc:
        print(f"odrzucone: {exc}", file=sys.stderr)
        return 1
    return 0


# ========================================================================= main
PANEL_ROLES = uprawnienia.ROLES


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
    # Rola z bazy panelu: `podglad` tylko oglada (uprawnienia.py — bez
    # zaleznosci, wiec CLI nie laduje argon2 przy kazdym poleceniu).
    users["user-add"].add_argument(
        "--rola", choices=PANEL_ROLES, default=PANEL_ROLES[0],
        help="wlasciciel (domyslnie) albo podglad: tylko ogladanie, bez MDM, czasu gry, "
        "pauzy TV, WhatsAppa i aplikacji TV",
    )
    users["user-add"].add_argument(
        "--bez-domu", action="store_true",
        help="konto bez zadnego domu (np. konto administracyjne przed user-admin on)",
    )
    user_rola = sub.add_parser(
        "user-rola", help="zmien role konta (wylogowuje jego sesje, kasuje odstepstwa uprawnien)"
    )
    user_rola.add_argument("login")
    user_rola.add_argument("rola", choices=PANEL_ROLES)
    user_upr = sub.add_parser(
        "user-uprawnienia",
        help="pojedyncze uprawnienia konta ponad role albo ponizej niej (wylogowuje)",
        description="+nazwa nadaje, -nazwa odbiera, =nazwa wraca do roli; bez zmian — "
        "wypisuje stan. Uprawnienia: " + ", ".join(uprawnienia.UPRAWNIENIA)
        + ". Zmiana roli (user-rola) kasuje odstepstwa.",
    )
    user_upr.add_argument("login")
    # REMAINDER: `-mdm.podglad` to zmiana, nie opcja argparse.
    user_upr.add_argument("zmiany", nargs=argparse.REMAINDER)
    user_del = sub.add_parser("user-del", help="usun konto panelu WWW razem z sesjami")
    user_del.add_argument("login")
    sub.add_parser("user-list", help="konta panelu WWW, ostatnie logowanie i blokady")

    # Powiadomienia per konto (odbiorcy.py).
    migruj = sub.add_parser(
        "konta-migruj",
        help="odbiorcy WhatsApp z bramki -> kanaly kont panelu (bez --zapisz: tylko plan)",
    )
    migruj.add_argument("--przypisz", action="append", default=[], metavar="POZYCJA=login",
                        help="numer z pozycji listy bramki -> konto (powtarzalne)")
    migruj.add_argument("--zapisz", action="store_true", help="zapisz kanaly i kategorie kont")
    migruj.add_argument("--wlacz", action="store_true",
                        help="po zapisie wlacz tryb kont (tylko gdy porownanie bez roznic)")
    tryb = sub.add_parser("konta-tryb", help="tryb powiadomien: trasy (stary) albo konta")
    tryb.add_argument("tryb", nargs="?", choices=("trasy", "konta"),
                      help="bez argumentu: pokaz tryb i kanaly kont")

    domy_p = sub.add_parser("domy", help="domy i ich czlonkowie (panel-auth.db)")
    domy_p.add_argument("--sprawdz", action="store_true",
                        help="odszyfruj wszystkie integracje (test kopii + KIDWATCH_KEK)")
    domy_p.add_argument("--baza", metavar="PANEL_AUTH_DB",
                        help="inna baza panelu, np. kopia do testu odtworzenia (bez config.yaml)")

    # Integracje domow i sejf (docs/sejf-domow.md). Tylko z CLI w podzie —
    # to droga administratora instancji.
    imp = sub.add_parser("dom-importuj",
                         help="Dom 1: config.yaml + sekrety -> baza (porownanie pole w pole)")
    imp.add_argument("dom", type=int)
    tryb_imp = imp.add_mutually_exclusive_group(required=True)
    tryb_imp.add_argument("--podglad", action="store_true",
                          help="pokaz, co zostanie zapisane (sekrety zamaskowane)")
    tryb_imp.add_argument("--zapisz", action="store_true",
                          help="zapisz i przelacz dom na konfiguracje z bazy")
    zrodlo = sub.add_parser("dom-zrodlo", help="skad dom bierze konfiguracje: yaml albo baza")
    zrodlo.add_argument("dom", type=int)
    zrodlo.add_argument("zrodlo", choices=("yaml", "baza"))
    sieci = sub.add_parser("dom-sieci",
                           help="sieci i hosty, do ktorych integracje domu moga sie laczyc")
    sieci.add_argument("dom", type=int)
    sieci.add_argument("--dodaj", action="append", default=[], metavar="CIDR")
    sieci.add_argument("--usun", action="append", default=[], metavar="CIDR")
    sieci.add_argument("--host", action="append", default=[], metavar="HOST",
                       help="host API (nextdns.base_url, ntfy.server) spoza listy wbudowanej")
    sieci.add_argument("--bez-hosta", action="append", default=[], metavar="HOST")
    sieci.add_argument("--wyczysc", action="store_true", help="usun wszystkie sieci i hosty")
    sub.add_parser("klucze-rotuj",
                   help="przepakuj klucze domow nowym KIDWATCH_KEK (po rotacji KEK)")
    potw = sub.add_parser(
        "klucze-potwierdz",
        help="klucz z menedzera hasel (stdin) otwiera wszystko? warunek usuniecia starego")
    potw.add_argument("--baza", metavar="PANEL_AUTH_DB",
                      help="sprawdz kopie bazy zamiast biezacej (bez wpisu w audycie)")
    dkr = sub.add_parser("dom-klucz-rotuj",
                         help="nowy klucz danych domu i przeszyfrowanie jego integracji")
    dkr.add_argument("dom", type=int)

    user_admin = sub.add_parser(
        "user-admin",
        help="administrator instalacji: widzi wszystkie domy (z wpisem w dzienniku); "
        "on wypisuje konto z domow",
    )
    user_admin.add_argument("login")
    user_admin.add_argument("stan", choices=("on", "off"))
    user_admin.add_argument("--zostaw-domy", action="store_true",
                            help="nie wypisuj z domow (niezalecane: §2.3)")
    dom_dodaj = sub.add_parser("dom-dodaj", help="zaloz nowy dom (bez czlonkow, pusta baza)")
    dom_dodaj.add_argument("nazwa")
    dom_dodaj.add_argument("--strefa", help="strefa czasowa (domyslnie jak w config.yaml)")
    dom_czl = sub.add_parser("dom-czlonek", help="rola konta w domu albo wypisanie (--usun)")
    dom_czl.add_argument("dom", type=int)
    dom_czl.add_argument("login")
    dom_czl.add_argument("rola", nargs="?", choices=uprawnienia.ROLE_DOMU)
    dom_czl.add_argument("--usun", action="store_true", help="wypisz konto z domu")

    return parser


def main(argv: list[str] | None = None) -> int:
    from .sejf import SejfError  # noqa: PLC0415

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
        "user-rola": cmd_user_rola,
        "user-uprawnienia": cmd_user_uprawnienia,
        "user-list": cmd_user_list,
        "konta-migruj": cmd_konta_migruj,
        "konta-tryb": cmd_konta_tryb,
        "domy": cmd_domy,
        "dom-importuj": cmd_dom_importuj,
        "dom-zrodlo": cmd_dom_zrodlo,
        "dom-sieci": cmd_dom_sieci,
        "klucze-rotuj": cmd_klucze_rotuj,
        "klucze-potwierdz": cmd_klucze_potwierdz,
        "dom-klucz-rotuj": cmd_dom_klucz_rotuj,
        "user-admin": cmd_user_admin,
        "dom-dodaj": cmd_dom_dodaj,
        "dom-czlonek": cmd_dom_czlonek,
    }
    try:
        return asyncio.run(handlers[args.command](args))
    except MissingSecretError as exc:
        print(f"\nBRAK SEKRETU: {exc}\n", file=sys.stderr)
        return 2
    except SejfError as exc:
        print(f"\nSEJF: {exc}\n", file=sys.stderr)
        return 2
    except FileNotFoundError as exc:
        print(f"\n{exc}\n", file=sys.stderr)
        return 2
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":
    sys.exit(main())
