"""Logika sesji i powiadomien.

Silnik nie wykonuje zadnego I/O sieciowego i nie zna zegara systemowego — czas
dostaje wstrzyknietym zegarem, a stan trzyma w przekazanym `Store`. Dzieki temu
kazda regula jest testowalna do konca, bez czekania i bez mockowania sieci.

Wejscie: `handle(event)` dla kazdego zapytania DNS oraz `tick(now)` wolane
cyklicznie. Wyjscie: lista `Notification`. Wysylka to nie jego sprawa.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import UTC, date, datetime, timedelta
from typing import Protocol

from .classifier import UNKNOWN_LABEL, Classifier, registrable
from .config import Config
from .formatting import payload, section, sections_text, short_title
from .models import DEVICE_KINDS, Classification, DnsEvent, Kind, Notification, NotifyKind
from .rollup import refresh_rollups
from .store import Store, episode_id, from_iso, to_iso
from .tvpause import TvPause, pause_facts

log = logging.getLogger(__name__)

#: Powiadomienia, ktorych limit godzinowy NIE dlawi. Zdlawienie informacji
#: "iPad wlaczyl sie o 2 w nocy" albo "kidwatch oslepl" zniweczylo by sens
#: calego serwisu. Start sesji jest z natury ograniczony przez idle_minutes,
#: wiec nie moze sam z siebie zrobic lawiny.
NEVER_THROTTLED = frozenset({
    NotifyKind.SESSION_START, NotifyKind.WATCHDOG, NotifyKind.DAILY, NotifyKind.THROTTLED,
    NotifyKind.NIGHT, NotifyKind.WEEKLY, NotifyKind.GAME, NotifyKind.TV_PAUSE,
})

#: Obecnosc z UniFi starsza niz to nie trafia do pusha — kontroler w restarcie
#: nie moze "trzymac dziecka w domu". Ten sam prog co w panelu.
PRESENCE_FRESH = timedelta(minutes=10)

#: Skroty dni do raportu tygodniowego. Nie z locale — w kontenerze jest C.
DNI_KROTKO = ("pon", "wt", "sr", "czw", "pt", "sob", "nd")

ESTIMATE_NOTE = "(czasy szacunkowe — liczba minut z ruchem DNS)"

# ================================================== reklamy wideo YouTube w grach
#: Sieci reklamowe, ktorych ruch w grze oznacza wyswietlanie reklamy. Osobny
#: zbior w kodzie, a nie odczyt sekcji `shared` z app_map.yaml: tam sa tez
#: CDN-y i zaplecze Google (google.com, googleapis.com), ktore NIE sa dowodem
#: reklamy. Liczy sie ruch wspoldzielony (AMBIGUOUS) i nieznany (domena z tej
#: listy, ktorej app_map nie zna, jest traktowana jak wspoldzielona). Domena
#: przypisana w mapie do APLIKACJI nie zostanie wzieta za reklame.
AD_NETWORK_SUFFIXES = frozenset({
    "unity3d.com", "unityads.unity3d.com", "applovin.com", "applvn.com",
    "ironsrc.com", "ironsrc.mobi", "supersonicads.com", "inmobi.com", "vungle.com",
    "chartboost.com", "tapjoy.com", "adcolony.com", "doubleclick.net",
    "googlesyndication.com", "googleadservices.com", "imasdk.googleapis.com",
    "inner-active.mobi", "fyber.com", "liftoff.io", "liftoff-creatives.io",
    "anzu.io", "anzuinfra.com", "anzu-us.com", "mintegral.com", "rayjump.com",
    "moloco.com", "bidmachine.io", "pangle.io", "pangleglobal.com",
})

#: Aplikacje, ktorych ruch w grze bywa reklama. Google IMA w grach odtwarza
#: reklamy z serwerow YouTube (youtubei.googleapis.com, googlevideo.com,
#: i.ytimg.com) — dla DNS wyglada to jak wlaczony YouTube.
AD_VIDEO_APPS = frozenset({"YouTube"})
#: Aplikacje, ktore NIE sa gra-gospodarzem reklamy: YouTube po YouTube Kids
#: (albo odwrotnie) to przelaczenie wideo, nie reklama w grze.
AD_NON_HOSTS = AD_VIDEO_APPS | {"YouTube Kids", "Netflix", "Disney+", "TikTok"}

#: Okno, w ktorym ruch sieci reklamowej wiaze ruch YouTube z reklama (±60 s:
#: SDK potrafi zapytac chwile przed albo po pobraniu klipu).
AD_WINDOW = timedelta(seconds=60)
#: Tyle YouTube bez jednego zdarzenia gry = prawdziwe ogladanie, takze gdy
#: reklamy byly w poblizu. Reklama wideo trwa 15-30 s, z ekranem koncowym
#: niewiele dluzej.
AD_MAX_RUN = timedelta(minutes=2)


def is_ad_network(domain: str) -> bool:
    parts = domain.strip().rstrip(".").lower().split(".")
    return any(".".join(parts[i:]) in AD_NETWORK_SUFFIXES for i in range(len(parts) - 1))


class Clock(Protocol):
    def now(self) -> datetime: ...


class SystemClock:
    def now(self) -> datetime:
        return datetime.now(UTC)


@dataclass(frozen=True, slots=True)
class FakeClock:
    """Zegar do testow. Nie jest zamrozony celowo — testy podmieniaja `at`."""

    at: datetime

    def now(self) -> datetime:
        return self.at


def fmt_duration(delta: timedelta) -> str:
    total = max(0, int(delta.total_seconds()))
    minutes = total // 60
    if minutes < 60:
        return f"{minutes} min"
    hours, mins = divmod(minutes, 60)
    return f"{hours} h" if mins == 0 else f"{hours} h {mins} min"


def plural_sesje(n: int) -> str:
    """Polska odmiana: 1 sesja, 2-4 sesje, 5+ sesji (i 12-14 sesji)."""
    if n % 10 == 1 and n % 100 != 11:
        return "sesja"
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return "sesje"
    return "sesji"


def fmt_domains(pairs: list[tuple[str, int]], limit: int = 6) -> str:
    """Zwija hosty do domen rejestrowalnych i skleja w czytelna liste.

    Kilkadziesiat hostow jednej witryny to dla czlowieka jedna nazwa. Bez
    zwijania push o przegladaniu bylby scianą tekstu.
    """
    counts: dict[str, int] = {}
    for host, n in pairs:
        key = registrable(host)
        counts[key] = counts.get(key, 0) + n
    ordered = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    shown = [name for name, _ in ordered[:limit]]
    rest = len(ordered) - limit
    if rest > 0:
        shown.append(f"+{rest}")
    return ", ".join(shown)


def tv_titles(segments) -> list[str]:
    """Rozne tytuly w kolejnosci pierwszego pojawienia. Bez tytulu (Netflix nie
    podaje metadanych) — nazwa aplikacji, zeby czas nie znikal z opisu."""
    out: list[str] = []
    for seg in segments:
        label = seg["title"] or seg["app"]
        if seg["title"] and seg["channel"]:
            label = f"{seg['channel']}: {seg['title']}"
        if label not in out:
            out.append(label)
    return out


def fmt_titles(titles: list[str], limit: int = 4) -> str:
    shown = titles[:limit]
    rest = len(titles) - limit
    if rest > 0:
        shown.append(f"+{rest}")
    return ", ".join(shown)


def week_label(monday: date) -> str:
    """Tydzien ISO jako "2026-W40" — klucz dedupu i argument CLI --week."""
    year, week, _ = monday.isocalendar()
    return f"{year}-W{week:02d}"


def report_week(day: date) -> date:
    """Poniedzialek tygodnia, ktory raportujemy w dniu `day`.

    W niedziele (ostatni dzien tygodnia ISO) — biezacy tydzien. W kazdy inny
    dzien — ostatni PELNY tydzien: porownanie z poprzednim tygodniem nie ma
    sensu dla tygodnia ucietego w polowie.
    """
    monday = day - timedelta(days=day.weekday())
    return monday if day.weekday() == 6 else monday - timedelta(days=7)


def fmt_change(cur: timedelta, prev: timedelta) -> str:
    if prev <= timedelta(0):
        return "poprzednio 0"
    pct = round((cur - prev) / prev * 100)
    return f"{pct:+d}% wzgledem {fmt_duration(prev)}"


def fmt_apps(pairs: list[tuple[str, int]], limit: int = 5) -> str:
    if not pairs:
        return "brak rozpoznanych aplikacji"
    shown = [f"{app} ~{n} min" for app, n in pairs[:limit]]
    rest = len(pairs) - limit
    if rest > 0:
        shown.append(f"+{rest} innych")
    return ", ".join(shown)


class Engine:
    #: Zdarzenie mlodsze niz to = strumien nadrobil przestoj po restarcie.
    CATCHUP_FRESH = timedelta(minutes=2)
    #: Dluzej tik nie czeka na nadrobienie strumienia.
    CATCHUP_MAX = timedelta(minutes=10)

    def __init__(
        self,
        cfg: Config,
        store: Store,
        classifier: Classifier,
        clock: Clock | None = None,
    ) -> None:
        self.cfg = cfg
        self.store = store
        self.classifier = classifier
        self.clock = clock or SystemClock()
        # Baza z historia = restart procesu; patrz _waiting_for_stream.
        self._catching_up = store.get_meta("alive:__all__") is not None
        self._catchup_since: datetime | None = None
        #: Pauza monitoringu TV (tvpause.py). Kolejke zadan z panelu
        #: podpina cmd_run — bez niej dziala samo domykanie po terminie.
        self.tv_pause = TvPause(cfg, store)

    # =========================================================== wejscie zdarzen
    def handle(self, event: DnsEvent) -> list[Notification]:
        """Przetwarza jedno zapytanie DNS.

        Najpierw domyka sesje, ktore wygasly przed tym zdarzeniem — dzieki temu
        kolejnosc powiadomien jest poprawna nawet gdy wolajacy nie wola `tick`,
        na przyklad przy odtwarzaniu pliku z zapisem dnia.
        """
        out: list[Notification] = self._expire_sessions(event.ts)
        out.extend(self._flush_ad_pending(event.ts))

        # Zrodlo podaje dwa tropy identyfikacji; konfiguracja moze wymieniac
        # dowolny z nich, wiec sprawdzamy oba.
        device_cfg = self.cfg.device_for(event.device_id)
        if device_cfg is None and event.device_alt:
            device_cfg = self.cfg.device_for(event.device_alt)
        verdict = self.classifier.classify(event.domain)
        if verdict.kind is Kind.UNKNOWN and is_ad_network(event.domain):
            # Siec reklamowa, ktorej app_map nie zna (mintegral, moloco, pangle,
            # applvn...), to ruch wspoldzielony, nie "przegladanie": nie otwiera
            # sesji pushem przy spiacym iPadzie i liczy sie jako dowod reklamy.
            # Bez tego takie SDK samo otwieralo sesje "Przegladarka / inne",
            # a reklama YouTube przy nim nie byla rozpoznawana.
            verdict = Classification(Kind.AMBIGUOUS)
        device = device_cfg.display_name if device_cfg else None

        self.store.record_event(
            ts=event.ts,
            device=device,
            source_id=event.device_id,
            domain=event.domain,
            kind=verdict.kind.value,
            app=verdict.app,
        )

        # Kazde zdarzenie, TAKZE szum, jest dowodem zycia potoku. Stad szum ma
        # wartosc: to on odroznia "iPad spi" od "przestalismy widziec iPada".
        self._mark_alive(event.ts, device)
        if device is None:
            return out
        if verdict.kind is Kind.NOISE:
            # Szum nie budzi sesji i nie przedluza jej — inaczej sesja nigdy by
            # sie nie skonczyla, bo iPad odpytuje Apple bez przerwy.
            return out

        if verdict.kind is Kind.AMBIGUOUS:
            # Wspoldzielone CDN-y i SDK reklamowe: PRZEDLUZAJA otwarta sesje, ale
            # jej nie otwieraja. Bez tego gra, ktora w trakcie rozgrywki gada
            # tylko z CloudFrontem, mialaby sztucznie krotka sesje; z otwieraniem
            # sesji — budzilaby pushem spiacy iPad.
            if is_ad_network(event.domain):
                self._note_ad(device, event.ts)
            self._extend_session(device, event.ts)
            return out

        label = verdict.app if verdict.kind is Kind.APP and verdict.app else UNKNOWN_LABEL
        assert device_cfg is not None
        verdict_ad, host = self._ad_verdict(device, label, event.ts)
        if verdict_ad == "ad":
            # Reklama wideo w grze: bez pusha "YouTube", minuta idzie grze.
            self._count_minute(device, host, event.ts)
            return out
        if verdict_ad == "tentative":
            # Moze reklama, moze nie: minuta YouTube, push czeka (patrz wyzej).
            self._count_minute(device, label, event.ts)
            return out
        out.extend(self._on_activity(device_cfg, label, event.ts))
        self._remember_app(device, label)
        return out

    # ===================================================== reklamy YouTube w grach
    #
    # Zaobserwowane 2026-10-02 16:07, Asphalt na obu iPadach: ruch YouTube
    # (youtubei.googleapis.com, googlevideo.com, i.ytimg.com) w tej samej
    # sekundzie co SDK reklamowe. To reklama Google IMA, nie ogladanie.
    #
    # Kontekst gry: w otwartej sesji ostatnia PRAWDZIWA aplikacja nie jest
    # wideo. "Przebieg" YouTube zaczyna sie od pierwszego zdarzenia YouTube po
    # zdarzeniu gry; kazde zdarzenie gry konczy przebieg.
    #
    # - siec reklamowa w ciagu 60 s PRZED poczatkiem przebiegu -> reklama:
    #   bez pusha, minuty dla gry;
    # - brak reklamy -> wstepnie YouTube (minuty YouTube), ale push "YouTube"
    #   czeka 60 s. Jesli w tym czasie odezwie sie siec reklamowa (SDK potrafi
    #   zapytac PO pobraniu klipu), minuty przebiegu przechodza na gre, a push
    #   przepada. Dopiero po 60 s bez reklamy push wychodzi;
    # - przebieg dluzszy niz 2 min to prawdziwe ogladanie, nawet z reklamami
    #   w poblizu — reklama wideo trwa 15-30 s.
    #
    # Stan per urzadzenie w meta `adctx:<urzadzenie>` (przezywa restart).

    def _ad_ctx(self, device: str, session_id: int | None) -> dict:
        ctx = self.store.get_json(f"adctx:{device}", {})
        ctx = ctx if isinstance(ctx, dict) else {}
        if session_id is not None and ctx.get("session") != session_id:
            # Nowa sesja = nowy kontekst; zostaje tylko czas ostatniej reklamy.
            ctx = {"session": session_id, "ad_at": ctx.get("ad_at")}
        return ctx

    def _save_ad_ctx(self, device: str, ctx: dict) -> None:
        self.store.set_json(f"adctx:{device}", ctx)

    def _note_ad(self, device: str, ts: datetime) -> None:
        session = self.store.get_open_session(device)
        ctx = self._ad_ctx(device, int(session["id"]) if session else None)
        prev = ctx.get("ad_at")
        if prev is None or from_iso(prev) < ts:
            ctx["ad_at"] = to_iso(ts)
        pending = ctx.get("pending")
        host = ctx.get("last_app")
        if session is not None and pending and host:
            since = from_iso(pending)
            if ts - since <= AD_WINDOW:
                # Reklama przyszla PO klipie: przebieg byl reklama. Minuty
                # YouTube z tego przebiegu wracaja do gry, push przepada.
                self.store.reassign_app_minutes(int(session["id"]), "YouTube", host, since)
                ctx.pop("pending", None)
        self._save_ad_ctx(device, ctx)

    def _ad_verdict(self, device: str, label: str, ts: datetime) -> tuple[str, str | None]:
        """("ad", gra) | ("tentative", gra) | ("normal", None)."""
        if label not in AD_VIDEO_APPS:
            return "normal", None
        session = self.store.get_open_session(device)
        if session is None:
            return "normal", None
        ctx = self._ad_ctx(device, int(session["id"]))
        host = ctx.get("last_app")
        if host is None or host in AD_NON_HOSTS:
            self._save_ad_ctx(device, ctx)
            return "normal", None
        run_start = from_iso(ctx.setdefault("run_start", to_iso(ts)))
        ad_at = from_iso(ctx["ad_at"]) if ctx.get("ad_at") else None
        ad_near = ad_at is not None and ad_at >= run_start - AD_WINDOW
        if ts - run_start > AD_MAX_RUN or (not ad_near and ts - run_start > AD_WINDOW):
            # Prawdziwe ogladanie: od teraz YouTube jest aplikacja sesji.
            ctx["last_app"] = label
            ctx.pop("run_start", None)
            ctx.pop("pending", None)
            self._save_ad_ctx(device, ctx)
            return "normal", None
        if ad_near:
            ctx.pop("pending", None)
            self._save_ad_ctx(device, ctx)
            return "ad", host
        ctx.setdefault("pending", to_iso(run_start))
        self._save_ad_ctx(device, ctx)
        return "tentative", host

    def _remember_app(self, device: str, label: str) -> None:
        """Po zwyklym zdarzeniu aplikacji: zapamietaj ja jako ostatnia prawdziwa.
        Wolane PO `_on_activity`, bo pierwsze zdarzenie dopiero otwiera sesje."""
        if label == UNKNOWN_LABEL:
            return
        session = self.store.get_open_session(device)
        if session is None:
            return
        ctx = self._ad_ctx(device, int(session["id"]))
        if label not in AD_NON_HOSTS:
            ctx.pop("run_start", None)
        ctx["last_app"] = label
        self._save_ad_ctx(device, ctx)

    def _count_minute(self, device: str, app: str, ts: datetime) -> None:
        session = self.store.get_open_session(device)
        if session is None:
            return
        self.store.touch_session(int(session["id"]), ts)
        self.store.record_app_minute(int(session["id"]), app, ts)

    def _flush_ad_pending(self, now: datetime) -> list[Notification]:
        """Wstrzymany push "YouTube", dla ktorego minelo 60 s bez reklamy."""
        out: list[Notification] = []
        for dev in self.cfg.devices:
            ctx = self.store.get_json(f"adctx:{dev.display_name}", {})
            if not isinstance(ctx, dict) or not ctx.get("pending"):
                continue
            if now - from_iso(ctx["pending"]) <= AD_WINDOW:
                continue
            ctx.pop("pending", None)
            ctx["last_app"] = "YouTube"
            ctx.pop("run_start", None)
            self._save_ad_ctx(dev.display_name, ctx)
            if self.store.get_open_session(dev.display_name) is not None:
                out.extend(self._maybe_app_notification(dev, "YouTube", now))
        return out

    def _extend_session(self, device: str, ts: datetime) -> None:
        """Przedluza sesje ruchem wspoldzielonym — ale tylko w oknie ograniczonym.

        OGRANICZNIK jest tu najwazniejszy. Bez niego odswiezanie aplikacji w tle,
        trafiajace w te same CDN-y, trzymaloby sesje otwarta w nieskonczonosc i
        sesja nigdy by sie nie skonczyla. Przedluzamy wiec tylko wtedy, gdy
        ROZPOZNANE zdarzenie bylo nie dawniej niz `shared_extend_minutes`.

        Prog jest osobny od `idle_minutes` swiadomie: gra potrafi gadac z wlasnym
        zapleczem raz na kilkanascie minut, a z CDN-em bez przerwy. Przy progu
        rownym idle_minutes godzinna rozgrywka rozpadlaby sie na kilka sesji.
        """
        window = self.cfg.engine.shared_extend_minutes
        if window <= 0:
            return
        session = self.store.get_open_session(device)
        if session is None:
            return
        identified = session["last_identified_at"]
        if identified is None:
            return
        if ts - from_iso(identified) >= timedelta(minutes=window):
            return
        # Tylko w przod: zdarzenia moga przyjsc lekko nie po kolei, a cofniecie
        # ostatniej aktywnosci zamknelo by sesje przedwczesnie.
        if ts > from_iso(session["last_activity_at"]):
            self.store.touch_session(int(session["id"]), ts, identified=False)

    def _on_activity(self, device_cfg, label: str, ts: datetime) -> list[Notification]:
        out: list[Notification] = []
        device = device_cfg.display_name
        session = self.store.get_open_session(device)

        if session is None:
            session_id = self.store.open_session(device, device_cfg.child, ts, confirmed=False)
            # Nie wysylamy jeszcze nic: sesja musi sie potwierdzic (patrz
            # _confirmed_start). Pojedyncze zapytanie lezacego iPada nie jest
            # "iPad aktywny".
            self.store.set_json(
                f"pending_start:{device}", {"id": session_id, "since": to_iso(ts)}
            )
        else:
            session_id = int(session["id"])
            self.store.touch_session(session_id, ts)

        self.store.record_app_minute(session_id, label, ts)

        pending = self.store.get_json(f"pending_start:{device}")
        if isinstance(pending, dict) and int(pending["id"]) == session_id:
            start = self._confirmed_start(pending, label, ts)
            if start is None:
                self.store.set_json(f"pending_start:{device}", pending)
                return out
            self.store.confirm_session(session_id, start)
            named = label if label != UNKNOWN_LABEL else self.store.last_app(
                session_id, exclude=UNKNOWN_LABEL
            )
            out.extend(self._emit_session_start(device_cfg, session_id, start, named, ts))
            return out

        out.extend(self._maybe_app_notification(device_cfg, label, ts))
        return out

    #: Zapytania blizej siebie niz tyle (liczac od pierwszego zapytania
    #: chwili) to JEDNA chwila aktywnosci. Odswiezenie aplikacji w tle to
    #: pakiet kilku-kilkunastu zapytan w tej samej sekundzie — surowa liczba
    #: zapytan potwierdzala je jako "otwarcie aplikacji" (2026-10: sesje
    #: YouTube po kilka sekund na lezacych iPadach, z pushem startu).
    MOMENT_GAP = timedelta(seconds=10)
    #: Najkrotsza rozpietosc (pierwsza do ostatniej aktywnosci w oknie
    #: confirm_minutes) potwierdzonej sesji. Liczona jako odstep, nie numer
    #: minuty na zegarze: 14:00:59 i 14:01:01 to jedno odswiezenie w tle.
    CONFIRM_SPAN = timedelta(seconds=60)
    #: Sama rozpietosc, bez wymogu liczby chwil: gra w trakcie rozgrywki
    #: odzywa sie do zaplecza co ~3-3,5 min (Asphalt w tests/fixtures/day.jsonl).
    #: Odswiezenia w tle z produkcji (2026-10) trwaly najwyzej 2 minuty.
    LONG_SPAN = timedelta(minutes=3)

    def _confirmed_start(self, pending: dict, label: str, ts: datetime) -> datetime | None:
        """Poczatek potwierdzonej sesji albo None (jeszcze niepotwierdzona).

        Sesja jest potwierdzona, gdy w oknie confirm_minutes sa co najmniej
        `confirm_moments` ODREBNE chwile aktywnosci (patrz MOMENT_GAP)
        rozpiete na CONFIRM_SPAN — albo gdy sama rozpietosc siega LONG_SPAN.
        Wzor odswiezenia w tle: pakiet w jednej sekundzie i czasem pojedyncze
        zapytanie CDN po 1-2 minutach — to dwie chwile, za malo.

        Aktualizuje `pending` w miejscu: "moments" to poczatki chwil w oknie,
        "last" — najpozniejsza aktywnosc. Zwracany poczatek to pierwsza chwila
        w oknie: samotny ping sprzed kilku minut nie przesuwa godziny startu.
        """
        eng = self.cfg.engine
        window = timedelta(minutes=eng.confirm_minutes)
        # "acts" to zapis sprzed MOMENT_GAP — sesja czekajaca w chwili wdrozenia.
        stored = pending.pop("acts", None) or pending.get("moments", [])
        pending.pop("apps", None)
        moments: list[datetime] = []
        for a in sorted([*(a for a in map(from_iso, stored) if ts - a <= window), ts]):
            # Kolejno, bo zapis "acts" ma po kilka zapytan z tej samej sekundy.
            if not moments or a - moments[-1] > self.MOMENT_GAP:
                moments.append(a)
        last = max(ts, from_iso(pending["last"])) if pending.get("last") else ts
        pending["moments"] = [to_iso(m) for m in moments]
        pending["last"] = to_iso(last)

        if eng.confirm_moments <= 1 and label != UNKNOWN_LABEL:
            # Tryb testow innych regul: zdarzenie aplikacji potwierdza od razu.
            return moments[0]
        span = last - moments[0]
        if (len(moments) >= eng.confirm_moments and span >= self.CONFIRM_SPAN) or (
            span >= self.LONG_SPAN
        ):
            return moments[0]
        return None

    # ============================================================ pojedyncze pushe
    def _emit_session_start(
        self,
        device_cfg,
        session_id: int,
        started_at: datetime,
        app: str | None,
        ts: datetime,
    ) -> list[Notification]:
        device = device_cfg.display_name
        self.store.mark_start_notified(session_id)
        self.store.set_meta(f"pending_start:{device}", "null")

        local = started_at.astimezone(self.cfg.tz)
        quiet = self._in_quiet_hours(started_at)
        night = self._in_night(started_at)
        priority = self.cfg.engine.quiet_hours.session_start_priority if quiet else 3

        title = f"{device} aktywny"
        if app:
            what = app
            self.store.set_app_notified(device, app, ts)
        else:
            # Sesja otwarta nierozpoznanym ruchem: powiedz CZYM, a nie tylko
            # "aktywny". To zwykle przegladanie stron.
            browsed = self.store.browsed_since(device, started_at, ts)
            what = fmt_domains(browsed, limit=4) if browsed else ""
        text = f"{local:%H:%M} — {what}" if what else f"{local:%H:%M}"
        if night:
            # Start w nocy to JEDEN push w formie nocnej — zamiast dopisku
            # o cichych godzinach, nie obok niego. Przypomnienia o trwajacej
            # sesji liczy _night_watch od tego pusha.
            title = f"\U0001F319 {device_cfg.child} uzywa iPada w nocy"
            text = ", ".join(x for x in (f"{local:%H:%M}", what, self._presence(device, ts)) if x)
            priority = self._night_priority()
            self.store.set_json(f"night:{session_id}", {"n": 1, "last": to_iso(ts)})
        elif quiet:
            title = f"{device} aktywny W CICHYCH GODZINACH"

        tags = ("warning", "ipad") if quiet or night else ("iphone", "ipad")
        return self._emit(
            Notification(
                kind=NotifyKind.SESSION_START,
                title=title,
                text=text,
                dedup_key=f"start:{session_id}",
                ts=ts,
                device=device,
                app=app,
                priority=priority,
                tags=tags,
            )
        )

    def _maybe_app_notification(self, device_cfg, label: str, ts: datetime) -> list[Notification]:
        device = device_cfg.display_name
        session = self.store.get_open_session(device)
        if session is None or not int(session["confirmed"]):
            # Niepotwierdzona sesja nie istnieje dla uzytkownika — takze dla
            # wstrzymanego pusha "YouTube" z _flush_ad_pending.
            return []

        # W cichych godzinach nie raportujemy aplikacji — sam fakt, ze iPad
        # dziala w nocy, zostal juz zgloszony przy starcie sesji.
        if self._in_quiet_hours(ts):
            return []
        if label == UNKNOWN_LABEL and not self.cfg.engine.notify_unknown:
            return []

        cooldown = timedelta(minutes=self.cfg.engine.app_cooldown_minutes)
        last = self.store.app_last_notified(device, label)
        if last is not None and ts - last < cooldown:
            return []
        # Nazwana aplikacja: jeden push na sesje ("nowa apka"). Sam cooldown
        # dawal "YouTube" co 15 min przez caly seans (audyt 3, S4). Nierozpoznany
        # ruch zostaje na cooldownie — kolejne push wymieniaja NOWE domeny.
        if (
            label != UNKNOWN_LABEL
            and last is not None
            and last >= from_iso(session["started_at"])
        ):
            return []

        text = label
        if label == UNKNOWN_LABEL:
            # Nierozpoznany ruch to najczesciej przegladanie stron. Sama etykieta
            # "Przegladarka / inne" nic nie mowi — nazywamy konkretne domeny,
            # widziane od poprzedniego takiego pusha.
            since = last or from_iso(
                (self.store.get_open_session(device) or {"started_at": to_iso(ts)})["started_at"]
            )
            browsed = self.store.browsed_since(device, since, ts)
            if browsed:
                text = f"{label}: {fmt_domains(browsed)}"

        self.store.set_app_notified(device, label, ts)
        return self._emit(
            Notification(
                kind=NotifyKind.APP,
                title=device_cfg.child,
                text=text,
                dedup_key=f"app:{device}:{label}:{ts.astimezone(UTC):%Y%m%dT%H%M%S}",
                ts=ts,
                device=device,
                app=label,
                tags=("play",),
            )
        )

    # ================================================================== zamykanie
    def _expire_sessions(self, now: datetime) -> list[Notification]:
        out: list[Notification] = []
        idle = timedelta(minutes=self.cfg.engine.idle_minutes)
        # Tylko sesje iPadow. Sesje telewizora (child NULL) nie dostaja zdarzen
        # DNS, wiec ten zegar zamknalby kazda po idle_minutes — i wyslal push
        # "koniec" w formacie iPada. Domyka je sources/tv.py.
        for row in self.store.all_open_sessions(child_only=True):
            last = from_iso(row["last_activity_at"])
            if now - last < idle:
                continue
            device = row["device"]
            session_id = int(row["id"])
            self.store.close_session(session_id, last)
            self.store.set_meta(f"pending_start:{device}", "null")
            self.store.delete_meta(f"night:{session_id}")

            # Sesja niepotwierdzona (samotne zapytanie w tle) albo taka, o ktorej
            # nie poszedl push startu, zamyka sie po cichu.
            if not int(row["confirmed"]) or not int(row["start_notified"]):
                continue

            started = from_iso(row["started_at"])
            apps = self.store.session_app_minutes(session_id)
            # Domeny odwiedzone w tej sesji — dla przegladania to jedyna tresc,
            # jaka DNS zna. Adresow stron ani tresci nie widzimy.
            browsed = self.store.browsed_since(device, started, last)
            # Bez naglowka: tytul pusha juz mowi, czyj iPad.
            sec = section(
                "",
                f"{started.astimezone(self.cfg.tz):%H:%M}"
                f"\u2013{last.astimezone(self.cfg.tz):%H:%M}, {fmt_duration(last - started)}",
                apps=apps,
                after=[f"strony: {fmt_domains(browsed)}"] if browsed else None,
            )
            out.extend(
                self._emit(
                    Notification(
                        kind=NotifyKind.SESSION_END,
                        title=f"{device} — koniec",
                        text=sections_text([sec], ESTIMATE_NOTE),
                        data=payload("session_end", [sec], note=ESTIMATE_NOTE),
                        dedup_key=f"end:{session_id}",
                        ts=now,
                        device=device,
                        priority=2,
                        tags=("sleeping",),
                    )
                )
            )
        return out

    # ===================================================================== tick
    def tick(self, now: datetime | None = None) -> list[Notification]:
        """Wolane cyklicznie: domyka sesje, wysyla podsumowanie dnia, pilnuje czujki."""
        now = now or self.clock.now()
        if self._waiting_for_stream(now):
            return []
        out: list[Notification] = []
        steps = (
            self._expire_sessions, self._flush_ad_pending, self._flush_pending_starts,
            self._tv_pause_step, self._night_watch, self._maybe_daily_summary,
            self._maybe_weekly_report, self._watchdog, self._drain_throttled,
        )
        for step in steps:
            # Kazdy krok osobno: klucz dedupu i znacznik daily_sent sa juz
            # zapisane, gdy krok zwraca notke. Wyjatek w pozniejszym kroku
            # wywracal caly tik i gubil podsumowanie na zawsze.
            try:
                out.extend(step(now))
            except Exception:
                log.exception("tik: krok %s padl — reszta tiku idzie dalej", step.__name__)
        self._rollup(now)
        return out

    def _waiting_for_stream(self, now: datetime) -> bool:
        """Po restarcie tik czeka, az zrodlo nadrobi przestoj.

        Pierwszy tik szedl z prawdziwym `now`, zanim zrodlo odczytalo pierwszy
        bajt. Po przestoju dluzszym niz idle_minutes zamykal wiec trwajaca
        sesje ("koniec"), czujka meldowala slepote, a zalegle zdarzenia
        otwieraly nowa sesje. Czekamy na zdarzenie swiezsze niz CATCHUP_FRESH —
        najdluzej CATCHUP_MAX, potem tik rusza normalnie (prawdziwa awaria
        strumienia zglosi czujka z tym opoznieniem).

        Dotyczy tylko bazy z historia: swieza baza nie ma czego nadrabiac.
        """
        if not self._catching_up:
            return False
        last = self.store.get_meta("alive:__all__")
        if last is not None and now - from_iso(last) < self.CATCHUP_FRESH:
            self._catching_up = False
            return False
        if self._catchup_since is None:
            self._catchup_since = now
            log.info("start: czekam, az zrodlo nadrobi zdarzenia od %s", last)
        if now - self._catchup_since < self.CATCHUP_MAX:
            return True
        log.warning("zrodlo nie nadrobilo zaleglosci w %s — tik rusza mimo to",
                    fmt_duration(self.CATCHUP_MAX))
        self._catching_up = False
        return False

    def _tv_pause_step(self, now: datetime) -> list[Notification]:
        """Zadania pauzy TV z panelu i koniec pauzy po terminie — przed
        podsumowaniem dnia, zeby raport widzial juz domknieta pauze."""
        out: list[Notification] = []
        for note in self.tv_pause.step(now):
            out.extend(self._emit(note))
        return out

    def _rollup(self, now: datetime) -> None:
        """Agregaty dzienne (rollup.py). Na koncu tiku i z wlasnym lapaniem
        wyjatkow: blad agregatu nie moze zjesc pushy wyliczonych wyzej."""
        try:
            refresh_rollups(self.cfg, self.store, now)
        except Exception:
            log.exception("agregaty dzienne: blad — sprobuje przy nastepnym tiku")

    def _flush_pending_starts(self, now: datetime) -> list[Notification]:
        """Sprzata `pending_start` sesji, ktorej juz nie ma. Push startu idzie
        wylacznie z potwierdzenia w _on_activity — tik niczego nie potwierdza:
        sama cisza po pojedynczym zapytaniu to wlasnie sesja do pominiecia."""
        for dev in self.cfg.devices:
            pending = self.store.get_json(f"pending_start:{dev.display_name}")
            if not isinstance(pending, dict):
                continue
            session = self.store.get_open_session(dev.display_name)
            if session is None or int(session["id"]) != int(pending["id"]):
                self.store.set_meta(f"pending_start:{dev.display_name}", "null")
        return []

    # ======================================================== podsumowanie dnia
    def _maybe_daily_summary(self, now: datetime) -> list[Notification]:
        local = now.astimezone(self.cfg.tz)
        target = self.cfg.engine.daily_summary_time
        if local.time() < target:
            return []
        day = local.date()
        if self.store.get_meta(f"daily_sent:{day.isoformat()}"):
            return []
        self.store.set_meta(f"daily_sent:{day.isoformat()}", to_iso(now))
        return self._emit(self.build_summary(day, now, cut=target))

    def summary_for(self, day: date, now: datetime) -> list[Notification]:
        """Podsumowanie doby lokalnej `day` do wysylki (dedup i log limitu)."""
        return self._emit(self.build_summary(day, now))

    def build_summary(self, day: date, now: datetime, cut=None) -> Notification:
        """Sama tresc podsumowania — bez _emit. Dla CLI `summary`: przejscie
        przez _emit zajmowalo klucz `daily:<dzien>`, a wtedy prawdziwe
        podsumowanie o daily_summary_time przepadalo na dedupie.

        Bez `cut` — doba lokalna. Z `cut` (godzina wysylki) — sesje zaczete
        w [dzien-1 cut, dzien cut). Push o 20:30 liczony za doba lokalna nie
        obejmowal nigdy wieczoru: sesja o 22:47 nie trafiala do zadnego
        podsumowania. Okno od poprzedniej wysylki liczy kazda sesje raz.
        """
        tz = self.cfg.tz
        if cut is None:
            start = datetime.combine(day, datetime.min.time(), tzinfo=tz)
            end = start + timedelta(days=1)
            note = ESTIMATE_NOTE
        else:
            start = datetime.combine(day - timedelta(days=1), cut, tzinfo=tz)
            end = datetime.combine(day, cut, tzinfo=tz)
            note = f"od {start:%d.%m %H:%M} {ESTIMATE_NOTE}"
        rows = self.store.sessions_between(start, end)

        per_device: dict[str, list] = {}
        for row in rows:
            # Sesja, o ktorej nigdy nie poszlo powiadomienie, nie istnieje dla
            # uzytkownika — liczenie jej w statystyce czyni liczbe bezwartosciowa.
            # Typowy przypadek: jedno nierozpoznane zapytanie DNS o 3 w nocy.
            if not int(row["start_notified"]):
                continue
            per_device.setdefault(row["device"], []).append(row)

        sections: list[dict] = []
        for dev in self.cfg.devices:
            sessions = per_device.get(dev.display_name, [])
            label = self._device_label(dev)
            if not sessions:
                sections.append(section(label, "brak aktywnosci"))
                continue
            total = timedelta()
            minutes: dict[str, int] = {}
            for row in sessions:
                started = from_iso(row["started_at"])
                finished = from_iso(row["ended_at"] or row["last_activity_at"])
                total += finished - started
                for app, n in self.store.session_app_minutes(int(row["id"])):
                    minutes[app] = minutes.get(app, 0) + n
            top = sorted(minutes.items(), key=lambda kv: (-kv[1], kv[0]))
            sections.append(section(
                label,
                f"{len(sessions)} {plural_sesje(len(sessions))}, {fmt_duration(total)}",
                apps=top,
            ))

        if self.cfg.tv.enabled:
            sections.append(self._tv_summary_section(per_device.get(self.cfg.tv.name, []),
                                                     start, end))

        return Notification(
            kind=NotifyKind.DAILY,
            title=f"Podsumowanie dnia {day:%d.%m}",
            text=sections_text(sections, note),
            dedup_key=f"daily:{day.isoformat()}",
            ts=now,
            priority=2,
            tags=("bar_chart",),
            data=payload("daily", sections, note=note),
        )

    def _device_label(self, dev) -> str:
        """Imie dziecka, a gdy ma kilka iPadow — z nazwa urzadzenia."""
        siblings = sum(1 for d in self.cfg.devices if d.child == dev.child)
        return dev.child if siblings == 1 else f"{dev.child} ({dev.display_name})"

    def _tv_summary_section(self, sessions: list, start: datetime, end: datetime) -> dict:
        """Telewizor w podsumowaniu: czas ogladania i co lecialo.

        Tu nie ma dopisku o szacunku z DNS — czas z telewizora to stan
        odtwarzacza odpytywany co poll_seconds, z dokladnoscia do tego odstepu.
        """
        name = self.cfg.tv.name
        paused, whole = pause_facts(self.store, self.cfg.tz, start, end)
        if not sessions:
            return section(name, "monitoring wstrzymany" if whole else "nic nie gralo",
                           kind="tv", facts=paused)
        total = sum((self._duration(r) for r in sessions), timedelta())
        titles = tv_titles(self.store.tv_segments_between(name, start, end))
        return section(
            name, f"{len(sessions)} {plural_sesje(len(sessions))}, {fmt_duration(total)}",
            kind="tv", titles=titles, facts=paused,
        )

    # ===================================================================== noc
    def _night_priority(self) -> int:
        night = self.cfg.engine.night
        if night.priority is not None:
            return night.priority
        qh = self.cfg.engine.quiet_hours
        return qh.session_start_priority if qh is not None else 5

    def _presence(self, device: str, now: datetime) -> str:
        """"w domu" / "poza domem" z czujki UniFi — tylko swieze. Pusty napis,
        gdy UniFi nie dziala: brak wiedzy to nie "poza domem"."""
        data = self.store.get_json(f"presence:{device}")
        if not isinstance(data, dict) or not data.get("checked"):
            return ""
        if abs(now - from_iso(data["checked"])) > PRESENCE_FRESH:
            return ""
        return "w domu" if data.get("home") else "poza domem"

    def _night_watch(self, now: datetime) -> list[Notification]:
        """Sesje trwajace w nocy: push raz na sesje i przypomnienia.

        Sesja zaczeta w nocy dostala juz push przy starcie (forma nocna,
        _emit_session_start) — tu przychodza tylko przypomnienia co
        `reminder_minutes`. Sesja zaczeta PRZED noca, ktora trwa dalej
        (21:00 -> 21:45), dostaje pierwszy push nocny tutaj.

        Liczy sie ostatnia AKTYWNOSC w oknie nocy, nie sam fakt otwartej
        sesji: sesja zamyka sie dopiero po idle_minutes ciszy, a w tym czasie
        dziecko moze juz spac. I to aktywnosc ROZPOZNANA (last_identified_at):
        ruch wspoldzielony (SDK reklamowe, CDN) przedluza sesje do
        shared_extend_minutes, wiec odlozony o 21:24 iPad, ktorego SDK odzywa
        sie co kilka minut, dawal o 21:32 alarm nocny z prio 5.
        """
        window = self.cfg.engine.night_window()
        if window is None:
            return []
        out: list[Notification] = []
        every = self.cfg.engine.night.reminder_minutes
        tz = self.cfg.tz
        for row in self.store.all_open_sessions(child_only=True):
            if not int(row["confirmed"]) or not int(row["start_notified"]):
                # Niepotwierdzona: alarm nocny dopiero po potwierdzeniu (start
                # wyjdzie wtedy od razu w formie nocnej).
                continue
            last_act = from_iso(row["last_identified_at"] or row["last_activity_at"])
            if not window.contains(last_act.astimezone(tz).time()):
                continue
            session_id = int(row["id"])
            state = self.store.get_json(f"night:{session_id}", {})
            state = state if isinstance(state, dict) else {}
            n = int(state.get("n", 0))
            if n and (every == 0 or now - from_iso(state["last"]) < timedelta(minutes=every)):
                continue
            device = row["device"]
            child = row["child"]
            started = from_iso(row["started_at"])
            app = self.store.last_app(session_id, exclude=UNKNOWN_LABEL)
            stamp = f"{last_act.astimezone(tz):%H:%M}"
            since = f"od {started.astimezone(tz):%H:%M} ({fmt_duration(last_act - started)})"
            parts = [stamp, app or "", since, self._presence(device, now)]
            self.store.set_json(f"night:{session_id}", {"n": n + 1, "last": to_iso(now)})
            out.extend(
                self._emit(
                    Notification(
                        kind=NotifyKind.NIGHT,
                        title=(
                            f"\U0001F319 {child} "
                            f"{'nadal uzywa' if n else 'uzywa'} iPada w nocy"
                        ),
                        text=", ".join(x for x in parts if x),
                        dedup_key=f"night:{session_id}:{n}",
                        ts=now,
                        device=device,
                        app=app,
                        priority=self._night_priority(),
                        tags=("warning", "ipad"),
                    )
                )
            )
        return out

    # ======================================================= raport tygodniowy
    def _maybe_weekly_report(self, now: datetime) -> list[Notification]:
        wr = self.cfg.engine.weekly_report
        if not wr.enabled:
            return []
        local = now.astimezone(self.cfg.tz)
        if local.weekday() != wr.weekday or local.time() < wr.time:
            return []
        monday = report_week(local.date())
        key = f"weekly_sent:{week_label(monday)}"
        if self.store.get_meta(key):
            return []
        self.store.set_meta(key, to_iso(now))
        # W niedziele raport obejmuje biezacy tydzien, wiec konczy sie na
        # godzinie wysylki, a zaczyna na tej samej godzinie poprzedniej
        # niedzieli — inaczej niedzielny wieczor nie trafial do zadnego raportu.
        cut = wr.time if local.weekday() == 6 else None
        return self._emit(self.build_weekly(monday, now, cut=cut))

    def _week_sessions(self, start: datetime, end: datetime) -> dict[str, list]:
        """{urzadzenie: [sesje]} z tygodnia — tylko te, o ktorych poszedl push
        (jak w podsumowaniu dnia)."""
        out: dict[str, list] = {}
        for row in self.store.sessions_between(start, end):
            if int(row["start_notified"]):
                out.setdefault(row["device"], []).append(row)
        return out

    @staticmethod
    def _duration(row) -> timedelta:
        return from_iso(row["ended_at"] or row["last_activity_at"]) - from_iso(row["started_at"])

    def build_weekly(self, monday: date, now: datetime, cut=None) -> Notification:
        """Raport tygodnia ISO zaczynajacego sie w `monday`. Bez _emit — CLI
        `weekly` drukuje go bez zajmowania klucza dedupu (jak build_summary).

        Z `cut` sesje licza sie od niedzieli przed `monday` o `cut` do
        niedzieli tygodnia o `cut` (patrz _maybe_weekly_report). Czas
        dokladny z TV (dzienne liczniki Androida) zostaje kalendarzowy.
        """
        tz = self.cfg.tz
        cal_start = datetime.combine(monday, datetime.min.time(), tzinfo=tz)
        cal_end = cal_start + timedelta(days=7)
        if cut is None:
            start, end = cal_start, cal_end
            prev_start = start - timedelta(days=7)
        else:
            start = datetime.combine(monday - timedelta(days=1), cut, tzinfo=tz)
            end = datetime.combine(monday + timedelta(days=6), cut, tzinfo=tz)
            prev_start = datetime.combine(monday - timedelta(days=8), cut, tzinfo=tz)
        cur = self._week_sessions(start, end)
        prev = self._week_sessions(prev_start, start)
        window = self.cfg.engine.night_window()

        children: dict[str, list[str]] = {}
        for dev in self.cfg.devices:
            children.setdefault(dev.child, []).append(dev.display_name)

        sections: list[dict] = []
        for child, names in children.items():
            sessions = [r for n in names for r in cur.get(n, [])]
            prev_total = sum(
                (self._duration(r) for n in names for r in prev.get(n, [])), timedelta()
            )
            if not sessions:
                sections.append(section(
                    child, f"brak aktywnosci ({fmt_change(timedelta(), prev_total)})"
                ))
                continue
            total = sum((self._duration(r) for r in sessions), timedelta())
            # Wieczor poprzedniej niedzieli (okno z `cut`) liczy sie do czasu,
            # ale nie jako aktywny dzien tego tygodnia — inaczej wyszloby 8/7.
            days = {from_iso(r["started_at"]).astimezone(tz).date() for r in sessions} - {
                monday - timedelta(days=1)
            }
            minutes: dict[str, int] = {}
            night = 0
            for row in sessions:
                sid = int(row["id"])
                for app, n in self.store.session_app_minutes(sid):
                    minutes[app] = minutes.get(app, 0) + n
                if window is not None and any(
                    window.contains(m.astimezone(tz).time())
                    for m in self.store.session_minutes(sid)
                ):
                    night += 1
            longest = max(sessions, key=self._duration)
            longest_at = from_iso(longest["started_at"]).astimezone(tz)
            top = sorted(minutes.items(), key=lambda kv: (-kv[1], kv[0]))
            facts = [
                f"{len(sessions)} {plural_sesje(len(sessions))}, aktywne dni: {len(days)}/7",
                f"najdluzsza sesja: {fmt_duration(self._duration(longest))} "
                f"({DNI_KROTKO[longest_at.weekday()]} {longest_at:%d.%m %H:%M})",
            ]
            if window is not None:
                facts.append(f"w nocy: {night} {'raz' if night == 1 else 'razy'}")
            sections.append(section(
                child, f"{fmt_duration(total)} ({fmt_change(total, prev_total)})",
                facts=facts, apps=top, apps_label="Top aplikacje",
            ))

        if self.cfg.tv.enabled:
            sections.append(
                self._tv_weekly_section(cur.get(self.cfg.tv.name, []), start, end, now,
                                        exact_range=(cal_start, cal_end))
            )

        sunday = monday + timedelta(days=6)
        return Notification(
            kind=NotifyKind.WEEKLY,
            title=f"Raport tygodnia {monday:%d.%m}\u2013{sunday:%d.%m}",
            text=sections_text(sections, ESTIMATE_NOTE),
            dedup_key=f"weekly:{week_label(monday)}",
            ts=now,
            priority=2,
            tags=("bar_chart",),
            data=payload("weekly", sections, note=ESTIMATE_NOTE, week=week_label(monday)),
        )

    def _tv_weekly_section(self, sessions: list, start: datetime, end: datetime, now,
                           exact_range: tuple[datetime, datetime] | None = None) -> dict:
        name = self.cfg.tv.name
        exact, exact_total = self._tv_exact(*(exact_range or (start, end)))
        exact_label = f"Dokladnie z TV ({fmt_duration(exact_total)})" if exact else None
        paused, whole = pause_facts(self.store, self.cfg.tz, start, end)
        if not sessions:
            return section(name, "monitoring wstrzymany" if whole else "nic nie gralo",
                           kind="tv", facts=paused, exact=exact, exact_label=exact_label)
        total = sum((self._duration(r) for r in sessions), timedelta())
        per_title: dict[str, timedelta] = {}
        for seg in self.store.tv_segments_between(name, start, end):
            label = tv_titles([seg])[0]
            stop = from_iso(seg["ended_at"]) if seg["ended_at"] else now
            per_title[label] = per_title.get(label, timedelta()) + max(
                timedelta(), stop - from_iso(seg["started_at"])
            )
        top = sorted(per_title.items(), key=lambda kv: (-kv[1], kv[0]))
        return section(
            name, f"{fmt_duration(total)}, {len(sessions)} {plural_sesje(len(sessions))}",
            kind="tv", titles=[f"{short_title(t)} {fmt_duration(d)}" for t, d in top],
            exact=exact, exact_label=exact_label, facts=paused,
        )

    def _tv_exact(self, start: datetime, end: datetime) -> tuple[list[tuple[str, int]], timedelta]:
        """Czas aplikacji wedlug samego Androida (usagestats, sources/tv.py):
        ([(aplikacja, minuty)], suma). Pusty, gdy odczyt nie dziala — wtedy
        zostaje sam szacunek z sesji."""
        tz = self.cfg.tz
        first = start.astimezone(tz).date().isoformat()
        last = (end.astimezone(tz) - timedelta(seconds=1)).date().isoformat()
        usage = self.store.tv_usage_between(self.cfg.tv.name, first, last)
        total = timedelta(milliseconds=sum(ms for _, ms in usage))
        return [(app, round(ms / 60000)) for app, ms in usage], total

    # ==================================================================== czujka
    def _mark_alive(self, ts: datetime, device: str | None) -> None:
        """Zapisuje ostatni dowod zycia — globalnie i per urzadzenie.

        Bierzemy maksimum, bo zdarzenia moga przyjsc lekko nie po kolei, a czujka
        nie moze sie cofac w czasie.
        """
        for key in ("alive:__all__", f"alive:{device}" if device else None):
            if key is None:
                continue
            prev = self.store.get_meta(key)
            if prev is None or from_iso(prev) < ts:
                self.store.set_meta(key, to_iso(ts))

    def _watchdog(self, now: datetime) -> list[Notification]:
        wd = self.cfg.watchdog
        if not wd.enabled:
            return []
        out: list[Notification] = []

        global_last = self.store.get_meta("alive:__all__")
        if global_last is None:
            # Jeszcze nic nie widzielismy — brak podstaw do alarmu o ciszy.
            return []
        global_silence = now - from_iso(global_last)
        stream_dead = global_silence >= timedelta(minutes=wd.stream_silence_minutes)

        if stream_dead:
            out.extend(
                self._watchdog_alert(
                    key="stream",
                    now=now,
                    title="kidwatch nie widzi ruchu DNS",
                    text=(
                        f"Zero zapytan od {fmt_duration(global_silence)} — a iPady odpytuja "
                        f"Apple nawet spiac, wiec to awaria po naszej stronie.\n"
                        f"Sprawdz: klucz API, siec, limity konta w zrodle DNS."
                    ),
                )
            )
            # Gdy padl caly strumien, cisza pojedynczych urzadzen nic nie znaczy.
            return out

        out.extend(self._watchdog_recovered("stream", now, "kidwatch znowu widzi ruch DNS"))

        for dev in self.cfg.devices:
            name = dev.display_name
            last = self.store.get_meta(f"alive:{name}")
            if last is None:
                continue
            silence = now - from_iso(last)
            if silence < timedelta(minutes=wd.device_silence_minutes):
                out.extend(
                    self._watchdog_recovered("dev:" + name, now, f"{name} znowu widoczny w DNS")
                )
                continue
            if wd.device_silence_ignore_quiet_hours and self._in_quiet_hours(now):
                continue
            out.extend(
                self._watchdog_alert(
                    key="dev:" + name,
                    now=now,
                    title=f"{name} nie zglasza sie do DNS",
                    text=(
                        f"Cisza od {fmt_duration(silence)}, a inne urzadzenia raportuja "
                        f"normalnie.\nNajczestsza przyczyna: zdjety profil DNS albo "
                        f"wylaczony szyfrowany DNS w Ustawieniach tego iPada."
                    ),
                )
            )
        return out

    def _watchdog_alert(self, key: str, now: datetime, title: str, text: str) -> list[Notification]:
        """Alarm z rosnacym odstepem powtorzen.

        Jedna awaria nie moze wygenerowac powiadomienia na kazdym tiku, wiec
        odstep podwaja sie po kazdym zgloszeniu: 20 min, 40, 80, 160... do sufitu.
        """
        wd = self.cfg.watchdog
        state = self.store.get_json(f"wd:{key}", {})
        assert isinstance(state, dict)
        count = int(state.get("n", 0))
        last_sent = state.get("last")

        # count to liczba JUZ wyslanych zgloszen tej awarii. Pierwsze przypomnienie
        # ma przyjsc po `base` minutach, kolejne po 2x, 4x... — stad count-1.
        base = wd.stream_silence_minutes
        wait = min(base * 2 ** max(0, count - 1), wd.repeat_backoff_max_minutes)
        if last_sent is not None and now - from_iso(last_sent) < timedelta(minutes=wait):
            return []

        since = episode_id(state, now)
        self.store.set_json(f"wd:{key}", {"n": count + 1, "last": to_iso(now), "since": since})
        suffix = "" if count == 0 else f"\n(przypomnienie {count + 1})"
        return self._emit(
            Notification(
                kind=NotifyKind.WATCHDOG,
                title=title,
                text=text + suffix,
                # Epizod w kluczu: `sent` trzyma klucze 7 dni, a licznik po
                # powrocie wraca do zera — bez niego druga awaria w tygodniu
                # trafiala na zajety "wd:<x>:0" i czujka milczala.
                dedup_key=f"wd:{key}:{since}:{count}",
                ts=now,
                priority=4,
                tags=("rotating_light",),
            )
        )

    def _watchdog_recovered(self, key: str, now: datetime, title: str) -> list[Notification]:
        state = self.store.get_json(f"wd:{key}", {})
        assert isinstance(state, dict)
        count = int(state.get("n", 0))
        if count == 0:
            return []
        since = episode_id(state, now)
        self.store.set_json(f"wd:{key}", {})
        return self._emit(
            Notification(
                kind=NotifyKind.WATCHDOG,
                title=title,
                text="Awaria ustapila.",
                dedup_key=f"wdok:{key}:{since}:{count}",
                ts=now,
                priority=2,
                tags=("white_check_mark",),
            )
        )

    # ================================================================ dlawienie
    def _drain_throttled(self, now: datetime) -> list[Notification]:
        out: list[Notification] = []
        for dev in self.cfg.devices:
            device = dev.display_name
            if not self.store.count_throttled(device):
                continue
            if self._over_limit(device, now):
                continue
            labels = self.store.drain_throttled(device)
            uniq = sorted(set(labels))
            out.extend(
                self._emit(
                    Notification(
                        kind=NotifyKind.THROTTLED,
                        title=f"{device} — zbiorczo",
                        text=(
                            f"{len(labels)} powiadomien pominietych przez limit godzinowy.\n"
                            f"Aplikacje: {', '.join(uniq)}"
                        ),
                        dedup_key=f"thr:{device}:{now.astimezone(UTC):%Y%m%dT%H%M%S}",
                        ts=now,
                        device=device,
                        priority=2,
                        tags=("bar_chart",),
                    )
                )
            )
        return out

    def _over_limit(self, device: str, now: datetime) -> bool:
        """Limit warstwy DNS. Powiadomienia z odczytu urzadzen sa WYLACZONE
        z tego licznika — maja wlasny budzet. Bez tego godzina grania wypelniala
        notify_log i silnik zaczynal dlawic wlasne pushe o sesjach."""
        window = now - timedelta(hours=1)
        used = self.store.count_notifications_since(
            device, window, exclude_kinds=tuple(k.value for k in DEVICE_KINDS)
        )
        return used >= self.cfg.engine.max_notifications_per_hour

    # ==================================================================== wspolne
    def _in_night(self, ts: datetime) -> bool:
        window = self.cfg.engine.night_window()
        return window is not None and window.contains(ts.astimezone(self.cfg.tz).time())

    def _in_quiet_hours(self, ts: datetime) -> bool:
        qh = self.cfg.engine.quiet_hours
        return qh is not None and qh.contains(ts.astimezone(self.cfg.tz).time())

    def _emit(self, note: Notification) -> list[Notification]:
        """Ostatnia bramka przed oddaniem powiadomienia: dedup i limit godzinowy."""
        if not self.store.mark_sent(note.dedup_key, note.ts):
            # Ten sam klucz juz przeszedl — najpewniej restart i powtorne
            # przetworzenie tych samych zdarzen. Nie dublujemy pusha.
            log.debug("pomijam duplikat %s", note.dedup_key)
            return []

        if (
            note.device
            and note.kind not in NEVER_THROTTLED
            and self._over_limit(note.device, note.ts)
        ):
            self.store.push_throttled(note.device, note.app or note.text, note.ts)
            return []

        self.store.log_notification(note.device, note.ts, note.kind.value)
        return [note]
