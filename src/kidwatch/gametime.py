"""Czas gry: blokada uslug w kontroli rodzicielskiej NextDNS sterowana z panelu.

STANY (per PROFIL NextDNS — blokady sa ustawieniem profilu, nie urzadzenia):
  * "allowed" — uslugi i kategorie z game_time maja active=false;
  * "blocked" — active=true;
  * "bonus"   — tymczasowo dozwolone do `bonus_until`, potem petla blokuje.
Stan lezy w kidwatch.db (meta `game:<profil>`), a jego jedynym pisarzem jest
ta petla — dziala w tym samym procesie i na tym samym polaczeniu co silnik.

DLACZEGO KOLEJKA ZADAN W panel-auth.db

Panel czyta kidwatch.db tylko do odczytu i tak ma zostac (store.py, panel.py).
Klikniecie "Zablokuj gry" zapisuje wiec ZADANIE do tabeli `game_requests`
w panel-auth.db, a petla je odbiera, wykonuje i odhacza. panel-auth.db juz
jest plikiem, do ktorego watek panelu pisze (sesje, liczniki logowan), i juz
jest zaprojektowany na dwoch niegroznych pisarzy — trzecia baza na wolumenie
oznaczalaby kolejna sciezke w konfiguracji, w kopii zapasowej i w chmod 600
bez zadnego zysku. Przy okazji zadanie pamieta login, ktory je zlecil.

ZAPIS DO NextDNS przez endpointy POZYCJI, nie przez PATCH calego
/parentalControl z tablicami: dokumentacja API nie mowi, czy tablica
w PATCH-u obiektu jest scalana, czy podmieniana, a podmiana skasowalaby
blokady ustawione recznie w my.nextdns.io (porno, hazard...). Pozycje maja
jednoznaczna semantyke (nextdns.github.io/api, "Nested objects and arrays"):
  PATCH  /profiles/:p/parentalControl/services/:id   {"active": ..}
  POST   /profiles/:p/parentalControl/services       {"id": .., "active": true}
i tak samo dla categories. Usluga nieobecna na liscie profilu nie jest
blokowana, wiec przy odblokowaniu nie trzeba jej dodawac. `recreation`
ustawiamy na false: "zablokowane, ale wolne w czasie rekreacji NextDNS"
rozjechaloby sie ze stanem pokazywanym w panelu — zrodlem prawdy o czasie
gry jest kidwatch.

Po kazdym zapisie i co `sync_minutes` stan jest czytany z NextDNS (GET).
Zmiana zrobiona recznie w my.nextdns.io jest PRZYJMOWANA (panel pokazuje to,
co jest naprawde), chyba ze to nasz wlasny zapis sie nie udal — wtedy go
ponawiamy.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import sqlite3
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

from .config import Config
from .models import Notification, NotifyKind
from .store import Store, from_iso, to_iso

log = logging.getLogger(__name__)

ACTIONS = frozenset({"block", "allow", "bonus"})
#: Zadanie starsze niz to (petla lezala) nie jest wykonywane: "+30 min"
#: klikniete godzine temu i zrealizowane teraz byloby niespodzianka.
REQUEST_TTL_SECONDS = 10 * 60
#: Po nieudanym zapisie ponawiamy nie czesciej niz co tyle. Petla chodzi co
#: kilka sekund, a blad 4xx (zle id uslugi) nie minie sam — bez tego
#: odpytywalibysmy API NextDNS co 3 s do konca swiata.
RETRY_SECONDS = 60
#: Wiecej oczekujacych zadan na dziecko to klikanie w kolko, nie intencja.
MAX_PENDING_PER_CHILD = 5

GAME_ICON = "\U0001F3AE"

REQUESTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS game_requests (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    child      TEXT NOT NULL,
    action     TEXT NOT NULL,
    minutes    INTEGER,
    login      TEXT,
    created_at REAL NOT NULL,
    done_at    REAL,
    ok         INTEGER,
    error      TEXT
);
CREATE INDEX IF NOT EXISTS ix_game_requests_open ON game_requests (done_at, id);
"""


class TooManyRequests(RuntimeError):
    pass


# ================================================================ kolejka zadan
class GameRequests:
    """Zadania z panelu w panel-auth.db. Kazda operacja na wlasnym polaczeniu
    — panel wola z watkow ThreadingHTTPServer, petla z watku glownego."""

    def __init__(self, path: str | Path, clock: Callable[[], float] = time.time) -> None:
        self.path = str(path)
        self.clock = clock
        new = not Path(self.path).exists()
        with self._conn() as conn:
            conn.executescript(REQUESTS_SCHEMA)
        if new:
            # Ten sam plik co konta panelu (hashe hasel) — jak w PanelAuth.
            with contextlib.suppress(OSError):
                os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()

    def submit(self, child: str, action: str, minutes: int | None, login: str | None) -> int:
        if action not in ACTIONS:
            raise ValueError(f"nieznana akcja {action!r}")
        with self._conn() as conn:
            pending = conn.execute(
                "SELECT COUNT(*) FROM game_requests WHERE child=? AND done_at IS NULL", (child,)
            ).fetchone()[0]
            if pending >= MAX_PENDING_PER_CHILD:
                raise TooManyRequests(child)
            cur = conn.execute(
                "INSERT INTO game_requests (child, action, minutes, login, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (child, action, minutes, login, self.clock()),
            )
            return int(cur.lastrowid)

    def pending(self) -> list[sqlite3.Row]:
        with self._conn() as conn:
            return list(
                conn.execute("SELECT * FROM game_requests WHERE done_at IS NULL ORDER BY id")
            )

    def finish(self, request_id: int, ok: bool, error: str | None = None) -> None:
        with self._conn() as conn:
            conn.execute(
                "UPDATE game_requests SET done_at=?, ok=?, error=? WHERE id=?",
                (self.clock(), int(ok), error, request_id),
            )

    def latest(self, child: str) -> dict | None:
        """Ostatnie zadanie dziecka — panel pokazuje "wysylanie..." albo blad."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM game_requests WHERE child=? ORDER BY id DESC LIMIT 1", (child,)
            ).fetchone()
        if row is None:
            return None
        return {
            "id": row["id"],
            "action": row["action"],
            "pending": row["done_at"] is None,
            "ok": None if row["ok"] is None else bool(row["ok"]),
            "error": row["error"],
            "created_at": datetime.fromtimestamp(row["created_at"], UTC).isoformat(),
        }

    def purge(self, older_than_days: int = 30) -> None:
        with self._conn() as conn:
            conn.execute(
                "DELETE FROM game_requests WHERE done_at IS NOT NULL AND done_at < ?",
                (self.clock() - older_than_days * 86400,),
            )


# ================================================================ klient NextDNS
class NextDnsError(RuntimeError):
    pass


def _error_text(response: httpx.Response) -> str:
    """NextDNS zwraca bledy jako {"errors": [{"code": .., "detail": ..}]}."""
    try:
        errors = response.json().get("errors") or []
    except (ValueError, AttributeError):
        errors = []
    parts = []
    for err in errors:
        if isinstance(err, dict):
            what = err.get("detail") or err.get("code") or "?"
            where = (err.get("source") or {}).get("parameter")
            parts.append(f"{what} ({where})" if where else str(what))
    return f"HTTP {response.status_code}" + (f": {'; '.join(parts)}" if parts else "")


class ParentalControlClient:
    """Minimalny klient /profiles/:p/parentalControl."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        client: httpx.AsyncClient | None = None,
        timeout: float = 10.0,
    ) -> None:
        self.base = base_url.rstrip("/")
        self._headers = {"X-Api-Key": api_key, "Accept": "application/json"}
        self._owns_client = client is None
        self._client = client or httpx.AsyncClient(timeout=timeout)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()

    async def _call(self, method: str, path: str, body: dict | None = None) -> dict:
        try:
            response = await self._client.request(
                method, f"{self.base}{path}", headers=self._headers, json=body
            )
        except httpx.HTTPError as exc:
            raise NextDnsError(f"{method} {path}: {exc}") from exc
        if response.status_code >= 400:
            raise NextDnsError(f"{method} {path}: {_error_text(response)}")
        if not response.content:
            return {}
        try:
            data = response.json()
        except ValueError:
            return {}
        if isinstance(data, dict) and data.get("errors"):
            # NextDNS potrafi oddac blad walidacji z kodem 200.
            raise NextDnsError(f"{method} {path}: {_error_text(response)}")
        return data if isinstance(data, dict) else {}

    async def get(self, profile: str) -> dict:
        data = await self._call("GET", f"/profiles/{profile}/parentalControl")
        return data.get("data") or {}

    async def set_blocked(
        self, profile: str, services: list[str], categories: list[str], blocked: bool
    ) -> dict:
        """Ustawia `active` dla wszystkich pozycji gry; zwraca stan po zapisie (GET)."""
        current = await self.get(profile)
        for kind, ids in (("services", services), ("categories", categories)):
            present = {
                str(item.get("id")): item
                for item in current.get(kind) or []
                if isinstance(item, dict)
            }
            for item_id in ids:
                item = present.get(item_id)
                base = f"/profiles/{profile}/parentalControl/{kind}"
                if item is not None:
                    if bool(item.get("active")) == blocked and not item.get("recreation"):
                        continue
                    await self._call(
                        "PATCH", f"{base}/{item_id}", {"active": blocked, "recreation": False}
                    )
                elif blocked:
                    await self._call(
                        "POST", base, {"id": item_id, "active": True, "recreation": False}
                    )
        return await self.get(profile)


def observed_state(data: dict, services: list[str], categories: list[str]) -> str:
    """"blocked" | "allowed" | "mixed" wedlug pozycji gry w profilu.

    Pozycja z recreation=true liczy sie jako NIE zablokowana na stale — w oknie
    rekreacji NextDNS ja przepuszcza, wiec "zablokowane" byloby klamstwem.
    """
    flags = []
    for kind, ids in (("services", services), ("categories", categories)):
        present = {
            str(i.get("id")): i for i in data.get(kind) or [] if isinstance(i, dict)
        }
        for item_id in ids:
            item = present.get(item_id)
            flags.append(bool(item and item.get("active") and not item.get("recreation")))
    if flags and all(flags):
        return "blocked"
    if not any(flags):
        return "allowed"
    return "mixed"


# ================================================================== sterownik
class GameTime:
    def __init__(
        self,
        cfg: Config,
        store: Store,
        requests: GameRequests,
        client: ParentalControlClient,
        dispatcher=None,
    ) -> None:
        self.cfg = cfg
        self.gt = cfg.game_time
        self.store = store
        self.requests = requests
        self.client = client
        self.dispatcher = dispatcher
        self.profiles = cfg.child_profiles()

    # ------------------------------------------------------------- pomocnicze
    def children_of(self, profile: str) -> list[str]:
        return [c for c, p in self.profiles.items() if p == profile]

    def device_of(self, child: str) -> str | None:
        return next((d.display_name for d in self.cfg.devices if d.child == child), None)

    def state(self, profile: str) -> dict:
        data = self.store.get_json(f"game:{profile}", {})
        return data if isinstance(data, dict) else {}

    def _save(self, profile: str, state: dict) -> None:
        self.store.set_json(f"game:{profile}", state)

    @staticmethod
    def expected(state: dict) -> str | None:
        mode = state.get("mode")
        if mode == "blocked":
            return "blocked"
        if mode in ("allowed", "bonus"):
            return "allowed"
        return None

    async def _notify(self, profile: str, key: str, title: str, text: str, now) -> None:
        if self.dispatcher is None or not self.store.mark_sent(key, now):
            return
        children = self.children_of(profile)
        note = Notification(
            kind=NotifyKind.GAME,
            title=f"{GAME_ICON} Czas gry dla {' i '.join(children)}: {title}",
            text=text,
            dedup_key=key,
            ts=now,
            device=self.device_of(children[0]) if children else None,
            priority=3,
            tags=("video_game",),
        )
        await self.dispatcher.send_all([note])

    def _hhmm(self, iso: str) -> str:
        return f"{from_iso(iso).astimezone(self.cfg.tz):%H:%M}"

    # ---------------------------------------------------------------- zapis
    async def _apply(self, profile: str, state: dict, now: datetime) -> bool:
        """Wypycha `state` do NextDNS i zapisuje wynik. Zwraca, czy sie udalo.
        Przy bledzie stan zostaje "brudny" — sync bedzie ponawial."""
        want = self.expected(state)
        assert want is not None
        state["attempt_at"] = to_iso(now)
        try:
            data = await self.client.set_blocked(
                profile, self.gt.services, self.gt.categories, want == "blocked"
            )
        except NextDnsError as exc:
            log.error("czas gry %s: zapis do NextDNS nie powiodl sie: %s", profile, exc)
            state.update(dirty=True, error=str(exc))
            self._save(profile, state)
            return False
        observed = observed_state(data, self.gt.services, self.gt.categories)
        state.update(observed=observed, confirmed_at=to_iso(now), dirty=observed != want,
                     error=None if observed == want else f"NextDNS pokazuje stan {observed}")
        self._save(profile, state)
        return observed == want

    # ------------------------------------------------------------- zadania
    async def process_requests(self, now: datetime) -> None:
        for req in self.requests.pending():
            child = req["child"]
            profile = self.profiles.get(child)
            if profile is None:
                self.requests.finish(req["id"], False, "dziecko nie jest juz w konfiguracji")
                continue
            if self.requests.clock() - req["created_at"] > REQUEST_TTL_SECONDS:
                self.requests.finish(req["id"], False, "przeterminowane (petla nie dzialala)")
                continue
            state = self.state(profile)
            action = req["action"]
            by = req["login"] or "panel"
            if action == "block":
                state.update(mode="blocked", bonus_until=None, source="panel", after_bonus=None)
                title = "zablokowany"
            elif action == "allow":
                state.update(mode="allowed", bonus_until=None, source="panel", after_bonus=None)
                title = "odblokowany"
            else:
                minutes = int(req["minutes"] or self.gt.default_bonus_minutes)
                base = now
                if state.get("mode") == "bonus" and state.get("bonus_until"):
                    base = max(now, from_iso(state["bonus_until"]))
                else:
                    # Stan sprzed bonusu — po bonusie wracamy do niego. Bez
                    # tego "+30 min" klikniete przy dozwolonych grach konczylo
                    # sie blokada, ktorej nikt potem nie zdejmowal.
                    state["after_bonus"] = {"mode": state.get("mode"),
                                            "source": state.get("source")}
                until = min(
                    base + timedelta(minutes=minutes),
                    now + timedelta(minutes=self.gt.max_bonus_minutes),
                )
                state.update(mode="bonus", bonus_until=to_iso(until), source="panel")
                title = f"+{minutes} min (do {self._hhmm(state['bonus_until'])})"
            state.update(changed_at=to_iso(now), by=by)
            ok = await self._apply(profile, state, now)
            self.requests.finish(req["id"], ok, None if ok else state.get("error"))
            if ok:
                await self._notify(profile, f"game:{profile}:req:{req['id']}", title,
                                   f"z panelu ({by})", now)
            else:
                await self._notify(
                    profile, f"game:{profile}:req:{req['id']}", f"NIE UDALO SIE ({title})",
                    f"{state.get('error')}\nkidwatch ponowi zapis przy nastepnej synchronizacji.",
                    now,
                )

    # ------------------------------------------------------- bonus, harmonogram
    async def expire_bonuses(self, now: datetime) -> None:
        for profile in dict.fromkeys(self.profiles.values()):
            state = self.state(profile)
            if state.get("mode") != "bonus" or not state.get("bonus_until"):
                continue
            until = from_iso(state["bonus_until"])
            if now < until:
                continue
            mode, source = self._after_bonus(state.get("after_bonus"), now)
            state.update(mode=mode, bonus_until=None, source=source, after_bonus=None,
                         changed_at=to_iso(now))
            ok = await self._apply(profile, state, now)
            title = "koniec bonusu — " + ("zablokowany" if mode == "blocked" else "odblokowany")
            await self._notify(profile, f"game:{profile}:end:{to_iso(until)}",
                               *self._outcome(ok, title, state,
                                              f"bonus minal o {self._hhmm(to_iso(until))}"),
                               now)

    def _after_bonus(self, before, now: datetime) -> tuple[str, str]:
        """(tryb, zrodlo) po koncu bonusu. Okno harmonogramu wygrywa — taka
        blokada nalezy do harmonogramu i rano zdejmie ja on sam. Poza oknem
        wracamy do stanu sprzed bonusu; blokada harmonogramu sprzed bonusu
        (bonus z 06:45 konczacy sie po 07:00) juz minela, wiec gry sa dozwolone.
        Bez zapamietanego stanu (bonus sprzed tej poprawki) — blokada jak dawniej."""
        if self._in_schedule(now):
            return "blocked", "schedule"
        before = before if isinstance(before, dict) else {}
        if before.get("source") == "schedule":
            return "allowed", "schedule"
        if before.get("mode") == "allowed":
            return "allowed", before.get("source") or "bonus"
        return "blocked", before.get("source") or "bonus"

    @staticmethod
    def _outcome(ok: bool, title: str, state: dict, text: str) -> tuple[str, str]:
        """Tytul i tresc pusha po zapisie. Nieudany zapis musi to powiedziec —
        "zablokowany" przy grach nadal dozwolonych to falszywe uspokojenie."""
        if ok:
            return title, text
        return (f"NIE UDALO SIE ({title})",
                f"{state.get('error')}\nkidwatch ponowi zapis przy nastepnej synchronizacji.")

    def _in_schedule(self, now: datetime) -> bool:
        sched = self.gt.block_schedule
        return sched is not None and sched.contains(now.astimezone(self.cfg.tz).time())

    def _sched_text(self) -> str:
        sched = self.gt.block_schedule
        assert sched is not None
        return f"codzienna blokada {sched.start:%H:%M}\u2013{sched.end:%H:%M}"

    async def run_schedule(self, now: datetime) -> None:
        if self.gt.block_schedule is None:
            return
        inside = self._in_schedule(now)
        day = f"{now.astimezone(self.cfg.tz):%Y-%m-%d}"
        for profile in dict.fromkeys(self.profiles.values()):
            key = f"game_sched:{profile}"
            was = self.store.get_meta(key)
            now_flag = "in" if inside else "out"
            if was == now_flag:
                continue
            self.store.set_meta(key, now_flag)
            state = self.state(profile)
            if inside:
                # Bonus trwa dalej — po nim i tak przyjdzie blokada.
                if state.get("mode") in ("blocked", "bonus"):
                    continue
                state.update(mode="blocked", bonus_until=None, source="schedule",
                             changed_at=to_iso(now))
                ok = await self._apply(profile, state, now)
                await self._notify(profile, f"game:{profile}:sched-in:{day}",
                                   *self._outcome(ok, "zablokowany (harmonogram)", state,
                                                  self._sched_text()), now)
            elif (
                was == "in"
                and state.get("mode") == "blocked"
                and state.get("source") == "schedule"
            ):
                state.update(mode="allowed", source="schedule", changed_at=to_iso(now))
                ok = await self._apply(profile, state, now)
                await self._notify(profile, f"game:{profile}:sched-out:{day}",
                                   *self._outcome(ok, "odblokowany (harmonogram)", state,
                                                  self._sched_text()), now)

    # ------------------------------------------------------------ synchronizacja
    async def sync(self, now: datetime, force: bool = False) -> None:
        every = timedelta(minutes=self.gt.sync_minutes)
        for profile in dict.fromkeys(self.profiles.values()):
            state = self.state(profile)
            last = state.get("synced_at")
            if not force and not state.get("dirty") and last and now - from_iso(last) < every:
                continue
            if state.get("dirty") and self.expected(state):
                # Nasz zapis sie nie udal — ponawiamy go, a nie przyjmujemy
                # stanu z NextDNS jako "recznej zmiany".
                attempt = state.get("attempt_at")
                if attempt and now - from_iso(attempt) < timedelta(seconds=RETRY_SECONDS):
                    continue
                state["synced_at"] = to_iso(now)
                await self._apply(profile, state, now)
                continue
            try:
                data = await self.client.get(profile)
            except NextDnsError as exc:
                log.warning("czas gry %s: odczyt z NextDNS nie powiodl sie: %s", profile, exc)
                state.update(synced_at=to_iso(now), error=str(exc))
                self._save(profile, state)
                continue
            observed = observed_state(data, self.gt.services, self.gt.categories)
            want = self.expected(state)
            state.update(observed=observed, synced_at=to_iso(now), confirmed_at=to_iso(now),
                         error=None)
            if want != observed:
                if observed in ("allowed", "blocked"):
                    if want is not None:
                        log.info("czas gry %s: zmiana w NextDNS poza kidwatch (%s -> %s)",
                                 profile, want, observed)
                    state.update(mode=observed, bonus_until=None, source="nextdns",
                                 changed_at=to_iso(now))
                else:
                    # Czesc pozycji zablokowana, czesc nie — ktos grzebal
                    # recznie. Pokazujemy to, nie zgadujemy intencji.
                    state.update(mode="mixed", bonus_until=None, source="nextdns")
            self._save(profile, state)

    async def step(self, now: datetime) -> None:
        await self.process_requests(now)
        await self.expire_bonuses(now)
        await self.run_schedule(now)
        await self.sync(now)


async def game_loop(
    game: GameTime,
    interval_seconds: float,
    sleep=asyncio.sleep,
    max_iterations: int | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> None:
    """Petla czasu gry. Blad NextDNS albo bazy nie moze jej zakonczyc —
    cmd_run zamyka proces po pierwszym zakonczonym zadaniu."""
    iteration = 0
    last_purge = 0.0
    while max_iterations is None or iteration < max_iterations:
        iteration += 1
        try:
            await game.step(clock())
            if time.time() - last_purge > 86400:
                game.requests.purge()
                last_purge = time.time()
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("czas gry: blad w petli — kontynuuje")
        await sleep(interval_seconds)
