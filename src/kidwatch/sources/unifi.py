"""UniFi (UDM): obecnosc iPadow w domowym Wi-Fi i czujka "profil DNS usuniety".

## Po co

Warstwa DNS widzi iPada tylko wtedy, gdy ten pyta przez NextDNS. Dziecko,
ktore usunie profil DNS (albo wylaczy szyfrowany DNS), znika z kidwatcha
dokladnie tak samo jak iPad, ktory spi — czujka ciszy w silniku z definicji
nie odrozni jednego od drugiego. Kontroler Wi-Fi odroznia: spiacy iPad nie
przesyla megabajtow, a iPad z YouTube bez profilu — owszem.

Regula alarmu: iPad jest w domowym Wi-Fi, w ostatnich `window_minutes`
przeslal co najmniej `alarm_mb` MB, a NextDNS nie ma od niego W TYM CZASIE
ani jednego zapytania (licznik `alive:<urzadzenie>` z silnika — liczy sie
kazde zapytanie, takze szum Apple). Gdy w tym samym oknie nie ma zapytan od
NIKOGO, to awaria strumienia DNS, nie profil — tym zajmuje sie czujka silnika.

## Certyfikat

UDM ma certyfikat samopodpisany. Weryfikacja przez urzad certyfikacji nie
przejdzie, a wylaczenie weryfikacji oddaloby klucz API kazdemu, kto w sieci
podszyje sie pod adres kontrolera. Dlatego PRZYPINAMY certyfikat: SHA-256
certyfikatu serwera porownujemy z `unifi.cert_sha256` po uzgodnieniu TLS,
a PRZED wyslaniem zadania — naglowek z kluczem nie opuszcza procesu, jesli
odcisk sie nie zgadza. `CERT_NONE` w kontekscie SSL oznacza tu tylko "nie
pytaj urzedow certyfikacji"; jedyna weryfikacja jest przypiety odcisk i jest
obowiazkowa.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import http.client
import json
import logging
import ssl
from collections import deque
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit

from ..models import Notification, NotifyKind
from ..store import Store, episode_id, from_iso, to_iso

log = logging.getLogger(__name__)


class UnifiError(RuntimeError):
    pass


class CertMismatch(UnifiError):
    """Serwer przedstawil inny certyfikat niz przypiety. Klucz NIE zostal wyslany."""

    def __init__(self, got: str) -> None:
        super().__init__(
            f"odcisk certyfikatu UniFi {got} nie zgadza sie z unifi.cert_sha256 — "
            f"zadanie NIE zostalo wyslane"
        )
        self.got = got


class UnifiAuthError(UnifiError):
    pass


def _context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Patrz docstring modulu: weryfikacja to przypiety odcisk, sprawdzany
    # recznie w `_connect` przed pierwszym bajtem zadania.
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _connect(url: str, timeout: float) -> tuple[http.client.HTTPSConnection, str]:
    parts = urlsplit(url)
    if parts.scheme != "https":
        raise UnifiError(f"unifi.url musi byc https://, jest {url!r}")
    conn = http.client.HTTPSConnection(
        parts.hostname, parts.port or 443, timeout=timeout, context=_context()
    )
    conn.connect()
    der = conn.sock.getpeercert(binary_form=True)
    return conn, hashlib.sha256(der).hexdigest()


def server_fingerprint(url: str, timeout: float = 10.0) -> str:
    """Odcisk SHA-256 certyfikatu, ktory serwer przedstawia. Nic nie wysyla."""
    conn, got = _connect(url, timeout)
    conn.close()
    return got


def fetch_pinned(url: str, path: str, api_key: str, pin: str, timeout: float) -> object:
    """GET z przypietym certyfikatem. Synchroniczne — wolane w watku."""
    conn, got = _connect(url, timeout)
    try:
        if not hmac.compare_digest(got, pin):
            raise CertMismatch(got)
        conn.request("GET", path, headers={"X-API-KEY": api_key, "Accept": "application/json"})
        resp = conn.getresponse()
        body = resp.read()
    finally:
        conn.close()
    if resp.status in (401, 403):
        raise UnifiAuthError(f"UniFi odrzucil klucz API (HTTP {resp.status})")
    if resp.status != 200:
        raise UnifiError(f"UniFi HTTP {resp.status}")
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise UnifiError("UniFi zwrocil nie-JSON") from exc


class UnifiClient:
    def __init__(self, url: str, site: str, api_key: str, pin: str, timeout: float) -> None:
        self.url = url.rstrip("/")
        self.path = f"/proxy/network/api/s/{site}/stat/sta"
        self.api_key, self.pin, self.timeout = api_key, pin, timeout

    async def stations(self) -> list[dict]:
        """Klienci podlaczeni TERAZ (stat/sta nie zwraca rozlaczonych)."""
        try:
            payload = await asyncio.to_thread(
                fetch_pinned, self.url, self.path, self.api_key, self.pin, self.timeout
            )
        except (OSError, http.client.HTTPException) as exc:
            raise UnifiError(f"{type(exc).__name__}: {exc}") from exc
        data = payload.get("data") if isinstance(payload, dict) else None
        if not isinstance(data, list):
            raise UnifiError("odpowiedz UniFi bez listy 'data'")
        return data


# ================================================================ obserwator
def _bytes(sta: dict) -> int:
    return int(sta.get("tx_bytes") or 0) + int(sta.get("rx_bytes") or 0)


class UnifiWatcher:
    """Obecnosc w domu i czujka profilu DNS.

    Probki ruchu trzymamy w pamieci (deque na urzadzenie): restart kosztuje
    najwyzej jedno okno bez czujki, a zapis co minute do bazy bylby szumem.
    Obecnosc idzie do `meta` (presence:<urzadzenie>), bo czyta ja panel.
    """

    def __init__(
        self,
        client: UnifiClient,
        devices: list[tuple[str, str | None, str | None]],
        store: Store,
        *,
        window_minutes: int = 15,
        alarm_mb: float = 20.0,
        repeat_backoff_max_minutes: int = 480,
    ) -> None:
        self.client = client
        self.devices = devices  # [(nazwa, mac, ip)]
        self.store = store
        self.window = timedelta(minutes=window_minutes)
        self.alarm_bytes = alarm_mb * 1_000_000
        self.backoff_max = repeat_backoff_max_minutes
        self.samples: dict[str, deque[tuple[datetime, int]]] = {}
        self._ip_only_logged: set[str] = set()

    async def poll(self, now: datetime) -> list[Notification]:
        return self.observe(await self.client.stations(), now)

    def observe(self, stations: list[dict], now: datetime) -> list[Notification]:
        by_mac = {str(s.get("mac", "")).lower(): s for s in stations}
        by_ip = {str(s.get("ip", "")): s for s in stations if s.get("ip")}
        out: list[Notification] = []
        for name, mac, ip in self.devices:
            sta = by_mac.get(mac) if mac else None
            ip_only = sta is None and ip is not None and ip in by_ip
            if ip_only:
                sta = by_ip[ip]
                if mac and name not in self._ip_only_logged:
                    # Raz na rozjazd, nie co odczyt.
                    self._ip_only_logged.add(name)
                    log.info("unifi: %s dopasowany tylko po IP %s (MAC %s zamiast %s)",
                             name, ip, sta.get("mac"), mac)
            else:
                self._ip_only_logged.discard(name)
            self._presence(name, sta, now)
            if sta is None:
                # Poza domem: czujka nie ma czego mierzyc, a probki sprzed
                # wyjscia nie moga sie skleic z tymi po powrocie.
                self.samples.pop(name, None)
                continue
            traffic, covered = self._traffic(name, _bytes(sta), now)
            out.extend(self._check(name, traffic, covered, now, ip_only=ip_only))
        return out

    # ------------------------------------------------------------ obecnosc
    def _presence(self, name: str, sta: dict | None, now: datetime) -> None:
        key = f"presence:{name}"
        prev = self.store.get_json(key, {})
        assert isinstance(prev, dict)
        home = sta is not None
        since = prev.get("since") if prev.get("home") == home else to_iso(now)
        self.store.set_json(key, {
            "home": home,
            "since": since or to_iso(now),
            "checked": to_iso(now),
            "essid": (sta or {}).get("essid"),
        })

    # --------------------------------------------------------------- ruch
    def _traffic(self, name: str, total: int, now: datetime) -> tuple[float, bool]:
        """(bajty w oknie, czy okno jest w calosci pokryte probkami).

        Licznik UniFi zeruje sie przy ponownym polaczeniu z AP — ujemna roznica
        znaczy "od zera", wiec bierzemy wtedy sama biezaca wartosc.
        """
        q = self.samples.setdefault(name, deque())
        q.append((now, total))
        start = now - self.window
        # Zostawiamy JEDNA probke sprzed okna — od niej liczy sie przyrost.
        while len(q) >= 2 and q[1][0] <= start:
            q.popleft()
        covered = q[0][0] <= start
        traffic = 0
        for (_, a), (_, b) in zip(q, list(q)[1:], strict=False):
            traffic += b - a if b >= a else b
        return traffic, covered

    def _dns_seen_since(self, key: str, since: datetime) -> bool:
        raw = self.store.get_meta(key)
        return raw is not None and from_iso(raw) >= since

    # --------------------------------------------------------------- czujka
    def _check(self, name: str, traffic: float, covered: bool, now: datetime,
               ip_only: bool = False):
        start = now - self.window
        if self._dns_seen_since(f"alive:{name}", start):
            return self._recovered(name, now)
        if not covered or traffic < self.alarm_bytes:
            return []
        if not self._dns_seen_since("alive:__all__", start):
            # Cisza od WSZYSTKICH = padl strumien DNS. To nie profil jednego iPada.
            return []
        return self._alert(name, traffic, now, ip_only=ip_only)

    def _alert(self, name: str, traffic: float, now: datetime,
               ip_only: bool = False) -> list[Notification]:
        """Backoff jak w czujce silnika: okno, 2x, 4x... do sufitu.

        Dopasowanie TYLKO po IP (MAC sie nie zgadza albo go nie podano) nie
        daje prio 5: po rotacji prywatnego MAC-a iPada ten adres z puli mogl
        dostac inny sprzet, ktory NextDNS-a nie uzywa wcale.
        """
        key = f"unifi-wd:{name}"
        state = self.store.get_json(key, {})
        assert isinstance(state, dict)
        count = int(state.get("n", 0))
        last = state.get("last")
        base = self.window.total_seconds() / 60
        wait = min(base * 2 ** max(0, count - 1), self.backoff_max)
        if last is not None and now - from_iso(last) < timedelta(minutes=wait):
            return []
        since = episode_id(state, now)
        self.store.set_json(key, {"n": count + 1, "last": to_iso(now), "since": since})
        minutes = int(self.window.total_seconds() // 60)
        suffix = "" if count == 0 else f"\n(przypomnienie {count + 1})"
        if ip_only:
            suffix = ("\nUrządzenie rozpoznane tylko po adresie IP — sprawdź, czy to "
                      "na pewno ten iPad." + suffix)
        return self._emit(Notification(
            kind=NotifyKind.DNS_PROFILE,
            title=f"{name} — profil DNS prawdopodobnie usunięty",
            text=(
                f"W domowym Wi-Fi przesłał {traffic / 1_000_000:.0f} MB w {minutes} min, "
                f"a NextDNS nie ma od niego ani jednego zapytania.\n"
                f"Sprawdź na iPadzie: Ustawienia → Ogólne → VPN i urządzenia → profil "
                f"NextDNS.{suffix}"
            ),
            dedup_key=f"unifi-wd:{name}:{since}:{count}",  # epizod: patrz episode_id
            ts=now,
            device=name,
            priority=5 if count == 0 and not ip_only else 4,
            tags=("rotating_light",),
        ))

    def _recovered(self, name: str, now: datetime) -> list[Notification]:
        key = f"unifi-wd:{name}"
        state = self.store.get_json(key, {})
        assert isinstance(state, dict)
        count = int(state.get("n", 0))
        if count == 0:
            return []
        since = episode_id(state, now)
        self.store.set_json(key, {})
        return self._emit(Notification(
            kind=NotifyKind.DNS_PROFILE,
            title=f"{name} — znowu pyta NextDNS",
            text="Zapytania DNS wróciły — profil działa.",
            dedup_key=f"unifi-ok:{name}:{since}:{count}",
            ts=now,
            device=name,
            priority=2,
            tags=("white_check_mark",),
        ))

    def _emit(self, note: Notification) -> list[Notification]:
        if not self.store.mark_sent(note.dedup_key, note.ts):
            return []
        self.store.log_notification(note.device, note.ts, note.kind.value)
        return [note]


async def unifi_loop(
    watcher: UnifiWatcher,
    dispatcher,
    interval_seconds: float,
    sleep=asyncio.sleep,
    max_iterations: int | None = None,
) -> None:
    """Odpytuje kontroler. Bledy logujemy raz na rodzaj — kontroler w
    restarcie to nie powod do zalewania logu co minute."""
    last_error: str | None = None
    iteration = 0
    while max_iterations is None or iteration < max_iterations:
        iteration += 1
        try:
            notes = await watcher.poll(datetime.now(UTC))
            if last_error is not None:
                log.info("unifi: kontroler znowu odpowiada")
                last_error = None
            await dispatcher.send_all(notes)
        except asyncio.CancelledError:
            raise
        except UnifiError as exc:
            kind = type(exc).__name__
            if kind != last_error:
                # Zly certyfikat i zly klucz to bledy konfiguracji — ERROR.
                config_error = isinstance(exc, CertMismatch | UnifiAuthError)
                log.log(logging.ERROR if config_error else logging.WARNING, "unifi: %s", exc)
                last_error = kind
        except Exception:
            log.exception("unifi: nieoczekiwany blad")
        await sleep(interval_seconds)
