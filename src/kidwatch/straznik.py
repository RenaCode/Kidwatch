"""Strażnik sieci domu: adresy wpisane przez zarządcę domu (SSRF, §3.6).

Pod ma trasę do LAN Domu 1 (tunel WireGuard) i do usług klastra, a
NetworkPolicy egress jest jedna na poda. Zarządca Domu 2, wpisując jako
„UniFi”, „TV” albo „Home Assistant” adres z LAN Domu 1 albo usługę klastra
(np. serwer MDM), dostałby z poda połączenie tam, gdzie nie powinien.

Reguła: adres jest dozwolony, gdy leży w `domy.dozwolone_sieci` tego domu
(ustawia je wyłącznie administrator instancji z CLI: `kidwatch dom-sieci`)
albo jest adresem publicznym (`is_global`) — wraz z każdym adresem IPv4
zaszytym w IPv6 (::ffff:, 6to4, Teredo, NAT64). Wszystko inne — prywatne,
pętla zwrotna, link-local, CGNAT/tailnet, ULA, multicast, zarezerwowane —
jest odmową.

Sprawdzamy PO ROZWIĄZANIU NAZWY i PRZY KAŻDYM POŁĄCZENIU, nie tylko przy
zapisie: nazwa, która przy zapisie wskazywała adres publiczny, może później
wskazać LAN (DNS rebinding). Połączenie idzie na DOKŁADNIE ten adres, który
przeszedł sprawdzenie (nazwa nie jest rozwiązywana drugi raz). Każdy skok
przekierowania HTTP przechodzi przez ten sam transport, więc też jest
sprawdzany. Nazwa, z której choć jeden adres jest zabroniony, jest odmową
w całości — mieszana odpowiedź DNS to typowy wzór ataku.

`nextdns.base_url` i `ntfy.server` dodatkowo muszą mieć host z listy
(`api.nextdns.io`, `ntfy.sh` + `domy.dozwolone_hosty` ustawione przez
administratora instancji).

Dom 1 w trybie `yaml` NIE ma strażnika — zachowanie sprzed domów bez zmian.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Callable, Iterable
from urllib.parse import urlsplit

import httpx

IP = ipaddress.IPv4Address | ipaddress.IPv6Address
Siec = ipaddress.IPv4Network | ipaddress.IPv6Network

#: Hosty API, na które wolno kierować integracje bez adresu „domowego”.
HOSTY_API: dict[str, frozenset[str]] = {
    "nextdns": frozenset({"api.nextdns.io"}),
    "ntfy": frozenset({"ntfy.sh"}),
}
#: NAT64 (RFC 6052, prefiks dobrze znany) — adres IPv4 w ostatnich 32 bitach.
_NAT64 = ipaddress.IPv6Network("64:ff9b::/96")


class OdmowaSieci(PermissionError):
    """Adres poza siecią domu. OSError — dla pętli to „nie odpowiada”."""


def sieci_z_tekstu(sieci: Iterable[str]) -> list[Siec]:
    """CIDR-y z `domy.dozwolone_sieci`. Ścisłe: `192.0.2.5/24` to błąd
    (pewnie miało być /32 albo 192.0.2.0/24), nie cicha poprawka."""
    out = []
    for s in sieci:
        try:
            out.append(ipaddress.ip_network(str(s).strip(), strict=True))
        except ValueError as exc:
            raise ValueError(f"{s!r} to nie sieć CIDR (np. 192.0.2.0/24 albo 192.0.2.7/32)") \
                from exc
    return out


def adres_literalny(host: str) -> IP | None:
    try:
        return ipaddress.ip_address(host.strip().strip("[]").split("%")[0])
    except ValueError:
        return None


def _zaszyte_ipv4(ip: IP) -> list[ipaddress.IPv4Address]:
    if not isinstance(ip, ipaddress.IPv6Address):
        return []
    out = []
    if ip.sixtofour is not None:
        out.append(ip.sixtofour)
    if ip.teredo is not None:
        out.extend(ip.teredo)
    if ip in _NAT64:
        out.append(ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF))
    return out


def _publiczny(ip: IP) -> bool:
    return (ip.is_global and not ip.is_multicast
            and all(_publiczny(z) for z in _zaszyte_ipv4(ip)))


def rozwiaz_systemowo(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(i[4][0]) for i in infos))


class Straznik:
    """Sieci domu i rozwiązywanie nazw z kontrolą. `resolver` (testy):
    (host, port) -> lista adresów tekstowo; domyślnie getaddrinfo."""

    def __init__(self, dom_id: int, sieci: Iterable[str] = (), hosty: Iterable[str] = (),
                 resolver: Callable[[str, int], list[str]] | None = None) -> None:
        self.dom_id = dom_id
        self.sieci = sieci_z_tekstu(sieci)
        self.hosty = frozenset(h.strip().lower() for h in hosty if h.strip())
        self._resolver = resolver or rozwiaz_systemowo

    def __repr__(self) -> str:
        return f"Straznik(dom={self.dom_id}, sieci={[str(s) for s in self.sieci]})"

    # ---------------------------------------------------------------- adresy
    def dozwolony(self, ip: IP) -> bool:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        if any(ip.version == s.version and ip in s for s in self.sieci):
            return True
        return _publiczny(ip)

    def sprawdz_ip(self, ip: IP, host: str | None = None) -> IP:
        if not self.dozwolony(ip):
            skad = f"{host} -> {ip}" if host and str(ip) != host else str(ip)
            raise OdmowaSieci(
                f"dom {self.dom_id}: adres {skad} jest poza siecią domu "
                f"(dozwolone_sieci ustawia administrator: kidwatch dom-sieci)")
        return ip

    def rozwiaz_sync(self, host: str, port: int) -> IP:
        """Adres, z którym WOLNO się połączyć — łączymy się z nim, nie z nazwą."""
        literal = adres_literalny(host)
        if literal is not None:
            return self.sprawdz_ip(literal, host)
        try:
            adresy = self._resolver(host, port)
        except OSError as exc:
            raise OdmowaSieci(f"dom {self.dom_id}: nazwa {host} nie rozwiązuje się") from exc
        ips = [ip for ip in (adres_literalny(a) for a in adresy) if ip is not None]
        if not ips:
            raise OdmowaSieci(f"dom {self.dom_id}: nazwa {host} nie rozwiązuje się")
        for ip in ips:
            self.sprawdz_ip(ip, host)
        return ips[0]

    async def rozwiaz(self, host: str, port: int) -> IP:
        if adres_literalny(host) is not None:
            return self.rozwiaz_sync(host, port)
        return await asyncio.to_thread(self.rozwiaz_sync, host, port)

    # ------------------------------------------------------------------ URL
    def sprawdz_url(self, url: str, *, pole: str, schematy: Iterable[str] = ("http", "https"),
                    typ_api: str | None = None) -> None:
        """Przy zapisie integracji: schemat, brak danych logowania w adresie,
        host z listy (dla API) i adres po rozwiązaniu."""
        czesci = urlsplit(url.strip())
        if czesci.scheme not in set(schematy):
            raise OdmowaSieci(f"{pole}: dozwolone schematy {sorted(schematy)}, jest "
                              f"{czesci.scheme or 'brak'}")
        if czesci.username or czesci.password:
            raise OdmowaSieci(f"{pole}: adres z loginem/hasłem jest niedozwolony")
        host = (czesci.hostname or "").lower()
        if not host:
            raise OdmowaSieci(f"{pole}: brak hosta")
        if typ_api is not None and host not in HOSTY_API.get(typ_api, frozenset()) | self.hosty:
            raise OdmowaSieci(f"{pole}: host {host} spoza listy dozwolonych "
                              f"({', '.join(sorted(HOSTY_API.get(typ_api, ())))} + "
                              f"dozwolone_hosty domu)")
        port = czesci.port or (443 if czesci.scheme == "https" else 80)
        self.rozwiaz_sync(host, port)

    def sprawdz_host(self, host: str, port: int, *, pole: str) -> None:
        if not host.strip():
            raise OdmowaSieci(f"{pole}: brak adresu")
        self.rozwiaz_sync(host, port)

    # ------------------------------------------------------------ transport
    def transport(self, inner: httpx.AsyncBaseTransport | None = None) -> StraznikTransport:
        return StraznikTransport(self, inner)


class StraznikTransport(httpx.AsyncBaseTransport):
    """httpx: każde żądanie (także każdy skok przekierowania) idzie na adres
    sprawdzony przez strażnika. Nazwa zostaje w nagłówku Host i w SNI."""

    def __init__(self, straznik: Straznik, inner: httpx.AsyncBaseTransport | None = None) -> None:
        self.straznik = straznik
        self._inner = inner or httpx.AsyncHTTPTransport()

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.scheme not in ("http", "https"):
            raise httpx.UnsupportedProtocol(f"schemat {url.scheme} niedozwolony",
                                            request=request)
        host = url.host
        port = url.port or (443 if url.scheme == "https" else 80)
        try:
            ip = await self.straznik.rozwiaz(host, port)
        except OdmowaSieci as exc:
            raise httpx.ConnectError(str(exc), request=request) from exc
        if adres_literalny(host) is None:
            request.url = url.copy_with(host=str(ip))
            if url.scheme == "https":
                request.extensions = {**request.extensions, "sni_hostname": host}
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()


def klient_http(straznik: Straznik | None, **kwargs) -> httpx.AsyncClient | None:
    """Klient z transportem strażnika albo None (bez strażnika — klasy
    źródeł budują wtedy swojego klienta jak przed domami)."""
    if straznik is None:
        return None
    return httpx.AsyncClient(transport=straznik.transport(), **kwargs)


def transport(straznik: Straznik | None) -> httpx.AsyncBaseTransport | None:
    return straznik.transport() if straznik is not None else None
