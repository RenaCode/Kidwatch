"""Strażnik sieci domu (E2, docs/architektura-domy.md §3.6, §4.4 p. 7): SSRF.

Adresy: pule dokumentacyjne (RFC 5737/3849), prywatne z RFC 1918 jako
przyklady sieci zabronionych i publiczne adresy resolwera Quad9 (9.9.9.9,
2620:fe::fe) jako przyklad adresu publicznego. Zadnego prawdziwego ruchu:
nazwy rozwiazuje atrapa, polaczenia przechwytuje MockTransport."""

from __future__ import annotations

import asyncio
import ipaddress

import httpx
import pytest

from kidwatch.sources import unifi as unifi_mod
from kidwatch.straznik import OdmowaSieci, Straznik, klient_http

pytestmark = pytest.mark.usefixtures("bez_sieci")

PUBLICZNY = "9.9.9.9"


class Resolver:
    """Atrapa DNS: nazwa -> kolejne odpowiedzi (ostatnia sie powtarza)."""

    def __init__(self, **odpowiedzi: list[list[str]]) -> None:
        self.odpowiedzi = {k.replace("_", "."): v for k, v in odpowiedzi.items()}
        self.pytania: list[str] = []

    def __call__(self, host: str, port: int) -> list[str]:
        self.pytania.append(host)
        kolejne = self.odpowiedzi.get(host)
        if not kolejne:
            raise OSError("NXDOMAIN")
        return kolejne.pop(0) if len(kolejne) > 1 else kolejne[0]


@pytest.mark.parametrize("adres", [
    "10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "169.254.169.254",
    "100.64.0.1",          # CGNAT / tailnet
    "0.0.0.0", "224.0.0.1", "255.255.255.255",
    "192.0.2.10",          # dokumentacyjna — nie publiczna
    "::1", "fe80::1", "fd00::1", "::",
    "::ffff:10.0.0.1",     # IPv4 zmapowany
    "2002:a00:1::1",       # 6to4 z 10.0.0.1
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",  # Teredo
    "64:ff9b::a00:1",      # NAT64 z 10.0.0.1 (sam prefiks jest „globalny”)
    "2001:db8::1",         # dokumentacyjna IPv6
])
def test_adresy_niepubliczne_sa_odrzucane(adres):
    straznik = Straznik(2)
    assert not straznik.dozwolony(ipaddress.ip_address(adres))
    with pytest.raises(OdmowaSieci, match="poza siecią domu"):
        straznik.rozwiaz_sync(adres, 443)


@pytest.mark.parametrize("adres", [PUBLICZNY, "2620:fe::fe", "64:ff9b::909:909"])
def test_adresy_publiczne_przechodza(adres):
    assert Straznik(2).dozwolony(ipaddress.ip_address(adres))


def test_dozwolone_sieci_domu():
    straznik = Straznik(1, ["192.0.2.20/32", "10.10.0.0/24", "fd00:1::/64"])
    for ok in ("192.0.2.20", "10.10.0.7", "::ffff:192.0.2.20", "fd00:1::5"):
        assert straznik.dozwolony(ipaddress.ip_address(ok)), ok
    for zle in ("192.0.2.21", "10.10.1.1", "fd00:2::5"):
        assert not straznik.dozwolony(ipaddress.ip_address(zle)), zle
    # Siec Domu 1 nie otwiera niczego Domowi 2.
    assert not Straznik(2).dozwolony(ipaddress.ip_address("192.0.2.20"))


def test_sieci_scisle():
    with pytest.raises(ValueError, match="CIDR"):
        Straznik(1, ["192.0.2.5/24"])
    with pytest.raises(ValueError, match="CIDR"):
        Straznik(1, ["nie-siec"])


def test_nazwa_rozwiazywana_i_kazdy_adres_sprawdzany():
    straznik = Straznik(2, resolver=Resolver(
        dobry_example_invalid=[[PUBLICZNY]],
        mieszany_example_invalid=[[PUBLICZNY, "192.168.0.1"]],
        lan_example_invalid=[["10.0.0.9"]],
    ))
    assert str(straznik.rozwiaz_sync("dobry.example.invalid", 443)) == PUBLICZNY
    for host in ("mieszany.example.invalid", "lan.example.invalid"):
        with pytest.raises(OdmowaSieci):
            straznik.rozwiaz_sync(host, 443)
    with pytest.raises(OdmowaSieci, match="nie rozwiązuje"):
        straznik.rozwiaz_sync("brak.example.invalid", 443)


def test_sprawdz_url_przy_zapisie():
    straznik = Straznik(2, resolver=Resolver(api_nextdns_io=[[PUBLICZNY]],
                                             ha_example_invalid=[["192.168.0.5"]],
                                             obce_example_invalid=[[PUBLICZNY]]))
    straznik.sprawdz_url("https://api.nextdns.io", pole="x", typ_api="nextdns")
    with pytest.raises(OdmowaSieci, match="spoza listy"):
        straznik.sprawdz_url("https://obce.example.invalid", pole="x", typ_api="nextdns")
    with pytest.raises(OdmowaSieci, match="poza siecią"):
        straznik.sprawdz_url("http://ha.example.invalid:8123", pole="ha")
    with pytest.raises(OdmowaSieci, match="schematy"):
        straznik.sprawdz_url("file:///etc/passwd", pole="ha")
    with pytest.raises(OdmowaSieci, match="loginem"):
        straznik.sprawdz_url(f"https://u:p@{PUBLICZNY}/", pole="ha")
    with pytest.raises(OdmowaSieci, match="poza siecią"):
        straznik.sprawdz_url("http://169.254.169.254/latest/meta-data", pole="ha")
    with pytest.raises(OdmowaSieci, match="poza siecią"):
        straznik.sprawdz_url("http://[::1]:8080/", pole="ha")
    # Host dopisany przez administratora instancji.
    Straznik(2, hosty=["obce.example.invalid"], resolver=Resolver(
        obce_example_invalid=[[PUBLICZNY]])).sprawdz_url(
        "https://obce.example.invalid", pole="x", typ_api="nextdns")


# ================================================================ transport
class Zapis:
    def __init__(self, odpowiedz=None) -> None:
        self.zadania: list[httpx.Request] = []
        self.odpowiedz = odpowiedz or (lambda r: httpx.Response(200, json={"ok": True}))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.zadania.append(request)
        return self.odpowiedz(request)


async def test_transport_laczy_sie_ze_sprawdzonym_adresem():
    zapis = Zapis()
    straznik = Straznik(2, resolver=Resolver(api_example_invalid=[[PUBLICZNY]]))
    async with httpx.AsyncClient(transport=straznik.transport(httpx.MockTransport(zapis))) as c:
        r = await c.get("https://api.example.invalid/v1/x?a=1")
    assert r.status_code == 200
    [req] = zapis.zadania
    assert req.url.host == PUBLICZNY and req.url.path == "/v1/x"
    assert req.headers["host"] == "api.example.invalid"
    assert req.extensions["sni_hostname"] == "api.example.invalid"


async def test_dns_rebinding_drugie_zapytanie_na_lan_odrzucone():
    """Nazwa raz publiczna, potem LAN: drugie polaczenie nie wychodzi."""
    zapis = Zapis()
    resolver = Resolver(ha_example_invalid=[[PUBLICZNY], ["192.168.1.10"]])
    straznik = Straznik(2, resolver=resolver)
    async with httpx.AsyncClient(transport=straznik.transport(httpx.MockTransport(zapis))) as c:
        await c.get("http://ha.example.invalid/api")
        with pytest.raises(httpx.ConnectError, match="poza siecią"):
            await c.get("http://ha.example.invalid/api")
    assert [r.url.host for r in zapis.zadania] == [PUBLICZNY]
    assert resolver.pytania == ["ha.example.invalid", "ha.example.invalid"]


@pytest.mark.parametrize("cel", [
    "http://192.168.0.1/admin", "http://169.254.169.254/latest/meta-data",
    "http://[fd00::1]/", "http://intranet.example.invalid/", "http://127.0.0.1:8081/api",
])
async def test_przekierowanie_do_lanu_odrzucone(cel):
    def odpowiedz(request):
        if request.url.host == PUBLICZNY:
            return httpx.Response(302, headers={"Location": cel})
        return httpx.Response(200)

    zapis = Zapis(odpowiedz)
    straznik = Straznik(2, resolver=Resolver(publiczny_example_invalid=[[PUBLICZNY]],
                                             intranet_example_invalid=[["10.1.2.3"]]))
    async with httpx.AsyncClient(transport=straznik.transport(httpx.MockTransport(zapis)),
                                 follow_redirects=True) as c:
        with pytest.raises(httpx.ConnectError):
            await c.get("http://publiczny.example.invalid/")
    assert [r.url.host for r in zapis.zadania] == [PUBLICZNY]


async def test_klient_http_bez_straznika_to_brak_klienta():
    assert klient_http(None, timeout=1) is None
    klient = klient_http(Straznik(1), timeout=1)
    assert klient is not None
    await klient.aclose()


# ============================================================ UniFi i ADB
def test_unifi_laczy_sie_ze_sprawdzonym_adresem(monkeypatch):
    hosty = []

    class Polaczenie:
        def __init__(self, host, port, timeout, context):
            hosty.append(host)

        def connect(self):
            raise ConnectionRefusedError("atrapa")

    monkeypatch.setattr(unifi_mod.http.client, "HTTPSConnection", Polaczenie)
    straznik = Straznik(1, ["192.0.2.1/32"], resolver=Resolver(udm_example_invalid=[["192.0.2.1"]]))
    with pytest.raises(ConnectionRefusedError):
        unifi_mod.fetch_pinned("https://udm.example.invalid", "/x", "k", "0" * 64, 1, straznik)
    assert hosty == ["192.0.2.1"]
    # Dom bez tej sieci: zadnego polaczenia, blad sieci (OSError) dla petli.
    with pytest.raises(OdmowaSieci):
        unifi_mod.fetch_pinned("https://192.0.2.1", "/x", "k", "0" * 64, 1, Straznik(2))
    assert hosty == ["192.0.2.1"]

    client = unifi_mod.UnifiClient("https://192.0.2.1", "default", "k", "0" * 64, 1,
                                   straznik=Straznik(2))
    with pytest.raises(unifi_mod.UnifiError, match="OdmowaSieci"):
        asyncio.run(client.stations())


async def test_adb_laczy_sie_ze_sprawdzonym_adresem(tmp_path, monkeypatch):
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415

    from kidwatch.sources import tv as tv_mod  # noqa: PLC0415

    klucz = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    (tmp_path / "adbkey").write_bytes(klucz.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    hosty = []

    class Urzadzenie:
        available = False

        def __init__(self, host, port, default_transport_timeout_s):
            hosty.append(host)

        async def connect(self, **kw):
            raise ConnectionRefusedError("atrapa")

        async def close(self):
            pass

    import adb_shell.adb_device_async as adb_async  # noqa: PLC0415

    monkeypatch.setattr(adb_async, "AdbDeviceTcpAsync", Urzadzenie)
    ok = tv_mod.AdbTcpShell("tv.example.invalid", 5555, tmp_path, 1, straznik=Straznik(
        1, ["192.0.2.20/32"], resolver=Resolver(tv_example_invalid=[["192.0.2.20"]])))
    with pytest.raises(tv_mod.TvUnavailable):
        await ok.shell("true")
    assert hosty == ["192.0.2.20"]
    obcy = tv_mod.AdbTcpShell("192.0.2.20", 5555, tmp_path, 1, straznik=Straznik(2))
    with pytest.raises(tv_mod.TvUnavailable, match="OdmowaSieci"):
        await obcy.shell("true")
    assert hosty == ["192.0.2.20"]


def test_fixture_bez_sieci_naprawde_blokuje():
    """Kanarek detektora: cisza `bez_sieci` coś znaczy tylko wtedy, gdy
    prawdziwa próba DNS i połączenia kończy się błędem testu."""
    import socket  # noqa: PLC0415

    with pytest.raises(AssertionError, match="rozwiazac"):
        socket.getaddrinfo("example.invalid", 443)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(AssertionError, match="polaczyc"):
            s.connect(("192.0.2.1", 443))
    finally:
        s.close()
