"""UniFi: przypiety certyfikat, obecnosc w domu, czujka "profil DNS usuniety"."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import ssl
import threading
from datetime import UTC, datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from kidwatch.config import UnifiConfig
from kidwatch.models import NotifyKind
from kidwatch.sources.unifi import (
    CertMismatch,
    UnifiAuthError,
    UnifiClient,
    UnifiWatcher,
    server_fingerprint,
)
from kidwatch.store import Store, to_iso

MAC_KUBY = "aa:bb:cc:00:00:01"
MB = 1_000_000


# =========================================================== serwer z TLS
def _self_signed(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "unifi.local")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    (tmp_path / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (tmp_path / "key.pem").write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    der = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der).hexdigest()


@pytest.fixture
def udm(tmp_path):
    """Udawany UDM z certyfikatem samopodpisanym. Zapamietuje naglowki zadan —
    tak sprawdzamy, ze przy zlym odcisku klucz NIE wyszedl z procesu."""
    pin = _self_signed(tmp_path)
    seen: list[dict] = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):  # noqa: N802
            seen.append(dict(self.headers))
            if self.headers.get("X-API-KEY") != "klucz-testowy":
                self.send_response(401)
                self.end_headers()
                return
            body = json.dumps({"meta": {"rc": "ok"}, "data": [
                {"mac": MAC_KUBY.upper(), "essid": "Dom", "ip": "192.168.1.50",
                 "tx_bytes": 1000, "rx_bytes": 2000},
            ]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(tmp_path / "cert.pem", tmp_path / "key.pem")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"https://127.0.0.1:{srv.server_address[1]}", pin, seen
    srv.shutdown()


async def test_przypiety_certyfikat_przechodzi(udm):
    url, pin, seen = udm
    client = UnifiClient(url, "default", "klucz-testowy", pin, 5)
    stations = await client.stations()
    assert stations[0]["essid"] == "Dom"
    assert seen[0]["X-API-KEY"] == "klucz-testowy"


async def test_zly_odcisk_NIE_wysyla_klucza(udm):
    url, _, seen = udm
    client = UnifiClient(url, "default", "klucz-testowy", "0" * 64, 5)
    with pytest.raises(CertMismatch):
        await client.stations()
    assert seen == [], "zadanie z kluczem poszlo mimo niezgodnego certyfikatu"


async def test_zly_klucz_to_blad_autoryzacji(udm):
    url, pin, _ = udm
    with pytest.raises(UnifiAuthError):
        await UnifiClient(url, "default", "zly", pin, 5).stations()


def test_odcisk_serwera_bez_wysylania_czegokolwiek(udm):
    url, pin, seen = udm
    assert server_fingerprint(url, 5) == pin
    assert seen == []


def test_odcisk_w_konfiguracji_w_formacie_openssl():
    raw = "sha256 Fingerprint=" + ":".join(["AB"] * 32)
    assert UnifiConfig(cert_sha256=raw).cert_sha256 == "ab" * 32
    with pytest.raises(ValueError, match="SHA-256"):
        UnifiConfig(cert_sha256="abc")


# ================================================================ czujka
class FakeClient:
    async def stations(self):
        return []


@pytest.fixture
def store():
    s = Store(":memory:")
    yield s
    s.close()


T0 = datetime(2026, 10, 2, 13, 0, tzinfo=UTC)


def sta(total_mb: float) -> list[dict]:
    return [{"mac": MAC_KUBY, "essid": "Dom", "tx_bytes": int(total_mb * MB), "rx_bytes": 0}]


def watcher(store, **kw):
    return UnifiWatcher(FakeClient(), [("iPad Kuby", MAC_KUBY, None)], store,
                        window_minutes=15, alarm_mb=20, **kw)


def feed(w, store, minutes: int, mb_per_min: float, start=T0, dns_from_ipad=False):
    """Probka co minute; DNS od innych urzadzen zawsze jest (strumien zyje)."""
    out = []
    for m in range(minutes + 1):
        now = start + timedelta(minutes=m)
        store.set_meta("alive:__all__", to_iso(now))
        if dns_from_ipad:
            store.set_meta("alive:iPad Kuby", to_iso(now))
        out += w.observe(sta(100 + m * mb_per_min), now)
    return out


def test_ruch_bez_DNS_w_domu_to_alarm(store):
    store.set_meta("alive:iPad Kuby", to_iso(T0 - timedelta(hours=2)))
    notes = feed(watcher(store), store, 16, mb_per_min=3)
    assert [n.kind for n in notes] == [NotifyKind.DNS_PROFILE]
    assert "profil DNS prawdopodobnie usunięty" in notes[0].title
    assert notes[0].priority == 5


def test_ruch_z_zapytaniami_DNS_to_nie_alarm(store):
    assert feed(watcher(store), store, 30, mb_per_min=3, dns_from_ipad=True) == []


def test_maly_ruch_spiacego_iPada_to_nie_alarm(store):
    assert feed(watcher(store), store, 30, mb_per_min=0.1) == []


def test_alarm_dopiero_gdy_okno_pokryte_probkami(store):
    """Tuz po starcie (albo powrocie do domu) nie ma 15 min historii."""
    assert feed(watcher(store), store, 10, mb_per_min=10) == []


def test_cisza_od_wszystkich_to_awaria_strumienia_nie_profil(store):
    w = watcher(store)
    store.set_meta("alive:__all__", to_iso(T0 - timedelta(hours=1)))
    out = []
    for m in range(20):
        out += w.observe(sta(100 + m * 5), T0 + timedelta(minutes=m))
    assert out == []


def test_backoff_przypomnien_i_powrot(store):
    w = watcher(store)
    notes = feed(w, store, 120, mb_per_min=3)
    sent = [n for n in notes if n.kind is NotifyKind.DNS_PROFILE]
    # 15 min na pokrycie okna, potem alarm i przypomnienia po 15, 30, 60 min.
    gaps = [(b.ts - a.ts) for a, b in zip(sent, sent[1:], strict=False)]
    assert gaps[:3] == [timedelta(minutes=15), timedelta(minutes=30), timedelta(minutes=60)]

    now = T0 + timedelta(minutes=121)
    store.set_meta("alive:iPad Kuby", to_iso(now))
    back = w.observe(sta(1000), now)
    assert [n.title for n in back] == ["iPad Kuby — znowu pyta NextDNS"]


def test_licznik_zerowany_po_ponownym_polaczeniu(store):
    """UniFi zeruje liczniki przy ponownej asocjacji — ujemna roznica to
    'od zera', a nie ujemny ruch ani gigantyczny skok."""
    w = watcher(store)
    w.observe(sta(500), T0)
    traffic, _ = w._traffic("iPad Kuby", 2 * MB, T0 + timedelta(minutes=1))
    assert traffic == 2 * MB


def test_obecnosc_w_domu_i_poza_domem(store):
    w = watcher(store)
    w.observe(sta(1), T0)
    p = store.get_json("presence:iPad Kuby")
    assert p["home"] is True and p["essid"] == "Dom"
    w.observe([], T0 + timedelta(minutes=5))
    p = store.get_json("presence:iPad Kuby")
    assert p["home"] is False
    assert p["since"] == to_iso(T0 + timedelta(minutes=5))
    # Poza domem nie ma probek — po powrocie okno liczy sie od nowa.
    assert "iPad Kuby" not in w.samples


def test_dopasowanie_po_stalym_IP_gdy_MAC_nie_pasuje(store):
    """iOS potrafi zmienic prywatny adres Wi-Fi; stale IP z rezerwacji DHCP
    jest drugim tropem."""
    w = UnifiWatcher(FakeClient(), [("iPad Kuby", "02:00:00:00:00:99", "192.168.0.81")], store)
    w.observe([{"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.0.81", "tx_bytes": 1}], T0)
    assert store.get_json("presence:iPad Kuby")["home"] is True


def test_alarm_przy_dopasowaniu_tylko_po_IP_nie_ma_prio_5(store):
    """Audyt runda 4, pkt 14: po rotacji prywatnego MAC-a adres z puli mogl
    dostac inny sprzet — falszywy "profil DNS usuniety" z prio 5."""
    w = UnifiWatcher(FakeClient(), [("iPad Kuby", "02:00:00:00:00:99", "192.168.0.81")],
                     store, window_minutes=15, alarm_mb=20)
    out = []
    for m in range(17):
        now = T0 + timedelta(minutes=m)
        store.set_meta("alive:__all__", to_iso(now))
        out += w.observe([{"mac": "aa:aa:aa:aa:aa:aa", "ip": "192.168.0.81",
                           "tx_bytes": int((100 + m * 3) * MB)}], now)
    assert [n.priority for n in out] == [4]
    assert "tylko po adresie IP" in out[0].text


def test_druga_awaria_profilu_w_tygodniu_daje_alarm_i_powrot(store):
    """Audyt 3, K1: klucze `unifi-wd:<iPad>:<n>` zaczynaly po powrocie od n=0,
    a `sent` trzyma je 7 dni — drugie zdjecie profilu nie dawalo alarmu
    (pierwszy wychodzil dopiero jako "przypomnienie" o numerze, ktorego
    pierwszy epizod nie zuzyl)."""
    w = watcher(store)
    for episode in range(2):
        start = T0 + timedelta(hours=3 * episode)
        notes = feed(w, store, 20, mb_per_min=3, start=start)
        alarms = [n for n in notes if "usunięty" in n.title]
        assert alarms, f"epizod {episode + 1}: brak alarmu"
        assert "przypomnienie" not in alarms[0].text
        assert alarms[0].priority == 5
        back = start + timedelta(minutes=30)
        store.set_meta("alive:iPad Kuby", to_iso(back))
        assert [n.title for n in w.observe(sta(5000), back)] == [
            "iPad Kuby — znowu pyta NextDNS"
        ]
