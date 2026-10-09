"""CLI kidwatch-mdm.

Konfiguracja serwera (`run`) wylacznie ze zmiennych srodowiska — w klastrze
ustawia je chart, sekrety przychodza z Secretow:

  KIDWATCH_MDM_PUBLIC_URL   https://mdm.renacode.com (bez ukosnika na koncu)
  KIDWATCH_MDM_DATA         katalog bazy (PVC), domyslnie /data
  KIDWATCH_MDM_CA_DIR       ca.crt + ca.key (Secret), domyslnie $DATA/ca
  KIDWATCH_MDM_POLICY       plik polityki YAML (ConfigMap)
  KIDWATCH_MDM_SCHEMA       indeks schematow Apple do walidacji polityki
  KIDWATCH_MDM_APNS_CERT    certyfikat push .pem z identity.apple.com (opcjonalny)
  KIDWATCH_MDM_APNS_KEY     klucz push.key (opcjonalny, razem z certyfikatem)
  KIDWATCH_MDM_ADMIN_TOKEN  token API dla Kidwatch (wymagany)
  KIDWATCH_MDM_SIGN_CERT    tls.crt do podpisu profilu zapisu (opcjonalny)
  KIDWATCH_MDM_SIGN_KEY     tls.key do podpisu profilu zapisu (opcjonalny)
  KIDWATCH_MDM_PORT / KIDWATCH_MDM_ADMIN_PORT   domyslnie 8080 / 8081
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import sys
import threading
import time
from pathlib import Path

from . import apns_cert

DEFAULT_APNS_DIR = Path.home() / ".kidwatch-mdm" / "apns"
#: Co ile uzgadniac stan iPadow z polityka. Zmiana z API wymusza obieg od razu.
RECONCILE_SECONDS = 300
#: Ponowienie po nieudanym uzgadnianiu.
RETRY_SECONDS = 60

log = logging.getLogger("kidwatch_mdm")


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name, default)
    return value.strip() if isinstance(value, str) and value.strip() else default


def build_service():
    from . import policy as policy_mod
    from .apns import ApnsPusher, NoPusher
    from .pki import CA
    from .service import MDMService
    from .store import Store

    data = Path(_env("KIDWATCH_MDM_DATA", "/data"))
    public_url = _env("KIDWATCH_MDM_PUBLIC_URL")
    if not public_url or not public_url.startswith("https://"):
        raise SystemExit("KIDWATCH_MDM_PUBLIC_URL musi byc adresem https://")
    schema = policy_mod.load_schema(_env("KIDWATCH_MDM_SCHEMA"))
    if schema is None:
        log.warning("brak KIDWATCH_MDM_SCHEMA — klucze polityki NIE sa walidowane")
    policy_path = _env("KIDWATCH_MDM_POLICY")
    policy = policy_mod.load(policy_path, schema) if policy_path else policy_mod.Policy()
    ca = CA.load(Path(_env("KIDWATCH_MDM_CA_DIR", str(data / "ca"))))
    cert, key = _env("KIDWATCH_MDM_APNS_CERT"), _env("KIDWATCH_MDM_APNS_KEY")
    # Chart ustawia sciezki zawsze, a Sekret z certyfikatem jest opcjonalny —
    # brak plikow to stan „jeszcze bez certyfikatu", nie blad startu.
    if cert and key and Path(cert).is_file() and Path(key).is_file():
        pusher = ApnsPusher(Path(cert), Path(key))
        log.info("APNs: temat %s, wazny do %s", pusher.topic, pusher.expires_at())
    else:
        pusher = NoPusher()
        log.warning("brak certyfikatu APNs — zapis iPadow zablokowany, pushe wylaczone")
    from .signing import build as build_signer

    signer = build_signer(_env("KIDWATCH_MDM_SIGN_CERT"), _env("KIDWATCH_MDM_SIGN_KEY"))
    if signer is None:
        log.warning('brak certyfikatu podpisu — profil zapisu bedzie „Niezweryfikowany"')
    return MDMService(
        signer=signer,
        store=Store(data / "kidwatch-mdm.db"),
        ca=ca,
        policy=policy,
        public_url=public_url,
        pusher=pusher,
    )


def loop_step(service, now: float) -> None:
    """Jeden krok petli: pushe odlozone i — gdy pora — uzgadnianie.

    Termin nastepnego obiegu laduje w `service.next_reconcile`. Po bledzie
    ponowienie za RETRY_SECONDS, nie w nastepnej sekundzie: trwaly blad
    dawal traceback co sekunde i zalewal log.
    """
    try:
        service.flush_kicks()
    except Exception:
        log.exception("blad wysylki pushy")
    if now < service.next_reconcile:
        return
    try:
        stats = service.reconcile()
    except Exception as exc:
        # Petla nie moze umrzec od jednego bledu — wtedy serwer HTTP dalej
        # odpowiada, a nikt nie uzgadnia stanu i nie wysyla pushy.
        log.exception("blad petli uzgadniania")
        service.last_reconcile_error = f"{type(exc).__name__}: {exc}"[:300]
        service.next_reconcile = now + RETRY_SECONDS
        return
    log.info("uzgadnianie: %s", stats)
    service.last_reconcile_error = None
    service.next_reconcile = now + RECONCILE_SECONDS


def cmd_run(args) -> int:
    from . import server

    token = _env("KIDWATCH_MDM_ADMIN_TOKEN")
    if not token or len(token) < 24:
        raise SystemExit("KIDWATCH_MDM_ADMIN_TOKEN wymagany (min. 24 znaki)")
    service = build_service()
    mdm = server.start(server.make_mdm_handler(service), int(_env("KIDWATCH_MDM_PORT", "8080")))
    admin = server.start(
        server.make_admin_handler(service, token), int(_env("KIDWATCH_MDM_ADMIN_PORT", "8081"))
    )
    log.info("kidwatch-mdm: MDM :%s, admin :%s", mdm.server_port, admin.server_port)

    stop = threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    heartbeat = _env("KIDWATCH_MDM_HEARTBEAT")
    while not stop.is_set():
        loop_step(service, time.monotonic())
        # Tetno = petla zyje (nie zawisla). Czy uzgadnianie sie UDAJE, mowi
        # last_reconcile_ok_at w /api/health — pilnuje tego czujka Kidwatch.
        # Restart poda nie naprawi zlej polityki ani bledu w kodzie, a co
        # kwadrans zrywalby polaczenia iPadow.
        if heartbeat:
            Path(heartbeat).touch()
        stop.wait(1.0)
    mdm.shutdown()
    admin.shutdown()
    return 0


def cmd_init_ca(args) -> int:
    from .pki import CA

    ca = CA.create(Path(args.dir), org=args.org)
    print(f"zapisano CA w {args.dir} (wazne do {ca.cert.not_valid_after_utc:%Y-%m-%d})")
    print("ZROB KOPIE ca.key — jego utrata odcina wszystkie zapisane iPady.")
    return 0


def cmd_enroll(args) -> int:
    from datetime import timedelta as td

    service = build_service()
    service.enrollment_ttl = td(hours=args.hours)
    out = service.create_enrollment(args.label)
    print(out["url"])
    print(f"wazny {args.hours} h, jednorazowy (wiaze sie z pierwszym iPadem, ktory sie zapisze)")
    return 0


def cmd_apns_new(args) -> int:
    out = Path(args.dir)
    apns_cert.new_request(out, email=args.email, country=args.country)
    print(f"zapisano klucze i wniosek w {out}")
    print(
        f"ZROB KOPIE {out / apns_cert.PUSH_KEY} — bez niego certyfikat od Apple jest bezuzyteczny."
    )
    print("Dalej: kidwatch-mdm apns send")
    return 0


def cmd_apns_send(args) -> int:
    apns_cert.send_request(Path(args.dir))
    print("mdmcert.download przyjal wniosek. Odpowiedz (*.plist.b64.p7) przyjdzie mailem.")
    print("Dalej: kidwatch-mdm apns decrypt <plik z maila>")
    return 0


def cmd_apns_decrypt(args) -> int:
    out = Path(args.dir)
    apns_cert.decrypt_response(out, Path(args.file))
    print(f"zapisano {out / apns_cert.PUSH_REQ}")
    print("Wgraj ten plik na https://identity.apple.com (Create a Certificate) i pobierz .pem.")
    print("ZAPISZ, jakim Apple ID sie logujesz — odnowienie za rok musi byc z tego samego.")
    print("Dalej: kidwatch-mdm apns check <pobrany .pem>")
    return 0


def cmd_apns_check(args) -> int:
    out = Path(args.dir)
    info = apns_cert.check_push_cert(
        Path(args.cert).read_bytes(), (out / apns_cert.PUSH_KEY).read_bytes()
    )
    print(f"temat:      {info.topic}")
    print(f"wazny do:   {info.not_after:%Y-%m-%d %H:%M} UTC")
    print(f"podmiot:    {info.subject}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kidwatch-mdm")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("run", help="serwer MDM (konfiguracja ze zmiennych srodowiska)")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("init-ca", help="nowe CA tozsamosci urzadzen (raz na zawsze)")
    sp.add_argument("--dir", required=True)
    sp.add_argument("--org", default="RenaCode")
    sp.set_defaults(func=cmd_init_ca)

    sp = sub.add_parser("enroll", help="link do profilu zapisu dla jednego iPada")
    sp.add_argument("label", help="etykieta z polityki, np. dziecko1")
    sp.add_argument("--hours", type=int, default=24)
    sp.set_defaults(func=cmd_enroll)

    apns = sub.add_parser("apns", help="certyfikat push APNs przez mdmcert.download")
    apns_sub = apns.add_subparsers(dest="apns_cmd", required=True)

    def with_dir(sp):
        sp.add_argument(
            "--dir", default=str(DEFAULT_APNS_DIR), help=f"domyslnie {DEFAULT_APNS_DIR}"
        )
        return sp

    sp = with_dir(apns_sub.add_parser("new", help="klucze, CSR i certyfikat wymiany"))
    sp.add_argument("--email", required=True, help="e-mail zarejestrowany na mdmcert.download")
    sp.add_argument("--country", default="PL")
    sp.set_defaults(func=cmd_apns_new)

    sp = with_dir(apns_sub.add_parser("send", help="wyslij wniosek do mdmcert.download"))
    sp.set_defaults(func=cmd_apns_send)

    sp = with_dir(apns_sub.add_parser("decrypt", help="odszyfruj odpowiedz z maila do push.req"))
    sp.add_argument("file")
    sp.set_defaults(func=cmd_apns_decrypt)

    sp = with_dir(apns_sub.add_parser("check", help="sprawdz certyfikat .pem od Apple"))
    sp.add_argument("cert")
    sp.set_defaults(func=cmd_apns_check)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("KIDWATCH_MDM_LOG", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except apns_cert.CertError as exc:
        print(f"BLAD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
