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
  KIDWATCH_MDM_ADE_TOKEN    token.json z `kidwatch-mdm ade import` (opcjonalny;
                            brak = bez Apple Business, zapis tylko z zaproszen)
  KIDWATCH_MDM_ADE_URL      adres API ADE (domyslnie mdmenrollment.apple.com)
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

from . import ade as ade_mod
from . import apns_cert

DEFAULT_APNS_DIR = Path.home() / ".kidwatch-mdm" / "apns"
#: Indeks schematu w repo (check-policy na Macu, bez zmiennych obrazu).
REPO_SCHEMA = Path(__file__).resolve().parents[2] / "tools" / "apple_schema_index.json"
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
    service = MDMService(
        signer=signer,
        store=Store(data / "kidwatch-mdm.db"),
        ca=ca,
        policy=policy,
        public_url=public_url,
        pusher=pusher,
    )
    tokens = ade_mod.tokens_from_file(_env("KIDWATCH_MDM_ADE_TOKEN"))
    if tokens is None:
        log.info("brak tokenu ADE — Apple Business wylaczone")
        ade_mod.report_unconfigured(service.store, policy)
    else:
        service.ade = ade_mod.AdeSync(
            store=service.store,
            policy=policy,
            public_url=public_url,
            client=ade_mod.AdeClient(
                tokens, base_url=_env("KIDWATCH_MDM_ADE_URL", ade_mod.APPLE_URL)
            ),
        )
        log.info("ADE: token wazny do %s", tokens.access_token_expiry)
    return service


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
    if stats.get("push_failed") and not stats.get("pushed"):
        # Obieg przeszedl, ale zaden iPad nie zostal obudzony: komendy stoja.
        service.last_reconcile_error = (
            f"wszystkie pushe APNs nieudane ({stats['push_failed']}): "
            f"{service.store.setting('last_push_error')}"
        )
        log.warning("uzgadnianie: %s", service.last_reconcile_error)
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
        if service.ade is not None:
            ade_mod.sync_step(service.ade, time.monotonic())
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


def cmd_check_policy(args) -> int:
    """Walidacja polityki na sucho — PRZED podmiana Sekretu i restartem."""
    from . import policy as policy_mod

    path = args.schema or _env("KIDWATCH_MDM_SCHEMA") or str(REPO_SCHEMA)
    if not Path(path).is_file():
        # Serwer w obrazie waliduje ze schematem — „OK" bez niego byloby falszywe.
        print(f"BLAD: brak indeksu schematu Apple ({path}); podaj --schema")
        return 2
    schema = policy_mod.load_schema(path)
    try:
        policy = policy_mod.load(args.file, schema)
    except (policy_mod.PolicyError, ValueError, OSError) as exc:
        print(f"BLAD — serwer NIE wystartuje z ta polityka:\n{exc}")
        return 1
    for label, errors in policy.rejected.items():
        print(f"BLAD — wpis {label} pojdzie do kwarantanny (bez wlasnych ograniczen):")
        for error in errors:
            print(f"  {error}")
    if policy.rejected:
        return 1
    kinds = ", ".join(f"{label}={d.kind}" for label, d in policy.devices.items())
    print(f"polityka poprawna: {kinds or 'brak urzadzen'}")
    return 0


def cmd_init_ca(args) -> int:
    from .pki import CA

    ca = CA.create(Path(args.dir), org=args.org)
    print(f"zapisano CA w {args.dir} (wazne do {ca.cert.not_valid_after_utc:%Y-%m-%d})")
    print("ZROB KOPIE ca.key — jego utrata odcina wszystkie zapisane iPady.")
    return 0


def cmd_enroll(args) -> int:
    from datetime import timedelta as td

    from .service import ServiceError

    service = build_service()
    service.enrollment_ttl = td(hours=args.hours)
    try:
        out = service.create_enrollment(args.label, args.dom)
    except ServiceError as exc:
        print(f"BLAD: {exc}", file=sys.stderr)
        return 1
    print(out["url"])
    print(f"wazny {args.hours} h, jednorazowy (wiaze sie z pierwszym iPadem, ktory sie zapisze)")
    return 0


def _store():
    from .store import Store

    return Store(Path(_env("KIDWATCH_MDM_DATA", "/data")) / "kidwatch-mdm.db")


def cmd_token_domu(args) -> int:
    """Token API domu (E3b). Wypisany RAZ — w bazie zostaje SHA-256."""
    if args.dom < 1:
        print("BLAD: numer domu >= 1", file=sys.stderr)
        return 1
    token_id, token = _store().create_home_token(args.dom, args.opis)
    print(token)
    print(
        f"token domu {args.dom} (id {token_id}) — pokazany tylko teraz. Wpisz go w Kidwatchu: "
        f"panel -> Dom {args.dom} -> Integracje -> MDM -> token.",
        file=sys.stderr,
    )
    return 0


def cmd_tokeny(args) -> int:
    rows = _store().home_tokens()
    for r in rows:
        stan = f"odwolany {r['revoked_at']}" if r["revoked_at"] else "aktywny"
        print(f"{r['id']:>4}  dom {r['dom_id']:<3} {stan:<36} {r['created_at']}  {r['opis'] or ''}")
    if not rows:
        print("brak tokenow domow (Kidwatch uzywa tokenu instancji)")
    return 0


def cmd_token_odwolaj(args) -> int:
    if not _store().revoke_home_token(args.id):
        print(f"BLAD: brak aktywnego tokenu o id {args.id}", file=sys.stderr)
        return 1
    print(f"token {args.id} odwolany")
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


def _ade_dir(args) -> Path:
    return Path(args.dir).expanduser()


def cmd_ade_keypair(args) -> int:
    cert = ade_mod.generate_keypair(_ade_dir(args))
    print(f"zapisano {cert} i klucz {ade_mod.KEY_FILE} w {_ade_dir(args)}")
    print("Wgraj ten .pem w Apple Business: Urzadzenia > Uslugi zarzadzania > Dodaj.")
    return 0


def cmd_ade_import(args) -> int:
    directory = _ade_dir(args)
    tokens = ade_mod.decrypt_server_token(
        Path(args.file).read_bytes(),
        directory / ade_mod.CERT_FILE,
        directory / ade_mod.KEY_FILE,
    )
    target = directory / ade_mod.TOKEN_FILE
    try:
        ade_mod.write_private(target, tokens.to_json(), force=args.force)
    except FileExistsError:
        print(f"BLAD: {target} juz istnieje — przy odnowieniu dodaj --force", file=sys.stderr)
        return 1
    # Tylko sciezka i data — sekretow NIE wypisujemy (trafilyby do historii
    # terminala i transkryptow).
    print(f"zapisano {target} (0600), token wazny do {tokens.access_token_expiry}")
    print("Sekret w klastrze (zastepuje poprzedni):")
    print(
        "  kubectl -n default create secret generic kidwatch-mdm-ade "
        f"--from-file=token.json={target} --dry-run=client -o yaml | kubectl apply -f -"
    )
    print("  kubectl -n default rollout restart deploy/kidwatch-mdm")
    return 0


def _ade_client(args) -> ade_mod.AdeClient:
    path = args.token or _env("KIDWATCH_MDM_ADE_TOKEN") or str(_ade_dir(args) / ade_mod.TOKEN_FILE)
    tokens = ade_mod.tokens_from_file(path)
    if tokens is None:
        raise SystemExit(f"brak tokenu ADE: {path} (najpierw `kidwatch-mdm ade import`)")
    return ade_mod.AdeClient(tokens, base_url=_env("KIDWATCH_MDM_ADE_URL", ade_mod.APPLE_URL))


def _ade_policy(args):
    from . import policy as policy_mod

    path = args.policy or _env("KIDWATCH_MDM_POLICY")
    return policy_mod.load(path) if path else policy_mod.Policy()


def cmd_ade_devices(args) -> int:
    client = _ade_client(args)
    policy = _ade_policy(args)
    account = client.account() or {}
    print(f"organizacja: {account.get('org_name')}  serwer: {account.get('server_name')}")
    devices, _ = client.fetch_devices()
    if not devices:
        print("brak urzadzen przypisanych do tego serwera w Apple Business")
    for dev in devices:
        serial = str(dev.get("serial_number") or "")
        label = policy.label_for_serial(serial) or "-"
        print(
            f"{serial:<14} {label:<12} {dev.get('model') or '?':<24} "
            f"profil: {dev.get('profile_status') or '-'} {dev.get('profile_uuid') or ''}"
        )
    return 0


def cmd_ade_assign(args) -> int:
    policy = _ade_policy(args)
    dev = policy.devices.get(args.label)
    if dev is None or not dev.serial:
        print(f"BLAD: wpis {args.label} nie istnieje albo nie ma `serial`", file=sys.stderr)
        return 1
    public_url = args.url or _env("KIDWATCH_MDM_PUBLIC_URL")
    if not public_url or not public_url.startswith("https://"):
        raise SystemExit("podaj --url https://... (adres serwera MDM)")
    client = _ade_client(args)
    uuid = client.define_profile(ade_mod.build_profile(policy, public_url))
    result = client.assign_profile(uuid, [dev.serial])
    status = result.get(dev.serial, "?")
    print(f"{args.label}: profil {uuid} -> {status}")
    if status != "SUCCESS":
        return 1
    print("Uwaga: serwer przy nastepnej synchronizacji wyrowna profil do swojego.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="kidwatch-mdm")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("run", help="serwer MDM (konfiguracja ze zmiennych srodowiska)")
    sp.set_defaults(func=cmd_run)

    sp = sub.add_parser("check-policy", help="sprawdz polityke na sucho, przed restartem")
    sp.add_argument("file", help="plik polityki YAML")
    sp.add_argument("--schema", help="indeks schematu Apple (domyslnie $KIDWATCH_MDM_SCHEMA "
                    "albo tools/apple_schema_index.json z repo)")
    sp.set_defaults(func=cmd_check_policy)

    sp = sub.add_parser("init-ca", help="nowe CA tozsamosci urzadzen (raz na zawsze)")
    sp.add_argument("--dir", required=True)
    sp.add_argument("--org", default="RenaCode")
    sp.set_defaults(func=cmd_init_ca)

    sp = sub.add_parser("enroll", help="link do profilu zapisu dla jednego iPada")
    sp.add_argument("label", help="etykieta z polityki, np. dziecko1")
    sp.add_argument("--hours", type=int, default=24)
    sp.add_argument("--dom", type=int, default=1,
                    help="dom urzadzenia (domyslnie 1; inny dom: etykieta <dom>/<label>)")
    sp.set_defaults(func=cmd_enroll)

    sp = sub.add_parser("token-domu", help="nowy token API domu (wypisany raz)")
    sp.add_argument("dom", type=int, help="numer domu z Kidwatcha (`kidwatch domy`)")
    sp.add_argument("--opis", default=None)
    sp.set_defaults(func=cmd_token_domu)

    sp = sub.add_parser("tokeny", help="tokeny domow (bez wartosci)")
    sp.set_defaults(func=cmd_tokeny)

    sp = sub.add_parser("token-odwolaj", help="odwolaj token domu")
    sp.add_argument("id", type=int)
    sp.set_defaults(func=cmd_token_odwolaj)

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

    ade = sub.add_parser("ade", help="Apple Business: automatyczny zapis (ADE)")
    ade_sub = ade.add_subparsers(dest="ade_cmd", required=True)

    def ade_opts(sp, *, token: bool = False, policy: bool = False):
        sp.add_argument(
            "--dir",
            default=str(ade_mod.DEFAULT_DIR),
            help=f"klucz, certyfikat i token (domyslnie {ade_mod.DEFAULT_DIR})",
        )
        if token:
            sp.add_argument(
                "--token",
                help="token.json (domyslnie $KIDWATCH_MDM_ADE_TOKEN albo <dir>/token.json)",
            )
        if policy:
            sp.add_argument("--policy", help="plik polityki (domyslnie $KIDWATCH_MDM_POLICY)")
        return sp

    sp = ade_opts(ade_sub.add_parser("keypair", help="klucz i certyfikat dla Apple Business"))
    sp.set_defaults(func=cmd_ade_keypair)

    sp = ade_opts(ade_sub.add_parser("import", help="odszyfruj token .p7m z Apple Business"))
    sp.add_argument("file", help="pobrany token (*.p7m)")
    sp.add_argument("--force", action="store_true", help="nadpisz istniejacy token.json")
    sp.set_defaults(func=cmd_ade_import)

    sp = ade_opts(
        ade_sub.add_parser("devices", help="urzadzenia przypisane do serwera"),
        token=True,
        policy=True,
    )
    sp.set_defaults(func=cmd_ade_devices)

    sp = ade_opts(
        ade_sub.add_parser("assign", help="przypisz profil ADE iPadowi z polityki"),
        token=True,
        policy=True,
    )
    sp.add_argument("label", help="etykieta z polityki (wpis z polem serial)")
    sp.add_argument("--url", help="adres serwera (domyslnie $KIDWATCH_MDM_PUBLIC_URL)")
    sp.set_defaults(func=cmd_ade_assign)
    return p


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(
        level=os.environ.get("KIDWATCH_MDM_LOG", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (apns_cert.CertError, ade_mod.AdeError) as exc:
        print(f"BLAD: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
