"""Logika protokolu MDM — bez HTTP, zeby testowac ja wprost.

Przeplyw jednego iPada:

  GET  /mdm/enroll/<token>   profil zapisu z nowa tozsamoscia
  PUT  /mdm/checkin  Authenticate   wiaze token z UDID (raz na zawsze)
  PUT  /mdm/checkin  TokenUpdate    token push + PushMagic -> zapis zakonczony
  ...  APNs push  ->  PUT /mdm/connect Idle -> odpowiadamy najstarsza komenda
  PUT  /mdm/connect  Acknowledged/Error/NotNow + wynik -> nastepna komenda
  PUT  /mdm/checkin  DeclarativeManagement (tokens / declaration-items / ...)
  PUT  /mdm/checkin  CheckOut       profil zdjety -> alarm

Kazda wiadomosc iPada musi miec poprawny Mdm-Signature (pki.py), a jej
certyfikat musi byc TYM, ktory urzadzenie przedstawilo przy Authenticate.
"""

from __future__ import annotations

import base64
import binascii
import json
import logging
import plistlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from . import profiles
from .apns import NoPusher, Pusher
from .pki import CA, SignatureError, fingerprint, verify_mdm_signature
from .policy import Policy
from .signing import ProfileSigner
from .store import Store, from_iso, iso, now_utc

log = logging.getLogger(__name__)

PLIST = "application/xml"
JSON = "application/json"
MOBILECONFIG = "application/x-apple-aspen-config"

#: Zapytania DeviceInformation (nazwy z mdm/commands/information.device.yaml).
DEVICE_QUERIES = [
    "DeviceName",
    "OSVersion",
    "BuildVersion",
    "SupplementalBuildVersion",
    "ModelName",
    "Model",
    "ProductName",
    "SerialNumber",
    "UDID",
    "IsSupervised",
    "BatteryLevel",
    "DeviceCapacity",
    "AvailableDeviceCapacity",
    "WiFiMAC",
    "IsActivationLockEnabled",
    "IsDeviceLocatorServiceEnabled",
    "IsCloudBackupEnabled",
    "LastCloudBackupDate",
    "IsMDMLostModeEnabled",
]

REFRESH_COMMANDS = ("DeviceInformation", "SecurityInfo", "ProfileList", "InstalledApplicationList")

#: Nie budzimy tego samego iPada czesciej — APNs i tak scala pushe, a petla
#: uzgadniania nie powinna zasypywac go co obieg.
MIN_PUSH_INTERVAL = timedelta(seconds=30)

#: Ile czekac miedzy pushami uzgadniania, gdy kolejka stoi: (czas od ostatniego
#: postepu, odstep). iPad z zablokowanym ekranem odpowiada NotNow i — wg Apple —
#: sam polaczy sie ponownie, gdy bedzie mogl wykonac komende. Push w kazdym
#: obiegu nic wtedy nie daje poza bateria i ryzykiem dlawienia przez APNs
#: (2026-10-09: iPad budzony co 5 min przez 5 h). Rzadki push zostaje jako
#: siatka bezpieczenstwa na wypadek zgubionego polaczenia.
PUSH_BACKOFF = (
    (timedelta(minutes=30), timedelta(0)),
    (timedelta(hours=2), timedelta(minutes=15)),
    (timedelta(hours=12), timedelta(hours=1)),
)
MAX_PUSH_GAP = timedelta(hours=4)


def push_gap(stalled: timedelta) -> timedelta:
    """Odstep miedzy pushami po `stalled` bez postepu kolejki."""
    for limit, gap in PUSH_BACKOFF:
        if stalled < limit:
            return gap
    return MAX_PUSH_GAP


@dataclass
class Response:
    status: int
    body: bytes = b""
    content_type: str = PLIST
    headers: dict[str, str] = field(default_factory=dict)


EMPTY_OK = Response(200, plistlib.dumps({}))


class ServiceError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status


class MDMService:
    def __init__(
        self,
        *,
        store: Store,
        ca: CA,
        policy: Policy,
        public_url: str,
        pusher: Pusher | None = None,
        enrollment_ttl: timedelta = timedelta(hours=24),
        signer: ProfileSigner | None = None,
    ) -> None:
        self.store = store
        self.ca = ca
        self.policy = policy
        self.public_url = public_url.rstrip("/")
        self.pusher: Pusher = pusher or NoPusher()
        self.enrollment_ttl = enrollment_ttl
        self.signer = signer
        #: Pushe odkladane poza watek odpowiedzi: iPad, ktoremu odpowiadamy na
        #: TokenUpdate, nie powinien dostac pusha w trakcie tej samej wymiany.
        self._kick_lock = threading.Lock()
        self._kicks: set[str] = set()
        #: Stan petli uzgadniania (ustawia __main__.loop_step) do /api/health.
        self.started_at = now_utc()
        self.next_reconcile = 0.0
        self.last_reconcile_error: str | None = None

    # ================================================================ zapis
    def create_enrollment(self, label: str) -> dict[str, str]:
        if label not in self.policy.devices:
            log.warning(
                "zaproszenie dla etykiety %r spoza polityki — dostanie wartosci domyslne", label
            )
        token = self.store.create_enrollment(label, self.enrollment_ttl)
        self.store.event("enrollment_created", detail={"label": label})
        return {"token": token, "url": f"{self.public_url}/mdm/enroll/{token}"}

    def enrollment_profile(self, token: str, now: datetime | None = None) -> Response:
        now = now or now_utc()
        row = self.store.enrollment(token)
        if row is None:
            raise ServiceError(404, "nieznane zaproszenie")
        if row["udid"]:
            raise ServiceError(410, "zaproszenie juz wykorzystane")
        if from_iso(row["expires_at"]) < now:
            raise ServiceError(410, "zaproszenie wygaslo")
        if not self.pusher.topic:
            # Topic nie moze sie zmienic po zapisie, a bez prawdziwego tematu
            # iPad nigdy nie dostanie pusha. Zapis przed certyfikatem = zapis
            # do powtorzenia, wiec odmawiamy od razu i glosno.
            raise ServiceError(503, "brak certyfikatu APNs — zapis niemozliwy")
        dev = self.policy.device(row["label"])
        prof = profiles.enrollment_profile(
            ca=self.ca,
            public_url=self.public_url,
            topic=self.pusher.topic,
            org=self.policy.org,
            label=row["label"],
            device_name=dev.name,
        )
        self.store.record_identity(token, prof.cert_fingerprint, now)
        data = prof.data
        if self.signer is not None:
            try:
                data = self.signer.sign(prof.data)
            except (OSError, ValueError) as exc:
                # Podpis zmienia tylko etykiete w iOS („Zweryfikowany"); zapis
                # dziala i bez niego. Brak podpisu nie moze zablokowac zapisu
                # iPada, ale ma byc widoczny w logu i w dzienniku zdarzen.
                log.error("profil zapisu NIEPODPISANY: %s", exc)
                self.store.event("profile_unsigned", detail=str(exc))
        return Response(
            200,
            data,
            MOBILECONFIG,
            {"Content-Disposition": f'attachment; filename="kidwatch-{row["label"]}.mobileconfig"'},
        )

    # ======================================================= uwierzytelnienie
    def _verified(self, body: bytes, signature: str | None) -> tuple[dict, str]:
        if not signature:
            raise ServiceError(401, "brak naglowka Mdm-Signature")
        try:
            cert = verify_mdm_signature(signature, body, self.ca)
        except SignatureError as exc:
            self.store.event("signature_rejected", detail=str(exc))
            raise ServiceError(401, str(exc)) from exc
        try:
            message = plistlib.loads(body)
        except (plistlib.InvalidFileException, ValueError, binascii.Error) as exc:
            raise ServiceError(400, f"cialo nie jest plistem: {exc}") from exc
        if not isinstance(message, dict):
            raise ServiceError(400, "cialo nie jest slownikiem")
        return message, fingerprint(cert)

    def _device_for(self, message: dict, fp: str):
        udid = message.get("UDID")
        if not udid:
            raise ServiceError(400, "brak UDID (zapis uzytkownika nieobslugiwany)")
        device = self.store.device(udid)
        if device is None:
            raise ServiceError(401, "nieznane urzadzenie — najpierw Authenticate")
        if device["cert_fp"] != fp:
            # Wiadomosc podpisana poprawnym certyfikatem z NASZEGO CA, ale nie
            # tym, ktory ten UDID przedstawil przy zapisie: inny iPad podszywa
            # sie pod ten albo to stary profil po ponownym zapisie.
            self.store.event("cert_mismatch", udid, {"fingerprint": fp})
            raise ServiceError(401, "certyfikat nie nalezy do tego urzadzenia")
        return device

    # ============================================================== check-in
    def checkin(self, body: bytes, signature: str | None) -> Response:
        message, fp = self._verified(body, signature)
        kind = message.get("MessageType")
        if kind == "Authenticate":
            return self._authenticate(message, fp)
        device = self._device_for(message, fp)
        udid = device["udid"]
        log.info("checkin %s: %s %s", device["label"], kind, message.get("Endpoint") or "")
        self.store.update_device(udid, last_seen_at=iso(now_utc()))
        if kind == "TokenUpdate":
            return self._token_update(device, message)
        if kind == "CheckOut":
            self.store.update_device(udid, checked_out_at=iso(now_utc()))
            cancelled = self.store.cancel_pending(udid)
            self.store.event("checkout", udid, {"cancelled_commands": cancelled})
            log.warning("CheckOut %s (%s): profil MDM zdjety", device["label"], udid)
            return EMPTY_OK
        if kind == "DeclarativeManagement":
            return self._declarative(device, message)
        # UserAuthenticate i pokrewne: 410 to umowiony sygnal „nie obslugujemy".
        return Response(410, b"")

    def _authenticate(self, message: dict, fp: str) -> Response:
        udid = message.get("UDID")
        if not udid:
            raise ServiceError(400, "Authenticate bez UDID (zapis uzytkownika nieobslugiwany)")
        ident = self.store.identity(fp)
        if ident is None:
            self.store.event("unknown_identity", udid, {"fingerprint": fp})
            raise ServiceError(401, "certyfikat nie pochodzi z zadnego zaproszenia")
        if ident["bound_udid"] and ident["bound_udid"] != udid:
            self.store.event("enrollment_reuse", udid, {"bound_to": ident["bound_udid"]})
            raise ServiceError(403, "zaproszenie przypisane do innego urzadzenia")
        if not ident["bound_udid"] and from_iso(ident["expires_at"]) < now_utc():
            raise ServiceError(403, "zaproszenie wygaslo")
        if self.pusher.topic and message.get("Topic") != self.pusher.topic:
            raise ServiceError(400, "temat push nie zgadza sie z certyfikatem serwera")

        now = iso(now_utc())
        fields = {
            "label": ident["label"],
            "enrollment_token": ident["token"],
            "cert_fp": fp,
            "serial": message.get("SerialNumber"),
            "product": message.get("ProductName"),
            "os_version": message.get("OSVersion"),
            "build_version": message.get("BuildVersion"),
            "topic": message.get("Topic"),
        }
        with self.store.tx() as c:
            exists = c.execute("SELECT 1 FROM devices WHERE udid = ?", (udid,)).fetchone()
            if exists:
                # Ponowny zapis tego samego iPada: nowa tozsamosc, czysta kolejka
                # i swiezy stan DDM. Historia komend zostaje.
                c.execute(
                    "UPDATE devices SET label=:label, enrollment_token=:enrollment_token, "
                    "cert_fp=:cert_fp, serial=:serial, product=:product, "
                    "os_version=:os_version, build_version=:build_version, topic=:topic, "
                    "checked_out_at=NULL, push_token=NULL, push_magic=NULL, ddm_token=NULL, "
                    "enrolled_at=:now, last_seen_at=:now WHERE udid=:udid",
                    {**fields, "now": now, "udid": udid},
                )
                c.execute(
                    "UPDATE commands SET status='cancelled', done_at=? "
                    "WHERE udid=? AND status IN ('queued','sent','not_now')",
                    (now, udid),
                )
                c.execute("DELETE FROM profile_state WHERE udid = ?", (udid,))
            else:
                c.execute(
                    "INSERT INTO devices (udid, label, enrollment_token, cert_fp, serial, "
                    "product, os_version, build_version, topic, enrolled_at, last_seen_at) "
                    "VALUES (:udid, :label, :enrollment_token, :cert_fp, :serial, :product, "
                    ":os_version, :build_version, :topic, :now, :now)",
                    {**fields, "now": now, "udid": udid},
                )
            c.execute(
                "UPDATE enrollments SET udid = ?, bound_at = ? WHERE token = ? AND udid IS NULL",
                (udid, now, ident["token"]),
            )
        self.store.event(
            "authenticate", udid, {"label": ident["label"], "serial": fields["serial"]}
        )
        return EMPTY_OK

    def _token_update(self, device, message: dict) -> Response:
        udid = device["udid"]
        token = message.get("Token")
        magic = message.get("PushMagic")
        if not isinstance(token, bytes) or not magic:
            raise ServiceError(400, "TokenUpdate bez Token/PushMagic")
        first = device["push_token"] is None
        fields: dict[str, Any] = {"push_token": token, "push_magic": magic, "push_error": None}
        if isinstance(message.get("UnlockToken"), bytes):
            fields["unlock_token"] = message["UnlockToken"]
        self.store.update_device(udid, **fields)
        if first:
            # Pierwszy TokenUpdate po Authenticate = zapis zakonczony.
            self.store.event("enrolled", udid, {"label": device["label"]})
            for request_type in REFRESH_COMMANDS:
                self._enqueue_refresh(udid, request_type)
            self.kick(udid)
        return EMPTY_OK

    # ================================================================ connect
    def connect(self, body: bytes, signature: str | None) -> Response:
        message, fp = self._verified(body, signature)
        device = self._device_for(message, fp)
        udid = device["udid"]
        self.store.update_device(udid, last_seen_at=iso(now_utc()))
        status = message.get("Status")
        cmd_uuid = message.get("CommandUUID")
        row = None

        if status == "Idle":
            self.store.requeue_not_now(udid)
        elif cmd_uuid:
            row = self.store.command(cmd_uuid)
            if row is None or row["udid"] != udid:
                log.warning("odpowiedz na nieznana komende %s od %s", cmd_uuid, udid)
            elif status == "Acknowledged":
                self.store.finish_command(cmd_uuid, "acknowledged", message)
                self._on_result(device, row["request_type"], cmd_uuid, message)
            elif status in ("Error", "CommandFormatError"):
                chain = message.get("ErrorChain") or []
                error = json.dumps(chain, ensure_ascii=False, default=str)
                final = "error" if status == "Error" else "format_error"
                self.store.finish_command(cmd_uuid, final, message, error)
                self.store.event(
                    "command_error",
                    udid,
                    {"request_type": row["request_type"], "status": status, "chain": chain},
                )
                if row["request_type"] == "InstallProfile":
                    self.store.mark_profile_failed(cmd_uuid)
            elif status == "NotNow":
                self.store.finish_command(cmd_uuid, "not_now", message)
            else:
                raise ServiceError(400, f"nieznany Status {status!r}")

        nxt = self.store.next_command(udid)
        # Jedna linia na wymiane: bez tego w logu widac tylko pushe, a nie to,
        # czy iPad w ogole sie laczy i co odpowiada. Etykieta, bez UDID i tresci.
        log.info(
            "connect %s: %s%s -> %s",
            device["label"],
            status,
            f" ({row['request_type']})" if cmd_uuid and status != "Idle" and row else "",
            nxt.command["Command"]["RequestType"] if nxt else "koniec kolejki",
        )
        if nxt is None:
            return Response(200, b"")
        return Response(200, plistlib.dumps(nxt.command))

    def _on_result(self, device, request_type: str, cmd_uuid: str, msg: dict) -> None:
        udid = device["udid"]
        now = iso(now_utc())
        if request_type == "DeviceInformation":
            info = msg.get("QueryResponses") or {}
            fields: dict[str, Any] = {"info_json": _json(info), "info_at": now}
            for col, key in (
                ("device_name", "DeviceName"),
                ("os_version", "OSVersion"),
                ("build_version", "BuildVersion"),
                ("serial", "SerialNumber"),
                ("product", "ProductName"),
            ):
                if info.get(key):
                    fields[col] = info[key]
            if "IsSupervised" in info:
                supervised = 1 if info["IsSupervised"] else 0
                fields["supervised"] = supervised
                if device["supervised"] is not None and device["supervised"] != supervised:
                    self.store.event("supervision_changed", udid, {"supervised": bool(supervised)})
            self.store.update_device(udid, **fields)
        elif request_type == "SecurityInfo":
            self.store.update_device(udid, security_json=_json(msg.get("SecurityInfo") or {}))
        elif request_type == "ProfileList":
            plist = msg.get("ProfileList") or []
            self.store.update_device(udid, profiles_json=_json(plist))
            present = {p.get("PayloadIdentifier") for p in plist}
            for ident, state in self.store.profile_states(udid).items():
                if state["installed_at"] and ident not in present:
                    # Profil zainstalowany przez nas zniknal. Bez nadzoru
                    # mozliwe tylko przez zdjecie calego MDM, wiec to sygnal
                    # alarmowy. Zapominamy stan — uzgadnianie wgra go ponownie.
                    self.store.event("profile_missing", udid, {"identifier": ident})
                    self.store.forget_profile(udid, ident)
        elif request_type == "InstalledApplicationList":
            apps = msg.get("InstalledApplicationList") or []
            slim = sorted(
                (
                    {
                        "id": a.get("Identifier"),
                        "name": a.get("Name"),
                        "version": a.get("ShortVersion") or a.get("Version"),
                    }
                    for a in apps
                    if a.get("Identifier")
                ),
                key=lambda a: a["id"],
            )
            if device["apps_json"]:
                before = {a["id"]: a for a in json.loads(device["apps_json"])}
                after = {a["id"]: a for a in slim}
                added = [after[i] for i in after.keys() - before.keys()]
                removed = [before[i] for i in before.keys() - after.keys()]
                if added:
                    self.store.event("apps_installed", udid, {"apps": added})
                if removed:
                    self.store.event("apps_removed", udid, {"apps": removed})
            self.store.update_device(udid, apps_json=_json(slim), apps_at=now)
        elif request_type == "InstallProfile":
            self.store.mark_profile_installed(cmd_uuid)

    # ========================================================== DDM (check-in)
    def os_update(self) -> dict | None:
        override = self.store.setting("os_update")
        if override is not None:
            return override or None  # {} = jawnie wylaczone z API
        return self.policy.os_update.model_dump() if self.policy.os_update else None

    def declarations_for(self, device) -> list[dict]:
        return profiles.declarations(
            self.policy,
            device["label"],
            supervised=bool(device["supervised"]),
            os_update=self.os_update(),
        )

    def _declarative(self, device, message: dict) -> Response:
        endpoint = message.get("Endpoint") or ""
        decls = self.declarations_for(device)
        udid = device["udid"]
        if endpoint == "tokens":
            body = {
                "SyncTokens": {
                    "DeclarationsToken": profiles.declarations_token(decls),
                    "Timestamp": now_utc().strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
            }
            return Response(200, json.dumps(body).encode(), JSON)
        if endpoint == "declaration-items":
            items = profiles.declaration_items(decls)
            self.store.update_device(udid, ddm_token=items["DeclarationsToken"])
            return Response(200, json.dumps(items).encode(), JSON)
        if endpoint.startswith("declaration/"):
            ident = endpoint.rsplit("/", 1)[-1]
            for d in decls:
                if d["Identifier"] == ident:
                    return Response(200, json.dumps(d, ensure_ascii=False).encode(), JSON)
            raise ServiceError(404, f"nieznana deklaracja {ident}")
        if endpoint == "status":
            report = _decode_data(message.get("Data"))
            self._store_status(device, report)
            return Response(200, b"")
        raise ServiceError(400, f"nieznany Endpoint DDM {endpoint!r}")

    def _store_status(self, device, report: dict) -> None:
        items = report.get("StatusItems") or {}
        current = {} if report.get("FullReport") else json.loads(device["ddm_status_json"] or "{}")
        merged = _deep_merge(current, items)
        self.store.update_device(
            device["udid"], ddm_status_json=_json(merged), ddm_status_at=iso(now_utc())
        )
        if report.get("Errors"):
            self.store.event("ddm_status_errors", device["udid"], report["Errors"])
        # failure-reason przychodzi ZAWSZE, takze bez awarii: {"count": 0}
        # (schemat: count = 0, gdy nie bylo porazek). Alarm tylko przy count > 0,
        # inaczej kazdy raport statusu bylby „nieudana aktualizacja".
        failure = (items.get("softwareupdate") or {}).get("failure-reason")
        if isinstance(failure, dict) and (failure.get("count") or 0) > 0:
            self.store.event("os_update_failed", device["udid"], failure)

    # =========================================================== uzgadnianie
    def _enqueue_refresh(self, udid: str, request_type: str) -> None:
        if self.store.pending(udid, request_type):
            return
        body: dict[str, Any] = {}
        if request_type == "DeviceInformation":
            body = {"Queries": DEVICE_QUERIES}
        elif request_type == "ProfileList":
            body = {"ManagedOnly": False}
        self.store.enqueue(udid, request_type, body, origin="refresh")

    def refresh(self, udid: str) -> None:
        for request_type in REFRESH_COMMANDS:
            self._enqueue_refresh(udid, request_type)
        self.kick(udid)

    def reconcile(self, now: datetime | None = None) -> dict[str, int]:
        """Jeden obieg: odswiezenie stanu, profile i DDM zgodne z polityka, pushe."""
        now = now or now_utc()
        stats = {"devices": 0, "enqueued": 0, "pushed": 0}
        refresh_after = timedelta(hours=self.policy.refresh_hours)
        for device in self.store.devices():
            if device["checked_out_at"] or device["push_token"] is None:
                continue
            stats["devices"] += 1
            udid = device["udid"]
            before = len(
                self.store.query(
                    "SELECT 1 FROM commands WHERE udid=? AND status IN ('queued','sent','not_now')",
                    (udid,),
                )
            )
            info_at = from_iso(device["info_at"])
            if info_at is None or now - info_at >= refresh_after:
                for request_type in REFRESH_COMMANDS:
                    self._enqueue_refresh(udid, request_type)

            profile, digest = profiles.restrictions_profile(self.policy, device["label"])
            state = self.store.profile_states(udid).get(profiles.RESTRICTIONS_ID)
            retry_after = from_iso(state["retry_after"]) if state else None
            if (
                state is None
                or state["content_hash"] != digest
                or (
                    state["installed_at"] is None and retry_after is not None and now >= retry_after
                )
            ) and not self.store.pending(udid, "InstallProfile"):
                cmd = self.store.enqueue(
                    udid,
                    "InstallProfile",
                    {"Payload": plistlib.dumps(profile, fmt=plistlib.FMT_XML, sort_keys=True)},
                    origin="policy",
                )
                self.store.set_profile_state(udid, profiles.RESTRICTIONS_ID, digest, cmd)

            token = profiles.declarations_token(self.declarations_for(device))
            if device["ddm_token"] != token and not self.store.pending(
                udid, "DeclarativeManagement"
            ):
                self.store.enqueue(udid, "DeclarativeManagement", {}, origin="policy")

            after = len(
                self.store.query(
                    "SELECT 1 FROM commands WHERE udid=? AND status IN ('queued','sent','not_now')",
                    (udid,),
                )
            )
            stats["enqueued"] += after - before
            if after and self._push_due(device, now) and self.push(udid, now=now):
                stats["pushed"] += 1
        # Trwale w bazie: liveness restartuje pod, a czujka Kidwatch ma widziec,
        # ze uzgadnianie nie przeszlo od godziny, takze po restarcie.
        self.store.set_setting("last_reconcile_ok_at", iso(now))
        return stats

    def _push_due(self, device, now: datetime) -> bool:
        last = from_iso(device["last_push_at"])
        if last is None:
            return True
        progress = self.store.last_progress_at(device["udid"])
        gap = push_gap(now - progress) if progress else timedelta(0)
        return now - last >= gap

    # ================================================================== push
    def kick(self, udid: str) -> None:
        """Zaplanuj push poza biezaca odpowiedzia (wykonuje go flush_kicks)."""
        with self._kick_lock:
            self._kicks.add(udid)

    def flush_kicks(self) -> int:
        with self._kick_lock:
            pending, self._kicks = self._kicks, set()
        return sum(1 for udid in pending if self.push(udid, force=True))

    def push(self, udid: str, *, now: datetime | None = None, force: bool = False) -> bool:
        now = now or now_utc()
        device = self.store.device(udid)
        if device is None or device["checked_out_at"] or not device["push_token"]:
            return False
        last = from_iso(device["last_push_at"])
        if not force and last is not None and now - last < MIN_PUSH_INTERVAL:
            return False
        result = self.pusher.push(device["push_token"], device["push_magic"])
        fields: dict[str, Any] = {"last_push_at": iso(now)}
        if result.ok:
            fields["push_error"] = None
        else:
            fields.update(push_error=f"{result.status} {result.reason}", push_error_at=iso(now))
            if result.token_dead:
                self.store.event("push_token_dead", udid, {"reason": result.reason})
        self.store.update_device(udid, **fields)
        return result.ok

    # =========================================================== komendy z API
    def enqueue_api(self, udid: str, request_type: str, body: dict) -> str:
        if self.store.device(udid) is None:
            raise ServiceError(404, "nieznane urzadzenie")
        cmd = self.store.enqueue(udid, request_type, body, origin="api")
        self.kick(udid)
        return cmd


def _json(obj: Any) -> str:
    return json.dumps(obj, ensure_ascii=False, default=_default)


def _default(obj: Any) -> Any:
    if isinstance(obj, bytes):
        return base64.b64encode(obj).decode("ascii")
    if isinstance(obj, datetime):
        return obj.isoformat()
    return str(obj)


def _decode_data(data: Any) -> dict:
    """Data w DeclarativeManagement: plist daje bajty JSON-a (typ <data>)."""
    if data is None:
        return {}
    raw = data if isinstance(data, bytes) else base64.b64decode(data)
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ServiceError(400, f"raport statusu nie jest JSON-em: {exc}") from exc
    return parsed if isinstance(parsed, dict) else {}


def _deep_merge(base: dict, extra: dict) -> dict:
    out = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out
