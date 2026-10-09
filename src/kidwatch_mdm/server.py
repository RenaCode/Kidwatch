"""Serwery HTTP kidwatch-mdm: publiczny dla iPadow i wewnetrzny dla Kidwatch.

Dwa porty celowo. Ingress wystawia na swiat WYLACZNIE port MDM (/mdm/*),
a port administracyjny jest osiagalny tylko w klastrze (NetworkPolicy:
tylko pod Kidwatch) i wymaga tokenu. Blad w routingu ingressu nie wystawi
wiec API sterujacego iPadami na zewnatrz.

Bez frameworka, tak jak panel Kidwatch: kilka endpointow nie uzasadnia
dodatkowej zaleznosci w obrazie.
"""

from __future__ import annotations

import hmac
import json
import logging
import re
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from pydantic import ValidationError

from . import profiles
from .policy import OsUpdate
from .service import JSON, MDMService, Response, ServiceError

log = logging.getLogger(__name__)

#: Odpowiedz InstalledApplicationList potrafi miec setki KB; 10 MB to zapas.
MAX_MDM_BODY = 10 * 1024 * 1024
MAX_API_BODY = 64 * 1024

#: Komendy, ktore Kidwatch moze zlecic wprost. Reszta (ograniczenia, DDM)
#: wynika z polityki i idzie przez uzgadnianie — nie przez reczne komendy.
API_COMMANDS: dict[str, Callable[[dict], dict]] = {
    "DeviceLock": lambda b: {k: str(b[k]) for k in ("Message", "PhoneNumber") if b.get(k)},
    "RestartDevice": lambda b: {},
}

UDID_RE = r"(?P<udid>[0-9A-Fa-f-]{8,64})"


def _send(handler: BaseHTTPRequestHandler, resp: Response) -> None:
    handler.send_response(resp.status)
    handler.send_header("Content-Type", resp.content_type)
    handler.send_header("Content-Length", str(len(resp.body)))
    handler.send_header("Cache-Control", "no-store")
    for k, v in resp.headers.items():
        handler.send_header(k, v)
    handler.end_headers()
    if handler.command != "HEAD":
        handler.wfile.write(resp.body)


def _json_response(status: int, obj: Any) -> Response:
    return Response(status, json.dumps(obj, ensure_ascii=False, default=str).encode(), JSON)


def _read_body(handler: BaseHTTPRequestHandler, limit: int) -> bytes:
    try:
        length = int(handler.headers.get("Content-Length") or 0)
    except ValueError as exc:
        raise ServiceError(400, "zly Content-Length") from exc
    if length > limit:
        raise ServiceError(413, "za duze cialo")
    return handler.rfile.read(length) if length else b""


# ================================================================ port MDM
def make_mdm_handler(service: MDMService):
    class MDMHandler(BaseHTTPRequestHandler):
        server_version = "kidwatch-mdm"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:  # noqa: D401 - nadpisanie stdlib
            log.debug("mdm %s " + fmt, self.client_address[0], *args)

        def _handle(self) -> None:
            path = self.path.split("?", 1)[0]
            try:
                if self.command == "PUT" and path == "/mdm/checkin":
                    body = _read_body(self, MAX_MDM_BODY)
                    resp = service.checkin(body, self.headers.get("Mdm-Signature"))
                elif self.command == "PUT" and path == "/mdm/connect":
                    body = _read_body(self, MAX_MDM_BODY)
                    resp = service.connect(body, self.headers.get("Mdm-Signature"))
                elif self.command in ("GET", "HEAD") and (
                    m := re.fullmatch(r"/mdm/enroll/(?P<token>[A-Za-z0-9_-]{16,64})", path)
                ):
                    resp = service.enrollment_profile(m["token"])
                elif self.command in ("GET", "HEAD") and path == "/healthz":
                    resp = Response(200, b"ok", "text/plain")
                else:
                    resp = Response(404, b"", "text/plain")
            except ServiceError as exc:
                log.warning("mdm %s %s -> %s: %s", self.command, path, exc.status, exc)
                resp = Response(exc.status, str(exc).encode(), "text/plain; charset=utf-8")
            except Exception:
                log.exception("mdm %s %s: blad serwera", self.command, path)
                resp = Response(500, b"", "text/plain")
            _send(self, resp)

        do_GET = do_HEAD = do_PUT = do_POST = _handle

    return MDMHandler


# ============================================================== port admina
def make_admin_handler(service: MDMService, token: str):
    store = service.store

    def device_summary(row) -> dict:
        return {
            "udid": row["udid"],
            "label": row["label"],
            "name": service.policy.device(row["label"]).name,
            "device_name": row["device_name"],
            "serial": row["serial"],
            "product": row["product"],
            "os_version": row["os_version"],
            "build_version": row["build_version"],
            "supervised": None if row["supervised"] is None else bool(row["supervised"]),
            "enrolled_at": row["enrolled_at"],
            "last_seen_at": row["last_seen_at"],
            "checked_out_at": row["checked_out_at"],
            "info_at": row["info_at"],
            "apps_at": row["apps_at"],
            "push_error": row["push_error"],
            "push_error_at": row["push_error_at"],
            "last_push_at": row["last_push_at"],
            # iPad pobral aktualny zestaw deklaracji (DDM) — False po zmianie
            # polityki, dopoki iPad nie polaczy sie ponownie.
            "ddm_synced": row["ddm_token"]
            == profiles.declarations_token(service.declarations_for(row)),
        }

    def device_detail(row) -> dict:
        out = device_summary(row)
        for col in ("info_json", "security_json", "profiles_json", "apps_json", "ddm_status_json"):
            out[col.removesuffix("_json")] = json.loads(row[col]) if row[col] else None
        out["ddm_status_at"] = row["ddm_status_at"]
        out["profiles_installed"] = [
            {
                "identifier": s["identifier"],
                "installed_at": s["installed_at"],
                "failures": s["failures"],
                "retry_after": s["retry_after"],
            }
            for s in store.profile_states(row["udid"]).values()
        ]
        out["commands"] = [dict(r) for r in store.commands_for(row["udid"])]
        return out

    def health() -> dict:
        expires = service.pusher.expires_at()
        days = None if expires is None else (expires - datetime.now(UTC)).days
        return {
            "ok": True,
            "apns": {
                "configured": service.pusher.topic is not None,
                "topic": service.pusher.topic,
                "expires_at": expires.isoformat() if expires else None,
                "days_left": days,
            },
            "devices": len(store.devices()),
            "time": datetime.now(UTC).isoformat(timespec="seconds"),
        }

    class AdminHandler(BaseHTTPRequestHandler):
        server_version = "kidwatch-mdm-admin"
        sys_version = ""

        def log_message(self, fmt: str, *args) -> None:
            log.debug("admin %s " + fmt, self.client_address[0], *args)

        def _authorized(self) -> bool:
            got = self.headers.get("Authorization") or ""
            expected = f"Bearer {token}"
            return hmac.compare_digest(got.encode(), expected.encode())

        def _payload(self) -> dict:
            raw = _read_body(self, MAX_API_BODY)
            if not raw:
                return {}
            try:
                data = json.loads(raw)
            except ValueError as exc:
                raise ServiceError(400, "cialo nie jest JSON-em") from exc
            if not isinstance(data, dict):
                raise ServiceError(400, "oczekiwano obiektu JSON")
            return data

        def _route(self, method: str, path: str, query: str) -> Response:
            if path == "/api/health" and method == "GET":
                return _json_response(200, health())
            if not self._authorized():
                return _json_response(401, {"error": "brak lub zly token"})

            if path == "/api/devices" and method == "GET":
                return _json_response(200, [device_summary(r) for r in store.devices()])
            if m := re.fullmatch(rf"/api/devices/{UDID_RE}", path):
                row = store.device(m["udid"])
                if row is None:
                    return _json_response(404, {"error": "nieznane urzadzenie"})
                if method == "GET":
                    return _json_response(200, device_detail(row))
            if (m := re.fullmatch(rf"/api/devices/{UDID_RE}/refresh", path)) and method == "POST":
                if store.device(m["udid"]) is None:
                    return _json_response(404, {"error": "nieznane urzadzenie"})
                service.refresh(m["udid"])
                return _json_response(202, {"queued": True})
            if (m := re.fullmatch(rf"/api/devices/{UDID_RE}/commands", path)) and method == "POST":
                data = self._payload()
                rtype = data.get("request_type")
                if rtype not in API_COMMANDS:
                    return _json_response(
                        400, {"error": f"dozwolone komendy: {', '.join(API_COMMANDS)}"}
                    )
                cmd = service.enqueue_api(m["udid"], rtype, API_COMMANDS[rtype](data))
                return _json_response(202, {"command_uuid": cmd})
            if path == "/api/enrollments" and method == "POST":
                label = str(self._payload().get("label") or "").strip()
                if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,31}", label):
                    return _json_response(400, {"error": "label: male litery, cyfry, - i _"})
                return _json_response(201, service.create_enrollment(label))
            if path == "/api/os-update":
                if method == "GET":
                    return _json_response(
                        200,
                        {"effective": service.os_update(), "override": store.setting("os_update")},
                    )
                if method == "PUT":
                    data = self._payload()
                    if data.get("clear"):
                        store.set_setting("os_update", None)  # wraca polityka z pliku
                    elif data.get("disabled"):
                        store.set_setting("os_update", {})
                    else:
                        try:
                            store.set_setting(
                                "os_update", OsUpdate.model_validate(data).model_dump()
                            )
                        except ValidationError as exc:
                            return _json_response(400, {"error": exc.errors(include_url=False)})
                    store.event("os_update_set", detail=service.os_update())
                    service.reconcile()
                    return _json_response(200, {"effective": service.os_update()})
            if path == "/api/events" and method == "GET":
                params = dict(p.split("=", 1) for p in query.split("&") if "=" in p)
                try:
                    since = int(params.get("since", 0))
                    last = int(params["last"]) if "last" in params else None
                except ValueError:
                    return _json_response(400, {"error": "since/last musza byc liczbami"})
                rows = store.last_events(min(last, 500)) if last else store.events(since)
                return _json_response(200, [dict(r) for r in rows])
            if path == "/api/policy" and method == "GET":
                return _json_response(200, service.policy.model_dump())
            return _json_response(404, {"error": "nie ma takiego zasobu"})

        def _handle(self) -> None:
            path, _, query = self.path.partition("?")
            try:
                resp = self._route(self.command, path, query)
            except ServiceError as exc:
                resp = _json_response(exc.status, {"error": str(exc)})
            except Exception:
                log.exception("admin %s %s: blad serwera", self.command, path)
                resp = _json_response(500, {"error": "blad serwera"})
            _send(self, resp)

        do_GET = do_POST = do_PUT = do_DELETE = _handle

    return AdminHandler


def start(handler_cls, port: int, host: str = "0.0.0.0") -> ThreadingHTTPServer:  # noqa: S104
    server = ThreadingHTTPServer((host, port), handler_cls)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, name=f"http-{port}", daemon=True).start()
    return server
