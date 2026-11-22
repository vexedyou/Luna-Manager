"""HTTP transport.

One handler class serves three surfaces:

  /v1/hs, /v1/b        implant handshake and beacon frames
  /api/...             operator REST API
  /                    the console SPA, embedded, no external CDN

The same handler is mounted twice: a plain listener for the operator console and
a TLS listener for implant traffic. Both are threaded and independent.
"""

from __future__ import annotations

import json
import mimetypes
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import protocol
from .api import OperatorAPI, Request, Response
from .core import SessionNotFound
from .crypto import CryptoError, b64d

MAX_BODY = 32 * 1024 * 1024
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")


class LunaHandler(BaseHTTPRequestHandler):
    server_version = "luna/1"
    protocol_version = "HTTP/1.1"

    # injected by make_server
    context: dict[str, Any] = {}

    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
        quiet = self.context.get("quiet", True)
        if not quiet:
            super().log_message(fmt, *args)

    # -- plumbing ---------------------------------------------------------
    def _read_body(self) -> bytes:
        length = int(self.headers.get("content-length", "0") or 0)
        if length <= 0:
            return b""
        if length > MAX_BODY:
            raise ValueError("body too large")
        return self.rfile.read(length)

    def _send(self, response: Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for key, value in response.headers.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(response.body)

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(
            Response(
                status=status,
                body=json.dumps(payload).encode("utf-8"),
                content_type="application/json",
            )
        )

    def _remote_ip(self) -> str:
        forwarded = self.headers.get("x-forwarded-for", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0] if self.client_address else ""

    # -- verbs ------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802
        self._route("GET")

    def do_POST(self) -> None:  # noqa: N802
        self._route("POST")

    def do_HEAD(self) -> None:  # noqa: N802
        self._route("GET")

    def do_OPTIONS(self) -> None:  # noqa: N802
        self._send(
            Response(
                status=204,
                body=b"",
                headers={
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Headers": "authorization,content-type,x-luna-session",
                    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
                },
            )
        )

    def _route(self, method: str) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        try:
            body = self._read_body()
        except ValueError:
            self._json({"error": "body too large"}, 413)
            return

        try:
            if path == "/v1/hs":
                self._handshake(body)
            elif path == "/v1/b":
                self._beacon(body)
            elif path.startswith("/api/"):
                request = Request(
                    method="GET" if self.command in ("GET", "HEAD") else "POST",
                    path=path,
                    query=parse_qs(parsed.query),
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=body,
                    remote_ip=self._remote_ip(),
                )
                api: OperatorAPI = self.context["api"]
                self._send(api.dispatch(request))
            else:
                self._static(path)
        except SessionNotFound:
            self._json({"error": "session not connected"}, 409)
        except CryptoError as exc:
            self._json({"error": f"crypto: {exc}"}, 400)
        except Exception as exc:  # noqa: BLE001
            self.context.setdefault("errors", []).append(f"{type(exc).__name__}: {exc}")
            self._json({"error": "internal error"}, 500)

    # -- implant surface --------------------------------------------------
    def _handshake(self, body: bytes) -> None:
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except Exception:  # noqa: BLE001
            self._json({"error": "bad json"}, 400)
            return
        registry = self.context["registry"]
        try:
            meta = protocol.SessionMeta.from_wire(payload.get("meta", {}))
            meta.transport = str(payload.get("transport", "https"))
            reply = registry.handshake(
                public_b64=str(payload.get("pk", "")),
                nonce_b64=str(payload.get("nonce", "")),
                proof=str(payload.get("proof", "")),
                meta=meta,
                external_ip=self._remote_ip(),
                transport=meta.transport,
                build_id=str(payload.get("build", "")),
                capabilities=int(payload.get("caps", 0) or 0),
            )
        except PermissionError:
            self._json({"error": "rejected"}, 403)
            return
        except ValueError as exc:
            self._json({"error": str(exc)}, 400)
            return
        self._json(reply)

    def _beacon(self, body: bytes) -> None:
        sid = self.headers.get("x-luna-session", "")
        if not sid:
            self._json({"error": "missing session"}, 400)
            return
        registry = self.context["registry"]
        frame = registry.beacon(sid, body)
        self._send(
            Response(
                status=200,
                body=frame,
                content_type="application/octet-stream",
            )
        )

    # -- console ----------------------------------------------------------
    def _static(self, path: str) -> None:
        rel = "index.html" if path in ("/", "") else path.lstrip("/")
        if ".." in rel or rel.startswith("/"):
            self._json({"error": "bad path"}, 400)
            return
        target = os.path.join(STATIC_DIR, rel)
        if not os.path.isfile(target):
            target = os.path.join(STATIC_DIR, "index.html")
        if not os.path.isfile(target):
            self._json({"error": "console not built"}, 404)
            return
        ctype, _ = mimetypes.guess_type(target)
        with open(target, "rb") as fh:
            data = fh.read()
        self._send(
            Response(
                status=200,
                body=data,
                content_type=ctype or "application/octet-stream",
            )
        )


class LunaHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(
    host: str,
    port: int,
    context: dict[str, Any],
    tls: tuple[str, str] | None = None,
) -> LunaHTTPServer:
    handler = type("BoundLunaHandler", (LunaHandler,), {"context": context})
    httpd = LunaHTTPServer((host, port), handler)
    if tls:
        cert_path, key_path = tls
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ssl_ctx.load_cert_chain(cert_path, key_path)
        httpd.socket = ssl_ctx.wrap_socket(httpd.socket, server_side=True)
    return httpd


def serve_forever_in_thread(httpd: LunaHTTPServer, name: str) -> threading.Thread:
    thread = threading.Thread(target=httpd.serve_forever, name=name, daemon=True)
    thread.start()
    return thread
