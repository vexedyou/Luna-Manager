"""Raw TCP transport.

Length-prefixed frames over a persistent connection. The handshake is a single
JSON line before any AEAD frame is exchanged; after that the connection carries
beacon frames in both directions until either side closes it.

framing:  length(4, big endian) || payload
"""

from __future__ import annotations

import json
import socket
import struct
import threading
from typing import Any

from . import protocol
from .core import SessionNotFound

MAX_FRAME = 32 * 1024 * 1024


def recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise ConnectionError("peer closed")
        buf.extend(chunk)
    return bytes(buf)


def recv_frame(sock: socket.socket) -> bytes:
    (length,) = struct.unpack(">I", recv_exact(sock, 4))
    if length <= 0 or length > MAX_FRAME:
        raise ValueError(f"bad frame length {length}")
    return recv_exact(sock, length)


def send_frame(sock: socket.socket, payload: bytes) -> None:
    sock.sendall(struct.pack(">I", len(payload)) + payload)


class TCPListener:
    def __init__(self, host: str, port: int, registry: Any, store: Any) -> None:
        self.host = host
        self.port = port
        self.registry = registry
        self.store = store
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._connections: set[socket.socket] = set()
        self._conn_lock = threading.Lock()

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(128)
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._accept_loop, name="luna-tcp", daemon=True)
        self._thread.start()

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            conn.settimeout(120)
            with self._conn_lock:
                self._connections.add(conn)
            threading.Thread(
                target=self._serve, args=(conn, addr[0]), daemon=True
            ).start()

    def _serve(self, conn: socket.socket, peer: str) -> None:
        sid = ""
        try:
            hello = json.loads(recv_frame(conn).decode("utf-8"))
            meta = protocol.SessionMeta.from_wire(hello.get("meta", {}))
            meta.transport = "tcp"
            reply = self.registry.handshake(
                public_b64=str(hello.get("pk", "")),
                nonce_b64=str(hello.get("nonce", "")),
                proof=str(hello.get("proof", "")),
                meta=meta,
                external_ip=peer,
                transport="tcp",
                build_id=str(hello.get("build", "")),
                capabilities=int(hello.get("caps", 0) or 0),
            )
            sid = reply["sid"]
            send_frame(conn, json.dumps(reply).encode("utf-8"))

            while not self._stop.is_set():
                frame = recv_frame(conn)
                response = self.registry.beacon(sid, frame, external_ip=peer)
                send_frame(conn, response)
        except (ConnectionError, socket.timeout, OSError):
            pass
        except SessionNotFound:
            pass
        except (ValueError, json.JSONDecodeError):
            # something that is not a Luna handshake touched the port; drop it
            pass
        except Exception as exc:  # noqa: BLE001
            self.store.log_event(
                "tcp", f"{peer}: {type(exc).__name__}: {exc}", sid
            )
        finally:
            with self._conn_lock:
                self._connections.discard(conn)
            try:
                conn.close()
            except OSError:
                pass
            if sid:
                self.registry.drop(sid)
                self.store.log_event("session", "tcp session closed", sid)

    def stop(self) -> None:
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        with self._conn_lock:
            for conn in list(self._connections):
                try:
                    conn.close()
                except OSError:
                    pass
