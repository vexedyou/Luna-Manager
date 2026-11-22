"""Operator REST API.

Every handler receives a Request and returns a Response. Authentication is a
signed bearer token issued by /api/login; nothing else is reachable without one.
Task dispatch is queue-based, so the console never blocks on an implant check-in.
"""

from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import parse_qs

from . import protocol
from .crypto import check_token, issue_token, verify_password
from .store import Store, enqueue_task, expire_stale_tasks, new_id, now, open_store


@dataclass
class Request:
    method: str
    path: str
    query: dict[str, list[str]]
    headers: dict[str, str]
    body: bytes
    remote_ip: str = ""

    def json(self) -> dict[str, Any]:
        if not self.body:
            return {}
        try:
            return json.loads(self.body.decode("utf-8"))
        except Exception:  # noqa: BLE001
            return {}

    def arg(self, name: str, default: str = "") -> str:
        values = self.query.get(name)
        return values[0] if values else default

    def bearer(self) -> str:
        raw = self.headers.get("authorization", "")
        if raw.lower().startswith("bearer "):
            return raw[7:].strip()
        return ""


@dataclass
class Response:
    status: int = 200
    body: bytes = b""
    content_type: str = "application/json"
    headers: dict[str, str] = field(default_factory=dict)


def json_response(payload: Any, status: int = 200) -> Response:
    return Response(
        status=status,
        body=json.dumps(payload).encode("utf-8"),
        content_type="application/json",
    )


def error(message: str, status: int = 400) -> Response:
    return json_response({"error": message}, status)


class OperatorAPI:
    def __init__(self, store: Store, registry: Any, builder: Any, secret: bytes) -> None:
        self.store = store
        self.registry = registry
        self.builder = builder
        self.secret = secret
        self.routes: list[tuple[str, str, Callable[..., Response | Any], bool]] = []
        self._register()

    def _add(
        self, method: str, pattern: str, handler: Callable[..., Any], auth: bool = True
    ) -> None:
        self.routes.append((method, pattern, handler, auth))

    def _register(self) -> None:
        self._add("POST", "/api/login", self.login, auth=False)
        self._add("GET", "/api/overview", self.overview)
        self._add("GET", "/api/sessions", self.list_sessions)
        self._add("GET", "/api/sessions/{sid}", self.get_session)
        self._add("POST", "/api/sessions/{sid}/task", self.post_task)
        self._add("GET", "/api/sessions/{sid}/tasks", self.list_tasks)
        self._add("POST", "/api/sessions/{sid}/kill", self.kill_session)
        self._add("GET", "/api/tasks/{tid}", self.get_task)
        self._add("GET", "/api/events", self.events)
        self._add("POST", "/api/build", self.build)
        self._add("GET", "/api/builds", self.list_builds)
        self._add("GET", "/api/builds/{bid}/artifact", self.build_artifact)
        self._add("GET", "/api/capabilities", self.capabilities)

    # -- dispatch ---------------------------------------------------------
    def dispatch(self, request: Request) -> Response:
        for method, pattern, handler, needs_auth in self.routes:
            params = self._match(pattern, request.path)
            if params is None:
                continue
            if method != request.method:
                continue
            operator = None
            if needs_auth:
                # a query-string token lets artifact links work without a
                # custom Authorization header on the anchor element
                supplied = request.bearer() or request.arg("token")
                operator = check_token(self.secret, supplied)
                if operator is None:
                    return error("unauthorized", 401)
                request.headers["x-operator"] = operator
            result = handler(request, **params)
            if isinstance(result, Response):
                return result
            return json_response(result)
        return error("not found", 404)

    @staticmethod
    def _match(pattern: str, path: str) -> dict[str, str] | None:
        pat_parts = pattern.strip("/").split("/")
        path_parts = path.strip("/").split("/")
        if len(pat_parts) != len(path_parts):
            return None
        params: dict[str, str] = {}
        for pat, actual in zip(pat_parts, path_parts):
            if pat.startswith("{") and pat.endswith("}"):
                params[pat[1:-1]] = actual
            elif pat != actual:
                return None
        return params

    # -- auth -------------------------------------------------------------
    def login(self, request: Request) -> Response:
        payload = request.json()
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        row = self.store.one(
            "SELECT username, password_hash FROM operators WHERE username = %s",
            (username,),
        )
        if not row or not verify_password(password, row["password_hash"]):
            self.store.log_event("auth", f"failed login for {username!r} from {request.remote_ip}")
            return error("invalid credentials", 401)
        self.store.audit(username, "login", request.remote_ip)
        return json_response(
            {"token": issue_token(self.secret, username), "operator": username}
        )

    # -- sessions ---------------------------------------------------------
    def overview(self, request: Request) -> dict[str, Any]:
        alive = self.store.one("SELECT COUNT(*) AS n FROM sessions WHERE alive = 1")
        total = self.store.one("SELECT COUNT(*) AS n FROM sessions")
        tasks = self.store.one(
            "SELECT COUNT(*) AS n FROM tasks WHERE state IN ('queued','dispatched')"
        )
        return {
            "alive": (alive or {}).get("n", 0),
            "total": (total or {}).get("n", 0),
            "pending_tasks": (tasks or {}).get("n", 0),
            "listeners": ["https", "tcp"],
        }

    def list_sessions(self, request: Request) -> dict[str, Any]:
        rows = self.store.query("SELECT * FROM sessions ORDER BY last_seen DESC")
        live = set(self.registry.live_ids())
        out = []
        for row in rows:
            row["alive"] = 1 if row["id"] in live else 0
            out.append(protocol.session_public_view(row))
        return {"sessions": out}

    def get_session(self, request: Request, sid: str) -> Any:
        row = self.store.one("SELECT * FROM sessions WHERE id = %s", (sid,))
        if not row:
            return error("no such session", 404)
        row["alive"] = 1 if sid in self.registry.live_ids() else 0
        return protocol.session_public_view(row)

    def kill_session(self, request: Request, sid: str) -> Any:
        if sid not in self.registry.live_ids():
            return error("session not connected", 409)
        self.registry.drop(sid)
        self.store.log_event("session", "operator dropped session", sid)
        self.store.audit(request.headers.get("x-operator", "?"), "kill", sid)
        return {"dropped": sid}

    # -- tasks ------------------------------------------------------------
    def post_task(self, request: Request, sid: str) -> Any:
        payload = request.json()
        kind = str(payload.get("kind", ""))
        if kind not in protocol.TASK_KINDS:
            return error(f"unknown task kind {kind!r}", 422)
        if not self.store.one("SELECT id FROM sessions WHERE id = %s", (sid,)):
            return error("no such session", 404)
        args = payload.get("args") or {}
        if not isinstance(args, dict):
            return error("args must be an object", 422)
        tid = enqueue_task(self.store, sid, kind, args)
        self.store.audit(
            request.headers.get("x-operator", "?"), "task", f"{sid} {kind} {tid}"
        )
        return {"task_id": tid, "kind": kind, "state": "queued"}

    def list_tasks(self, request: Request, sid: str) -> dict[str, Any]:
        limit = min(int(request.arg("limit", "100") or 100), 500)
        rows = self.store.query(
            "SELECT id, session_id, kind, args_json, state, created_at, "
            "dispatched_at, completed_at, ok, result_size, err FROM tasks "
            "WHERE session_id = %s ORDER BY created_at DESC LIMIT %s",
            (sid, limit),
        )
        for row in rows:
            row["args"] = json.loads(row.pop("args_json") or "{}")
        return {"tasks": rows}

    def get_task(self, request: Request, tid: str) -> Any:
        row = self.store.one("SELECT * FROM tasks WHERE id = %s", (tid,))
        if not row:
            return error("no such task", 404)
        row["args"] = json.loads(row.pop("args_json") or "{}")
        include = request.arg("result", "1") == "1"
        if not include:
            row.pop("result", None)
        return row

    # -- events -----------------------------------------------------------
    def events(self, request: Request) -> dict[str, Any]:
        since = int(request.arg("since", "0") or 0)
        rows = self.store.query(
            "SELECT id, session_id, kind, message, ts FROM events "
            "WHERE id > %s ORDER BY id ASC LIMIT 500",
            (since,),
        )
        return {"events": rows, "cursor": rows[-1]["id"] if rows else since}

    def capabilities(self, request: Request) -> dict[str, Any]:
        return {
            "kinds": {k: v for k, v in protocol.TASK_KINDS.items()},
            "all": protocol.ALL_CAPS,
        }

    # -- builds -----------------------------------------------------------
    def build(self, request: Request) -> Any:
        payload = request.json()
        config, err = self.builder.validate(payload)
        if err:
            return error(err, 422)
        build = self.builder.submit(config)
        self.store.audit(
            request.headers.get("x-operator", "?"), "build", build["id"]
        )
        return build

    def list_builds(self, request: Request) -> dict[str, Any]:
        rows = self.store.query(
            "SELECT id, config_json, status, message, sha256, size, created_at, "
            "finished_at FROM builds ORDER BY created_at DESC LIMIT 100"
        )
        for row in rows:
            row["config"] = json.loads(row.pop("config_json") or "{}")
        return {"builds": rows}

    def build_artifact(self, request: Request, bid: str) -> Any:
        row = self.store.one("SELECT * FROM builds WHERE id = %s", (bid,))
        if not row:
            return error("no such build", 404)
        path = row["artifact_path"]
        if not path or not os.path.exists(path):
            return error("artifact not available", 409)
        with open(path, "rb") as fh:
            data = fh.read()
        name = os.path.basename(path)
        return Response(
            status=200,
            body=data,
            content_type="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{name}"'},
        )
