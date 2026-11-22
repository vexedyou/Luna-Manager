"""Persistence for sessions, tasks, results, builds, and the audit log.

Postgres is the production backend. SQLite is included so the framework runs
standalone in a lab box with no database service; both speak the same interface,
so nothing above this layer knows which one is live. Select with LUNA_DSN:

    postgresql://luna:secret@127.0.0.1:5432/luna
    sqlite:///var/lib/luna/luna.db
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Iterable, Sequence

PG_SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at    BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL DEFAULT '',
    username     TEXT NOT NULL DEFAULT '',
    os_name      TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    pid          BIGINT NOT NULL DEFAULT 0,
    internal_ip  TEXT NOT NULL DEFAULT '',
    external_ip  TEXT NOT NULL DEFAULT '',
    transport    TEXT NOT NULL DEFAULT '',
    elevated     INTEGER NOT NULL DEFAULT 0,
    integrity    TEXT NOT NULL DEFAULT '',
    alive        INTEGER NOT NULL DEFAULT 1,
    first_seen   BIGINT NOT NULL,
    last_seen    BIGINT NOT NULL,
    sleep        INTEGER NOT NULL DEFAULT 60,
    jitter       INTEGER NOT NULL DEFAULT 20,
    capabilities BIGINT NOT NULL DEFAULT 0,
    build_id     TEXT NOT NULL DEFAULT '',
    meta_json    TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS tasks (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    kind          TEXT NOT NULL,
    args_json     TEXT NOT NULL DEFAULT '{}',
    state         TEXT NOT NULL DEFAULT 'queued',
    created_at    BIGINT NOT NULL,
    dispatched_at BIGINT,
    completed_at  BIGINT,
    ok            INTEGER,
    result        TEXT NOT NULL DEFAULT '',
    result_size   BIGINT NOT NULL DEFAULT 0,
    err           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS tasks_queue ON tasks (session_id, state, created_at);

CREATE TABLE IF NOT EXISTS events (
    id         BIGSERIAL PRIMARY KEY,
    session_id TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL,
    message    TEXT NOT NULL,
    ts         BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);

CREATE TABLE IF NOT EXISTS builds (
    id            TEXT PRIMARY KEY,
    config_json   TEXT NOT NULL,
    reg_key       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending',
    message       TEXT NOT NULL DEFAULT '',
    artifact_path TEXT NOT NULL DEFAULT '',
    sha256        TEXT NOT NULL DEFAULT '',
    size          BIGINT NOT NULL DEFAULT 0,
    created_at    BIGINT NOT NULL,
    finished_at   BIGINT
);

CREATE TABLE IF NOT EXISTS audit (
    id       BIGSERIAL PRIMARY KEY,
    operator TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    ts       BIGINT NOT NULL
);
"""

SQLITE_SCHEMA = """
CREATE TABLE IF NOT EXISTS operators (
    username      TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    id           TEXT PRIMARY KEY,
    hostname     TEXT NOT NULL DEFAULT '',
    username     TEXT NOT NULL DEFAULT '',
    os_name      TEXT NOT NULL DEFAULT '',
    arch         TEXT NOT NULL DEFAULT '',
    pid          INTEGER NOT NULL DEFAULT 0,
    internal_ip  TEXT NOT NULL DEFAULT '',
    external_ip  TEXT NOT NULL DEFAULT '',
    transport    TEXT NOT NULL DEFAULT '',
    elevated     INTEGER NOT NULL DEFAULT 0,
    integrity    TEXT NOT NULL DEFAULT '',
    alive        INTEGER NOT NULL DEFAULT 1,
    first_seen   INTEGER NOT NULL,
    last_seen    INTEGER NOT NULL,
    sleep        INTEGER NOT NULL DEFAULT 60,
    jitter       INTEGER NOT NULL DEFAULT 20,
    capabilities INTEGER NOT NULL DEFAULT 0,
    build_id     TEXT NOT NULL DEFAULT '',
    meta_json    TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS tasks (
    id            TEXT PRIMARY KEY,
    session_id    TEXT NOT NULL,
    kind          TEXT NOT NULL,
    args_json     TEXT NOT NULL DEFAULT '{}',
    state         TEXT NOT NULL DEFAULT 'queued',
    created_at    INTEGER NOT NULL,
    dispatched_at INTEGER,
    completed_at  INTEGER,
    ok            INTEGER,
    result        TEXT NOT NULL DEFAULT '',
    result_size   INTEGER NOT NULL DEFAULT 0,
    err           TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS tasks_queue ON tasks (session_id, state, created_at);
CREATE TABLE IF NOT EXISTS events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL DEFAULT '',
    kind       TEXT NOT NULL,
    message    TEXT NOT NULL,
    ts         INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
CREATE TABLE IF NOT EXISTS builds (
    id            TEXT PRIMARY KEY,
    config_json   TEXT NOT NULL,
    reg_key       TEXT NOT NULL DEFAULT '',
    status        TEXT NOT NULL DEFAULT 'pending',
    message       TEXT NOT NULL DEFAULT '',
    artifact_path TEXT NOT NULL DEFAULT '',
    sha256        TEXT NOT NULL DEFAULT '',
    size          INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL,
    finished_at   INTEGER
);
CREATE TABLE IF NOT EXISTS audit (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    operator TEXT NOT NULL,
    action   TEXT NOT NULL,
    detail   TEXT NOT NULL DEFAULT '',
    ts       INTEGER NOT NULL
);
"""


def now() -> int:
    return int(time.time())


def new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:24]}"


class Store:
    """Thread-safe database handle with per-thread connections."""

    dialect = "sqlite"

    def __init__(self, dsn: str) -> None:
        self.dsn = dsn
        self._local = threading.local()
        self._init_schema()
        self.seed_operator()

    # -- backend hooks ---------------------------------------------------
    def _connect(self) -> Any:
        raise NotImplementedError

    def _ph(self, sql: str) -> str:
        return sql

    def _init_schema(self) -> None:
        raise NotImplementedError

    # -- public API ------------------------------------------------------
    @property
    def conn(self) -> Any:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = self._connect()
            self._local.conn = conn
        return conn

    def execute(self, sql: str, params: Sequence[Any] = ()) -> None:
        cur = self.conn.cursor()
        cur.execute(self._ph(sql), tuple(params))
        self.conn.commit()

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        cur = self.conn.cursor()
        cur.execute(self._ph(sql), tuple(params))
        cols = [c[0] for c in cur.description or []]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

    def one(self, sql: str, params: Sequence[Any] = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- helpers ---------------------------------------------------------
    def seed_operator(self) -> None:
        from .crypto import hash_password

        username = os.environ.get("LUNA_OPERATOR", "admin")
        password = os.environ.get("LUNA_PASSWORD", "")
        existing = self.one("SELECT username FROM operators WHERE username = %s", (username,))
        if existing:
            return
        if not password:
            import secrets

            password = secrets.token_urlsafe(18)
            os.environ["LUNA_PASSWORD"] = password
            print(f"[luna] generated operator password for {username}: {password}")
        self.execute(
            "INSERT INTO operators (username, password_hash, created_at) VALUES (%s, %s, %s)",
            (username, hash_password(password), now()),
        )

    def log_event(self, kind: str, message: str, session_id: str = "") -> None:
        self.execute(
            "INSERT INTO events (session_id, kind, message, ts) VALUES (%s, %s, %s, %s)",
            (session_id, kind, message[:4000], now()),
        )

    def audit(self, operator: str, action: str, detail: str = "") -> None:
        self.execute(
            "INSERT INTO audit (operator, action, detail, ts) VALUES (%s, %s, %s, %s)",
            (operator, action, detail[:4000], now()),
        )


class SQLiteStore(Store):
    dialect = "sqlite"

    def _connect(self) -> Any:
        path = self.dsn[len("sqlite://") :] if self.dsn.startswith("sqlite://") else self.dsn
        if path in ("/:memory:", ":memory:"):
            path = ":memory:"
        else:
            os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        conn = sqlite3.connect(
            path, timeout=15, isolation_level=None, check_same_thread=False
        )
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=15000")
        return conn

    def _ph(self, sql: str) -> str:
        return sql.replace("%s", "?")

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript(SQLITE_SCHEMA)
        self.conn.commit()


class PostgresStore(Store):
    dialect = "postgres"

    def _connect(self) -> Any:
        import psycopg  # imported lazily so sqlite-only deployments need no driver

        conn = psycopg.connect(self.dsn, autocommit=True)
        return conn

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.execute(PG_SCHEMA)
        self.conn.commit()

    def query(self, sql: str, params: Sequence[Any] = ()) -> list[dict[str, Any]]:
        import psycopg.rows

        with self.conn.cursor(row_factory=psycopg.rows.dict_row) as cur:
            cur.execute(sql, tuple(params))
            return list(cur.fetchall())


def open_store(dsn: str | None = None) -> Store:
    dsn = dsn or os.environ.get("LUNA_DSN", "sqlite:///var/lib/luna/luna.db")
    if dsn.startswith("sqlite://") or dsn.endswith(".db"):
        return SQLiteStore(dsn)
    return PostgresStore(dsn)


# --- task queue -------------------------------------------------------------


def enqueue_task(
    store: Store,
    session_id: str,
    kind: str,
    args: dict[str, Any] | None = None,
    task_id: str | None = None,
) -> str:
    tid = task_id or new_id("t")
    store.execute(
        "INSERT INTO tasks (id, session_id, kind, args_json, state, created_at) "
        "VALUES (%s, %s, %s, %s, 'queued', %s)",
        (tid, session_id, kind, json.dumps(args or {}), now()),
    )
    return tid


def claim_tasks(store: Store, session_id: str, limit: int) -> list[dict[str, Any]]:
    """Atomically move up to `limit` queued tasks for a session to 'dispatched'."""
    rows = store.query(
        "SELECT id, kind, args_json FROM tasks "
        "WHERE session_id = %s AND state = 'queued' "
        "ORDER BY created_at ASC LIMIT %s",
        (session_id, max(1, min(limit, 64))),
    )
    claimed: list[dict[str, Any]] = []
    for row in rows:
        store.execute(
            "UPDATE tasks SET state = 'dispatched', dispatched_at = %s "
            "WHERE id = %s AND state = 'queued'",
            (now(), row["id"]),
        )
        claimed.append(
            {
                "id": row["id"],
                "kind": row["kind"],
                "args": json.loads(row["args_json"] or "{}"),
            }
        )
    return claimed


def store_result(
    store: Store, session_id: str, task_id: str, ok: bool, data: str, err: str
) -> None:
    size = len(data or "")
    store.execute(
        "UPDATE tasks SET state = %s, ok = %s, result = %s, result_size = %s, "
        "err = %s, completed_at = %s WHERE id = %s AND session_id = %s",
        (
            "done" if ok else "error",
            1 if ok else 0,
            (data or "")[:8 * 1024 * 1024],
            size,
            (err or "")[:4000],
            now(),
            task_id,
            session_id,
        ),
    )


def expire_stale_tasks(store: Store, older_than: int = 900) -> int:
    cutoff = now() - older_than
    rows = store.query(
        "SELECT id FROM tasks WHERE state = 'dispatched' AND dispatched_at < %s",
        (cutoff,),
    )
    for row in rows:
        store.execute(
            "UPDATE tasks SET state = 'expired', completed_at = %s WHERE id = %s",
            (now(), row["id"]),
        )
    return len(rows)


def upsert_session(store: Store, meta: Any, external_ip: str, build_id: str,
                   session_id: str | None = None, capabilities: int = 0) -> str:
    ts = now()
    sid = session_id
    existing = (
        store.one("SELECT id FROM sessions WHERE id = %s", (sid,)) if sid else None
    )
    if existing:
        store.execute(
            "UPDATE sessions SET last_seen = %s, alive = 1, internal_ip = %s, "
            "external_ip = %s WHERE id = %s",
            (ts, meta.internal_ip, external_ip, sid),
        )
        return sid
    sid = sid or new_id("s")
    store.execute(
        "INSERT INTO sessions (id, hostname, username, os_name, arch, pid, "
        "internal_ip, external_ip, transport, elevated, integrity, alive, "
        "first_seen, last_seen, capabilities, build_id, meta_json) "
        "VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s,%s)",
        (
            sid,
            meta.hostname,
            meta.username,
            meta.os_name,
            meta.arch,
            meta.pid,
            meta.internal_ip,
            external_ip,
            meta.transport,
            1 if meta.elevated else 0,
            meta.integrity,
            ts,
            ts,
            capabilities,
            build_id,
            json.dumps({"integrity": meta.integrity}),
        ),
    )
    return sid
