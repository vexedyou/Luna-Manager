# Luna wire protocol v1

Two transports carry identical envelopes: HTTPS beaconing and raw framed TCP.
Only the carriage differs, so an implant built for one behaves the same as the
other once connected.

## Identifiers

| value | meaning |
| --- | --- |
| `PROTO` | `1` |
| `AAD` | `luna-v1` (7 bytes, used as AES-GCM associated data) |
| `INFO_TX` | `luna/v1/tx` — HKDF info for the initiator's send key |
| `INFO_RX` | `luna/v1/rx` — HKDF info for the initiator's receive key |
| session id | `s_` + 24 hex chars, assigned by the server |
| task id | `t_` + 24 hex chars, assigned by the operator API |
| build id | `b_` + 24 hex chars, assigned at build time |

## Handshake

`POST /v1/hs` (plaintext JSON over TLS), or a single length-prefixed JSON frame
on TCP.

```json
{
  "v": 1,
  "pk": "<base64, 32-byte X25519 public key>",
  "nonce": "<base64, 32 random bytes>",
  "proof": "<hex, HMAC-SHA256>",
  "build": "b_1ae089e870aa4985ba68f868",
  "caps": 65535,
  "transport": "https",
  "meta": {
    "hostname": "LAB-WS01", "username": "LAB\\analyst",
    "os": "Windows 10.0.19045", "arch": "x64", "pid": 4242,
    "ip": "10.0.2.15", "elevated": true, "integrity": "High"
  }
}
```

`proof = HMAC-SHA256(reg_key, "luna-reg-v1" || pk_raw || nonce_raw)`, hex-encoded.
`reg_key` is the 32-byte key minted for that specific build, stored in the
`builds` table. If `build` is empty or unknown the server falls back to
`LUNA_REG_KEY`, and rejects the handshake when neither is present.

Response:

```json
{ "v": 1, "sid": "s_...", "pk": "<base64>", "salt": "<base64, 16 bytes>",
  "sleep": 60, "jitter": 20 }
```

Both sides then compute:

```
shared  = X25519(own_private, peer_public)          # reject if all-zero
send_key = HKDF-SHA256(salt, shared, "luna/v1/tx", 32)
recv_key = HKDF-SHA256(salt, shared, "luna/v1/rx", 32)
```

The initiator sends with `send_key`; the responder mirrors, so the server's
outbound key is the implant's `recv_key`. Directional keys mean the two counters
can run independently without nonce reuse.

A new handshake creates a new session id and resets both counters. The server
drops any prior in-memory state for that session, which is what makes
reconnection after a server restart work.

## Frames

```
nonce(4) || counter(8)   -> 12-byte GCM nonce, big-endian
ciphertext(N)
tag(16)
```

`AES-256-GCM`, `AAD = "luna-v1"`. The receiver parses the counter from the nonce
and rejects any frame where `counter <= highest_seen`, so replays and reordering
fail closed. Authentication failure is treated as session loss and forces a
re-handshake.

TCP adds a 4-byte big-endian length prefix in front of the whole frame. Maximum
frame is 32 MiB on both sides.

## Beacon

`POST /v1/b` with `X-Luna-Session: <sid>` and `Content-Type: application/octet-stream`,
or a framed TCP message. Body is one AEAD frame.

Request (encrypted JSON):

```json
{
  "seq": 12,
  "want": 4,
  "since": "",
  "meta": { "hostname": "...", "username": "...", "elevated": false, "...": "..." },
  "results": [
    { "id": "t_...", "ok": true, "data": "output text or base64", "err": "" }
  ]
}
```

Response (encrypted JSON):

```json
{
  "tasks": [
    { "id": "t_...", "kind": "shell", "args": { "cmd": "whoami" } }
  ],
  "sleep": 60,
  "jitter": 20,
  "kill": false
}
```

`results` is capped at 16 per beacon by the implant (it keeps up to 64 queued and
drains across check-ins). `want` is clamped to 64 server-side. `kill: true` makes
the implant flush its final result set and exit.

### Status codes

| code | meaning | implant action |
| --- | --- | --- |
| 200 | accepted | process tasks |
| 401 / 403 | registration proof or token rejected | re-handshake |
| 409 | session not connected (server restarted, session reaped) | re-handshake |
| 4xx other | malformed frame | re-handshake |
| 5xx | server fault | back off, retry |

## Task arguments

| kind | args |
| --- | --- |
| `shell` | `{"cmd": "...", "timeout": 120}` |
| `pwd` | `{}` |
| `cd` | `{"path": "C:\\Windows"}` |
| `ls` | `{"path": "C:\\"}` → result is JSON `{path, entries:[{name,dir,size,mtime}]}` |
| `cat` | `{"path": "..."}` → text, capped at 1 MiB |
| `download` | `{"path": "..."}` → base64, capped at 24 MiB |
| `upload` | `{"path": "...", "data": "<base64>"}` |
| `rm` | `{"path": "..."}` |
| `mkdir` | `{"path": "..."}` |
| `ps` | `{}` → JSON array of `{pid,ppid,threads,name}` |
| `kill` | `{"pid": 1234}` |
| `env` | `{}` → `KEY=VALUE` lines |
| `sysinfo` | `{}` → JSON object |
| `sleep` | `{"seconds": 120, "jitter": 30}` |
| `exit` | `{}` |
| `whoami` | `{}` → user, SID, integrity, privileges |

Every kind maps to a capability bit; a build compiled without that bit returns
`ok=false, err="capability <kind> not compiled into this build"` instead of
executing.

## State machine

```
            +-----------+
            |  offline  |
            +-----+-----+
                  | handshake ok
                  v
            +-----------+
     +----->|   online  |---- beacon failure / 4xx ----> re-handshake
     |      +-----+-----+
     |            | response parsed
     |            v
     |      execute tasks, queue results
     |            |
     +--- sleep with jitter (60s +/- 20% by default)
```

Backoff on transport failure: 5s, doubling to a 300s ceiling, reset to 5s after
any successful beacon.

## Operator API

All routes except `/api/login` require `Authorization: Bearer <token>`; a
`?token=` query parameter is also accepted so artifact links work from a plain
anchor.

| method | path | purpose |
| --- | --- | --- |
| POST | `/api/login` | `{username,password}` → `{token, operator}` |
| GET | `/api/overview` | counts for the console header |
| GET | `/api/sessions` | all sessions, `alive` recomputed from live state |
| GET | `/api/sessions/{sid}` | one session |
| POST | `/api/sessions/{sid}/task` | `{kind,args}` → `{task_id,state}` |
| GET | `/api/sessions/{sid}/tasks?limit=` | task history |
| POST | `/api/sessions/{sid}/kill` | drop the live session |
| GET | `/api/tasks/{tid}?result=1` | one task, optionally with output |
| GET | `/api/events?since=` | event log since a cursor |
| GET | `/api/capabilities` | kind → bit map |
| POST | `/api/build` | submit a build |
| GET | `/api/builds` | build history |
| GET | `/api/builds/{bid}/artifact` | download the `.exe` or source bundle |

Tokens are HMAC-SHA256 signed (`luna-tok-v1`), 12-hour expiry, secret persisted
in `var/operator.secret`. Passwords are scrypt (N=2^14, r=8, p=1).

## Storage

Postgres or SQLite behind one interface (`c2/store.py`). Tables: `operators`,
`sessions`, `tasks`, `events`, `builds`, `audit`. Task claiming reads queued rows
per session ordered by `created_at` and flips them to `dispatched`; results land
in the same row with `state` set to `done` or `error`.
