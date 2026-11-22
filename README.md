# Luna-Manager

A C2 framework for an isolated lab: HTTPS and raw-TCP listeners, X25519 handshake
with directional AES-256-GCM framing, a Postgres-backed task queue, a browser
console served by the C2 itself, a C++20 Windows x64 implant, and a build
pipeline that emits a configured `.exe`.

```
c2/          operator backend: listeners, crypto, store, REST API, console SPA
implant/     C++20 Windows x64 implant + CMake project
  src/       beacon loop, transport, dispatch, modules, crypto, JSON
  config/    luna_config.hpp.in, the single build-time config template
docs/        wire protocol and operations notes
var/         runtime state (gitignored): sqlite db, certs, build artifacts
```

## Quickstart

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt        # cryptography; psycopg for Postgres
.venv/bin/pip install ziglang                     # optional: in-process Windows cross-compiler

.venv/bin/python -m c2.main
```

On first start the framework creates `var/`, generates a self-signed listener
certificate, generates an operator password, and prints everything:

```
====================================================================
 Luna-Manager
  console     http://0.0.0.0:8080/
  implant     https://0.0.0.0:8443/v1/
  tcp         tcp://0.0.0.0:9443
  database    sqlite:///path/to/var/luna.db
  cert sha256 4477102a0ad7ebfe...
  operator    admin
====================================================================
```

Open the console, sign in, hit **Build implant**, pick transport, endpoints, XOR
key, mutex, sleep/jitter and capabilities, and download the `.exe`.

## Configuration

Everything is environment-driven:

| variable | default | meaning |
| --- | --- | --- |
| `LUNA_DATA` | `./var` | data dir: sqlite db, certs, build output |
| `LUNA_DSN` | `sqlite://$LUNA_DATA/luna.db` | `postgresql://user:pass@host/db` for Postgres |
| `LUNA_HOST` | `0.0.0.0` | bind address |
| `LUNA_CONSOLE_PORT` | `8080` | plain HTTP console + operator API |
| `LUNA_HTTPS_PORT` | `8443` | TLS implant listener |
| `LUNA_TCP_PORT` | `9443` | raw TCP implant listener |
| `LUNA_OPERATOR` | `admin` | operator username |
| `LUNA_PASSWORD` | generated | operator password |
| `LUNA_REG_KEY` | unset | shared registration key, hex, used when no per-build key applies |
| `LUNA_INSECURE` | unset | `1` serves the implant listener without TLS (lab shortcut) |

Postgres needs the driver: `.venv/bin/pip install "psycopg[binary]"`. The schema
in `c2/store.py` is applied on first connect.

## Architecture

**Listeners.** One `ThreadingHTTPServer` handler serves three surfaces — `/v1/hs`
and `/v1/b` for implants, `/api/*` for operators, and the console at `/`. It is
mounted twice: plain HTTP on the console port and TLS on the implant port. The
TCP listener runs its own accept loop with length-prefixed frames.

**Handshake.** The implant generates an X25519 keypair, sends its public key plus
a 32-byte nonce and an HMAC proof over the build's registration key. The server
replies with its own public key and a random salt. Both sides derive two
independent 32-byte keys with HKDF-SHA256 (`luna/v1/tx`, `luna/v1/rx`), so the
outbound and inbound nonce counters can never collide.

**Framing.** `nonce(12) || ciphertext || tag(16)`, AES-256-GCM with
`AAD = "luna-v1"`. The nonce is `epoch(4) || counter(8)`, both big-endian. The
receiver rejects any frame whose counter does not strictly advance, which fails
replay and reordering closed. See `docs/protocol.md`.

**Task queue.** Operator REST calls enqueue rows; the implant claims up to four
per check-in, which the store atomically flips to `dispatched`. Results ride back
on the next beacon and land in the `tasks` row. Stale dispatches expire after 15
minutes, and idle sessions are reaped.

**Builds.** `POST /api/build` validates the config, mints a fresh 32-byte
registration key for that build, renders `implant/config/luna_config.hpp.in`,
copies the implant sources into `var/builds/<id>/`, and invokes the first
available Windows cross-compiler. Three outcomes, all real: `ok` (a PE was
produced), `source_only` (no cross toolchain present — a source bundle with the
config baked in is returned instead), `error` (compiler output captured verbatim).

Registration keys are per build, so revoking one artifact means deleting its
`builds` row; every other implant is unaffected.

## Implant

C++20, x64, no CRT dependency beyond the platform libs it links
(`ws2_32 winhttp bcrypt crypt32 advapi32 shell32 psapi userenv ntdll`).

- **Transport** — WinHTTP for HTTPS with certificate pinning (the builder bakes in
  the listener's SHA-256), WinSock for raw TCP. Both drive the same handshake and
  framing code.
- **Beacon loop** — poll, execute, queue results, sleep with jitter. Transport
  failure tears the session down and re-handshakes with exponential backoff to
  300s.
- **Dispatch table** — `kind -> capability bit -> handler`, gated by the mask
  compiled into the build, so a stripped build genuinely cannot run a task it was
  not built for.
- **Config strings** — endpoints, mutex, registration key, user agent and build id
  are XOR-encoded at compile time by a `consteval` helper and decoded on use. The
  plaintext never lands in `.rdata`; verify with `strings`.

### Capabilities

| kind | bit | kind | bit |
| --- | --- | --- | --- |
| `shell` | `0x0001` | `mkdir` | `0x0100` |
| `pwd` | `0x0002` | `ps` | `0x0200` |
| `cd` | `0x0004` | `kill` | `0x0400` |
| `ls` | `0x0008` | `env` | `0x0800` |
| `cat` | `0x0010` | `sysinfo` | `0x1000` |
| `upload` | `0x0020` | `sleep` | `0x2000` |
| `download` | `0x0040` | `exit` | `0x4000` |
| `rm` | `0x0080` | `whoami` | `0x8000` |

### Building the implant by hand

```bash
# on Windows
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release

# cross-compiling
zig c++ -target x86_64-windows-gnu -std=c++20 -O2 \
  -o luna.exe implant/src/*.cpp \
  -lws2_32 -lwinhttp -lbcrypt -lcrypt32 -ladvapi32 -lshell32 -lpsapi -luserenv -lntdll \
  -Wl,--subsystem,windows
```

CMake exposes the same knobs as `-D` variables (`-DTRANSPORT=tcp -DENDPOINTS=...`
and so on); see `implant/CMakeLists.txt`.

## Console

Single page, dark, no external assets — everything is served from the C2's own
HTTP listener out of `c2/static/`. Session list with live status, terminal that
round-trips through the task queue, file browser with upload/download, task table
with result sizes, build form and build history with artifact download.

## Protocol reference

`docs/protocol.md` has the handshake exchange, frame layout, every envelope
schema, and the state machine for both transports.
