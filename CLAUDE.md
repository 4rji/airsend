# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run Commands

```bash
# Build local binary
make build                          # produces ./airsend
make build-all                      # Linux amd64, Windows amd64, macOS arm64

# Install into $GOBIN
make install                        # or: go install .

# Run locally (tidies deps first)
make run ARGS="-sw 0.0.0.0 3888 0.0.0.0 8443"
go run . -sw 0.0.0.0 3888 0.0.0.0 443     # sudo needed for QUIC on 443

# Tidy / clean
make tidy
make clean

# Desktop app (Wails) — run from airsend-app/
cd airsend-app
wails dev                           # hot-reload dev mode
wails build -platform darwin/universal
```

Build always includes both `main.go` and `chat-window.go` (see `MAIN_FILES` in Makefile). Building only `main.go` will fail because `RunChatUI` lives in the other file.

The desktop app (`airsend-app/`) calls `findBinary()` at runtime to locate the `airsend` executable — build it first with `make build` before running `wails dev`.

There are currently no `_test.go` files in the repo, so `go test ./...` is a no-op.

## Runtime Modes (single binary dispatched in `main()` switch)

| Flag | Purpose |
|------|---------|
| `-s <host> <port>` | QUIC-only relay server |
| `-sw [web-host] [web-port] [quic-host] [quic-port]` | Web UI (TCP) + QUIC relay in one process. Defaults: web `0.0.0.0:3888`, QUIC `0.0.0.0:443` |
| `-f [code] [host] [port] <file>...` | Send file(s) through relay, optional code override |
| `-r <code> [host] [port]` | Receive file from relay by code |
| `-d <file> [host[:port]]` | Direct peer-to-peer send (no relay) |
| `-ds <listen-host> <port>` | Listen for a direct peer-to-peer send |
| `-m [code] [host] [port]` | Chat client (relay), generates code if omitted |
| `-mr <code> <host> <port>` | Chat receiver (relay) |

Arg parsing is positional and order-sensitive — `isValidIP()` decides whether an early arg is a host or a code. Be careful when editing the switch in `main()`: each mode has its own ad-hoc parser.

## Architecture

### Two-transport design

- **QUIC (UDP)** via `quic-go` handles file transfer and chat relay. TLS certs are generated at startup (`generateTLSConfig`) with `InsecureSkipVerify: true` on the client side — this is intentional, the protocol is `"airsend"` over self-signed TLS.
- **HTTP/WebSocket (TCP)** is only active in `-sw` mode (`startWebServer`). It exposes `/api/upload`, `/api/paste`, `/api/download`, `/ws`, and serves the embedded `indexHTML` at `/`.

Both transports share the same in-memory room/file state, so a file uploaded from the web UI can be pulled with `airsend -r <code>` from the CLI and vice versa.

### QUIC wire protocol

`handleClient` dispatches on the first line received from each QUIC stream:

| First line | Handler |
|-----------|---------|
| `FILE SEND` | `handleFileSend` — reads code/filename/size headers, buffers to `pendingFiles` |
| `FILE RECV` | `handleFileRecv` — looks up `pendingFiles` by code, streams to receiver |
| `PASTE SEND` | same as FILE SEND path (text payloads) |
| `PASTE RECV` | same as FILE RECV path |
| anything else | `handleChatOrRelay` — treated as a room code for chat broadcast |

All framing is newline-delimited text over `net.Conn`. The code format is `word + digit + digit` (e.g. `wave21`) generated from a fixed 30-word list in `generateCode()`.

### Shared state (package-level, all in `main.go`)

- `pending map[string]PendingChat` + `pendingLock` — in-flight relay connections while sender and receiver are handshaking (chat and relay modes). Entries are removed after both sides connect.
- `pendingFiles map[code]FileInfo` + `pendingFilesLock` — file pickups: added by `FILE SEND`, consumed on download via `claimPendingFile` (both QUIC `FILE RECV` and HTTP `/api/download` share it). `FileInfo.downloads` is the remaining pickup count; the entry is deleted when it hits 0. Default is 1 (one-shot); `airsend -f -n<N>` allows up to `MAX_DOWNLOAD_COUNT` (25) downloads of the same upload. The count rides on the `FILE SEND` size header as an optional `"<size> <count>"` second field, so old senders (and the desktop app) that send size alone default to 1.
- `chatRooms map[code]*ChatRoom` + `chatRoomsLock` — multi-user broadcast rooms. `handleChatOrRelay` is used by BOTH the QUIC handler and the WebSocket handler (`/ws`), so room semantics are identical across transports.
- `rateLimiter` (`memoryRateLimiter`) — per-scope+IP token bucket with separate rules for `upload`, `paste`, `download`, `download_miss`, `ws`. Cleanup goroutine started by `startRateLimiterCleanup()`.

### Per-request client IP resolution

Reverse-proxy aware: `clientAddressFromRequest` checks `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, `X-Forwarded-For`, then RFC 7239 `Forwarded`, then `RemoteAddr`. Used for rate limiting and `connections.log`. Don't replace with `r.RemoteAddr` directly — you'll break rate limiting behind Cloudflare/Caddy.

### QUIC stream adapter

`quicStreamConn` wraps a `*quic.Stream` + `*quic.Conn` to satisfy `net.Conn`. All file/chat handlers operate on `net.Conn`, so the same relay/chat code paths are reused for QUIC streams and WebSocket (`websocket.Conn` also implements `net.Conn` via `x/net/websocket`).

### Runtime storage paths

`configureRuntimePaths()` resolves `logDir` and `filesDir` with fallback:
1. `AIRSEND_LOG_DIR` / `AIRSEND_FILES_DIR` env vars
2. `/opt/4rji/airsend` (preferred)
3. `./airsend-logs` / `./airsend-files` (cwd fallback)
4. `$TMPDIR/airsend-*`

Connection events are written to `${logDir}/connections.log` via `logConnectionEvent`.

### TUI chat (`chat-window.go`)

`RunChatUI(conn, code)` uses `rivo/tview` + `gdamore/tcell/v2` with a hardcoded Dracula-style background. It's invoked only from the `-m` / `-mr` modes after the QUIC stream is opened and the code is sent. The goroutine that reads from `conn` writes directly into the `tview.TextView` — don't add a second reader to the same `conn` or you'll race on the buffered reader.

### Embedded web UI

The entire web UI is a single Go string constant `indexHTML` in `main.go` (served inline by `mux.HandleFunc("/")`). It is **not** the same file as `index.html` at the repo root — that root file is a separate project-overview landing page, unrelated to what the server serves. When changing the in-app UI, edit the `indexHTML` constant; when changing the marketing/overview page, edit `index.html`.

### Desktop app (`airsend-app/`)

A fully implemented Wails v2 desktop client with its own `go.mod` (`module airsend-app`). Key design:

- `app.go` exposes Go methods to the JS frontend: `StartServer`/`StopServer`/`GetServerStatus` (spawns the `airsend` CLI binary in `-sw` mode), `ChatConnect`/`ChatSend`/`ChatLeave` (direct QUIC to relay), `FileSend`/`FileRecv`/`FileSendText` (direct QUIC), `PickFile`/`PickSaveDir` (native OS dialogs).
- `findBinary()` looks for the `airsend` executable next to the app bundle, then in cwd/parent, then in `$PATH`.
- The frontend lives in `frontend/dist/` (embedded via `//go:embed all:frontend/dist`). Build the frontend before `wails build` if it needs updating.
- `cyberpunk-website/index.html` is the UI source/palette reference; the Wails frontend reuses its CSS variables.

## Defaults & Network Notes

- `DEFAULT_SERVER_HOST = "app.airsend.us"`, `DEFAULT_SERVER_PORT = 443` — baked into the binary as the fallback relay target for client modes.
- QUIC uses `KeepAlivePeriod: 2m`, `MaxIdleTimeout: 10m`. Lowering these will cause premature disconnects for large transfers or idle chats.
- Web UI requires **TCP** on the web port and **UDP** on the QUIC port — firewall must open both. If QUIC port 443 bind fails the process exits; use a high port (e.g. 8443) to keep both servers up.

## Legacy / Non-Build Paths

- `airsend-old-working/` — historical snapshots of `main.go` and friends. Not compiled by the Makefile. Don't edit unless explicitly asked.
- `noseusacaddy/` — unused Caddy + Docker scaffolding (`Dockerfile`, `docker-compose.yaml`, `Caddyfile`). Not part of the build.
- `web/` — static landing page (`index.html` + icon). Not served by the Go binary.
