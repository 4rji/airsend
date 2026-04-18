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

# Desktop app (Wails)
go install github.com/wailsapp/wails/v2/cmd/wails@latest
export PATH=$PATH:$(go env GOPATH)/bin
wails build -platform darwin/universal
```

Build always includes both `main.go` and `chat-window.go` (see `MAIN_FILES` in Makefile). Building only `main.go` will fail because `RunChatUI` lives in the other file.

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

### Shared state (package-level, all in `main.go`)

- `pendingFiles map[code]FileInfo` + `pendingFilesLock` — one-shot file pickups, deleted on download (both QUIC `FILE RECV` and HTTP `/api/download`).
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

## Defaults & Network Notes

- `DEFAULT_SERVER_HOST = "app.airsend.us"`, `DEFAULT_SERVER_PORT = 443` — baked into the binary as the fallback relay target for client modes.
- QUIC uses `KeepAlivePeriod: 2m`, `MaxIdleTimeout: 10m`. Lowering these will cause premature disconnects for large transfers or idle chats.
- Web UI requires **TCP** on the web port and **UDP** on the QUIC port — firewall must open both. If QUIC port 443 bind fails the process exits; use a high port (e.g. 8443) to keep both servers up.

## Legacy / Non-Build Paths

- `airsend-old-working/` — historical snapshots of `main.go` and friends. Not compiled by the Makefile. Don't edit unless explicitly asked.
- `noseusacaddy/` — unused Caddy + Docker scaffolding (`Dockerfile`, `docker-compose.yaml`, `Caddyfile`). Not part of the build.
