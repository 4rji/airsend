# AirSend — Project Understanding

**What it is:** A lightweight Go binary for fast file transfer and multi-user chat over QUIC (UDP) + HTTP/WebSocket (TCP). Works both from the CLI and from a browser-based web UI. No accounts, no cloud services — just room codes.

---

## Core Transports

- **QUIC (UDP)** — all file transfers and chat relay between CLI clients
- **HTTP + WebSocket (TCP)** — web UI only, active in `-sw` mode on port 3888 by default

Both transports share the same in-memory room/file state, so a CLI client and a browser client with the same code are in the same room.

---

## Runtime Modes (CLI Flags)

| Flag | What it does |
|------|-------------|
| `-s <host> <port>` | QUIC-only relay server |
| `-sw [web-host] [web-port] [quic-host] [quic-port]` | Full server: web UI (TCP) + QUIC relay |
| `-f [code] [host] [port] <file>` | Send file(s) through relay |
| `-r <code> [host] [port]` | Receive file from relay by code |
| `-d <file> [host[:port]]` | Direct peer-to-peer send (no relay) |
| `-ds <listen-host> <port>` | Listen for direct peer-to-peer send |
| `-m [code] [host] [port]` | Chat client (relay) — TUI |
| `-mr <code> <host> <port>` | Chat receiver (relay) |

---

## Web UI Features (Browser)

- Upload a file → get a code
- Enter a code → download the file (forced save-as)
- Paste text/scripts and send via code
- Chat room: multiple users connect with same code, broadcast room, Enter to send

### Web API Endpoints

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/upload` | POST | Upload a file |
| `/api/paste` | POST | Send text/script |
| `/api/download` | GET | Download file by code |
| `/ws` | WebSocket | Chat room |

---

## Chat

- **CLI:** TUI built with `tview` + `tcell`, Dracula-style colors
- **Web:** WebSocket broadcast room, "You/Peer" labels, auto-scroll, Enter to send
- Custom secret word as room code for private chats
- Currently client-client-server topology (not pure P2P for chat)

---

## File Transfer

- **One-shot:** file is deleted from server after first download
- Code-based lookup (e.g. `dock42`, `wave21`)
- **Direct mode** (`-d` / `-ds`) bypasses the relay entirely — pure P2P

---

## Key Defaults (Baked into Binary)

| Variable | Default |
|----------|---------|
| `DEFAULT_SERVER_HOST` | `airsend.4rji.com` |
| `DEFAULT_SERVER_PORT` | `443` |
| `FILES_DIR` | `/opt/4rji/airsend` (fallbacks: `./airsend-files`, `$TMPDIR`) |
| QUIC keepalive | 2 minutes |
| QUIC idle timeout | 10 minutes |

---

## Security & Rate Limiting

- TLS certs generated at startup (self-signed), `InsecureSkipVerify: true` — intentional
- Protocol: `"airsend"` over self-signed TLS
- Per-scope + per-IP token bucket rate limiting: `upload`, `paste`, `download`, `download_miss`, `ws`
- Reverse-proxy aware IP resolution: checks `CF-Connecting-IP`, `True-Client-IP`, `X-Real-IP`, `X-Forwarded-For`, RFC 7239 `Forwarded`, then `RemoteAddr`
- Connection events logged to `${logDir}/connections.log`

---

## Architecture Notes

- `quicStreamConn` wraps `*quic.Stream` + `*quic.Conn` to satisfy `net.Conn` — same handler code for QUIC and WebSocket
- `pendingFiles map[code]FileInfo` — one-shot file pickup, deleted on download
- `chatRooms map[code]*ChatRoom` — multi-user broadcast, identical semantics across CLI and web
- Embedded web UI is the `indexHTML` Go string constant in `main.go` — **not** `index.html` at repo root (that is the marketing page)

---

## Visual Style (Existing Site)

- Dark background `#030303`, accents: cyan `#0891b2` and green `#059669`
- Fonts: `Outfit` + `Work Sans`
- Card-based layout with subtle radial gradients

---

## Planned Webpage

- **Format:** Single HTML file (CSS + JS embedded)
- **Style:** Cyberpunk / Neon (dark + purple/fuchsia/cyan accents)
- **Language:** English
- **Sections:**
  1. Hero / Intro
  2. Features (cards)
  3. How it works / Demo (terminal simulator with real commands)
  4. Technical docs (CLI table, API, architecture)
- **No** installation section
