# airsend-app

Native desktop client for AirSend. Built with [Wails v2](https://wails.io).

The app is a **native chat client** for the AirSend relay. By default it
connects directly to the public relay at `airsend.4rji.com:443` over QUIC (same
protocol as `airsend -m` / `-mr`), so chat rooms interoperate with the CLI and
with any browser hitting a `-sw` instance on the same network.

Running your own local `airsend -sw` relay is supported but secondary — it
lives inside the ⚙ settings modal, not on the main screen.

## Architecture

```
┌────────────────┐        spawns         ┌───────────────────────────────┐
│ airsend-app    │ ────────────────────▶ │ airsend -sw 127.0.0.1 3888 …  │
│ (Wails webview)│                       │   HTTP :3888  QUIC :8443      │
└────────────────┘  fetch /api + /ws     └───────────────────────────────┘
         ▲                                          ▲
         │ same shared state                        │
         ▼                                          ▼
   browser client                               CLI clients
   (http://127.0.0.1:3888)                      (airsend -m / -f / -r)
```

## Prerequisites

1. **Go 1.23+**
2. **Wails CLI**

   ```bash
   go install github.com/wailsapp/wails/v2/cmd/wails@latest
   ```

   Check `wails doctor` to verify platform dependencies (WebKit on Linux, Xcode
   command-line tools on macOS, WebView2 on Windows).

3. **Built `airsend` binary** in the parent repo — only needed if you intend
   to run a local relay from inside settings:

   ```bash
   cd ..            # into the airsend root
   make build       # produces ./airsend
   ```

   The app looks for `airsend` in this order:
   1. same directory as the app executable
   2. current working directory and its parent
   3. `$PATH`

   Chat itself does NOT need the local binary — it dials the relay directly
   over QUIC from the app process.

## Development

```bash
cd airsend-app
go mod tidy          # pulls quic-go + wails deps (first run only)
wails dev
```

The first `wails dev` run also generates `frontend/dist/wailsjs/` which provides
the JS bindings (`window.go.main.App.*`) used by `app.js`.

## Build

```bash
# macOS (arm64 + amd64)
wails build -platform darwin/universal

# Windows
wails build -platform windows/amd64

# Linux
wails build -platform linux/amd64
```

Artifacts land in `build/bin/`:

- macOS → `airsend-app.app`
- Windows → `airsend-app.exe`
- Linux → `airsend-app`

To ship a turnkey package, drop the `airsend` CLI binary next to the app
executable (same directory) so `findBinary()` resolves it on first launch.

## Notes

- **Ports** default to web `3888` / QUIC `8443`. QUIC on `:443` requires `sudo`
  on most systems — the app uses a high port to avoid that.
- **CORS**: the webview hits `http://127.0.0.1:<webPort>` directly. The `-sw`
  server allows same-host requests out of the box; if you bind the server to a
  non-loopback interface, confirm that the Wails webview can still reach it.
- **External mode**: the app currently manages a local subprocess. To target a
  remote relay, stop the local one and (future work) extend the UI to let
  users enter a remote URL.
- **Shutdown**: closing the window calls `shutdown()` which kills the managed
  subprocess. Files still registered in memory (not yet downloaded) are lost
  — by design, same as `-sw` in the CLI.
