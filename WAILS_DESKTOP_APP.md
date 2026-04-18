# AirSend Desktop App with Wails

## Architecture Overview

The desktop app is **not a standalone wrapper**. Instead, it's a native UI client that connects to the shared AirSend server (QUIC relay + WebSocket).

```
┌─────────────────────────────────────────────────────────────┐
│                  AirSend Server (Central)                   │
│  airsend -sw localhost 3888 localhost 8443                  │
│  ┌─────────────────────────────────────────────────────┐   │
│  │ Shared State:                                       │   │
│  │ • pendingFiles (map[code]FileInfo)                  │   │
│  │ • chatRooms (map[code]*ChatRoom)                    │   │
│  │ • rateLimiter                                       │   │
│  └─────────────────────────────────────────────────────┘   │
│  ├─ QUIC Listener (UDP, default :443)                      │
│  └─ WebSocket Listener (TCP, default :3888)               │
└─────────────────────────────────────────────────────────────┘
       ▲                      ▲                        ▲
       │                      │                        │
    [CLI Clients]      [Desktop App]            [Web Browser]
    airsend -m         airsend.app                localhost:3888
    airsend -r         (embedded UI)
    airsend -f
```

**Key principle**: All clients (CLI, Desktop App, Web Browser) connect to the **same server instance** and share state. A file uploaded from the CLI can be downloaded via the Desktop App. A chat room created in the app is visible to terminal clients.

---

## Folder Structure

Keep the desktop app **separate but linked**:

```
airsend/
├── main.go                          (CLI entry point)
├── chat-window.go
├── main.go                          (existing, unchanged)
├── WAILS_DESKTOP_APP.md             (this file)
│
└── airsend-app/                     (NEW: Wails project)
    ├── wails.json                   (Wails config)
    ├── app.go                       (Go backend for Wails)
    ├── go.mod
    ├── go.sum
    ├── frontend/
    │   ├── index.html               (embed cyberpunk UI)
    │   ├── style.css
    │   ├── app.js                   (connects to WebSocket)
    │   └── assets/
    └── build/
        └── appicon.png              (logo)
```

**app.go** imports the parent airsend package to reuse code where possible (shared types, constants).

---

## Implementation Plan

### Phase 1: Wails Setup

1. Install Wails (macOS, Linux, Windows):
   ```bash
   go install github.com/wailsapp/wails/v2/cmd/wails@latest
   ```

2. Create the Wails project:
   ```bash
   cd airsend
   wails create -name airsend-app -projecttype vanilla
   cd airsend-app
   ```

3. Initialize Go module (if needed):
   ```bash
   go mod init github.com/4rji/airsend-app
   ```

### Phase 2: Backend (app.go)

`app.go` serves two purposes:
- **Manages lifecycle**: start/stop the server, detect port availability
- **Exposes Go functions to JS** via Wails bindings

```go
package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

type App struct {
	ctx           context.Context
	serverProcess *exec.Cmd
	serverPid     int
}

// Lifecycle hooks
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	// Don't start the server here. User must do it manually or via button.
}

func (a *App) shutdown(ctx context.Context) {
	if a.serverProcess != nil {
		a.serverProcess.Kill()
	}
}

// Exposed Go functions (callable from JS)

// StartServer launches: airsend -sw 127.0.0.1 3888 127.0.0.1 8443
func (a *App) StartServer(webHost string, webPort int, quicHost string, quicPort int) (string, error) {
	// Check if ports are free
	// Launch the main airsend binary with -sw flags
	// Return server URL to JS
}

// StopServer kills the running server
func (a *App) StopServer() error {
	if a.serverProcess != nil {
		return a.serverProcess.Kill()
	}
	return nil
}

// GetServerStatus checks if server is running
func (a *App) GetServerStatus() (map[string]interface{}, error) {
	return map[string]interface{}{
		"running": a.serverProcess != nil,
		"pid":     a.serverPid,
	}, nil
}

// OpenFileDialog (OS native file picker)
func (a *App) OpenFileDialog() (string, error) {
	// Use runtime.EventsOn to call native OS dialogs
	return "", nil
}
```

### Phase 3: Frontend (index.html + app.js)

Reuse the cyberpunk website UI from `cyberpunk-website/index.html`, but adapt it for **app mode**:

**index.html**:
```html
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>AirSend</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <div id="app">
    <!-- Server Control Panel -->
    <div class="server-panel">
      <button id="startServer">Start Server</button>
      <button id="stopServer" disabled>Stop Server</button>
      <div id="serverStatus">Status: Offline</div>
      <div id="serverUrl"></div>
    </div>

    <!-- Tabs: Upload / Chat / Download -->
    <div class="tabs">
      <button class="tab-btn active" data-tab="upload">Upload File</button>
      <button class="tab-btn" data-tab="chat">Chat Room</button>
      <button class="tab-btn" data-tab="download">Download</button>
    </div>

    <!-- Tab Content -->
    <div id="upload" class="tab-content active">
      <input type="file" id="fileInput">
      <button id="uploadBtn">Send File</button>
      <div id="uploadStatus"></div>
    </div>

    <div id="chat" class="tab-content">
      <input type="text" id="roomCode" placeholder="Room code (e.g., neon-lab)">
      <button id="joinChatBtn">Join Room</button>
      <div id="chatArea" style="height: 300px; overflow-y: auto; border: 1px solid #a855f7;"></div>
      <input type="text" id="chatInput" placeholder="Type message...">
      <button id="sendChatBtn">Send</button>
    </div>

    <div id="download" class="tab-content">
      <input type="text" id="downloadCode" placeholder="Enter code">
      <button id="downloadBtn">Download</button>
      <div id="downloadStatus"></div>
    </div>
  </div>

  <script src="wailsjs/runtime.js"></script>
  <script src="app.js"></script>
</body>
</html>
```

**app.js**:
```javascript
import { StartServer, StopServer, GetServerStatus } from '/wailsjs/go/main/App.js';

let wsConn = null;
let serverRunning = false;
const serverUrl = 'ws://127.0.0.1:3888';

// Start Server button
document.getElementById('startServer').addEventListener('click', async () => {
  try {
    const result = await StartServer('127.0.0.1', 3888, '127.0.0.1', 8443);
    serverRunning = true;
    updateUI();
    connectWebSocket();
  } catch (err) {
    alert(`Server start failed: ${err}`);
  }
});

// Stop Server button
document.getElementById('stopServer').addEventListener('click', async () => {
  try {
    await StopServer();
    serverRunning = false;
    updateUI();
    if (wsConn) wsConn.close();
  } catch (err) {
    alert(`Server stop failed: ${err}`);
  }
});

// Connect to WebSocket
function connectWebSocket() {
  wsConn = new WebSocket(serverUrl);
  wsConn.onopen = () => {
    console.log('Connected to AirSend server');
    document.getElementById('serverStatus').textContent = 'Status: Connected';
  };
  wsConn.onmessage = (evt) => {
    // Handle incoming messages
    console.log('Message from server:', evt.data);
  };
  wsConn.onerror = (err) => {
    console.error('WebSocket error:', err);
  };
}

// File Upload
document.getElementById('uploadBtn').addEventListener('click', async () => {
  const fileInput = document.getElementById('fileInput');
  const file = fileInput.files[0];
  if (!file) {
    alert('Select a file first');
    return;
  }

  const formData = new FormData();
  formData.append('file', file);

  try {
    const res = await fetch(`http://127.0.0.1:3888/api/upload`, {
      method: 'POST',
      body: formData,
    });
    const json = await res.json();
    document.getElementById('uploadStatus').textContent = `Code: ${json.code}`;
  } catch (err) {
    alert(`Upload failed: ${err}`);
  }
});

// Chat Room
document.getElementById('joinChatBtn').addEventListener('click', () => {
  const code = document.getElementById('roomCode').value;
  if (!code) {
    alert('Enter a room code');
    return;
  }
  // Send JOIN message to server
  wsConn.send(JSON.stringify({ action: 'join', code }));
});

document.getElementById('sendChatBtn').addEventListener('click', () => {
  const msg = document.getElementById('chatInput').value;
  if (!msg) return;
  wsConn.send(msg + '\n');
  document.getElementById('chatInput').value = '';
});

// Download
document.getElementById('downloadBtn').addEventListener('click', async () => {
  const code = document.getElementById('downloadCode').value;
  if (!code) {
    alert('Enter a code');
    return;
  }

  try {
    const res = await fetch(`http://127.0.0.1:3888/api/download?code=${code}`);
    const blob = await res.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = code;
    a.click();
  } catch (err) {
    alert(`Download failed: ${err}`);
  }
});

function updateUI() {
  document.getElementById('startServer').disabled = serverRunning;
  document.getElementById('stopServer').disabled = !serverRunning;
}

updateUI();
```

**style.css**: Reuse the cyberpunk palette from the website.

```css
:root {
  --bg: #05020f;
  --purple: #a855f7;
  --fuchsia: #d946ef;
  --cyan: #22d3ee;
  --text: #e9e6ff;
  --muted: #9a92c7;
}

* { box-sizing: border-box; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'IBM Plex Sans', system-ui, -apple-system, sans-serif;
  padding: 20px;
}

.server-panel {
  padding: 20px;
  border: 1px solid var(--purple);
  border-radius: 10px;
  margin-bottom: 20px;
}

button {
  padding: 10px 20px;
  background: linear-gradient(135deg, var(--purple), var(--fuchsia));
  color: white;
  border: none;
  border-radius: 8px;
  cursor: pointer;
  margin-right: 10px;
  font-weight: 600;
}

button:hover {
  opacity: 0.9;
}

button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.tabs {
  display: flex;
  gap: 10px;
  margin-bottom: 20px;
}

.tab-btn {
  padding: 8px 16px;
  background: rgba(168, 85, 247, 0.1);
  border: 1px solid var(--purple);
  color: var(--cyan);
}

.tab-btn.active {
  background: linear-gradient(135deg, var(--purple), var(--fuchsia));
  color: white;
}

.tab-content {
  display: none;
  padding: 20px;
  border: 1px solid var(--purple);
  border-radius: 10px;
}

.tab-content.active {
  display: block;
}

input {
  padding: 10px;
  background: rgba(13, 8, 35, 0.7);
  border: 1px solid var(--purple);
  color: var(--text);
  border-radius: 6px;
  margin-bottom: 10px;
  width: 100%;
}

#chatArea {
  margin-bottom: 10px;
  padding: 10px;
  background: rgba(13, 8, 35, 0.5);
  border-radius: 6px;
  color: var(--muted);
  font-size: 14px;
}
```

### Phase 4: Build & Distribution

**Development**:
```bash
cd airsend-app
wails dev
```

This opens the app with hot-reload and dev tools.

**Build for distribution**:
```bash
wails build -o airsend -platform darwin/universal
wails build -o airsend.exe -platform windows/amd64
wails build -o airsend -platform linux/amd64
```

Output:
- macOS: `build/bin/airsend.app`
- Windows: `build/bin/airsend.exe`
- Linux: `build/bin/airsend`

**Create installers** (optional):
- macOS: `.dmg` or `.pkg`
- Windows: NSIS/MSI (WiX)
- Linux: `.deb` or `.rpm`

---

## Compatibility with CLI Clients

**Example workflow** (all clients connected to same server):

1. User starts the desktop app: `airsend.app`
   - App backend starts: `airsend -sw 127.0.0.1 3888 127.0.0.1 8443`
   - Web UI connects via WebSocket

2. Terminal user on another machine:
   ```bash
   airsend -f myfile.txt -host airsend.example.com -port 443
   # Gets code: wave21
   ```

3. Desktop app user:
   - Sees the uploaded file in Downloads tab
   - Enters code `wave21`, downloads it

4. Terminal user opens a chat room:
   ```bash
   airsend -m neon-lab -host airsend.example.com
   ```

5. Desktop app user:
   - Opens Chat tab, enters room code `neon-lab`, joins
   - Both see each other's messages

**All state is shared** because they connect to the same server.

---

## Edge Cases & Considerations

### Port Conflicts
- App tries ports 3888 (web) and 8443 (QUIC) by default
- If busy, UI should allow user to specify alternate ports
- `StartServer(webHost, webPort, quicHost, quicPort)` takes parameters

### External Server Mode
- If user already has a server running on `airsend.example.com:443`
- App could have a "Connect to Remote Server" mode
- Skip the `StartServer` step, just connect to WebSocket at that address

### Permissions
- macOS: may require network permissions (first run)
- Linux: might need `sudo` for ports < 1024 (use high ports instead)

### Auto-start
- Optional: "Start server on app launch" checkbox
- Wails lifecycle hooks: `startup()` could auto-launch if enabled

---

## Next Steps (After Approval)

1. ✅ Create `airsend-app/` folder with Wails scaffolding
2. ✅ Write `app.go` with server lifecycle management
3. ✅ Implement `index.html` + `app.js` + `style.css`
4. ✅ Test locally: `wails dev`
5. ✅ Build for macOS, Windows, Linux
6. ✅ Create distribution packages (.dmg, .exe, .deb)
7. ✅ Document installation (in README.md or separate guide)

---

## References

- [Wails Docs](https://wails.io/)
- [Go bindings to JS](https://wails.io/docs/guides/frontend/)
- [WebSocket API in Go](https://pkg.go.dev/net/http)
- Existing: `cyberpunk-website/index.html` (CSS palette)
