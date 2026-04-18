(() => {
  const $ = (id) => document.getElementById(id);

  const DEFAULTS = {
    relayHost: "airsend.4rji.com",
    relayPort: 443,
    webHost: "127.0.0.1",
    webPort: 3888,
    quicHost: "127.0.0.1",
    quicPort: 8443,
  };
  const SETTINGS_KEY = "airsend.settings.v2";

  const loadSettings = () => {
    try {
      const raw = localStorage.getItem(SETTINGS_KEY);
      if (!raw) return { ...DEFAULTS };
      return { ...DEFAULTS, ...JSON.parse(raw) };
    } catch {
      return { ...DEFAULTS };
    }
  };

  const saveSettings = (s) => {
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(s)); } catch {}
  };

  const state = {
    settings: loadSettings(),
    chat: { connected: false, code: "" },
    server: { running: false, pid: 0, webUrl: "" },
  };

  // --- chat log helpers ------------------------------------------------------

  const chatMsg = (kind, tag, text) => {
    const area = $("chatArea");
    const row = document.createElement("div");
    row.className = `msg ${kind}`;
    if (tag) {
      const t = document.createElement("span");
      t.className = "tag";
      t.textContent = tag;
      row.appendChild(t);
    }
    row.appendChild(document.createTextNode(text));
    area.appendChild(row);
    area.scrollTop = area.scrollHeight;
  };

  const clearChat = () => {
    $("chatArea").innerHTML = "";
  };

  // --- chat connection -------------------------------------------------------

  const setChatUI = () => {
    const { connected, code } = state.chat;
    $("statusText").textContent = connected
      ? `connected · ${code}`
      : "disconnected";
    $("codeText").textContent = code || "—";
    $("copyCodeBtn").disabled = !code;
    $("joinCode").disabled = connected;
    $("joinBtn").disabled = connected;
    $("leaveBtn").disabled = !connected;
    $("chatInput").disabled = !connected;
    $("chatInput").placeholder = connected
      ? "type a message and press enter"
      : "join a room to start chatting";
  };

  const connect = async () => {
    const userCode = $("joinCode").value.trim();
    const { relayHost, relayPort } = state.settings;

    chatMsg("sys", "", `connecting to ${relayHost}:${relayPort}…`);
    try {
      const code = await window.go.main.App.ChatConnect(
        userCode,
        relayHost,
        relayPort,
      );
      state.chat = { connected: true, code };
      setChatUI();
      chatMsg("sys", "", `joined room ${code}`);
      $("chatInput").focus();
    } catch (e) {
      chatMsg("sys", "", `connect failed: ${e}`);
    }
  };

  const disconnect = async () => {
    try { await window.go.main.App.ChatLeave(); } catch {}
    state.chat = { connected: false, code: "" };
    setChatUI();
  };

  $("joinBtn").addEventListener("click", connect);
  $("leaveBtn").addEventListener("click", disconnect);
  $("joinCode").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !state.chat.connected) connect();
  });

  $("copyCodeBtn").addEventListener("click", async () => {
    if (!state.chat.code) return;
    try {
      await navigator.clipboard.writeText(state.chat.code);
      chatMsg("sys", "", "code copied");
    } catch {
      chatMsg("sys", "", "copy failed");
    }
  });

  // --- chat send -------------------------------------------------------------

  const sendChat = async () => {
    if (!state.chat.connected) return;
    const input = $("chatInput");
    const text = input.value;
    if (!text) return;
    try {
      await window.go.main.App.ChatSend(text);
      chatMsg("you", "you", text);
      input.value = "";
    } catch (e) {
      chatMsg("sys", "", `send failed: ${e}`);
    }
  };

  $("chatInput").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendChat();
  });

  // --- wails events ---------------------------------------------------------

  if (window.runtime?.EventsOn) {
    window.runtime.EventsOn("chat:message", (line) => {
      chatMsg("peer", "peer", String(line));
    });
    window.runtime.EventsOn("chat:disconnected", () => {
      if (state.chat.connected) chatMsg("sys", "", "disconnected from relay");
      state.chat = { connected: false, code: "" };
      setChatUI();
    });
    window.runtime.EventsOn("chat:error", (err) => {
      chatMsg("sys", "", `chat error: ${err}`);
    });
    window.runtime.EventsOn("server:stopped", (msg) => {
      state.server = { running: false, pid: 0, webUrl: "" };
      refreshServerUI();
      console.log("local server stopped:", msg);
    });
  }

  // --- tabs ------------------------------------------------------------------

  const activateTab = (name) => {
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.classList.toggle("active", b.dataset.tab === name);
    });
    document.querySelectorAll(".view").forEach((v) => {
      v.classList.toggle("active", v.id === `view-${name}`);
    });
    // input bar only visible on chat tab
    $("inputBar").style.display = name === "chat" ? "" : "none";
    if (name === "chat" && state.chat.connected) $("chatInput").focus();
    refreshServerUI();
  };

  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => activateTab(btn.dataset.tab));
  });

  // --- file transfer over QUIC relay ----------------------------------------

  const fileState = {
    pickedPath: "",
    saveDir: "",
  };

  const updateRelayNotes = () => {
    const { relayHost, relayPort } = state.settings;
    const note = `via ${relayHost}:${relayPort}`;
    ["uploadRelayNote", "pasteRelayNote", "downloadRelayNote"].forEach((id) => {
      const el = $(id);
      if (el) el.textContent = note;
    });
  };

  const appendLog = (id, text) => {
    const el = $(id);
    el.textContent += (el.textContent ? "\n" : "") + text;
    el.scrollTop = el.scrollHeight;
  };

  const basename = (p) => p.split(/[\\/]/).pop() || p;
  const humanBytes = (n) => {
    if (n < 1024) return `${n}B`;
    const units = ["KB", "MB", "GB", "TB"];
    let v = n / 1024, i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return `${v.toFixed(2)}${units[i]}`;
  };

  $("pickFileBtn").addEventListener("click", async () => {
    try {
      const path = await window.go.main.App.PickFile();
      if (!path) return;
      fileState.pickedPath = path;
      $("pickedFile").textContent = basename(path);
    } catch (e) {
      appendLog("uploadStatus", `pick failed: ${e}`);
    }
  });

  $("uploadBtn").addEventListener("click", async () => {
    if (!fileState.pickedPath) return alert("choose a file first");
    const { relayHost, relayPort } = state.settings;
    const code = $("sendFileCode").value.trim();
    $("uploadBtn").disabled = true;
    appendLog("uploadStatus", `uploading ${basename(fileState.pickedPath)}…`);
    try {
      const r = await window.go.main.App.FileSend(
        fileState.pickedPath,
        code,
        relayHost,
        relayPort,
      );
      appendLog(
        "uploadStatus",
        `done\ncode: ${r.code}\nfilename: ${r.filename}\nsize: ${humanBytes(r.size)}`,
      );
    } catch (e) {
      appendLog("uploadStatus", `upload failed: ${e}`);
    } finally {
      $("uploadBtn").disabled = false;
    }
  });

  $("pasteBtn").addEventListener("click", async () => {
    const text = $("pasteBody").value;
    if (!text) return alert("nothing to send");
    const { relayHost, relayPort } = state.settings;
    const filename = $("pasteFilename").value.trim();
    const code = $("pasteCode").value.trim();
    $("pasteBtn").disabled = true;
    appendLog("pasteStatus", `sending text (${humanBytes(new Blob([text]).size)})…`);
    try {
      const r = await window.go.main.App.FileSendText(
        text,
        filename,
        code,
        relayHost,
        relayPort,
      );
      appendLog(
        "pasteStatus",
        `done\ncode: ${r.code}\nfilename: ${r.filename}\nsize: ${humanBytes(r.size)}`,
      );
    } catch (e) {
      appendLog("pasteStatus", `send failed: ${e}`);
    } finally {
      $("pasteBtn").disabled = false;
    }
  });

  $("pickSaveDirBtn").addEventListener("click", async () => {
    try {
      const dir = await window.go.main.App.PickSaveDir();
      if (!dir) return;
      fileState.saveDir = dir;
      $("saveDirLabel").textContent = dir;
    } catch (e) {
      appendLog("downloadStatus", `pick failed: ${e}`);
    }
  });

  $("downloadBtn").addEventListener("click", async () => {
    const code = $("downloadCode").value.trim();
    if (!code) return alert("enter a code");
    const { relayHost, relayPort } = state.settings;
    $("downloadBtn").disabled = true;
    appendLog("downloadStatus", `downloading ${code}…`);
    try {
      const r = await window.go.main.App.FileRecv(
        code,
        fileState.saveDir,
        relayHost,
        relayPort,
      );
      appendLog(
        "downloadStatus",
        `saved: ${r.path}\nsize: ${humanBytes(r.size)}`,
      );
    } catch (e) {
      appendLog("downloadStatus", `download failed: ${e}`);
    } finally {
      $("downloadBtn").disabled = false;
    }
  });

  // --- keyboard shortcuts ---------------------------------------------------

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      if (!$("settingsModal").hidden) {
        closeSettings();
      } else if (
        document.querySelector(".view.active")?.id === "view-chat"
      ) {
        clearChat();
      }
    }
  });

  // --- settings modal --------------------------------------------------------

  const fillSettingsForm = (s) => {
    $("relayHost").value = s.relayHost;
    $("relayPort").value = s.relayPort;
    $("webHost").value = s.webHost;
    $("webPort").value = s.webPort;
    $("quicHost").value = s.quicHost;
    $("quicPort").value = s.quicPort;
  };

  const openSettings = () => {
    fillSettingsForm(state.settings);
    $("settingsModal").hidden = false;
  };

  const closeSettings = () => {
    $("settingsModal").hidden = true;
  };

  $("settingsBtn").addEventListener("click", openSettings);
  $("settingsClose").addEventListener("click", closeSettings);

  $("settingsModal").addEventListener("click", (e) => {
    if (e.target.id === "settingsModal") closeSettings();
  });

  $("settingsReset").addEventListener("click", () => {
    fillSettingsForm(DEFAULTS);
  });

  $("settingsSave").addEventListener("click", () => {
    const next = {
      relayHost: $("relayHost").value.trim() || DEFAULTS.relayHost,
      relayPort: parseInt($("relayPort").value, 10) || DEFAULTS.relayPort,
      webHost: $("webHost").value.trim() || DEFAULTS.webHost,
      webPort: parseInt($("webPort").value, 10) || DEFAULTS.webPort,
      quicHost: $("quicHost").value.trim() || DEFAULTS.quicHost,
      quicPort: parseInt($("quicPort").value, 10) || DEFAULTS.quicPort,
    };
    state.settings = next;
    saveSettings(next);
    closeSettings();
  });

  // --- local server (inside settings) ---------------------------------------

  const refreshServerUI = () => {
    const { running, pid, webUrl } = state.server;
    $("startServer").disabled = running;
    $("stopServer").disabled = !running;
    $("serverUrl").textContent = running
      ? `${webUrl} (pid ${pid || "?"})`
      : "not running";
    if (typeof updateServerNotes === "function") updateServerNotes();
  };

  const refreshServerStatus = async () => {
    if (!window.go?.main?.App?.GetServerStatus) return;
    try {
      const s = await window.go.main.App.GetServerStatus();
      state.server = {
        running: !!s.running,
        pid: s.pid || 0,
        webUrl: s.webUrl || "",
      };
      refreshServerUI();
    } catch (e) {
      console.warn("GetServerStatus failed", e);
    }
  };

  $("startServer").addEventListener("click", async () => {
    const { webHost, webPort, quicHost, quicPort } = state.settings;
    try {
      const url = await window.go.main.App.StartServer(
        webHost,
        webPort,
        quicHost,
        quicPort,
      );
      state.server = { running: true, pid: 0, webUrl: url };
      refreshServerUI();
      await refreshServerStatus();
    } catch (e) {
      alert(`start failed: ${e}`);
    }
  });

  $("stopServer").addEventListener("click", async () => {
    try { await window.go.main.App.StopServer(); } catch (e) {
      alert(`stop failed: ${e}`);
    }
    state.server = { running: false, pid: 0, webUrl: "" };
    refreshServerUI();
  });

  // --- relay health ----------------------------------------------------------

  const relayDot   = $("relayHealth");
  const relayLabel = $("relayLabel");

  const checkRelayHealth = async () => {
    if (!window.go?.main?.App?.CheckRelayHealth) return;
    const { relayHost, relayPort } = state.settings;
    relayDot.className  = "relay-dot checking";
    relayLabel.textContent = "checking…";
    relayLabel.style.color = "";
    try {
      const ok = await window.go.main.App.CheckRelayHealth(relayHost, relayPort);
      relayDot.className     = `relay-dot ${ok ? "online" : "offline"}`;
      relayLabel.textContent = ok ? "online" : "offline";
      relayLabel.style.color = ok ? "var(--lime)" : "var(--danger)";
      relayDot.title = `${relayHost}:${relayPort}`;
    } catch {
      relayDot.className     = "relay-dot offline";
      relayLabel.textContent = "offline";
      relayLabel.style.color = "var(--danger)";
    }
  };

  // re-check when settings change (host/port may have changed)
  const origSave = $("settingsSave").onclick;
  $("settingsSave").addEventListener("click", () => setTimeout(checkRelayHealth, 200));

  // --- boot ------------------------------------------------------------------

  fillSettingsForm(state.settings);
  setChatUI();
  refreshServerUI();
  refreshServerStatus();
  checkRelayHealth();
  setInterval(checkRelayHealth, 30_000);

  // restore code if backend says we're already connected (e.g. reload during dev)
  if (window.go?.main?.App?.ChatStatus) {
    window.go.main.App.ChatStatus().then((cs) => {
      if (cs && cs.connected) {
        state.chat = { connected: true, code: cs.code };
        setChatUI();
      }
    }).catch(() => {});
  }
})();
