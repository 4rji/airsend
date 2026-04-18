package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx context.Context

	srvMu  sync.Mutex
	cmd    *exec.Cmd
	binary string
	webURL string

	chatMu     sync.Mutex
	chatQConn  *quic.Conn
	chatStream *quic.Stream
	chatWriter *bufio.Writer
	chatCancel context.CancelFunc
	chatCode   string
}

type ServerStatus struct {
	Running bool   `json:"running"`
	PID     int    `json:"pid"`
	WebURL  string `json:"webUrl"`
	Binary  string `json:"binary"`
}

type ChatStatus struct {
	Connected bool   `json:"connected"`
	Code      string `json:"code"`
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

func (a *App) shutdown(ctx context.Context) {
	_ = a.ChatLeave()
	_ = a.StopServer()
}

// --- local server lifecycle ------------------------------------------------

// StartServer spawns `airsend -sw <webHost> <webPort> <quicHost> <quicPort>`.
func (a *App) StartServer(webHost string, webPort int, quicHost string, quicPort int) (string, error) {
	a.srvMu.Lock()
	defer a.srvMu.Unlock()

	if a.cmd != nil && a.cmd.Process != nil {
		return a.webURL, fmt.Errorf("server already running (pid %d)", a.cmd.Process.Pid)
	}

	bin, err := findBinary()
	if err != nil {
		return "", err
	}
	a.binary = bin

	args := []string{
		"-sw",
		webHost, strconv.Itoa(webPort),
		quicHost, strconv.Itoa(quicPort),
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("failed to start airsend: %w", err)
	}

	a.cmd = cmd
	a.webURL = fmt.Sprintf("http://%s:%d", webHost, webPort)

	go a.waitExit(cmd)

	return a.webURL, nil
}

func (a *App) waitExit(cmd *exec.Cmd) {
	err := cmd.Wait()

	a.srvMu.Lock()
	if a.cmd == cmd {
		a.cmd = nil
		a.webURL = ""
	}
	a.srvMu.Unlock()

	msg := "exited"
	if err != nil {
		msg = err.Error()
	}
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "server:stopped", msg)
	}
}

func (a *App) StopServer() error {
	a.srvMu.Lock()
	cmd := a.cmd
	a.srvMu.Unlock()

	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func (a *App) GetServerStatus() ServerStatus {
	a.srvMu.Lock()
	defer a.srvMu.Unlock()

	s := ServerStatus{Binary: a.binary}
	if a.cmd != nil && a.cmd.Process != nil {
		s.Running = true
		s.PID = a.cmd.Process.Pid
		s.WebURL = a.webURL
	}
	return s
}

// --- chat over QUIC (mirrors main.go -m mode) ------------------------------

func (a *App) GenerateCode() string {
	return generateCode()
}

func (a *App) ChatStatus() ChatStatus {
	a.chatMu.Lock()
	defer a.chatMu.Unlock()
	return ChatStatus{Connected: a.chatStream != nil, Code: a.chatCode}
}

// ChatConnect dials the relay over QUIC, opens a stream, sends the code,
// then streams incoming peer lines via the "chat:message" Wails event.
// Returns the effective code used (generated if `code` was empty).
func (a *App) ChatConnect(code, host string, port int) (string, error) {
	a.chatMu.Lock()
	if a.chatStream != nil {
		a.chatMu.Unlock()
		return a.chatCode, fmt.Errorf("already connected to room %q", a.chatCode)
	}
	a.chatMu.Unlock()

	code = strings.TrimSpace(code)
	if code == "" {
		code = generateCode()
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("relay host required")
	}
	if port <= 0 {
		return "", fmt.Errorf("relay port required")
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer dialCancel()

	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"airsend"},
	}
	quicConf := &quic.Config{
		KeepAlivePeriod: 2 * time.Minute,
		MaxIdleTimeout:  10 * time.Minute,
	}

	qconn, err := quic.DialAddr(dialCtx, addr, tlsConf, quicConf)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
	}
	stream, err := qconn.OpenStreamSync(dialCtx)
	if err != nil {
		_ = qconn.CloseWithError(0, "open stream failed")
		return "", fmt.Errorf("open stream: %w", err)
	}

	writer := bufio.NewWriter(stream)
	if _, err := writer.WriteString(code + "\n"); err != nil {
		_ = stream.Close()
		_ = qconn.CloseWithError(0, "send code failed")
		return "", fmt.Errorf("send code: %w", err)
	}
	if err := writer.Flush(); err != nil {
		_ = stream.Close()
		_ = qconn.CloseWithError(0, "flush code failed")
		return "", fmt.Errorf("flush code: %w", err)
	}

	runCtx, runCancel := context.WithCancel(context.Background())

	a.chatMu.Lock()
	a.chatQConn = qconn
	a.chatStream = stream
	a.chatWriter = writer
	a.chatCancel = runCancel
	a.chatCode = code
	a.chatMu.Unlock()

	go a.readChat(runCtx, stream, addr)

	return code, nil
}

func (a *App) readChat(ctx context.Context, stream *quic.Stream, addr string) {
	reader := bufio.NewReader(stream)
	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 {
			msg := strings.TrimRight(line, "\r\n")
			if a.ctx != nil {
				wailsruntime.EventsEmit(a.ctx, "chat:message", msg)
			}
		}
		if err != nil {
			if err != io.EOF && a.ctx != nil {
				wailsruntime.EventsEmit(a.ctx, "chat:error", err.Error())
			}
			break
		}
		select {
		case <-ctx.Done():
			a.cleanupChat()
			return
		default:
		}
	}
	a.cleanupChat()
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "chat:disconnected", addr)
	}
}

func (a *App) cleanupChat() {
	a.chatMu.Lock()
	defer a.chatMu.Unlock()

	if a.chatStream != nil {
		_ = a.chatStream.Close()
	}
	if a.chatQConn != nil {
		_ = a.chatQConn.CloseWithError(0, "chat ended")
	}
	if a.chatCancel != nil {
		a.chatCancel()
	}
	a.chatStream = nil
	a.chatQConn = nil
	a.chatWriter = nil
	a.chatCancel = nil
	a.chatCode = ""
}

func (a *App) ChatSend(text string) error {
	a.chatMu.Lock()
	w := a.chatWriter
	a.chatMu.Unlock()
	if w == nil {
		return fmt.Errorf("not connected")
	}
	if _, err := w.WriteString(text + "\n"); err != nil {
		return err
	}
	return w.Flush()
}

func (a *App) ChatLeave() error {
	a.chatMu.Lock()
	connected := a.chatStream != nil
	a.chatMu.Unlock()
	if !connected {
		return nil
	}
	a.cleanupChat()
	if a.ctx != nil {
		wailsruntime.EventsEmit(a.ctx, "chat:disconnected", "local")
	}
	return nil
}

// --- helpers ---------------------------------------------------------------

var chatCodeWords = []string{
	"dock", "lamp", "mint", "reef", "glow", "bird", "leaf", "sand", "wave", "mist",
	"dust", "wind", "rain", "snow", "star", "pine", "fern", "opal", "jade", "ruby",
	"gear", "bolt", "cord", "plug", "chip", "note", "tune", "beat", "drum", "riff",
}

func generateCode() string {
	word := chatCodeWords[rand.Intn(len(chatCodeWords))]
	return fmt.Sprintf("%s%d%d", word, rand.Intn(10), rand.Intn(10))
}

func findBinary() (string, error) {
	name := "airsend"
	if runtime.GOOS == "windows" {
		name = "airsend.exe"
	}

	if exe, err := os.Executable(); err == nil {
		candidate := filepath.Join(filepath.Dir(exe), name)
		if fileExists(candidate) {
			return candidate, nil
		}
	}

	if cwd, err := os.Getwd(); err == nil {
		candidate := filepath.Join(cwd, name)
		if fileExists(candidate) {
			return candidate, nil
		}
		parent := filepath.Join(cwd, "..", name)
		if fileExists(parent) {
			return parent, nil
		}
	}

	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}

	return "", fmt.Errorf("airsend binary not found — build it first with `make build` in the parent project")
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	return !info.IsDir()
}
