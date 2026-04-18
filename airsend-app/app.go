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

type FileSendResult struct {
	Code     string `json:"code"`
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type FileRecvResult struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	Path     string `json:"path"`
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

// --- QUIC relay dial (shared by chat + file) -------------------------------

func dialRelay(ctx context.Context, addr string) (*quic.Conn, *quic.Stream, error) {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"airsend"},
	}
	quicConf := &quic.Config{
		KeepAlivePeriod: 2 * time.Minute,
		MaxIdleTimeout:  10 * time.Minute,
	}
	qconn, err := quic.DialAddr(ctx, addr, tlsConf, quicConf)
	if err != nil {
		return nil, nil, err
	}
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		_ = qconn.CloseWithError(0, "open stream failed")
		return nil, nil, err
	}
	return qconn, stream, nil
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

	qconn, stream, err := dialRelay(dialCtx, addr)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", addr, err)
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

// --- file transfer over QUIC (mirrors -f / -r modes) -----------------------

// PickFile opens the native file picker and returns the selected absolute path.
// Returns an empty string if the user cancels.
func (a *App) PickFile() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("app not ready")
	}
	return wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Select a file to send",
	})
}

// PickSaveDir opens the native directory picker for choosing a download target.
func (a *App) PickSaveDir() (string, error) {
	if a.ctx == nil {
		return "", fmt.Errorf("app not ready")
	}
	return wailsruntime.OpenDirectoryDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Choose download folder",
	})
}

// FileSend uploads a local file to the relay under the given code.
// If code is empty, one is generated and returned.
func (a *App) FileSend(path, code, host string, port int) (FileSendResult, error) {
	var empty FileSendResult

	info, err := os.Stat(path)
	if err != nil {
		return empty, fmt.Errorf("file not found: %w", err)
	}
	if info.IsDir() {
		return empty, fmt.Errorf("path is a directory")
	}
	return a.sendBody(path, filepath.Base(path), info.Size(), nil, code, host, port)
}

// FileSendText sends a text/script payload as a file under the given code.
func (a *App) FileSendText(text, filename, code, host string, port int) (FileSendResult, error) {
	var empty FileSendResult
	if text == "" {
		return empty, fmt.Errorf("text is empty")
	}
	if strings.TrimSpace(filename) == "" {
		filename = fmt.Sprintf("pasted-%d.txt", time.Now().Unix())
	}
	body := []byte(text)
	return a.sendBody("", filename, int64(len(body)), body, code, host, port)
}

// sendBody performs the FILE SEND flow. Either `path` is set (streams the file)
// or `body` is set (writes the byte slice directly).
func (a *App) sendBody(path, filename string, size int64, body []byte, code, host string, port int) (FileSendResult, error) {
	var empty FileSendResult

	host = strings.TrimSpace(host)
	if host == "" {
		return empty, fmt.Errorf("relay host required")
	}
	if port <= 0 {
		return empty, fmt.Errorf("relay port required")
	}
	code = strings.TrimSpace(code)
	if code == "" {
		code = generateCode()
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	qconn, stream, err := dialRelay(dialCtx, addr)
	if err != nil {
		return empty, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() {
		_ = stream.Close()
		_ = qconn.CloseWithError(0, "done")
	}()

	writer := bufio.NewWriter(stream)
	headers := []string{"FILE SEND", code, filename, strconv.FormatInt(size, 10)}
	for _, h := range headers {
		if _, err := writer.WriteString(h + "\n"); err != nil {
			return empty, fmt.Errorf("send header %q: %w", h, err)
		}
	}
	if err := writer.Flush(); err != nil {
		return empty, fmt.Errorf("flush headers: %w", err)
	}

	if body != nil {
		if _, err := writer.Write(body); err != nil {
			return empty, fmt.Errorf("write body: %w", err)
		}
	} else {
		f, err := os.Open(path)
		if err != nil {
			return empty, fmt.Errorf("open file: %w", err)
		}
		if _, err := io.CopyN(writer, f, size); err != nil {
			_ = f.Close()
			return empty, fmt.Errorf("stream file: %w", err)
		}
		_ = f.Close()
	}
	if err := writer.Flush(); err != nil {
		return empty, fmt.Errorf("flush body: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(5 * time.Minute))
	resp, err := bufio.NewReader(stream).ReadString('\n')
	if err != nil {
		return empty, fmt.Errorf("wait confirmation: %w", err)
	}
	if strings.TrimSpace(resp) != "OK" {
		return empty, fmt.Errorf("server refused: %q", strings.TrimSpace(resp))
	}

	return FileSendResult{Code: code, Filename: filename, Size: size}, nil
}

// FileRecv downloads a file by code to saveDir (defaults to ~/Downloads).
func (a *App) FileRecv(code, saveDir, host string, port int) (FileRecvResult, error) {
	var empty FileRecvResult

	code = strings.TrimSpace(code)
	if code == "" {
		return empty, fmt.Errorf("code required")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return empty, fmt.Errorf("relay host required")
	}
	if port <= 0 {
		return empty, fmt.Errorf("relay port required")
	}
	if strings.TrimSpace(saveDir) == "" {
		saveDir = defaultDownloadsDir()
	}
	if err := os.MkdirAll(saveDir, 0o755); err != nil {
		return empty, fmt.Errorf("prepare save dir: %w", err)
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	qconn, stream, err := dialRelay(dialCtx, addr)
	if err != nil {
		return empty, fmt.Errorf("dial %s: %w", addr, err)
	}
	defer func() {
		_ = stream.Close()
		_ = qconn.CloseWithError(0, "done")
	}()

	writer := bufio.NewWriter(stream)
	if _, err := writer.WriteString("FILE RECV\n" + code + "\n"); err != nil {
		return empty, fmt.Errorf("send headers: %w", err)
	}
	if err := writer.Flush(); err != nil {
		return empty, fmt.Errorf("flush headers: %w", err)
	}

	_ = stream.SetReadDeadline(time.Now().Add(30 * time.Second))
	reader := bufio.NewReader(stream)
	filename, err := reader.ReadString('\n')
	if err != nil {
		return empty, fmt.Errorf("read filename: %w", err)
	}
	filename = strings.TrimSpace(filename)
	if filename == "" || filename == "ERR" {
		return empty, fmt.Errorf("file not available for code %q", code)
	}

	sizeStr, err := reader.ReadString('\n')
	if err != nil {
		return empty, fmt.Errorf("read size: %w", err)
	}
	size, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		return empty, fmt.Errorf("parse size: %w", err)
	}

	outPath := uniquePath(saveDir, filename)
	out, err := os.Create(outPath)
	if err != nil {
		return empty, fmt.Errorf("create file: %w", err)
	}
	_ = stream.SetReadDeadline(time.Time{}) // clear deadline; body can be large
	n, err := io.CopyN(out, reader, size)
	_ = out.Close()
	if err != nil {
		return empty, fmt.Errorf("receive body (%d/%d): %w", n, size, err)
	}

	return FileRecvResult{Filename: filename, Size: size, Path: outPath}, nil
}

// --- helpers ---------------------------------------------------------------

func defaultDownloadsDir() string {
	if home, err := os.UserHomeDir(); err == nil {
		d := filepath.Join(home, "Downloads")
		if info, err := os.Stat(d); err == nil && info.IsDir() {
			return d
		}
		return home
	}
	return os.TempDir()
}

func uniquePath(dir, filename string) string {
	base := filepath.Join(dir, filename)
	if _, err := os.Stat(base); os.IsNotExist(err) {
		return base
	}
	ext := filepath.Ext(filename)
	stem := strings.TrimSuffix(filename, ext)
	for i := 1; i < 10000; i++ {
		candidate := filepath.Join(dir, fmt.Sprintf("%s (%d)%s", stem, i, ext))
		if _, err := os.Stat(candidate); os.IsNotExist(err) {
			return candidate
		}
	}
	return base
}

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
