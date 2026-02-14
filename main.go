package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"golang.org/x/net/websocket"
)

const (
	DEFAULT_SERVER_HOST = "airsend.us"
	DEFAULT_SERVER_PORT = 443
	DEFAULT_LOG_DIR     = "/opt/4rji/airsend"
	DEFAULT_FILES_DIR   = "/opt/4rji/airsend"
	CONNECTIONS_LOG     = "connections.log"
)

type PendingChat struct {
	conn         net.Conn
	logFilename  string
	relayStarted bool
	cancelCh     chan bool
	done         chan struct{}
}

type FileInfo struct {
	filename string
	filesize int64
	fullPath string
}

var (
	pending          = make(map[string]PendingChat)
	pendingLock      sync.Mutex
	pendingFiles     = make(map[string]FileInfo)
	pendingFilesLock sync.Mutex
	logLock          sync.Mutex
	connectionLogMu  sync.Mutex
	activeRelays     = make(map[string]bool)
	logDir           = DEFAULT_LOG_DIR
	filesDir         = DEFAULT_FILES_DIR
	webQUICHost      = DEFAULT_SERVER_HOST
	webQUICPort      = DEFAULT_SERVER_PORT
)

// ChatRoom permite más de dos usuarios por código.
type ChatRoom struct {
	code  string
	conns map[net.Conn]struct{}
	mu    sync.Mutex
}

var chatRooms = make(map[string]*ChatRoom)
var chatRoomsLock sync.Mutex

var clientTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
	NextProtos:         []string{"airsend"},
}

var quicConfig = &quic.Config{
	KeepAlivePeriod: 2 * time.Minute,
	MaxIdleTimeout:  10 * time.Minute,
}

type quicStreamConn struct {
	*quic.Stream
	session *quic.Conn
}

func newQUICStreamConn(session *quic.Conn, stream *quic.Stream) *quicStreamConn {
	return &quicStreamConn{Stream: stream, session: session}
}

func (q *quicStreamConn) Close() error {
	return q.Stream.Close()
}

func (q *quicStreamConn) LocalAddr() net.Addr {
	return q.session.LocalAddr()
}

func (q *quicStreamConn) RemoteAddr() net.Addr {
	return q.session.RemoteAddr()
}

func (q *quicStreamConn) SetDeadline(t time.Time) error {
	return q.Stream.SetDeadline(t)
}

func (q *quicStreamConn) SetReadDeadline(t time.Time) error {
	return q.Stream.SetReadDeadline(t)
}

func (q *quicStreamConn) SetWriteDeadline(t time.Time) error {
	return q.Stream.SetWriteDeadline(t)
}

func generateTLSConfig() (*tls.Config, error) {
	key, err := rsa.GenerateKey(crand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 62)
	serialNumber, err := crand.Int(crand.Reader, serialLimit)
	if err != nil {
		return nil, err
	}
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject:      pkix.Name{Organization: []string{"airsend"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
			x509.ExtKeyUsageClientAuth,
		},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(crand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"airsend"},
	}, nil
}

func dialQUIC(addr string) (net.Conn, error) {
	conn, err := quic.DialAddr(context.Background(), addr, clientTLSConfig, quicConfig)
	if err != nil {
		return nil, err
	}
	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		conn.CloseWithError(0, "open stream failed")
		return nil, err
	}
	return newQUICStreamConn(conn, stream), nil
}

func generateCode(length int) string {
	words := []string{
		"dock", "lamp", "mint", "reef", "glow",
		"bird", "leaf", "sand", "wave", "mist",
		"dust", "wind", "rain", "snow", "star",
		"pine", "fern", "opal", "jade", "ruby",
		"gear", "bolt", "cord", "plug", "chip",
		"note", "tune", "beat", "drum", "riff",
	}

	// Generate 2 random numbers between 0 and 9
	numbers := make([]int, 2)
	for i := 0; i < 2; i++ {
		numbers[i] = mrand.Intn(10)
	}

	// Combine word and numbers
	word := words[mrand.Intn(len(words))]
	return fmt.Sprintf("%s%d%d", word, numbers[0], numbers[1])
}

func resolveStorageDir(envName, preferredDir, fallbackName string) string {
	if configured := strings.TrimSpace(os.Getenv(envName)); configured != "" {
		return configured
	}

	if err := os.MkdirAll(preferredDir, 0755); err == nil {
		return preferredDir
	}

	wd, err := os.Getwd()
	if err != nil {
		wd = os.TempDir()
	}
	localFallback := filepath.Join(wd, fallbackName)
	if err := os.MkdirAll(localFallback, 0755); err == nil {
		fmt.Printf("No write access to %s, using %s\n", preferredDir, localFallback)
		return localFallback
	}

	tmpFallback := filepath.Join(os.TempDir(), fallbackName)
	fmt.Printf("No write access to %s, using %s\n", preferredDir, tmpFallback)
	return tmpFallback
}

func configureRuntimePaths() {
	logDir = resolveStorageDir("AIRSEND_LOG_DIR", DEFAULT_LOG_DIR, "airsend-logs")
	filesDir = resolveStorageDir("AIRSEND_FILES_DIR", DEFAULT_FILES_DIR, "airsend-files")
}

func resolveReceiveHost(r *http.Request) string {
	host := strings.TrimSpace(webQUICHost)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = r.Host
		if parsedHost, _, err := net.SplitHostPort(host); err == nil {
			host = parsedHost
		}
		if host == "" {
			host = DEFAULT_SERVER_HOST
		}
	}
	return host
}

func buildReceiveCommand(r *http.Request, code string) (string, int, string) {
	host := resolveReceiveHost(r)
	port := webQUICPort
	if port <= 0 {
		port = DEFAULT_SERVER_PORT
	}
	cmd := fmt.Sprintf("airsend -r %s %s %d", code, host, port)
	return host, port, cmd
}

func isValidIP(address string) bool {
	parts := strings.Split(address, ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		num, err := strconv.Atoi(part)
		if err != nil || num < 0 || num > 255 {
			return false
		}
	}
	return true
}

func logData(logFilename, direction string, data []byte) {
	logLock.Lock()
	defer logLock.Unlock()
	f, err := os.OpenFile(logFilename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()
	header := fmt.Sprintf("\n[%s %s]:\n", time.Now().Format("2006-01-02 15:04:05"), direction)
	f.WriteString(header)
	f.Write(data)
}

func trimForLog(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max] + "..."
}

func normalizeClientIP(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}

	value = strings.Trim(value, "\"'")
	lower := strings.ToLower(value)
	if strings.HasPrefix(lower, "for=") {
		value = strings.TrimSpace(value[4:])
		value = strings.Trim(value, "\"'")
	}
	if strings.EqualFold(value, "unknown") {
		return ""
	}

	// IPv6 in RFC 7239 format: [2001:db8::1]:1234 or [2001:db8::1]
	if strings.HasPrefix(value, "[") {
		if end := strings.Index(value, "]"); end > 1 {
			candidate := value[1:end]
			if ip := net.ParseIP(candidate); ip != nil {
				return ip.String()
			}
			return candidate
		}
	}

	if host, _, err := net.SplitHostPort(value); err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
		return host
	}

	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func firstValidClientIP(values ...string) string {
	for _, raw := range values {
		if raw == "" {
			continue
		}
		for _, part := range strings.Split(raw, ",") {
			if ip := normalizeClientIP(part); ip != "" {
				return ip
			}
		}
	}
	return ""
}

func clientAddressFromRequest(r *http.Request) string {
	if ip := firstValidClientIP(
		r.Header.Get("CF-Connecting-IP"),
		r.Header.Get("True-Client-IP"),
		r.Header.Get("X-Real-IP"),
		r.Header.Get("X-Forwarded-For"),
	); ip != "" {
		return ip
	}

	// RFC 7239 Forwarded: for=1.2.3.4;proto=https
	forwarded := strings.TrimSpace(r.Header.Get("Forwarded"))
	if forwarded != "" {
		for _, segment := range strings.Split(forwarded, ";") {
			keyVal := strings.SplitN(strings.TrimSpace(segment), "=", 2)
			if len(keyVal) == 2 && strings.EqualFold(strings.TrimSpace(keyVal[0]), "for") {
				if ip := firstValidClientIP(keyVal[1]); ip != "" {
					return ip
				}
			}
		}
	}

	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	if ip := normalizeClientIP(r.RemoteAddr); ip != "" {
		return ip
	}
	return "unknown"
}

func httpRemoteDetails(r *http.Request) (string, string) {
	raw := strings.TrimSpace(r.RemoteAddr)
	ip := clientAddressFromRequest(r)
	if ip == "" || ip == "unknown" {
		if host, _, err := net.SplitHostPort(raw); err == nil && host != "" {
			ip = host
		} else if raw != "" {
			ip = raw
		} else {
			ip = "unknown"
		}
	}
	if raw == "" {
		raw = "unknown"
	}
	return ip, raw
}

func logConnectionEvent(transport, remoteAddr, detail string) {
	line := fmt.Sprintf("[%s] transport=%s remote=%s detail=%s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		trimForLog(transport, 32),
		trimForLog(remoteAddr, 128),
		trimForLog(detail, 512),
	)
	fmt.Printf("[CONN] %s", line)

	connectionLogMu.Lock()
	defer connectionLogMu.Unlock()

	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Error creating log dir %s: %v\n", logDir, err)
		return
	}

	logPath := filepath.Join(logDir, CONNECTIONS_LOG)
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		fmt.Printf("Error opening connection log %s: %v\n", logPath, err)
		return
	}
	defer f.Close()

	_, _ = f.WriteString(line)
}

func relay(src, dst net.Conn, logFilename, direction string, wg *sync.WaitGroup) {
	defer wg.Done()
	fmt.Printf("Starting relay: %s from %s to %s\n",
		direction, src.RemoteAddr(), dst.RemoteAddr())
	defer func() {
		fmt.Printf("Relay ending: %s from %s to %s\n",
			direction, src.RemoteAddr(), dst.RemoteAddr())
	}()

	buf := make([]byte, 32*1024) // 32KB buffer

	var totalBytes int64
	startTime := time.Now()
	consecutiveErrors := 0
	maxConsecutiveErrors := 5
	lastActivity := time.Now()

	for {
		// Set a reasonable read deadline
		src.SetReadDeadline(time.Now().Add(5 * time.Minute))

		n, err := src.Read(buf)
		if n > 0 {
			data := buf[:n]
			totalBytes += int64(n)
			lastActivity = time.Now()

			// Log transfer stats
			elapsed := time.Since(startTime).Seconds()
			rate := float64(totalBytes) / elapsed / 1024 // KB/s
			fmt.Printf("Relay %s: %d bytes (Total: %s, Rate: %.2f KB/s)\n",
				direction, n, humanizeBytes(totalBytes), rate)

			// Set a shorter write deadline
			dst.SetWriteDeadline(time.Now().Add(30 * time.Second))

			if _, writeErr := dst.Write(data); writeErr != nil {
				if netErr, ok := writeErr.(net.Error); ok && netErr.Temporary() {
					fmt.Printf("Relay %s temporary write error: %v\n", direction, writeErr)
					time.Sleep(time.Second) // Back off briefly
					consecutiveErrors++
					if consecutiveErrors > maxConsecutiveErrors {
						fmt.Printf("Relay %s too many consecutive write errors\n", direction)
						return
					}
					continue
				}
				fmt.Printf("Relay %s write error: %v\n", direction, writeErr)
				return
			}

			// Reset error counter on successful write
			consecutiveErrors = 0
		}

		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Check for inactivity timeout
				if time.Since(lastActivity) > 10*time.Minute {
					fmt.Printf("Relay %s: no activity for too long, closing\n", direction)
					return
				}
				continue
			}

			if netErr, ok := err.(net.Error); ok && netErr.Temporary() {
				fmt.Printf("Relay %s temporary read error: %v\n", direction, err)
				time.Sleep(time.Second) // Back off briefly
				consecutiveErrors++
				if consecutiveErrors > maxConsecutiveErrors {
					fmt.Printf("Relay %s too many consecutive read errors\n", direction)
					return
				}
				continue
			}

			if err != io.EOF {
				fmt.Printf("Relay %s read error: %v\n", direction, err)
			} else {
				fmt.Printf("Relay %s connection closed by peer\n", direction)
			}
			return
		}
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

func handleFileSend(commandLine string, reader *bufio.Reader, conn net.Conn) {
	defer conn.Close()
	if commandLine != "FILE SEND" {
		fmt.Printf("Invalid command received: '%s'\n", commandLine)
		return
	}

	// Lee el código
	code, err := readLine(reader)
	if err != nil || code == "" {
		fmt.Printf("Error reading code: %v\n", err)
		return
	}

	// Lee el nombre del archivo
	filename, err := readLine(reader)
	if err != nil || filename == "" {
		fmt.Printf("Error reading filename: %v\n", err)
		return
	}

	// Lee el tamaño del archivo
	sizeStr, err := readLine(reader)
	if err != nil {
		fmt.Printf("Error reading size: %v\n", err)
		return
	}

	filesize, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		fmt.Printf("Invalid file size '%s': %v\n", sizeStr, err)
		return
	}
	fmt.Printf("File size: %s\n", humanizeBytes(filesize))

	// Crea el archivo de salida
	serverFilename := fmt.Sprintf("%s_%s", code, filename)
	fullPath := filepath.Join(filesDir, serverFilename)
	file, err := os.Create(fullPath)
	if err != nil {
		fmt.Printf("Error creating file: %v\n", err)
		return
	}
	defer file.Close()

	// Recibe los datos del archivo

	n, err := io.CopyN(file, reader, filesize)
	if err != nil {
		fmt.Printf("\nError receiving file data: %v\n", err)
		return
	}
	if n != filesize {
		fmt.Printf("\nIncomplete file received: got %s, expected %s\n", humanizeBytes(n), humanizeBytes(filesize))
		return
	}
	fmt.Printf("\nFile received successfully (%s)\n", humanizeBytes(n))

	// Guarda la info del archivo para posteriores recepciones
	pendingFilesLock.Lock()
	pendingFiles[code] = FileInfo{filename: filename, filesize: filesize, fullPath: fullPath}
	pendingFilesLock.Unlock()

	// Envía confirmación

	_, err = conn.Write([]byte("OK\n"))
	if err != nil {
		fmt.Printf("Error sending confirmation: %v\n", err)
	} else {

	}
}

// Helper function to find minimum of two int64s
func min(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func humanizeBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.2f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func handleFileRecv(reader *bufio.Reader, conn net.Conn) {
	defer conn.Close()
	code, err := readLine(reader)
	if err != nil || code == "" {
		return
	}

	pendingFilesLock.Lock()
	fileInfo, ok := pendingFiles[code]
	if ok {
		delete(pendingFiles, code)
	}
	pendingFilesLock.Unlock()
	if !ok {
		conn.Write([]byte("ERR\n"))
		return
	}

	conn.Write([]byte(fileInfo.filename + "\n"))
	conn.Write([]byte(fmt.Sprintf("%d\n", fileInfo.filesize)))
	file, err := os.Open(fileInfo.fullPath)
	if err != nil {
		return
	}
	defer file.Close()
	buf := make([]byte, 4096)
	for {
		n, err := file.Read(buf)
		if n > 0 {
			conn.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// handleChatOrRelay returns a channel that closes when the chat session ends (or immediately on error).
func handleChatOrRelay(conn net.Conn, firstLine string) chan struct{} {
	code := strings.TrimSpace(firstLine)
	if code == "" {
		fmt.Println("Empty code received, closing connection")
		conn.Close()
		return nil
	}

	// Join or create room
	chatRoomsLock.Lock()
	room, ok := chatRooms[code]
	if !ok {
		room = &ChatRoom{code: code, conns: make(map[net.Conn]struct{})}
		chatRooms[code] = room
	}
	chatRoomsLock.Unlock()

	room.mu.Lock()
	room.conns[conn] = struct{}{}
	room.mu.Unlock()

	done := make(chan struct{})
	conn.Write([]byte("Chat session started!\n"))

	// Reader: broadcast to others
	go func() {
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					fmt.Printf("Chat read error (%s): %v\n", code, err)
				}
				break
			}
			room.mu.Lock()
			for peer := range room.conns {
				if peer == conn {
					continue
				}
				peer.SetWriteDeadline(time.Now().Add(30 * time.Second))
				if _, werr := peer.Write([]byte(line)); werr != nil {
					fmt.Printf("Chat write error (%s): %v\n", code, werr)
				}
			}
			room.mu.Unlock()
		}
		// cleanup on exit
		room.mu.Lock()
		delete(room.conns, conn)
		empty := len(room.conns) == 0
		room.mu.Unlock()
		if empty {
			chatRoomsLock.Lock()
			delete(chatRooms, code)
			chatRoomsLock.Unlock()
		}
		close(done)
	}()

	return done
}

// handleClient dispatches incoming connections: file transfers or chat relays.
// For chat relays, connection lifecycle is managed by relay functions.
func handleClient(conn net.Conn) {
	remote := conn.RemoteAddr().String()

	// Read the command line (first message)
	reader := bufio.NewReader(conn)
	firstLine, err := readLine(reader)
	if err != nil || firstLine == "" {
		logConnectionEvent("quic", remote, "empty_or_invalid_header")
		conn.Close()
		return
	}

	logConnectionEvent("quic", remote, fmt.Sprintf("first_line=%s", firstLine))
	// File transfer commands
	if strings.HasPrefix(firstLine, "FILE") {
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 2 {
			mode := parts[1]
			if mode == "SEND" {
				logConnectionEvent("quic", remote, "command=FILE SEND")
				handleFileSend("FILE SEND", reader, conn)
				return
			} else if mode == "RECV" {
				logConnectionEvent("quic", remote, "command=FILE RECV")
				handleFileRecv(reader, conn)
				return
			}
		}
		// Unrecognized FILE command
		logConnectionEvent("quic", remote, fmt.Sprintf("command=FILE unknown line=%s", firstLine))
		conn.Close()
		return
	}
	// Chat or relay: do not close here; relay() will clean up
	logConnectionEvent("quic", remote, fmt.Sprintf("command=CHAT code=%s", firstLine))
	handleChatOrRelay(conn, firstLine)
}

func runServer(host string, port int) {
	// Crear directorios necesarios con mejor manejo de errores
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Error creando directorio de logs %s: %v\n", logDir, err)
		os.Exit(1)
	}

	if err := os.MkdirAll(filesDir, 0755); err != nil {
		fmt.Printf("Error creando directorio de archivos %s: %v\n", filesDir, err)
		os.Exit(1)
	}

	// Configurar el servidor
	addr := fmt.Sprintf("%s:%d", host, port)
	tlsConf, err := generateTLSConfig()
	if err != nil {
		fmt.Printf("Error preparando certificados TLS: %v\n", err)
		os.Exit(1)
	}
	listener, err := quic.ListenAddr(addr, tlsConf, quicConfig)
	if err != nil {
		fmt.Printf("Error iniciando servidor QUIC en %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()

	// Suppress go runtime warnings (noop, placeholder)
	// Mostrar información de inicio
	fmt.Printf("Servidor escuchando en %s\n", addr)
	fmt.Printf("Directorio de archivos: %s\n", filesDir)

	// Bucle principal del servidor
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Printf("Error aceptando conexión QUIC: %v\n", err)
			continue
		}
		go func(session *quic.Conn) {
			stream, err := session.AcceptStream(context.Background())
			if err != nil {
				fmt.Printf("Error aceptando stream QUIC: %v\n", err)
				session.CloseWithError(0, "stream error")
				return
			}
			conn := newQUICStreamConn(session, stream)
			fmt.Printf("Nueva conexión desde %s\n", conn.RemoteAddr().String())
			logConnectionEvent("quic", conn.RemoteAddr().String(), "stream_accepted")
			handleClient(conn)
		}(sess)
	}
}

func sanitizeFilename(filename, fallback string) string {
	name := strings.TrimSpace(filename)
	if name == "" {
		name = fallback
	}
	name = filepath.Base(name)
	name = strings.ReplaceAll(name, "\x00", "")
	name = strings.ReplaceAll(name, "/", "_")
	name = strings.ReplaceAll(name, "\\", "_")
	if name == "" || name == "." || name == ".." {
		name = fallback
	}
	return name
}

func normalizeTextToLF(text string) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	return strings.ReplaceAll(text, "\r", "\n")
}

func savePendingFile(code, filename string, src io.Reader) (string, FileInfo, error) {
	normalizedCode := strings.TrimSpace(code)
	if normalizedCode == "" {
		normalizedCode = generateCode(6)
	}

	safeFilename := sanitizeFilename(filename, "script.txt")
	serverFilename := fmt.Sprintf("%s_%s", normalizedCode, safeFilename)
	fullPath := filepath.Join(filesDir, serverFilename)

	dst, err := os.Create(fullPath)
	if err != nil {
		return "", FileInfo{}, err
	}
	defer dst.Close()

	n, err := io.Copy(dst, src)
	if err != nil {
		return "", FileInfo{}, err
	}

	info := FileInfo{
		filename: safeFilename,
		filesize: n,
		fullPath: fullPath,
	}

	pendingFilesLock.Lock()
	pendingFiles[normalizedCode] = info
	pendingFilesLock.Unlock()

	return normalizedCode, info, nil
}

// startWebServer levanta una interfaz HTTP simple para subir/descargar archivos.
// Reutiliza el mismo mapa pendingFiles para interoperar con el flujo CLI.
func startWebServer(addr string) {
	// Asegura que los directorios existen, igual que el servidor QUIC.
	if err := os.MkdirAll(filesDir, 0755); err != nil {
		fmt.Printf("Error creando directorio de archivos %s: %v\n", filesDir, err)
		return
	}
	if err := os.MkdirAll(logDir, 0755); err != nil {
		fmt.Printf("Error creando directorio de logs %s: %v\n", logDir, err)
		return
	}

	mux := http.NewServeMux()

	// Página principal minimalista.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		clientIP, rawRemote := httpRemoteDetails(r)
		logConnectionEvent("http", clientIP, fmt.Sprintf("%s %s raw_remote=%s", r.Method, r.URL.Path, rawRemote))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, indexHTML)
	})

	// Endpoint de subida: acepta multipart/form-data con campo "file" y opcional "code".
	mux.HandleFunc("/api/upload", func(w http.ResponseWriter, r *http.Request) {
		clientIP, rawRemote := httpRemoteDetails(r)
		logConnectionEvent("http", clientIP, fmt.Sprintf("%s %s raw_remote=%s", r.Method, r.URL.Path, rawRemote))
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(32 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		file, header, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "file required", http.StatusBadRequest)
			return
		}
		defer file.Close()

		code, info, err := savePendingFile(r.FormValue("code"), header.Filename, file)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logConnectionEvent("http", clientIP, fmt.Sprintf("upload_saved code=%s file=%s bytes=%d raw_remote=%s", code, info.filename, info.filesize, rawRemote))
		recvHost, recvPort, recvCmd := buildReceiveCommand(r, code)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":      code,
			"filename":  info.filename,
			"bytes":     info.filesize,
			"recv_host": recvHost,
			"recv_port": recvPort,
			"recv_cmd":  recvCmd,
		})
	})

	// Endpoint para pegar texto/script desde web y mandarlo como archivo AirSend.
	mux.HandleFunc("/api/paste", func(w http.ResponseWriter, r *http.Request) {
		clientIP, rawRemote := httpRemoteDetails(r)
		logConnectionEvent("http", clientIP, fmt.Sprintf("%s %s raw_remote=%s", r.Method, r.URL.Path, rawRemote))
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var payload struct {
			Text     string `json:"text"`
			Filename string `json:"filename"`
			Code     string `json:"code"`
		}

		if strings.Contains(r.Header.Get("Content-Type"), "application/json") {
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				http.Error(w, "invalid json payload", http.StatusBadRequest)
				return
			}
		} else {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid form payload", http.StatusBadRequest)
				return
			}
			payload.Text = r.FormValue("text")
			payload.Filename = r.FormValue("filename")
			payload.Code = r.FormValue("code")
		}

		text := normalizeTextToLF(payload.Text)
		if strings.TrimSpace(text) == "" {
			http.Error(w, "text required", http.StatusBadRequest)
			return
		}

		filename := payload.Filename
		if strings.TrimSpace(filename) == "" {
			filename = "script.txt"
		}

		code, info, err := savePendingFile(payload.Code, filename, strings.NewReader(text))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		logConnectionEvent("http", clientIP, fmt.Sprintf("paste_saved code=%s file=%s bytes=%d raw_remote=%s", code, info.filename, info.filesize, rawRemote))
		recvHost, recvPort, recvCmd := buildReceiveCommand(r, code)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"code":         code,
			"filename":     info.filename,
			"bytes":        info.filesize,
			"line_endings": "LF",
			"recv_host":    recvHost,
			"recv_port":    recvPort,
			"recv_cmd":     recvCmd,
		})
	})

	// Endpoint de descarga por código.
	mux.HandleFunc("/api/download", func(w http.ResponseWriter, r *http.Request) {
		clientIP, rawRemote := httpRemoteDetails(r)
		logConnectionEvent("http", clientIP, fmt.Sprintf("%s %s code=%s raw_remote=%s", r.Method, r.URL.Path, r.URL.Query().Get("code"), rawRemote))
		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "code requerido", http.StatusBadRequest)
			return
		}

		pendingFilesLock.Lock()
		fileInfo, ok := pendingFiles[code]
		if ok {
			delete(pendingFiles, code) // consumo único, igual que el flujo CLI
		}
		pendingFilesLock.Unlock()

		if !ok {
			logConnectionEvent("http", clientIP, fmt.Sprintf("download_miss code=%s raw_remote=%s", code, rawRemote))
			http.Error(w, "code not found", http.StatusNotFound)
			return
		}
		logConnectionEvent("http", clientIP, fmt.Sprintf("download_hit code=%s file=%s bytes=%d raw_remote=%s", code, fileInfo.filename, fileInfo.filesize, rawRemote))

		// Force download instead of inline display
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", fileInfo.filename))
		w.Header().Set("Content-Type", "application/octet-stream")
		http.ServeFile(w, r, fileInfo.fullPath)
	})

	// WebSocket chat, compatible con -m/-mr (usa el mismo handleChatOrRelay).
	mux.Handle("/ws", websocket.Handler(func(ws *websocket.Conn) {
		logConnectionEvent("ws", ws.Request().RemoteAddr, fmt.Sprintf("connect path=%s", ws.Request().URL.Path))
		code := ws.Request().URL.Query().Get("code")
		if code == "" {
			logConnectionEvent("ws", ws.Request().RemoteAddr, "connect_rejected missing_code")
			ws.Write([]byte("code query param required\n"))
			ws.Close()
			return
		}
		logConnectionEvent("ws", ws.Request().RemoteAddr, fmt.Sprintf("connect_ok code=%s", code))
		ws.PayloadType = websocket.BinaryFrame
		done := handleChatOrRelay(ws, code)
		if done == nil {
			return
		}
		<-done // mantiene viva la conexión hasta que termine la sesión
	}))

	go func() {
		fmt.Printf("Web UI escuchando en http://%s\n", addr)
		if err := http.ListenAndServe(addr, mux); err != nil {
			fmt.Printf("Web server error: %v\n", err)
		}
	}()
}

const indexHTML = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Airsend Web</title>
<style>
:root{
  --bg:#282a36;
  --panel:#2f3244;
  --panel-2:#343748;
  --text:#f8f8f2;
  --muted:#8a8fa3;
  --accent:#bd93f9;
  --accent-2:#50fa7b;
  --border:#44475a;
}
*{box-sizing:border-box;}
body{
  margin:24px auto;
  padding:0 14px;
  max-width:860px;
  font-family:Inter,system-ui,-apple-system,sans-serif;
  background:radial-gradient(circle at 15% 20%, #31354a 0, rgba(40,42,54,0) 30%),
             radial-gradient(circle at 80% 0%, #2d3042 0, rgba(40,42,54,0) 28%),
             var(--bg);
  color:var(--text);
}
h1,h3{color:var(--text);margin-bottom:12px;}
label{display:block;margin:12px 0 4px;color:var(--muted);font-size:13px;letter-spacing:0.02em;}
input,button,textarea{
  width:100%;
  padding:10px 12px;
  font-size:14px;
  border-radius:10px;
  border:1px solid var(--border);
  background:var(--panel);
  color:var(--text);
  outline:none;
}
input:focus,textarea:focus{border-color:var(--accent);}
button{
  width:auto;
  cursor:pointer;
  background:linear-gradient(135deg,var(--accent),#9a7bff);
  color:#12121a;
  border:none;
  font-weight:600;
  transition:transform 120ms ease, box-shadow 120ms ease;
  box-shadow:0 8px 18px rgba(0,0,0,0.25);
}
button:hover{transform:translateY(-1px);box-shadow:0 10px 22px rgba(0,0,0,0.28);}
button:active{transform:translateY(0);}
.card{
  background:var(--panel-2);
  border:1px solid var(--border);
  border-radius:14px;
  padding:16px;
  margin-bottom:20px;
  box-shadow:0 10px 30px rgba(0,0,0,0.25);
}
.file-stack{
  display:grid;
  grid-template-columns:repeat(2,minmax(0,1fr));
  gap:12px;
}
.file-block{
  background:rgba(0,0,0,0.14);
  border:1px solid var(--border);
  border-radius:12px;
  padding:12px;
}
.file-block h4{
  margin:2px 0 10px;
  font-size:14px;
  color:var(--text);
}
.btn-upload{
  background:linear-gradient(135deg,#50fa7b,#3ddf68);
  color:#0a1a10;
}
.btn-download{
  background:linear-gradient(135deg,#8be9fd,#6dd6ff);
  color:#09121a;
}
#status,#pasteStatus{margin:10px 0;color:var(--accent-2);}
.form-actions{
  margin-top:10px;
  display:flex;
  align-items:center;
  gap:12px;
  flex-wrap:wrap;
}
#uploadCode{margin-top:0;}
#pasteCodeOut{margin-top:0;}
.upload-meta{
  line-height:1.15;
}
.upload-meta-label{
  font-size:10px;
  letter-spacing:0.08em;
  text-transform:uppercase;
  color:#8bf9a9;
}
.upload-meta-file{
  margin-top:2px;
  font-size:11px;
  color:#8bf9a9;
}
.result-code{
  display:inline;
  padding:0;
  border-radius:0;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  font-size:21px;
  font-weight:800;
  letter-spacing:0.08em;
  color:#ffffff;
  background:none;
}
.code-label{
  font-size:13px;
  color:#d6d9e6;
  margin-right:6px;
  vertical-align:baseline;
}
#pasteText{
  min-height:180px;
  font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  line-height:1.45;
}
#chatLog{
  background:var(--panel);
  border:1px solid var(--border);
  color:var(--text);
  min-height:240px;
  max-height:360px;
  overflow:auto;
  white-space:pre-wrap;
}
.chat-row{
  margin-top:10px;
  display:flex;
  gap:8px;
}
#chatInput{
  border-radius:10px 0 0 10px;
  width:78%;
}
#sendBtn{
  border-radius:0 10px 10px 0;
  width:22%;
}
a{color:var(--accent);}
@media (max-width:700px){
  body{margin:16px auto;padding:0 10px;}
  .file-stack{grid-template-columns:1fr;}
  .chat-row{flex-direction:column;}
  #chatInput,#sendBtn{width:100%;border-radius:10px;}
}
</style>
</head><body>
<h1>Airsend Web</h1>
<div class="card">
  <h3>Files</h3>
  <div class="file-stack">
    <div class="file-block">
      <h4>Upload File</h4>
      <form id="uploadForm">
        <label>File</label><input name="file" type="file" required>
        <label>Code (optional to reuse)</label><input name="code" placeholder="e.g. rio42">
        <div class="form-actions">
          <button class="btn-upload" type="submit">Upload</button>
          <div id="uploadCode"></div>
        </div>
      </form>
      <p id="status"></p>
    </div>
    <div class="file-block">
      <h4>Download File</h4>
      <form id="downloadForm">
        <label>Code</label><input id="downloadCode" name="code" required>
        <button class="btn-download" type="submit">Download</button>
      </form>
    </div>
  </div>
</div>

<div class="card">
  <h3>Paste Script / Text</h3>
  <form id="pasteForm">
    <label>Filename (optional)</label><input id="pasteFilename" name="filename" placeholder="script.sh">
    <label>Code (optional to reuse)</label><input id="pasteCode" name="code" placeholder="e.g. wave21">
    <label>Text to send</label><textarea id="pasteText" name="text" required></textarea>
    <div class="form-actions">
      <button type="submit">Send text and generate code</button>
      <div id="pasteCodeOut"></div>
    </div>
  </form>
  <p id="pasteStatus"></p>
  <a id="pasteDownloadLink" href="#" style="display:none;">Download this file now</a>
</div>

<div class="card">
  <h3>Chat</h3>
  <form id="chatForm">
    <label>Code</label><input id="chatCode" required>
    <button type="button" id="connectBtn">Connect</button>
  </form>
  <div style="margin:12px 0;">
    <textarea id="chatLog" rows="14" readonly></textarea>
    <div class="chat-row">
      <textarea id="chatInput" rows="3" placeholder="Type message"></textarea>
      <button id="sendBtn" type="button">Send</button>
    </div>
  </div>
</div>
<script>
const statusEl = document.getElementById('status');
const uploadCodeEl = document.getElementById('uploadCode');
const pasteCodeOutEl = document.getElementById('pasteCodeOut');
const pasteStatusEl = document.getElementById('pasteStatus');
const pasteDownloadLink = document.getElementById('pasteDownloadLink');
const downloadCodeInput = document.getElementById('downloadCode');
const escapeHtml = (value) => String(value ?? '').replace(/[&<>"']/g, (ch) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));

const parseApiResponse = async (response) => {
  const raw = await response.text();
  try {
    return { ok: response.ok, data: JSON.parse(raw), raw };
  } catch (_) {
    return { ok: response.ok, data: null, raw };
  }
};

document.getElementById('uploadForm').onsubmit = async (e) => {
  e.preventDefault();
  const data = new FormData(e.target);
  statusEl.textContent = 'Uploading...';
  uploadCodeEl.innerHTML = '';
  try {
    const response = await fetch('/api/upload', { method:'POST', body:data });
    const parsed = await parseApiResponse(response);
    if (!parsed.ok || !parsed.data) {
      statusEl.textContent = parsed.raw || 'Upload failed';
      uploadCodeEl.innerHTML = '';
      return;
    }
    downloadCodeInput.value = parsed.data.code;
    const safeFile = escapeHtml(parsed.data.filename || '');
    const safeCode = escapeHtml(parsed.data.code || '');
    statusEl.innerHTML = '<div class="upload-meta"><div class="upload-meta-label">UPLOADED</div><div class="upload-meta-file">' + safeFile + '</div></div>';
    uploadCodeEl.innerHTML = '<span class="code-label">Code:</span><span class="result-code">' + safeCode + '</span>';
  } catch(err) {
    statusEl.textContent = 'Error: ' + err;
    uploadCodeEl.innerHTML = '';
  }
};

document.getElementById('pasteForm').onsubmit = async (e) => {
  e.preventDefault();
  pasteStatusEl.textContent = 'Sending text...';
  pasteDownloadLink.style.display = 'none';
  pasteCodeOutEl.innerHTML = '';

  const payload = {
    filename: document.getElementById('pasteFilename').value,
    code: document.getElementById('pasteCode').value,
    text: document.getElementById('pasteText').value,
  };

  try {
    const response = await fetch('/api/paste', {
      method:'POST',
      headers:{ 'Content-Type':'application/json' },
      body: JSON.stringify(payload),
    });
    const parsed = await parseApiResponse(response);
    if (!parsed.ok || !parsed.data) {
      pasteStatusEl.textContent = parsed.raw || 'Send failed';
      return;
    }

    downloadCodeInput.value = parsed.data.code;
    pasteStatusEl.textContent = '';
    const safeCode = escapeHtml(parsed.data.code || '');
    pasteCodeOutEl.innerHTML = '<span class="code-label">Code:</span><span class="result-code">' + safeCode + '</span>';
    pasteDownloadLink.href = '/api/download?code=' + encodeURIComponent(parsed.data.code);
    pasteDownloadLink.style.display = 'inline';
  } catch(err) {
    pasteStatusEl.textContent = 'Error: ' + err;
    pasteCodeOutEl.innerHTML = '';
  }
};

document.getElementById('downloadForm').onsubmit = (e) => {
  e.preventDefault();
  const code = new FormData(e.target).get('code');
  window.location = '/api/download?code=' + encodeURIComponent(code);
};

let ws;
const log = document.getElementById('chatLog');
const input = document.getElementById('chatInput');
const appendLog = (prefix, text) => {
  log.value += prefix + text + '\n';
  log.scrollTop = log.scrollHeight;
};

document.getElementById('connectBtn').onclick = () => {
  const code = document.getElementById('chatCode').value.trim();
  if (!code) return alert('Code required');
  if (ws) ws.close();
  const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
  ws = new WebSocket(proto + location.host + '/ws?code=' + encodeURIComponent(code));
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => log.value += 'Connected\n';
  ws.onmessage = (ev) => {
    const text = typeof ev.data === 'string' ? ev.data : new TextDecoder().decode(ev.data);
    appendLog('Peer: ', text.trim());
  };
  ws.onclose = () => log.value += 'Disconnected\n';
  ws.onerror = (err) => log.value += 'Error: ' + err + '\n';
};

const sendMsg = () => {
  if (!ws || ws.readyState !== WebSocket.OPEN) return alert('Not connected');
  const msg = input.value;
  if (!msg.trim()) return;
  ws.send(new TextEncoder().encode(msg + '\n'));
  appendLog('You: ', msg.trim());
  input.value = '';
};

document.getElementById('sendBtn').onclick = sendMsg;
input.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMsg();
  }
});
</script>
</body></html>`

func sendFile(filePath, serverHost string, serverPort int, codeOverride string) {
	// Validate file exists and get size
	info, err := os.Stat(filePath)
	if err != nil {
		fmt.Println("File not found:", filePath)
		return
	}

	var code string
	if codeOverride != "" {
		code = codeOverride
		fmt.Println("\033[94mCode:\033[0m", code)
	} else {
		code = generateCode(6)
		fmt.Println("\033[94mCode:\033[0m", code)
	}

	// Connect to server
	addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
	conn, err := dialQUIC(addr)
	if err != nil {
		fmt.Println("Connection error:", err)
		return
	}
	defer conn.Close()

	// Refresh per-write deadlines while transferring so slow/large sends don't hit a fixed total timeout.
	const writeTimeout = 30 * time.Second

	// Send headers with buffered writer
	writer := bufio.NewWriter(conn)
	headers := []string{
		"FILE SEND",
		code,
		filepath.Base(filePath),
		fmt.Sprintf("%d", info.Size()),
	}

	for _, header := range headers {
		_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := writer.WriteString(header + "\n"); err != nil {
			fmt.Printf("Error sending header '%s': %v\n", header, err)
			return
		}
	}
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := writer.Flush(); err != nil {
		fmt.Printf("Error flushing headers: %v\n", err)
		return
	}

	// Send file content with progress bar
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	totalWritten := int64(0)
	startTime := time.Now()

	// Create a buffered reader for the file
	reader := bufio.NewReader(file)
	buf := make([]byte, 4096)

	fmt.Printf("Sending file: %s (%s)\n", filepath.Base(filePath), humanizeBytes(info.Size()))

	for totalWritten < info.Size() {
		n, err := reader.Read(buf)
		if n > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			written, writeErr := writer.Write(buf[:n])
			if writeErr != nil {
				fmt.Printf("\nError sending file data: %v\n", writeErr)
				return
			}
			totalWritten += int64(written)

			// Use the common updateProgress function
			updateProgress(addr, info.Size(), totalWritten, startTime)
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("\nError reading file: %v\n", err)
				return
			}
			break
		}
	}

	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err := writer.Flush(); err != nil {
		fmt.Printf("\nError flushing file data: %v\n", err)
		return
	}

	fmt.Printf("\nSent %s, waiting for confirmation... \033[94mCode:\033[0m %s\n", humanizeBytes(totalWritten), code)

	// Wait for confirmation
	conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
	response, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		fmt.Printf("Error waiting for confirmation: %v\n", err)
		return
	}

	if strings.TrimSpace(response) == "OK" {
		fmt.Println("Transfer complete. \033[94mCode:\033[0m", code)
	} else {
		fmt.Printf("Invalid confirmation from server: '%s'\n", strings.TrimSpace(response))
	}
}

func receiveFile(code, serverHost string, serverPort int) {
	addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
	conn, err := dialQUIC(addr)
	if err != nil {
		fmt.Println("Connection error:", err)
		return
	}
	defer conn.Close()
	writer := bufio.NewWriter(conn)
	writer.WriteString("FILE RECV\n")
	writer.WriteString(code + "\n")
	writer.Flush()

	reader := bufio.NewReader(conn)
	filename, err := readLine(reader)
	if err != nil || filename == "ERR" || filename == "" {
		fmt.Println("File not available on server.")
		return
	}
	sizeStr, err := readLine(reader)
	if err != nil {
		fmt.Println("Error reading file size.")
		return
	}
	filesize, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
	if err != nil {
		fmt.Println("Error reading file size:", err)
		return
	}
	fmt.Printf("Receiving file: %s (%s)\n", filename, humanizeBytes(filesize))
	outFile, err := os.Create(filename)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer outFile.Close()
	remaining := filesize
	buf := make([]byte, 4096)
	totalRead := int64(0)
	startTime := time.Now()
	for remaining > 0 {
		n, err := reader.Read(buf)
		if n > 0 {
			outFile.Write(buf[:n])
			totalRead += int64(n)
			remaining -= int64(n)

			// Use the common updateProgress function
			updateProgress(conn.RemoteAddr().String(), filesize, totalRead, startTime)
		}
		if err != nil {
			if err != io.EOF {
				fmt.Printf("\nError receiving file data: %v\n", err)
			}
			break
		}
	}
	fmt.Printf("\nFile saved as: %s (%s)\n", filename, humanizeBytes(totalRead))
}

func messageChat(code, serverHost string, serverPort int) {
	addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
	fmt.Printf("Connecting to %s...\n", addr)

	// Retry connection with exponential backoff
	var conn net.Conn
	var err error
	maxRetries := 3
	retryDelay := 2 * time.Second

	for i := 0; i < maxRetries; i++ {
		conn, err = dialQUIC(addr)
		if err == nil {
			break
		}
		fmt.Printf("Connection attempt %d failed: %v\n", i+1, err)
		if i < maxRetries-1 {
			time.Sleep(retryDelay)
			retryDelay *= 2
		}
	}
	if err != nil {
		fmt.Printf("Failed to connect after %d attempts: %v\n", maxRetries, err)
		return
	}
	defer conn.Close()

	fmt.Printf("Connected to %s\n", addr)

	// Send initial code
	fmt.Printf("Sending code: %s\n", code)
	writer := bufio.NewWriter(conn)
	if _, err := writer.WriteString(code + "\n"); err != nil {
		fmt.Printf("Error sending code: %v\n", err)
		return
	}
	if err := writer.Flush(); err != nil {
		fmt.Printf("Error flushing code: %v\n", err)
		return
	}

	// Create channel to signal when receiver goroutine ends
	done := make(chan bool)

	// Start receiver goroutine
	go func() {
		defer func() {
			done <- true
		}()

		reader := bufio.NewReader(conn)
		for {
			// Set read deadline
			conn.SetReadDeadline(time.Now().Add(5 * time.Minute))

			line, err := reader.ReadString('\n')
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if err != io.EOF {
					fmt.Printf("\nConnection error: %v\n", err)
				}
				return
			}
			fmt.Printf("Received: %s", line)
		}
	}()

	// Main loop for sending messages
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Type your message ('/exit' to quit): ")
	for scanner.Scan() {
		text := scanner.Text()
		if text == "/exit" {
			fmt.Println("Exiting chat.")
			return
		}

		// Retry logic for broken pipe errors
		for retries := 0; retries < 3; retries++ {
			if _, err := writer.WriteString(text + "\n"); err != nil {
				if strings.Contains(err.Error(), "broken pipe") {
					fmt.Printf("Broken pipe error, retrying (%d/3)...\n", retries+1)
					time.Sleep(2 * time.Second) // Wait before retrying
					continue
				}
				fmt.Printf("Error sending message: %v\n", err)
				return
			}
			if err := writer.Flush(); err != nil {
				if strings.Contains(err.Error(), "broken pipe") {
					fmt.Printf("Broken pipe error, retrying (%d/3)...\n", retries+1)
					time.Sleep(2 * time.Second) // Wait before retrying
					continue
				}
				fmt.Printf("Error flushing message: %v\n", err)
				return
			}
			break // Exit retry loop on success
		}
		fmt.Print("Type your message ('/exit' to quit): ")
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Scanner error: %v\n", err)
	}

	// Wait for receiver to finish
	<-done
}

func updateProgress(addr string, totalBytes, currentBytes int64, startTime time.Time) {
	percent := float64(currentBytes) / float64(totalBytes) * 100
	elapsed := time.Since(startTime).Seconds()
	speed := float64(currentBytes) / 1024 / elapsed
	barWidth := 50
	filled := int(percent / (100.0 / float64(barWidth)))

	bar := strings.Repeat("█", filled) + strings.Repeat(" ", barWidth-filled)

	// Move cursor to beginning of line and clear it
	fmt.Print("\r\033[2K")

	// Print progress without newline
	fmt.Printf("%s %3.0f%% %s %s/%s %.0fkB/s",
		addr,
		percent,
		bar,
		humanizeBytes(currentBytes),
		humanizeBytes(totalBytes),
		speed)
}

func directSend(filePath, targetHost string, targetPort int) {
	info, err := os.Stat(filePath)
	if err != nil {
		fmt.Println("File not found:", filePath)
		return
	}
	addr := fmt.Sprintf("%s:%d", targetHost, targetPort)
	conn, err := dialQUIC(addr)
	if err != nil {
		fmt.Println("Connection error:", err)
		return
	}
	defer conn.Close()

	// Refresh per-write deadlines while transferring so slow/large sends don't hang indefinitely.
	const writeTimeout = 30 * time.Second

	writer := bufio.NewWriter(conn)
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	writer.WriteString(filepath.Base(filePath) + "\n")
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	writer.WriteString(fmt.Sprintf("%d\n", info.Size()))
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	writer.Flush()

	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}
	defer file.Close()

	totalWritten := int64(0)
	startTime := time.Now()
	buf := make([]byte, 4096)

	fmt.Printf("Sending file: %s (%s)\n", filepath.Base(filePath), humanizeBytes(info.Size()))

	for totalWritten < info.Size() {
		n, err := file.Read(buf)
		if n > 0 {
			_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			written, writeErr := conn.Write(buf[:n])
			if writeErr != nil {
				fmt.Printf("\nError sending file data: %v\n", writeErr)
				return
			}
			totalWritten += int64(written)
			updateProgress(addr, info.Size(), totalWritten, startTime)
		}
		if err != nil {
			break
		}
	}
	fmt.Printf("\nFile sent successfully (%s)\n", humanizeBytes(totalWritten))
}

func directReceive(listenHost string, listenPort int) {
	addr := fmt.Sprintf("%s:%d", listenHost, listenPort)
	tlsConf, err := generateTLSConfig()
	if err != nil {
		fmt.Println("Error preparando certificados TLS:", err)
		return
	}
	listener, err := quic.ListenAddr(addr, tlsConf, quicConfig)
	if err != nil {
		fmt.Println("Error escuchando en QUIC:", err)
		return
	}
	fmt.Printf("Listening on %s...\n", addr)
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Printf("Error aceptando conexión QUIC: %v\n", err)
			continue
		}
		go func(session *quic.Conn) {
			stream, err := session.AcceptStream(context.Background())
			if err != nil {
				fmt.Printf("Error aceptando stream QUIC: %v\n", err)
				session.CloseWithError(0, "stream error")
				return
			}
			c := newQUICStreamConn(session, stream)
			defer c.Close()
			reader := bufio.NewReader(c)
			filename, err := readLine(reader)
			if err != nil || filename == "" {
				fmt.Println("No file specified. Waiting for the next connection...")
				return
			}
			sizeStr, err := readLine(reader)
			if err != nil {
				fmt.Println("Error reading file size.")
				return
			}
			filesize, err := strconv.ParseInt(strings.TrimSpace(sizeStr), 10, 64)
			if err != nil {
				fmt.Println("Error reading file size:", err)
				return
			}

			fmt.Printf("Receiving file: %s (%s)\n", filename, humanizeBytes(filesize))
			outFile, err := os.Create(filename)
			if err != nil {
				fmt.Println("Error creating file:", err)
				return
			}
			defer outFile.Close()

			totalRead := int64(0)
			startTime := time.Now()
			buf := make([]byte, 4096)

			for totalRead < filesize {
				n, err := reader.Read(buf)
				if n > 0 {
					outFile.Write(buf[:n])
					totalRead += int64(n)
					updateProgress(c.RemoteAddr().String(), filesize, totalRead, startTime)
				}
				if err != nil {
					break
				}
			}
			fmt.Printf("\nFile received successfully (%s)\n", humanizeBytes(totalRead))
		}(sess)
	}
}

func printUsage() {
	fmt.Println("\033[92mUsage:\033[0m")
	fmt.Println("  \033[94mServer:\033[0m             sudo airsend -s <host> <port>")
	fmt.Println("  \033[94mSend file:\033[0m          airsend -f [<code>] [<host>] [<port>] <file1> [<file2> ...]")
	fmt.Println("  \033[94mSend file DIRECT:\033[0m          airsend -f IP Port FILE")
	fmt.Println("  \033[94mReceive file DIRECT:\033[0m       airsend -r <code> IP Port ")
	fmt.Println("  \033[94mReceive file:\033[0m       airsend -r <code> [<host>] [ Port ]")
	fmt.Println("  \033[94mMessage (send):\033[0m     airsend -m [<code>] [<host>] [ Port ]")
	fmt.Println("  \033[94mMessage (recv):\033[0m     airsend -mr <code> <host> Port ")
	fmt.Println("  \033[94mDirect send:\033[0m        airsend -d <file> [target-host[:port]]")
	fmt.Println("  \033[94mDirect receive:\033[0m     airsend -ds <listen-host> <port>")
	fmt.Println("  \033[94mServer + web:\033[0m      airsend -sw [web-host] [web-port] [quic-host] [quic-port]")
	fmt.Println("                          defaults: web 0.0.0.0:3888, quic 0.0.0.0:443")
}

func main() {
	mrand.Seed(time.Now().UnixNano())
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	mode := os.Args[1]
	switch mode {
	case "-s":
		configureRuntimePaths()
		host := DEFAULT_SERVER_HOST
		port := DEFAULT_SERVER_PORT
		if len(os.Args) >= 3 {
			host = os.Args[2]
		}
		if len(os.Args) >= 4 {
			if p, err := strconv.Atoi(os.Args[3]); err == nil {
				port = p
			}
		}
		runServer(host, port)
	case "-sw":
		configureRuntimePaths()
		webHost := "0.0.0.0"
		webPort := 3888
		quicHost := webHost             // por defecto escucha en la misma IP que el web
		quicPort := DEFAULT_SERVER_PORT // 443

		if len(os.Args) >= 3 {
			webHost = os.Args[2]
			quicHost = webHost // si no se pasa quicHost, igual al webHost
		}
		if len(os.Args) >= 4 {
			if p, err := strconv.Atoi(os.Args[3]); err == nil {
				webPort = p
			}
		}
		if len(os.Args) >= 5 {
			quicHost = os.Args[4]
		}
		if len(os.Args) >= 6 {
			if p, err := strconv.Atoi(os.Args[5]); err == nil {
				quicPort = p
			}
		}

		webQUICHost = quicHost
		webQUICPort = quicPort
		go runServer(quicHost, quicPort)
		startWebServer(fmt.Sprintf("%s:%d", webHost, webPort))
		select {} // block forever
	case "-f":
		args := os.Args[2:]
		host := DEFAULT_SERVER_HOST
		port := DEFAULT_SERVER_PORT
		var codeOverride string
		var files []string

		if len(args) == 0 {
			fmt.Println("Please specify at least one file to send.")
			printUsage()
			os.Exit(1)
		}

		idx := 0
		// Detect code override: if first arg is not an IP and not an existing file, treat as code
		if !isValidIP(args[0]) {
			if _, err := os.Stat(args[0]); os.IsNotExist(err) {
				codeOverride = args[0]
				idx = 1
			}
		}
		// Detect host (IP) override
		if len(args) > idx && isValidIP(args[idx]) {
			host = args[idx]
			idx++
			// Optional port override
			if len(args) > idx {
				if p, err := strconv.Atoi(args[idx]); err == nil {
					port = p
					idx++
				}
			}
		}
		// Remaining args are files
		files = args[idx:]

		if len(files) == 0 {
			fmt.Println("Please specify at least one file to send.")
			printUsage()
			os.Exit(1)
		}
		// Send each file with optional code override
		for _, filePath := range files {
			sendFile(filePath, host, port, codeOverride)
		}
	case "-r":
		// Receive mode: syntax -r <code> [<host>] [<port>]
		if len(os.Args) < 3 {
			fmt.Println("Usage: airsend -r <code> [<host>] [<port>]")
			printUsage()
			os.Exit(1)
		}
		args := os.Args[2:]
		code := args[0]
		host := DEFAULT_SERVER_HOST
		port := DEFAULT_SERVER_PORT
		if len(args) >= 2 {
			// If second arg is numeric, treat as port; else host
			if p, err := strconv.Atoi(args[1]); err == nil {
				port = p
			} else {
				host = args[1]
				if len(args) >= 3 {
					if p2, err2 := strconv.Atoi(args[2]); err2 == nil {
						port = p2
					} else {
						fmt.Println("Invalid port number:", args[2])
						printUsage()
						os.Exit(1)
					}
				}
			}
		}
		fmt.Printf("Receiving with: host=%s, code=%s, port=%d\n", host, code, port)
		receiveFile(code, host, port)
	case "-d":
		if len(os.Args) < 3 {
			fmt.Println("Usage: airsend -d <file> [target-host[:port]]")
			fmt.Println("   or: airsend -d <target-host[:port]> <file>")
			return
		}

		var filePath string
		targetHost := DEFAULT_SERVER_HOST // Default to mic2.4rji.com
		targetPort := DEFAULT_SERVER_PORT

		// Determine if first argument is a file or host:port
		firstArg := os.Args[2]
		if strings.Contains(firstArg, ":") || isValidIP(firstArg) {
			// First argument is host or host:port
			if len(os.Args) < 4 {
				fmt.Println("Please specify a file to send after host")
				return
			}

			// Parse host and optional port
			if strings.Contains(firstArg, ":") {
				parts := strings.Split(firstArg, ":")
				targetHost = parts[0]
				if len(parts) == 2 {
					if p, err := strconv.Atoi(parts[1]); err == nil {
						targetPort = p
					} else {
						fmt.Println("Invalid port number:", parts[1])
						return
					}
				}
			} else {
				targetHost = firstArg
			}

			filePath = os.Args[3]
		} else {
			// First argument is the file
			filePath = firstArg

			// If a target host (with optional port) is specified
			if len(os.Args) >= 4 {
				hostPort := os.Args[3]
				if strings.Contains(hostPort, ":") {
					parts := strings.Split(hostPort, ":")
					targetHost = parts[0]
					if len(parts) == 2 {
						if p, err := strconv.Atoi(parts[1]); err == nil {
							targetPort = p
						} else {
							fmt.Println("Invalid port number:", parts[1])
							return
						}
					}
				} else {
					targetHost = hostPort
				}
			}
		}

		// Display the target host and port
		fmt.Printf("Sending file to %s:%d\n", targetHost, targetPort)

		// Send the file
		directSend(filePath, targetHost, targetPort)

	case "-ds":
		listenHost := "0.0.0.0"
		listenPort := DEFAULT_SERVER_PORT
		if len(os.Args) >= 3 {
			listenHost = os.Args[2]
		}
		if len(os.Args) >= 4 {
			if p, err := strconv.Atoi(os.Args[3]); err == nil {
				listenPort = p
			}
		}
		directReceive(listenHost, listenPort)

	case "-m", "-mr":
		var code, host string
		port := DEFAULT_SERVER_PORT

		if mode == "-mr" {
			// Receive chat mode: pairing code provided
			if len(os.Args) < 3 {
				fmt.Println("Please specify the pairing code.")
				printUsage()
				os.Exit(1)
			}
			code = os.Args[2]
			host = DEFAULT_SERVER_HOST
			// Optional host and port override
			if len(os.Args) >= 4 {
				host = os.Args[3]
				if len(os.Args) >= 5 {
					if p, err := strconv.Atoi(os.Args[4]); err == nil {
						port = p
					} else {
						fmt.Println("Invalid port number:", os.Args[4])
						printUsage()
						os.Exit(1)
					}
				}
			}
		} else {
			// Send chat mode
			// Determine if first arg is host override or code override
			if len(os.Args) >= 3 && isValidIP(os.Args[2]) {
				// Host (IP) override, generate a new code
				host = os.Args[2]
				if len(os.Args) >= 4 {
					if p, err := strconv.Atoi(os.Args[3]); err == nil {
						port = p
					} else {
						fmt.Println("Invalid port number:", os.Args[3])
						printUsage()
						os.Exit(1)
					}
				}
				code = generateCode(6)
				fmt.Println("\033[94mCode:\033[0m", code)
			} else if len(os.Args) >= 3 {
				// Code override provided
				code = os.Args[2]
				host = DEFAULT_SERVER_HOST
				if len(os.Args) >= 4 {
					host = os.Args[3]
				}
				if len(os.Args) >= 5 {
					if p, err := strconv.Atoi(os.Args[4]); err == nil {
						port = p
					} else {
						fmt.Println("Invalid port number:", os.Args[4])
						printUsage()
						os.Exit(1)
					}
				}
			} else {
				// No overrides: use defaults and generate a code
				host = DEFAULT_SERVER_HOST
				code = generateCode(6)
				fmt.Println("\033[94mCode:\033[0m", code)
			}
		}
		// Connect to server for chat
		addr := fmt.Sprintf("%s:%d", host, port)
		fmt.Printf("Connecting to %s...\n", addr)
		conn, err := dialQUIC(addr)
		if err != nil {
			fmt.Printf("Connection error: %v\n", err)
			return
		}
		defer conn.Close()
		fmt.Printf("Connected to %s\n", addr)
		// Send initial code
		writer := bufio.NewWriter(conn)
		if _, err := writer.WriteString(code + "\n"); err != nil {
			fmt.Printf("Error sending code: %v\n", err)
			return
		}
		if err := writer.Flush(); err != nil {
			fmt.Printf("Error flushing code: %v\n", err)
			return
		}
		// Launch chat UI with pairing code displayed
		RunChatUI(conn, code)

	default:
		fmt.Println("Unknown mode:", mode)
		printUsage()
		os.Exit(1)
	}
}
