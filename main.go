package main

import (
	"bufio"
	"context"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	DEFAULT_SERVER_HOST = "cc.4rji.com"
	DEFAULT_SERVER_PORT = 443
	LOG_DIR             = "/opt/4rji/airsend"
	FILES_DIR           = "/opt/4rji/airsend"
)

type PendingChat struct {
	conn         net.Conn
	logFilename  string
	relayStarted bool
	cancelCh     chan bool
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
	activeRelays     = make(map[string]bool)
)

var clientTLSConfig = &tls.Config{
	InsecureSkipVerify: true,
	NextProtos:         []string{"airsend"},
}

type quicStreamConn struct {
	quic.Stream
	session quic.Connection
}

func newQUICStreamConn(session quic.Connection, stream quic.Stream) *quicStreamConn {
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
	conn, err := quic.DialAddr(context.Background(), addr, clientTLSConfig, nil)
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
		"home", "dog", "cat", "sun", "moon",
		"water", "fire", "air", "earth", "light",
		"tree", "rose", "desk", "chair", "book",
		"note", "pen", "red", "sky", "sea",
		"bread", "milk", "tea", "wine", "juice",
		"pink", "blue", "green", "gold", "black",
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

func relay(src, dst net.Conn, logFilename, direction string) {
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
	fullPath := filepath.Join(FILES_DIR, serverFilename)
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

func handleChatOrRelay(conn net.Conn, firstLine string) {
	code := strings.TrimSpace(firstLine)
	if code == "" {
		fmt.Println("Empty code received, closing connection")
		conn.Close()
		return
	}

	fmt.Printf("Connection with code: %s from %s\n", code, conn.RemoteAddr())

	// Check for a waiting peer
	pendingLock.Lock()
	chat, exists := pending[code]
	if exists {
		fmt.Printf("Found pending connection for code %s, setting up relay\n", code)
		// Signal waiting keep-alive goroutine to stop
		if chat.cancelCh != nil {
			chat.cancelCh <- true
		}
		delete(pending, code)
		pendingLock.Unlock()

		// Send confirmation to both clients
		fmt.Printf("Sending confirmation to both clients\n")
		if _, err := chat.conn.Write([]byte("Chat session started!\n")); err != nil {
			fmt.Printf("Error sending confirmation to first client: %v\n", err)
		}
		if _, err := conn.Write([]byte("Chat session started!\n")); err != nil {
			fmt.Printf("Error sending confirmation to second client: %v\n", err)
		}

		// Setup relay in both directions
		go relay(conn, chat.conn, chat.logFilename, "Client2 -> Client1")
		go relay(chat.conn, conn, chat.logFilename, "Client1 -> Client2")
	} else {
		fmt.Printf("No pending connection for code %s, waiting for peer\n", code)
		if _, err := os.Stat(LOG_DIR); os.IsNotExist(err) {
			os.MkdirAll(LOG_DIR, 0755)
		}
		timestamp := time.Now().Format("20060102_150405")
		logFilename := filepath.Join(LOG_DIR, fmt.Sprintf("session_%s_%s.log", code, timestamp))

		// Initialize cancel channel and store pending chat
		cancelCh := make(chan bool)
		pending[code] = PendingChat{conn: conn, logFilename: logFilename, cancelCh: cancelCh}
		pendingLock.Unlock()

		// Send waiting message to client
		if _, err := conn.Write([]byte("Waiting for peer to connect...\n")); err != nil {
			fmt.Printf("Error sending waiting message to client: %v\n", err)
			pendingLock.Lock()
			delete(pending, code)
			pendingLock.Unlock()
			conn.Close()
			return
		}

		// Start keep-alive for first client while waiting
		go func(p PendingChat) {
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-p.cancelCh:
					return
				case <-ticker.C:
					if _, err := p.conn.Write([]byte("Still waiting for peer...\n")); err != nil {
						fmt.Printf("Error sending keep-alive to client with code %s: %v\n", code, err)
						pendingLock.Lock()
						delete(pending, code)
						pendingLock.Unlock()
						p.conn.Close()
						return
					}
				}
			}
		}(pending[code])
	}
}

// handleClient dispatches incoming connections: file transfers or chat relays.
// For chat relays, connection lifecycle is managed by relay functions.
func handleClient(conn net.Conn) {
	// Read the command line (first message)
	reader := bufio.NewReader(conn)
	firstLine, err := readLine(reader)
	if err != nil || firstLine == "" {
		conn.Close()
		return
	}
	// File transfer commands
	if strings.HasPrefix(firstLine, "FILE") {
		parts := strings.Split(firstLine, " ")
		if len(parts) >= 2 {
			mode := parts[1]
			if mode == "SEND" {
				handleFileSend("FILE SEND", reader, conn)
				return
			} else if mode == "RECV" {
				handleFileRecv(reader, conn)
				return
			}
		}
		// Unrecognized FILE command
		conn.Close()
		return
	}
	// Chat or relay: do not close here; relay() will clean up
	handleChatOrRelay(conn, firstLine)
}

func runServer(host string, port int) {
	// Crear directorios necesarios con mejor manejo de errores
	if err := os.MkdirAll(LOG_DIR, 0755); err != nil {
		fmt.Printf("Error creando directorio de logs %s: %v\n", LOG_DIR, err)
		os.Exit(1)
	}

	if err := os.MkdirAll(FILES_DIR, 0755); err != nil {
		fmt.Printf("Error creando directorio de archivos %s: %v\n", FILES_DIR, err)
		os.Exit(1)
	}

	// Configurar el servidor
	addr := fmt.Sprintf("%s:%d", host, port)
	tlsConf, err := generateTLSConfig()
	if err != nil {
		fmt.Printf("Error preparando certificados TLS: %v\n", err)
		os.Exit(1)
	}
	listener, err := quic.ListenAddr(addr, tlsConf, nil)
	if err != nil {
		fmt.Printf("Error iniciando servidor QUIC en %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer listener.Close()

	// Suppress go runtime warnings (noop, placeholder)
	// Mostrar información de inicio
	fmt.Printf("Servidor escuchando en %s\n", addr)
	fmt.Printf("Directorio de archivos: %s\n", FILES_DIR)

	// Bucle principal del servidor
	for {
		sess, err := listener.Accept(context.Background())
		if err != nil {
			fmt.Printf("Error aceptando conexión QUIC: %v\n", err)
			continue
		}
		go func(session quic.Connection) {
			stream, err := session.AcceptStream(context.Background())
			if err != nil {
				fmt.Printf("Error aceptando stream QUIC: %v\n", err)
				session.CloseWithError(0, "stream error")
				return
			}
			conn := newQUICStreamConn(session, stream)
			fmt.Printf("Nueva conexión desde %s\n", conn.RemoteAddr().String())
			handleClient(conn)
		}(sess)
	}
}

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

	// Set timeouts
	conn.SetWriteDeadline(time.Now().Add(30 * time.Second))

	// Send headers with buffered writer
	writer := bufio.NewWriter(conn)
	headers := []string{
		"FILE SEND",
		code,
		filepath.Base(filePath),
		fmt.Sprintf("%d", info.Size()),
	}

	for _, header := range headers {
		if _, err := writer.WriteString(header + "\n"); err != nil {
			fmt.Printf("Error sending header '%s': %v\n", header, err)
			return
		}
	}
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

	writer := bufio.NewWriter(conn)
	writer.WriteString(filepath.Base(filePath) + "\n")
	writer.WriteString(fmt.Sprintf("%d\n", info.Size()))
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
	listener, err := quic.ListenAddr(addr, tlsConf, nil)
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
		go func(session quic.Connection) {
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
