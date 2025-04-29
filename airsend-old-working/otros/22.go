//go:build ignore
// +build ignore

package main

import (
    "bufio"
    "fmt"
    "io"
    "math/rand"
    "net"
    "os"
    "path/filepath"
    "strconv"
    "strings"
    "sync"
    "time"
)

const (
    DEFAULT_SERVER_HOST = "mic2.4rji.com"
    DEFAULT_SERVER_PORT = 443
    LOG_DIR             = "/opt/4rji/airsend"  
    FILES_DIR           = "/opt/4rji/airsend"  
)

type PendingChat struct {
    conn       net.Conn
    logFilename string
}

type FileInfo struct {
    filename string
    filesize int64
    fullPath string
}

var (
    pending         = make(map[string]PendingChat)
    pendingLock     sync.Mutex
    pendingFiles    = make(map[string]FileInfo)
    pendingFilesLock sync.Mutex
    logLock         sync.Mutex
)

func generateCode(length int) string {
    words := []string{
        "casa", "perro", "gato", "sol", "luna",
        "agua", "fuego", "aire", "tierra", "luz",
        "arbol", "flor", "mesa", "silla", "libro",
        "papel", "lapiz", "color", "cielo", "mar",
        "pan", "leche", "cafe", "vino", "jugo",
        "rosa", "azul", "rojo", "verde", "negro",
    } // <-- Faltaba la coma aquí
    
    // Generar 4 números aleatorios entre 0 y 9
    numbers := make([]int, 4)
    for i := 0; i < 4; i++ {
        numbers[i] = rand.Intn(10)
    }
    
    // Combinar palabra y números
    word := words[rand.Intn(len(words))]
    return fmt.Sprintf("%s%d%d%d%d", word, numbers[0], numbers[1], numbers[2], numbers[3])
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
    buf := make([]byte, 4096)
    fmt.Printf("Starting relay: %s\n", direction)
    defer func() {
        fmt.Printf("Relay ending: %s\n", direction)
        src.Close()
    }()

    for {
        src.SetReadDeadline(time.Now().Add(24 * time.Hour))
        n, err := src.Read(buf)
        if n > 0 {
            data := buf[:n]
            fmt.Printf("Relay %s: %d bytes\n", direction, n)
            _, writeErr := dst.Write(data)
            if writeErr != nil {
                fmt.Printf("Relay %s write error: %v\n", direction, writeErr)
                return
            }
            if logFilename != "" {
                logData(logFilename, direction, data)
            }
        }
        if err != nil {
            if err != io.EOF {
                fmt.Printf("Relay %s read error: %v\n", direction, err)
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

    fmt.Printf("Connection with code: %s\n", code)

    pendingLock.Lock()
    chat, exists := pending[code]
    if exists {
        fmt.Printf("Found pending connection for code %s, setting up relay\n", code)
        delete(pending, code)
        pendingLock.Unlock()
        go relay(conn, chat.conn, chat.logFilename, "Client2 -> Client1")
        go relay(chat.conn, conn, chat.logFilename, "Client1 -> Client2")
    } else {
        fmt.Printf("No pending connection for code %s, waiting for peer\n", code)
        if _, err := os.Stat(LOG_DIR); os.IsNotExist(err) {
            os.MkdirAll(LOG_DIR, 0755)
        }
        timestamp := time.Now().Format("20060102_150405")
        logFilename := filepath.Join(LOG_DIR, fmt.Sprintf("session_%s_%s.log", code, timestamp))
        pending[code] = PendingChat{conn: conn, logFilename: logFilename}
        pendingLock.Unlock()
    }
}

func handleClient(conn net.Conn) {
    defer conn.Close()
    reader := bufio.NewReader(conn)
    firstLine, err := readLine(reader)
    if err != nil || firstLine == "" {
        return
    }
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
        return
    } else {
        handleChatOrRelay(conn, firstLine)
    }
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
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        fmt.Printf("Error iniciando servidor en %s: %v\n", addr, err)
        os.Exit(1)
    }
    defer listener.Close()

    // Suppress go runtime warnings (noop, placeholder)
    // Mostrar información de inicio
    fmt.Printf("Servidor escuchando en %s\n", addr)
    fmt.Printf("Directorio de archivos: %s\n", FILES_DIR)

    // Bucle principal del servidor
    for {
        conn, err := listener.Accept()
        if err != nil {
            fmt.Printf("Error aceptando conexión: %v\n", err)
            continue
        }
        fmt.Printf("Nueva conexión desde %s\n", conn.RemoteAddr().String())
        go handleClient(conn)
    }
}

func sendFile(filePath, serverHost string, serverPort int) {
    // Validate file exists and get size
    info, err := os.Stat(filePath)
    if (err != nil) {
        fmt.Println("File not found:", filePath)
        return
    }
    
    code := generateCode(6)
    fmt.Println("\033[94mCode:\033[0m", code)
    
    // Connect to server
    addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
    conn, err := net.Dial("tcp", addr)
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
    
    fmt.Printf("\nSent %s, waiting for confirmation...\n", humanizeBytes(totalWritten))
    
    // Wait for confirmation
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    response, err := bufio.NewReader(conn).ReadString('\n')
    if err != nil {
        fmt.Printf("Error waiting for confirmation: %v\n", err)
        return
    }
    
    if strings.TrimSpace(response) == "OK" {
        fmt.Println("Transfer complete.")
    } else {
        fmt.Printf("Invalid confirmation from server: '%s'\n", strings.TrimSpace(response))
    }
}

func receiveFile(code, serverHost string, serverPort int) {
    addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
    conn, err := net.Dial("tcp", addr)
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
    conn, err := net.Dial("tcp", addr)
    if err != nil {
        fmt.Println("Connection error:", err)
        return
    }
    defer conn.Close()

    // Send initial code with proper newline
    if _, err := conn.Write([]byte(code + "\n")); err != nil {
        fmt.Println("Error sending code:", err)
        return
    }

    // Create channel to signal when receiver goroutine ends
    done := make(chan bool)

    // Start receiver goroutine
    go func() {
        defer func() {
            done <- true
        }()
        
        buf := make([]byte, 4096)
        for {
            n, err := conn.Read(buf)
            if n > 0 {
                fmt.Print(string(buf[:n]))
            }
            if err != nil {
                if err != io.EOF {
                    fmt.Printf("\nRead error: %v\n", err)
                }
                return
            }
        }
    }()

    prompt := "\033[93mType your message ('/exit' to quit):\033[0m "
    fmt.Print(prompt)
    scanner := bufio.NewScanner(os.Stdin)
    for scanner.Scan() {
        line := scanner.Text()
        if line == "/exit" {
            break
        }
        
        // Send message with proper newline
        _, err := conn.Write([]byte(line + "\n"))
        if err != nil {
            fmt.Printf("\nWrite error: %v\n", err)
            break
        }
        fmt.Print(prompt)
    }

    // Wait for receiver to finish
    <-done
}

func updateProgress(addr string, totalBytes, currentBytes int64, startTime time.Time) {
    if os.Args[1] == "-d" || os.Args[1] == "-f" {
        return
    }
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
    conn, err := net.Dial("tcp", addr)
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
    listener, err := net.Listen("tcp", addr)
    if err != nil {
        fmt.Println("Error listening:", err)
        return
    }
    fmt.Printf("Listening on %s...\n", addr)
    for {
        conn, err := listener.Accept()
        if err != nil {
            continue
        }
        go func(c net.Conn) {
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
        }(conn)
    }
}

func printUsage() {
    fmt.Println("\033[92mUsage:\033[0m")
    fmt.Println("  \033[94mServer:\033[0m             sudo airsend -s <host> <port>")
    fmt.Println("  \033[94mSend file:\033[0m          airsend -f <host> <port> <file1> <file2>")
    fmt.Println("  \033[94mReceive file:\033[0m       airsend -r <code> [host] [port]")
    fmt.Println("  \033[94mMessage (send):\033[0m     airsend -m <host> <port>")
    fmt.Println("  \033[94mMessage (recv):\033[0m     airsend -mr <code> <host> <port>")
    fmt.Println("  \033[94mDirect send:\033[0m        airsend -d <file> [target-host] [port]")
    fmt.Println("  \033[94mDirect receive:\033[0m     airsend -ds <listen-host> <port>")
}

func main() {
    rand.Seed(time.Now().UnixNano())
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
        files := []string{}
        
        if len(args) == 0 {
            fmt.Println("Please specify at least one file to send.")
            printUsage()
            os.Exit(1)
        }
        
        // First check if the first argument is a file or IP
        if isValidIP(args[0]) {
            host = args[0]
            if len(args) >= 2 {
                if p, err := strconv.Atoi(args[1]); err == nil {
                    port = p
                    files = args[2:]
                } else {
                    // If port isn't valid, assume it's a file
                    files = args[1:]
                }
            } else {
                fmt.Println("Please specify at least one file to send after IP.")
                printUsage()
                os.Exit(1)
            }
        } else {
            files = args
        }
        
        if len(files) == 0 {
            fmt.Println("Please specify at least one file to send.")
            printUsage()
            os.Exit(1)
        }
        
        for _, filePath := range files {
            sendFile(filePath, host, port)
        }
    case "-r":
        if len(os.Args) < 3 {
            fmt.Println("Please specify the code to receive.")
            printUsage()
            os.Exit(1)
        }
        
        code := os.Args[2]
        host := DEFAULT_SERVER_HOST // Using mic2.4rji.com by default
        port := DEFAULT_SERVER_PORT

        // If there's a third argument and it's an IP address
        if len(os.Args) >= 4 && isValidIP(os.Args[3]) {
            host = os.Args[3]
            // Check if there's a port specified
            if len(os.Args) >= 5 {
                if p, err := strconv.Atoi(os.Args[4]); err == nil {
                    port = p
                }
            }
        }
        
        receiveFile(code, host, port)

    case "-d":
        if len(os.Args) < 3 {
            fmt.Println("Usage: airsend -d file1 [target-host] [port]")
            return
        }
        
        filePath := os.Args[2]
        targetHost := DEFAULT_SERVER_HOST // Using mic2.4rji.com by default
        targetPort := DEFAULT_SERVER_PORT
        
        // If we have a host specified
        if len(os.Args) >= 4 {
            targetHost = os.Args[3]
        }
        
        // If we have a port specified
        if len(os.Args) >= 5 {
            if p, err := strconv.Atoi(os.Args[4]); err == nil {
                targetPort = p
            }
        }
        
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
            if len(os.Args) < 3 {
                fmt.Println("Please specify the pairing code.")
                printUsage()
                os.Exit(1)
            }
            code = os.Args[2]
            host = DEFAULT_SERVER_HOST
            if len(os.Args) >= 4 {
                host = os.Args[3]
            }
            if len(os.Args) >= 5 {
                if p, err := strconv.Atoi(os.Args[4]); err == nil {
                    port = p
                }
            }
        } else {
            if len(os.Args) >= 3 && isValidIP(os.Args[2]) {
                code := generateCode(6)
                fmt.Println("\033[94mCode:\033[0m", code)
                host = os.Args[2]
                if len(os.Args) >= 4 {
                    if p, err := strconv.Atoi(os.Args[3]); err == nil {
                        port = p
                    }
                }
            } else {
                code := generateCode(6)
                fmt.Println("\033[94mCode:\033[0m", code)
                host = DEFAULT_SERVER_HOST
            }
        }
        messageChat(code, host, port)
    
    default:
        fmt.Println("Unknown mode:", mode)
        printUsage()
        os.Exit(1)
    }
}

