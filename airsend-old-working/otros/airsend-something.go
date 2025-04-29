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
    letters := "abcdefghijklmnopqrstuvwxyz"
    code := make([]byte, length)
    for i := range code {
        code[i] = letters[rand.Intn(len(letters))]
    }
    return string(code)
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

func handleFileSend(conn net.Conn) {
    defer conn.Close()
    reader := bufio.NewReader(conn)
    
    // Read file info with additional debugging
    code, err := readLine(reader)
    if err != nil || code == "" {
        fmt.Printf("Error reading code: %v\n", err)
        return
    }
    fmt.Printf("Received code: %s\n", code)
    
    filename, err := readLine(reader)
    if err != nil || filename == "" {
        fmt.Printf("Error reading filename: %v\n", err)
        return
    }
    fmt.Printf("Received filename: %s\n", filename)
    
    sizeStr, err := readLine(reader)
    if err != nil {
        fmt.Printf("Error reading size string: %v\n", err)
        return
    }
    fmt.Printf("Received size string: '%s'\n", sizeStr)
    
    // Validate size string format
    sizeStr = strings.TrimSpace(sizeStr)
    if !strings.ContainsAny(sizeStr, "0123456789") {
        fmt.Printf("Invalid size format: '%s'\n", sizeStr)
        return
    }
    
    filesize, err := strconv.ParseInt(sizeStr, 10, 64)
    if err != nil {
        fmt.Printf("Invalid file size '%s': %v\n", sizeStr, err)
        return
    }

    // Ensure directory exists
    if err := os.MkdirAll(FILES_DIR, 0755); err != nil {
        fmt.Printf("Error creating directory: %v\n", err)
        return
    }

    // Create and write file
    serverFilename := fmt.Sprintf("%s_%s", code, filename)
    fullPath := filepath.Join(FILES_DIR, serverFilename)
    
    file, err := os.Create(fullPath)
    if err != nil {
        fmt.Printf("Error creating file: %v\n", err)
        return
    }
    defer file.Close()

    // Read file data
    remaining := filesize
    buf := make([]byte, 4096)
    for remaining > 0 {
        n, err := reader.Read(buf)
        if n > 0 {
            if _, err := file.Write(buf[:n]); err != nil {
                fmt.Printf("Error writing file: %v\n", err)
                return
            }
            remaining -= int64(n)
        }
        if err != nil {
            if err != io.EOF {
                fmt.Printf("Error reading file data: %v\n", err)
            }
            break
        }
    }

    // Store file info and send confirmation
    pendingFilesLock.Lock()
    pendingFiles[code] = FileInfo{filename: filename, filesize: filesize, fullPath: fullPath}
    pendingFilesLock.Unlock()

    fmt.Printf("File received successfully, code: %s, sending OK\n", code)
    if _, err := conn.Write([]byte("OK\n")); err != nil {
        fmt.Printf("Error sending confirmation: %v\n", err)
    }
}

func handleFileRecv(conn net.Conn) {
    defer conn.Close()
    reader := bufio.NewReader(conn)
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
                handleFileSend(conn)
                return
            } else if mode == "RECV" {
                handleFileRecv(conn)
                return
            } else {
                return
            }
        } else {
            return
        }
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

    // Mostrar información de inicio
    fmt.Printf("Servidor escuchando en %s\n", addr)
    fmt.Printf("Directorio de logs: %s\n", LOG_DIR)
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
    info, err := os.Stat(filePath)
    if err != nil {
        fmt.Println("File not found:", filePath)
        return
    }
    
    code := generateCode(6)
    fmt.Println("Code:", code)
    
    addr := fmt.Sprintf("%s:%d", serverHost, serverPort)
    conn, err := net.Dial("tcp", addr)
    if err != nil {
        fmt.Println("Connection error:", err)
        return
    }
    defer conn.Close()
    
    // Use buffered writer for better performance
    writer := bufio.NewWriter(conn)
    
    // Send headers with explicit flushing after each write
    if _, err := writer.WriteString("FILE SEND\n"); err != nil {
        fmt.Println("Error sending FILE SEND:", err)
        return
    }
    writer.Flush()
    
    if _, err := writer.WriteString(code + "\n"); err != nil {
        fmt.Println("Error sending code:", err)
        return
    }
    writer.Flush()
    
    if _, err := writer.WriteString(filepath.Base(filePath) + "\n"); err != nil {
        fmt.Println("Error sending filename:", err)
        return
    }
    writer.Flush()
    
    sizeStr := fmt.Sprintf("%d\n", info.Size())
    if _, err := writer.WriteString(sizeStr); err != nil {
        fmt.Println("Error sending size:", err)
        return
    }
    writer.Flush()
    
    // Send file content
    file, err := os.Open(filePath)
    if err != nil {
        fmt.Println("Error opening file:", err)
        return
    }
    defer file.Close()
    
    // Use larger buffer for file transfer
    buf := make([]byte, 32*1024)
    for {
        n, err := file.Read(buf)
        if n > 0 {
            if _, err := conn.Write(buf[:n]); err != nil {
                fmt.Printf("Error sending file data: %v\n", err)
                return
            }
        }
        if err == io.EOF {
            break
        }
        if err != nil {
            fmt.Printf("Error reading file: %v\n", err)
            return
        }
    }
    
    // Wait for confirmation with timeout
    fmt.Println("File sent, waiting for confirmation...")
    conn.SetReadDeadline(time.Now().Add(30 * time.Second))
    
    response := make([]byte, 1024)
    n, err := conn.Read(response)
    if err != nil {
        fmt.Printf("Error waiting for confirmation: %v\n", err)
        return
    }
    
    if strings.TrimSpace(string(response[:n])) == "OK" {
        fmt.Println("Transfer complete.")
    } else {
        fmt.Println("Invalid confirmation from server.")
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
    fmt.Printf("Receiving file: %s (%d bytes)\n", filename, filesize)
    outFile, err := os.Create(filename)
    if err != nil {
        fmt.Println("Error creating file:", err)
        return
    }
    defer outFile.Close()
    remaining := filesize
    buf := make([]byte, 4096)
    for remaining > 0 {
        n, err := reader.Read(buf)
        if n > 0 {
            outFile.Write(buf[:n])
            remaining -= int64(n)
        }
        if err != nil {
            break
        }
    }
    fmt.Println("File saved as:", filename)
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
    fmt.Println("File sent successfully.")
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
            fmt.Printf("Receiving file: %s (%d bytes)\n", filename, filesize)
            outFile, err := os.Create(filename)
            if err != nil {
                fmt.Println("Error creating file:", err)
                return
            }
            defer outFile.Close()
            remaining := filesize
            buf := make([]byte, 4096)
            for remaining > 0 {
                n, err := reader.Read(buf)
                if n > 0 {
                    outFile.Write(buf[:n])
                    remaining -= int64(n)
                }
                if err != nil {
                    break
                }
            }
            fmt.Println("File received successfully.")
        }(conn)
    }
}

func printUsage() {
    fmt.Println("\033[92mUsage:\033[0m")
    fmt.Println("  \033[94mServer:\033[0m                sudo airsend -s [host] [port]")
    fmt.Println("  \033[94mSend file:\033[0m             airsend -f <file-path> [host] [port]")
    fmt.Println("  \033[94mReceive file:\033[0m          airsend -r <code> [host] [port]")
    fmt.Println("  \033[94mMessage (sender):\033[0m      airsend -m [host] [port]")
    fmt.Println("  \033[94mMessage (receiver):\033[0m    airsend -mr <code> [host] [port]")
    fmt.Println("  \033[94mDirect send:\033[0m           airsend -d FILE <target-host> [port]")
    fmt.Println("  \033[94mDirect receive:\033[0m        airsend -ds [listen-host] [port]")
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
        if len(os.Args) < 3 {
            fmt.Println("Please specify the file to send.")
            printUsage()
            os.Exit(1)
        }
        filePath := os.Args[2]
        host := DEFAULT_SERVER_HOST
        port := DEFAULT_SERVER_PORT
        if len(os.Args) >= 4 {
            host = os.Args[3]
        }
        if len(os.Args) >= 5 {
            if p, err := strconv.Atoi(os.Args[4]); err == nil {
                port = p
            }
        }
        sendFile(filePath, host, port)
    case "-r":
        if len(os.Args) < 3 {
            fmt.Println("Please specify the pairing code.")
            printUsage()
            os.Exit(1)
        }
        code := os.Args[2]
        host := DEFAULT_SERVER_HOST
        port := DEFAULT_SERVER_PORT
        if len(os.Args) >= 4 {
            host = os.Args[3]
        }
        if len(os.Args) >= 5 {
            if p, err := strconv.Atoi(os.Args[4]); err == nil {
                port = p
            }
        }
        receiveFile(code, host, port)
    case "-d":
        if os.Args[2] == "-" {
            targetHost := DEFAULT_SERVER_HOST
            targetPort := DEFAULT_SERVER_PORT
            if len(os.Args) >= 4 {
                targetHost = os.Args[3]
            }
            if len(os.Args) >= 5 {
                if p, err := strconv.Atoi(os.Args[4]); err == nil {
                    targetPort = p
                }
            }
            fmt.Println("No file specified. Entering message mode.")
            messageChat(generateCode(6), targetHost, targetPort)
        } else {
            filePath := os.Args[2]
            if len(os.Args) < 4 {
                fmt.Println("Target host required for direct send.")
                return
            }
            targetHost := os.Args[3]
            targetPort := DEFAULT_SERVER_PORT
            if len(os.Args) >= 5 {
                if p, err := strconv.Atoi(os.Args[4]); err == nil {
                    targetPort = p
                }
            }
            directSend(filePath, targetHost, targetPort)
        }
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
                code = generateCode(6)
                fmt.Println("Code:", code)
                host = os.Args[2]
                if len(os.Args) >= 4 {
                    if p, err := strconv.Atoi(os.Args[3]); err == nil {
                        port = p
                    }
                }
            } else if len(os.Args) >= 3 {
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
                code = generateCode(6)
                fmt.Println("Code:", code)
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
