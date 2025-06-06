#!/usr/bin/env python3
import socket
import threading
import sys
import os
import random
import string
import time

#DEFAULT_SERVER_HOST = "0.0.0.0"
DEFAULT_SERVER_HOST = "mic2.4rji.com"
DEFAULT_SERVER_PORT = 443

# Directorios:
LOG_DIR = "/opt/4rji/airsend"       # Para chat/relay
FILES_DIR = "/opt/4rji/airsend"      # Para guardar archivos enviados

# Diccionarios globales:
pending = {}       # Para chat/relay (clave: code, valor: (socket, log_filename))
pending_files = {} # Para archivos enviados (clave: code, valor: dict con filename, filesize, full_path)

log_lock = threading.Lock()

def generate_code(length=6):
    return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))

def is_valid_ip(address):
    parts = address.split('.')
    if len(parts) != 4:
        return False
    for part in parts:
        try:
            num = int(part)
        except:
            return False
        if num < 0 or num > 255:
            return False
    return True

def log_data(log_filename, direction, data):
    with log_lock:
        with open(log_filename, "ab") as lf:
            header = f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')} {direction}]:\n".encode()
            lf.write(header)
            lf.write(data)

def relay(src, dst, log_filename, direction):
    try:
        while True:
            data = src.recv(4096)
            if not data:
                break
            dst.sendall(data)
            if log_filename:
                log_data(log_filename, direction, data)
    except:
        pass
    finally:
        src.close()
        dst.close()

def read_line(sock):
    data = b""
    while b"\n" not in data:
        part = sock.recv(1)
        if not part:
            break
        data += part
    return data.decode().strip()

### Funciones para manejo de archivos en modo FILE

def handle_file_send(conn):
    try:
        code = read_line(conn)
        if not code:
            conn.close()
            return
        filename = read_line(conn)
        if not filename:
            conn.close()
            return
        size_str = read_line(conn)
        try:
            filesize = int(size_str)
        except:
            conn.close()
            return

        if not os.path.exists(FILES_DIR):
            os.makedirs(FILES_DIR)

        server_filename = f"{code}_{filename}"
        full_path = os.path.join(FILES_DIR, server_filename)

        remaining = filesize
        with open(full_path, "wb") as f:
            while remaining > 0:
                chunk = conn.recv(min(4096, remaining))
                if not chunk:
                    break
                f.write(chunk)
                remaining -= len(chunk)

        pending_files[code] = {"filename": filename, "filesize": filesize, "full_path": full_path}
        conn.sendall(b"OK\n")
    except:
        pass
    finally:
        conn.close()

def handle_file_recv(conn):
    try:
        code = read_line(conn)
        if not code:
            conn.close()
            return
        if code not in pending_files:
            conn.sendall(b"ERR\n")
            conn.close()
            return
        file_info = pending_files.pop(code)
        filename = file_info["filename"]
        filesize = file_info["filesize"]
        full_path = file_info["full_path"]

        conn.sendall(filename.encode() + b"\n")
        conn.sendall(str(filesize).encode() + b"\n")
        with open(full_path, "rb") as f:
            while True:
                chunk = f.read(4096)
                if not chunk:
                    break
                conn.sendall(chunk)
    except:
        pass
    finally:
        conn.close()

### Funciones para chat / relay (modo normal)

def handle_chat_or_relay(conn, first_line):
    code = first_line.strip()
    if not code:
        conn.close()
        return

    with threading.Lock():
        if code in pending:
            other_conn, log_filename = pending.pop(code)
            threading.Thread(target=relay,
                             args=(conn, other_conn, log_filename, "Client2 -> Client1"),
                             daemon=True).start()
            threading.Thread(target=relay,
                             args=(other_conn, conn, log_filename, "Client1 -> Client2"),
                             daemon=True).start()
        else:
            if not os.path.exists(LOG_DIR):
                os.makedirs(LOG_DIR)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            log_filename = os.path.join(LOG_DIR, f"session_{code}_{timestamp}.log")
            pending[code] = (conn, log_filename)

def handle_client(conn, addr):
    try:
        first_line = read_line(conn)
        if not first_line:
            conn.close()
            return

        if first_line.startswith("FILE"):
            parts = first_line.split()
            if len(parts) >= 2:
                mode = parts[1]
                if mode == "SEND":
                    handle_file_send(conn)
                    return
                elif mode == "RECV":
                    handle_file_recv(conn)
                    return
                else:
                    conn.close()
                    return
            else:
                conn.close()
                return
        else:
            handle_chat_or_relay(conn, first_line)
    except:
        conn.close()

def run_server(host=DEFAULT_SERVER_HOST, port=DEFAULT_SERVER_PORT):
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(5)
    print(f"Server listening on {host}:{port}")
    try:
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
    except KeyboardInterrupt:
        s.close()
        print("\nServer stopped.")

### Funciones cliente

def send_file(file_path, server_host=DEFAULT_SERVER_HOST, server_port=DEFAULT_SERVER_PORT):
    if not os.path.isfile(file_path):
        print("File not found:", file_path)
        return
    code = generate_code()
    print("Code:", code)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_host, server_port))
    s.sendall(b"FILE SEND\n")
    s.sendall(code.encode() + b"\n")
    filename = os.path.basename(file_path)
    s.sendall(filename.encode() + b"\n")
    filesize = os.path.getsize(file_path)
    s.sendall(str(filesize).encode() + b"\n")
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            s.sendall(chunk)
    s.settimeout(10)
    try:
        ack = s.recv(1024)
        if ack.strip() == b"OK":
            print("Transfer complete.")
        else:
            print("No confirmation received from server.")
    except socket.timeout:
        print("Timeout waiting for confirmation from server.")
    finally:
        s.close()

def receive_file(code, server_host=DEFAULT_SERVER_HOST, server_port=DEFAULT_SERVER_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_host, server_port))
    s.sendall(b"FILE RECV\n")
    s.sendall(code.encode() + b"\n")
    filename_bytes = b""
    while True:
        chunk = s.recv(1)
        if not chunk or chunk == b"\n":
            break
        filename_bytes += chunk
    filename = filename_bytes.decode()
    if filename == "ERR" or not filename:
        print("File not available on server.")
        s.close()
        return
    size_bytes = b""
    while True:
        chunk = s.recv(1)
        if not chunk or chunk == b"\n":
            break
        size_bytes += chunk
    try:
        filesize = int(size_bytes.decode().strip())
    except Exception as e:
        print("Error reading file size:", e)
        s.close()
        return
    print(f"Receiving file: {filename} ({filesize} bytes)")
    with open(filename, "wb") as f:
        remaining = filesize
        while remaining > 0:
            data = s.recv(min(4096, remaining))
            if not data:
                break
            f.write(data)
            remaining -= len(data)
    s.close()
    print("File saved as:", filename)

def message_chat(code, server_host=DEFAULT_SERVER_HOST, server_port=DEFAULT_SERVER_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server_host, server_port))
    s.sendall(code.encode() + b"\n")
    def recv_thread():
        while True:
            data = s.recv(4096)
            if not data:
                break
            sys.stdout.write(data.decode())
            sys.stdout.flush()
    threading.Thread(target=recv_thread, daemon=True).start()
    prompt = "\033[93mType your message ('/exit' to quit):\033[0m "
    sys.stdout.write(prompt)
    sys.stdout.flush()
    try:
        while True:
            line = sys.stdin.readline()
            if not line:
                break
            if line.strip() == "/exit":
                break
            s.sendall(line.encode())
    except KeyboardInterrupt:
        pass
    s.close()

def direct_send(file_path, target_host, target_port=DEFAULT_SERVER_PORT):
    if not os.path.isfile(file_path):
        print("File not found:", file_path)
        return

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.connect((target_host, target_port))
        filename = os.path.basename(file_path)
        filesize = os.path.getsize(file_path)

        s.sendall(f"{filename}\n".encode())
        s.sendall(f"{filesize}\n".encode())

        with open(file_path, "rb") as f:
            while chunk := f.read(4096):
                s.sendall(chunk)

        print("File sent successfully.")
    except Exception as e:
        print("Error during file transfer:", e)
    finally:
        s.close()

def direct_receive(listen_host="0.0.0.0", listen_port=DEFAULT_SERVER_PORT):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((listen_host, listen_port))
    s.listen(1)
    print(f"Listening on {listen_host}:{listen_port}...")

    while True:
        conn, addr = s.accept()
        print(f"Connection established with {addr}")

        try:
            filename = read_line(conn)
            if not filename:
                print("No file specified. Waiting for the next connection...")
                conn.close()
                continue

            filesize = int(read_line(conn))
            print(f"Receiving file: {filename} ({filesize} bytes)")

            with open(filename, "wb") as f:
                remaining = filesize
                while remaining > 0:
                    chunk = conn.recv(min(4096, remaining))
                    if not chunk:
                        break
                    f.write(chunk)
                    remaining -= len(chunk)

            print("File received successfully.")
        except Exception as e:
            print("Error during file reception:", e)
        finally:
            conn.close()

def print_usage():
    print("\033[92mUsage:\033[0m")
    print("  \033[94mServer:\033[0m                sudo airsend -s [host] [port]")
    print("  \033[94mSend file:\033[0m             airsend -f <file-path> [host] [port]")
    print("  \033[94mReceive file:\033[0m          airsend -r <code> [host] [port]")
    print("  \033[94mMessage (sender):\033[0m      airsend -m [host] [port]")
    print("  \033[94mMessage (receiver):\033[0m    airsend -mr <code> [host] [port]")
    print("  \033[94mDirect send:\033[0m           airsend -d FILE <target-host> [port]")
    print("  \033[94mDirect receive:\033[0m        airsend -ds [listen-host] [port]")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    mode = sys.argv[1]
    if mode == "-s":
        host = sys.argv[2] if len(sys.argv) >= 3 else DEFAULT_SERVER_HOST
        port = int(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_SERVER_PORT
        run_server(host, port)
    elif mode == "-f":
        if len(sys.argv) < 3:
            print("Please specify the file to send.")
            print_usage()
            sys.exit(1)
        file_path = sys.argv[2]
        host = sys.argv[3] if len(sys.argv) >= 4 else DEFAULT_SERVER_HOST
        port = int(sys.argv[4]) if len(sys.argv) >= 5 else DEFAULT_SERVER_PORT
        send_file(file_path, host, port)
    elif mode == "-r":
        if len(sys.argv) < 3:
            print("Please specify the pairing code.")
            print_usage()
            sys.exit(1)
        code = sys.argv[2]
        host = sys.argv[3] if len(sys.argv) >= 4 else DEFAULT_SERVER_HOST
        port = int(sys.argv[4]) if len(sys.argv) >= 5 else DEFAULT_SERVER_PORT
        receive_file(code, host, port)
    elif mode == "-d":
        if sys.argv[2] == "-":
            target_host = sys.argv[3] if len(sys.argv) >= 4 else DEFAULT_SERVER_HOST
            target_port = int(sys.argv[4]) if len(sys.argv) >= 5 else DEFAULT_SERVER_PORT
            print("No file specified. Entering message mode.")
            message_chat(generate_code(), target_host, target_port)
        else:
            file_path = sys.argv[2]
            target_host = sys.argv[3]
            target_port = int(sys.argv[4]) if len(sys.argv) >= 5 else DEFAULT_SERVER_PORT
            direct_send(file_path, target_host, target_port)
    elif mode == "-ds":
        listen_host = sys.argv[2] if len(sys.argv) >= 3 else "0.0.0.0"
        listen_port = int(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_SERVER_PORT
        direct_receive(listen_host, listen_port)
    elif mode in ("-m", "-mr"):
        if mode == "-mr":
            if len(sys.argv) < 3:
                print("Please specify the pairing code.")
                print_usage()
                sys.exit(1)
            code = sys.argv[2]
            host = sys.argv[3] if len(sys.argv) >= 4 else DEFAULT_SERVER_HOST
            port = int(sys.argv[4]) if len(sys.argv) >= 5 else DEFAULT_SERVER_PORT
        else:
            if len(sys.argv) >= 3 and is_valid_ip(sys.argv[2]):
                code = generate_code()
                print("Code:", code)
                host = sys.argv[2]
                port = int(sys.argv[3]) if len(sys.argv) >= 4 else DEFAULT_SERVER_PORT
            elif len(sys.argv) >= 3:
                code = sys.argv[2]
                host = sys.argv[3] if len(sys.argv) >= 4 else DEFAULT_SERVER_HOST
                port = int(sys.argv[4]) if len(sys.argv) >= 5 else DEFAULT_SERVER_PORT
            else:
                code = generate_code()
                print("Code:", code)
                host = DEFAULT_SERVER_HOST
                port = DEFAULT_SERVER_PORT
        message_chat(code, host, port)
    else:
        print("Unknown mode:", mode)
        print_usage()
        sys.exit(1)
