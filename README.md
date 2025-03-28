
# AirSend

AirSend is a lightweight command-line tool for transferring files and exchanging messages directly between machines without requiring a persistent server. It supports multiple modes for file transfer and chat relay, including a direct send/receive mode. Precompiled binaries for AMD and ARM architectures are available in the Releases section.

## Features and Usage

AirSend supports various modes:

- **Server Mode:** Run a persistent server to handle file transfers or chat sessions. Start the server with:
  ```bash
  sudo ./airsend -s [host] [port]
  ```
  where `host` is the IP address to bind (default: `0.0.0.0`) and `port` is the port to listen on (default: `443`).

- **File Transfer (Client):**  
  - **Send File (Store on Server):** Use this mode to send a file to the server, which stores it with a generated pairing code:
    ```bash
    ./airsend -f <file-path> [host] [port]
    ```
  - **Receive File:** Retrieve the file stored on the server using the provided pairing code:
    ```bash
    ./airsend -r <code> [host] [port]
    ```

- **Chat Relay:**  
  - **Chat Sender:** Generates a pairing code and connects as a chat sender:
    ```bash
    ./airsend -m [host] [port]
    ```
  - **Chat Receiver:** Connects as a chat receiver using the provided pairing code:
    ```bash
    ./airsend -mr <code> [host] [port]
    ```

- **Direct Transfer Mode (-d):** Send files directly between two machines without requiring a persistent server.
  - **Direct Send:**
    ```bash
    ./airsend -d send <file> <dest_ip> [port]
    ```
  - **Direct Receive:**
    ```bash
    ./airsend -d recv [listen_ip] [port]
    ```

## Releases

Precompiled binaries for AMD and ARM are available in the releases section.

## License

This project is licensed under the MIT License.
