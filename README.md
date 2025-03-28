# AirSend

AirSend is a lightweight, command-line tool for transferring files and exchanging messages directly between machines without requiring a persistent server. The script supports multiple modes for file transfer and chat relay, including a direct send/receive mode.

## Features

- **File Transfer (Server Mode):** Send and receive files using a pairing code.
- **Chat Relay:** Establish a chat session between two clients.
- **Direct Transfer (-d Mode):** Send files directly between machines without a running server.
- **Binary Releases:** Precompiled binaries for both AMD and ARM architectures are available in the [Releases](https://github.com/yourusername/AirSend/releases) section.

## Usage

### Server Mode
Start the server to handle chat relay or file transfers.
```bash
sudo ./airsend -s [host] [port]

	•	host: IP address to bind (default: 0.0.0.0).
	•	port: Port to listen on (default: 443).

File Transfer (Client)

Send File (Store on Server)

./airsend -f <file-path> [host] [port]

	•	Sends the file to the server, which stores it with a generated code.

Receive File

./airsend -r <code> [host] [port]

	•	Retrieves the file stored on the server using the provided pairing code.

Chat Relay

Sender

./airsend -m [host] [port]

	•	Generates a pairing code and connects as a chat sender.

Receiver

./airsend -mr <code> [host] [port]

	•	Connects as a chat receiver using the provided pairing code.

Direct Transfer Mode (-d)

Transfer files directly between machines without a persistent server.

Direct Send

./airsend -d send <file> <dest_ip> [port]

	•	file: Path to the file to send.
	•	dest_ip: IP address of the destination machine.
	•	port: Port to connect to (default: 443).

Direct Receive

./airsend -d recv [listen_ip] [port]

	•	listen_ip: IP address to bind for listening (default: 0.0.0.0).
	•	port: Port to listen on (default: 443).

Releases

Precompiled binaries for different architectures are available:
	•	AMD: Download
	•	ARM: Download

License

Distributed under the MIT License. See LICENSE for more information.


