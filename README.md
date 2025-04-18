The tutorial and usage steps are also available on my [https://docs.4rji.com/airsend](https://docs.4rji.com/airsend).


# AirSend

AirSend is a lightweight command-line tool developed to transfer files and exchange messages directly between machines with customized IP and port settings, overcoming limitations found in similar tools like Wormhole.

I created AirSend out of the necessity for flexibility that other tools like Wormhole lacked—particularly the ability to customize IP addresses and ports. AirSend addresses these gaps by supporting multiple file transfers, direct peer-to-peer connections, customizable ports, and the option to store files and messages on a relay server (C2).


# Update April 8 2025

Finally fixed the chat. An interactive window has been added when the chat is activated. A unique code feature was also implemented, so instead of waiting for a random code, users can now use a specific code to share with another user.

Thanks to a goMN and the talk "Creating a TUI chat app" by Michael Duren yesterday  https://github.com/michael-duren/tui-chat.git, I was able to get the chat option working in AirSend. I copied the interface Michael created and implemented it, since previously it only displayed messages like netcat.

Michael also had a menu using a secret word to enable private connections. So instead of AirSend generating random codes, I added the option to set a secret word to access the chat with another person using the same word. I’ll work later on adding support for more people in the chat, but for now it’s just client and server.




### AirSend Default Configuration

| Variable               | Description                                             | Default Value            |
|------------------------|---------------------------------------------------------|--------------------------|
| `DEFAULT_SERVER_HOST`  | Default relay server host. *(Upcoming releases will allow specifying your own custom C2 domain.)* | `c2server.com`           |
| `DEFAULT_SERVER_PORT`  | Default port used for secure communications.            | `443`                    |
| `FILES_DIR`            | Directory for storing files in server (`-s`) mode.      | `/opt/4rji/airsend`      |



## Key Features

- Customize IP addresses and ports
- Send and receive multiple files
- Direct peer-to-peer connections
- Relay server support (C2)

## Usage

### Server Mode
Start a server to manage file transfers and message relays:
```bash
sudo airsend -s <host> <port>
```

### File Transfer
**Send Files:**
```bash
airsend -f <host> <port> <file1> <file2>
```

**Receive Files:**
```bash
airsend -r <host> <port> <code>
```


### Direct Transfer Mode

**Direct Receive:**
```bash
airsend -ds <listen-host> <port>
```



**Direct Send:**
```bash
airsend -d <target-host> [port] <file>
```



### Messaging
**Send Messages:**
```bash
coming soon```

**Receive Messages:**
```bash
coming soon
```


## Releases

Precompiled binaries for AMD and ARM architectures are available in the Releases section.
