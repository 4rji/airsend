The tutorial and usage steps are also available on my [https://docs.4rji.com/airsend](https://docs.4rji.com/airsend).


# AirSend

AirSend is a lightweight command-line tool developed to transfer files and exchange messages directly between machines with customized IP and port settings, overcoming limitations found in similar tools like Wormhole.

I created AirSend out of the necessity for flexibility that other tools like Wormhole lacked—particularly the ability to customize IP addresses and ports. AirSend addresses these gaps by supporting multiple file transfers, direct peer-to-peer connections, customizable ports, and the option to store files and messages on a relay server (C2).


# Update April 8

Finally fixed the chat.

Thanks to a goMN and the talk "Creating a TUI chat app" by Michael Duren (https://github.com/michael-duren/tui-chat.git), I was able to get the chat option working in AirSend. I copied the interface Michael created and implemented it, since previously messages were displayed more like in netcat.


An interactive window has been added when the chat is activated. Instead of waiting for a random code, users can now use a custom secret word to connect with another person using the same word — enabling private, direct chats.


For now, the chat supports only a client-client-server connection. I’ll work later on enabling group chats.


<img width="1147" alt="Image" src="https://github.com/user-attachments/assets/5c7b3ecf-3862-44a2-80a3-d2418c1e9630" />




# Execution

With the new chat addition, run it like this:

```bash
go run main.go chat-window.go


```





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
