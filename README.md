# ChatSSH

ChatSSH is a browser-based SSH client that proxies SSH sessions over WebSockets. It consists of:

- A **Go server** (`/server`) that serves the static web UI, handles a JSON-over-WebSocket handshake,
  and establishes a real SSH connection (using `golang.org/x/crypto/ssh`) to the target host.
- A **WebAssembly (WASM) client** (`/wasm`) that runs in the browser, reads an Ed25519 private key,
  performs a challenge-response signature handshake, and proxies terminal I/O over the WebSocket.
- A **static front-end** (`/server/static/index.html`) using xterm.js to render an interactive terminal.
- A **dummy SSH server** (`/sshserver`) for local testing, which accepts any public key and
  prints received input.
- End-to-end **Go test** (`/server/ws_test.go`) that verifies the full WebSocket↔SSH handshake,
  including an interactive shell and data echo.

## Features
- Pure Go server: no external dependencies beyond Go modules
- Ed25519-based public-key authentication
- Interactive PTY allocation and shell proxy
- WASM client: runs entirely in the browser without a native SSH client
- End-to-end automated tests for the WebSocket+SSH flow

## Prerequisites
- Go 1.24+ (for building server and WASM)
- A modern browser with WebAssembly support

## Building and Running
1. Clone the repository:
    ```bash
    git clone https://github.com/gustavosbarreto/chatssh.git
    cd chatssh
    ```
2. Build the WebAssembly client, copy `wasm_exec.js`, and compile the Go server:
    ```bash
    ./build.sh
    ```
3. Start the server:
    ```bash
    go run ./server
    ```
   By default it listens on `:8080` and serves:
   - `http://localhost:8080/` static files (including `index.html`)
   - `ws://localhost:8080/ws` WebSocket SSH proxy endpoint

4. Open your browser at `http://localhost:8080/`, select your Ed25519 private key (.pem or raw seed),
   and click **Connect**.

## Using the Dummy SSH Server
For local end-to-end testing without a real SSH host, run the dummy server:
```bash
go run ./sshserver/main.go   # or ./sshserver/main3.go for pure crypto/ssh version
```
It listens on port `2221`, accepts any public key, and greets the user.
Then point the web UI to `localhost:2221` when prompted for the SSH address.

## Protocol Details

Below is a detailed description of the JSON-over-WebSocket protocol used to authenticate the browser client and proxy SSH sessions.

### Message Types

All messages exchanged over the WebSocket use the following JSON structure:

```json
{
  "type":   "<message type>",
  "data":   "<data payload>",
  "user":   "<SSH username (init only)>",
  "addr":   "<SSH host:port (init only)>",
  "pubkey": "<public key in authorized_keys format (init only)>"
}
```

### Message Type Definitions

- **challenge**:  
  - Server → Client (initial): data=raw challenge string.  
  - Proxy (SSH auth) → Client: data=base64 SSH authentication challenge.
- **init**:  
  - Client → Server: data omitted; includes `user`, `addr`, and `pubkey` fields to request a new SSH session.
- **signature**:  
  - Client → Server: data=`base64` signature of the last challenge. Used both for initial handshake and SSH publickey auth.
- **input**:  
  - Client → Server: data=raw stdin bytes (key presses and control sequences).
- **output**:  
  - Server → Client: data=raw stdout/stderr bytes from the SSH session.

### Handshake Sequence

1. Browser loads the WASM client, imports the Ed25519 private key, derives the public key, and opens a WebSocket to `ws://<host>/ws`.
2. Server upgrades the HTTP connection and immediately sends the initial challenge:
   ```json
   { "type": "challenge", "data": "<initial-challenge>" }
   ```
3. Upon WebSocket open, the client sends the `init` message:
   ```json
   { "type": "init", "user": "<user>", "addr": "<host:port>", "pubkey": "<authorized_keys format>" }
   ```
4. The client signs the initial challenge and sends:
   ```json
   { "type": "signature", "data": "<base64 signature>" }
   ```
5. Server verifies the signature against the provided public key. On success, it establishes an SSH connection to `<addr>`.
6. For SSH publickey authentication, the Go server uses a `remoteSigner` that:
   - Sends the SSH login challenge to the client as:
     ```json
     { "type": "challenge", "data": "<base64 SSH auth challenge>" }
     ```
   - Waits for the client’s signature response:
     ```json
     { "type": "signature", "data": "<base64 signature>" }
     ```
   - Forwards the signature to the SSH handshake to complete authentication.

### Terminal I/O Proxy

Once the SSH session is authenticated and a PTY is allocated, all terminal I/O is proxied:

- **Client → Server** (`input`):  
  Browser key presses and control sequences are sent as `input` messages.
- **Server → Client** (`output`):  
  Server wraps SSH stdout and stderr bytes in `output` messages for the browser terminal.

This JSON-over-WebSocket protocol allows the browser to retain sole access to the private key while the Go server handles SSH transport and PTY management.

## Automated Testing
Run the Go tests for the server:
```bash
go test ./server
```
This covers the full handshake and interactive echo validation over WASM + WebSocket + SSH.

## License
MIT License (see LICENSE file)