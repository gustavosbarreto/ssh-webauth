package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

// TestWebSocketSSHHandshake sets up a dummy SSH server and a WebSocket server,
// then verifies that the WebSocket endpoint performs the ed25519-based handshake
// and connects to the SSH server using publickey auth.
func TestWebSocketSSHHandshake(t *testing.T) {
	// 1) generate client keypair for ed25519
	pubClient, privClient, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate client key: %v", err)
	}
	// 2) generate host key for SSH server
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("ssh.NewSignerFromKey: %v", err)
	}

	// channel to receive the public key used during SSH auth
	pubCh := make(chan ed25519.PublicKey, 1)
	// channel to capture data received by the SSH server
	inputCh := make(chan []byte, 1)
	// 3) SSH server config
	serverConfig := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			cryptoPub, ok := key.(ssh.CryptoPublicKey)
			if !ok {
				return nil, fmt.Errorf("unauthorized public key type")
			}
			edPub := cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
			// report the received key for verification
			pubCh <- edPub
			// accept only if it matches
			if !bytes.Equal(edPub, pubClient) {
				return nil, fmt.Errorf("unauthorized public key")
			}
			return nil, nil
		},
	}
	serverConfig.AddHostKey(hostSigner)

	// 4) start dummy SSH server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen for ssh: %v", err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(nc net.Conn) {
				defer nc.Close()
				sshConn, chans, reqs, err := ssh.NewServerConn(nc, serverConfig)
				if err != nil {
					fmt.Printf("dummy ssh handshake error: %v\n", err)
					return
				}
				go ssh.DiscardRequests(reqs)
				// accept session channels and shell requests, then close
				for newChan := range chans {
					if newChan.ChannelType() != "session" {
						newChan.Reject(ssh.UnknownChannelType, "only session")
						continue
					}
					ch, requests, err := newChan.Accept()
					if err != nil {
						continue
					}
					for req := range requests {
						switch req.Type {
						case "pty-req":
							req.Reply(true, nil)
						case "shell":
							req.Reply(true, nil)
							// send a welcome message
							ch.Write([]byte("HELLO\n"))
							// echo back any input, capture it for test
							go func() {
								buf := make([]byte, 1024)
								for {
									n, err := ch.Read(buf)
									if err != nil {
										return
									}
									data := make([]byte, n)
									copy(data, buf[:n])
									select {
									case inputCh <- data:
									default:
									}
									ch.Write(data)
								}
							}()
						default:
							req.Reply(false, nil)
						}
					}
					ch.Close()
				}
				sshConn.Close()
			}(conn)
		}
	}()

	// 5) start WebSocket test server on /ws
	wsServer := httptest.NewServer(http.HandlerFunc(handleWebSocket))
	defer wsServer.Close()

	// 6) dial WebSocket
	wsURL := "ws://" + strings.TrimPrefix(wsServer.URL, "http://") + "/ws"
	wsConn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("websocket dial: %v", err)
	}
	//defer wsConn.Close()

	// 7) read challenge
	_, rawMsg, err := wsConn.ReadMessage()
	if err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	var msg struct{ Type, Data string }
	if err := json.Unmarshal(rawMsg, &msg); err != nil {
		t.Fatalf("unmarshal challenge: %v", err)
	}
	if msg.Type != "challenge" {
		t.Fatalf("expected challenge, got %q", msg.Type)
	}

	// 8) send init with SSH public key in authorized_keys format
	sshPub, err := ssh.NewPublicKey(pubClient)
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	authLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	initMsg := map[string]string{
		"type":   "init",
		"user":   "testuser",
		"addr":   listener.Addr().String(),
		"pubkey": authLine,
	}
	if err := wsConn.WriteJSON(initMsg); err != nil {
		t.Fatalf("write init: %v", err)
	}

	// 9) send signature
	sigB := ed25519.Sign(privClient, []byte(msg.Data))
	sigB64 := base64.StdEncoding.EncodeToString(sigB)
	sigMsg := map[string]string{"type": "signature", "data": sigB64}
	if err := wsConn.WriteJSON(sigMsg); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	// 10) wait for SSH server auth callback and verify the key
	select {
	case got := <-pubCh:
		if !bytes.Equal(got, pubClient) {
			t.Fatalf("public key mismatch: got %x want %x", got, pubClient)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SSH publickey auth")
	}

	// 11) perform SSH proxy's publickey auth: read challenge and respond
	var sshCh struct{ Type, Data string }
	if err := wsConn.ReadJSON(&sshCh); err != nil {
		t.Fatalf("read ssh auth challenge: %v", err)
	}
	if sshCh.Type != "challenge" {
		t.Fatalf("expected ssh auth challenge, got %q", sshCh.Type)
	}
	// decode the base64-encoded challenge
	challengeData, err := base64.StdEncoding.DecodeString(sshCh.Data)
	if err != nil {
		t.Fatalf("decode ssh auth challenge: %v", err)
	}
	sig2 := ed25519.Sign(privClient, challengeData)
	sig2B64 := base64.StdEncoding.EncodeToString(sig2)
	resp := map[string]string{"type": "signature", "data": sig2B64}
	if err := wsConn.WriteJSON(resp); err != nil {
		t.Fatalf("write ssh auth signature: %v", err)
	}

	// 12) read SSH session welcome output
	var out Message
	if err := wsConn.ReadJSON(&out); err != nil {
		t.Fatalf("read welcome output: %v", err)
	}
	if out.Type != "output" {
		t.Fatalf("expected output type, got %q", out.Type)
	}
	if out.Data != "HELLO\n" {
		t.Fatalf("unexpected welcome data: %q", out.Data)
	}

	// 12) send input and verify echo
	input := Message{Type: "input", Data: "world\n"}
	if err := wsConn.WriteJSON(input); err != nil {
		t.Fatalf("write input: %v", err)
	}
	var echo Message
	if err := wsConn.ReadJSON(&echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if echo.Type != "output" {
		t.Fatalf("expected output type, got %q", echo.Type)
	}
	if echo.Data != "world\n" {
		t.Fatalf("unexpected echo data: %q", echo.Data)
	}
	// 13) verify the SSH server received the input
	select {
	case got := <-inputCh:
		if string(got) != "world\n" {
			t.Fatalf("SSH server received wrong data: %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for SSH server to receive input")
	}

	// close the WebSocket to clean up
	wsConn.Close()
}
