// server/server.go
package main

import (
	"crypto/ed25519"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
)

//go:embed static/*
var content embed.FS

type Message struct {
	Type   string `json:"type"`
	Data   string `json:"data"`
	User   string `json:"user,omitempty"`
	Addr   string `json:"addr,omitempty"`
	Pubkey string `json:"pubkey,omitempty"`
}

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

func main() {
	// serve embedded static files from the 'static' folder as root
	staticFS, err := fs.Sub(content, "static")
	if err != nil {
		log.Fatal("failed to access embedded static files: ", err)
	}
	http.Handle("/", http.FileServer(http.FS(staticFS)))
	http.HandleFunc("/ws", handleWebSocket)
	log.Println("Server listening on :8080")
	http.ListenAndServe(":8080", nil)
	select {}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade error:", err)
		return
	}
	defer conn.Close()

	var user, addr string
	var clientPub ed25519.PublicKey
	var once sync.Once
	challenge := []byte("ssh-challenge")

	err = conn.WriteJSON(Message{Type: "challenge", Data: string(challenge)})
	if err != nil {
		log.Println("send challenge error:", err)
		return
	}

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			log.Println("read error:", err)
			return
		}
		var m Message
		if err := json.Unmarshal(msg, &m); err != nil {
			log.Println("json unmarshal error:", err)
			continue
		}

		switch m.Type {
		case "init":
			// store user, addr, and parse provided public key
			user = m.User
			addr = m.Addr
			sshPub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(m.Pubkey))
			if err != nil {
				log.Println("parse client pubkey error:", err)
				return
			}
			cryptoPub, ok := sshPub.(ssh.CryptoPublicKey)
			if !ok {
				log.Println("client pubkey not CryptoPublicKey")
				return
			}
			clientPub = cryptoPub.CryptoPublicKey().(ed25519.PublicKey)
			// log the public key line so it can be added to authorized_keys
			log.Println("Init received:", user, addr, "pubkey:", m.Pubkey)
		case "signature":
			// verify signature from client
			sig, err := base64.StdEncoding.DecodeString(m.Data)
			if err != nil {
				log.Println("decode signature error:", err)
				return
			}
			if !ed25519.Verify(clientPub, challenge, sig) {
				log.Println("signature invalid")
				return
			}
			log.Println("✅ assinatura válida, criando ssh connection para", addr, "com user", user)

			once.Do(func() {
				// start SSH session using the client's public key as remote signer
				startSSHSession(conn, user, addr, clientPub)
			})
		}
	}
}

type remoteSigner struct {
	pub     ed25519.PublicKey
	ws      *websocket.Conn
	comment string
}

func (r *remoteSigner) PublicKey() ssh.PublicKey {
	pk, _ := ssh.NewPublicKey(r.pub)
	return pk
}

func (r *remoteSigner) Sign(rand io.Reader, data []byte) (*ssh.Signature, error) {
   // send the challenge data as base64 to avoid JSON encoding issues
   dataB64 := base64.StdEncoding.EncodeToString(data)
   err := r.ws.WriteJSON(Message{Type: "challenge", Data: dataB64})
	if err != nil {
		return nil, err
	}

	_, msg, err := r.ws.ReadMessage()
	if err != nil {
		return nil, err
	}
	var res Message
	if err := json.Unmarshal(msg, &res); err != nil || res.Type != "signature" {
		return nil, fmt.Errorf("invalid signature response")
	}
	decoded, err := base64.StdEncoding.DecodeString(res.Data)
	if err != nil {
		return nil, err
	}
	// return a signature with the correct algorithm name
	return &ssh.Signature{
		Format: r.PublicKey().Type(),
		Blob:   decoded,
	}, nil
}

type wsWriter struct {
	ws *websocket.Conn
}

func (w *wsWriter) Write(p []byte) (int, error) {
	msg := Message{Type: "output", Data: string(p)}
	return len(p), w.ws.WriteJSON(msg)
}

func startSSHSession(conn *websocket.Conn, user, addr string, pub ed25519.PublicKey) {
	signer := &remoteSigner{
		pub:     pub,
		ws:      conn,
		comment: "remote-browser",
	}

	sshConfig := &ssh.ClientConfig{
		User: user,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	realConn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		log.Println("dial tcp error:", err)
		return
	}
	defer realConn.Close()

	clientConn, chans, reqs, err := ssh.NewClientConn(realConn, addr, sshConfig)
	if err != nil {
		log.Println("ssh connect error:", err)
		return
	}
	client := ssh.NewClient(clientConn, chans, reqs)
	defer client.Close()

	sess, err := client.NewSession()
	if err != nil {
		log.Println("new session error:", err)
		return
	}
	defer sess.Close()

	// request a PTY for the session
	modes := ssh.TerminalModes{
		ssh.ECHO:          1,     // enable echoing
		ssh.TTY_OP_ISPEED: 14400, // input speed = 14.4kbaud
		ssh.TTY_OP_OSPEED: 14400, // output speed = 14.4kbaud
	}
	if err := sess.RequestPty("xterm-256color", 80, 24, modes); err != nil {
		log.Println("request pty failed:", err)
		return
	}

	sess.Stdout = &wsWriter{conn}
	sess.Stderr = &wsWriter{conn}
	stdin, _ := sess.StdinPipe()

	go func() {
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				log.Println("stdin pipe read error:", err)
				return
			}
			var input Message
			if json.Unmarshal(msg, &input) == nil && input.Type == "input" {
				stdin.Write([]byte(input.Data))
			}
		}
	}()

	sess.Shell()
	sess.Wait()
}
