// wasm/main.go
package main

import (
   "crypto/ed25519"
   "encoding/base64"
   "encoding/json"
   "log"
   "strings"
   "syscall/js"
   "golang.org/x/crypto/ssh"
)

var (
	ws         js.Value
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	user       string
	addr       string
)

func sendJSON(obj any) {
	if !ws.Truthy() {
		return
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
		}
	}()
	ws.Call("send", string(b))
}

func loadKeyFromJS() {
	keyB64 := js.Global().Get("_wasm_key").String()
	keyRaw, err := base64.StdEncoding.DecodeString(keyB64)
	log.Println("Key length:", len(keyRaw))
	log.Println(keyRaw)

	if err != nil || len(keyRaw) != ed25519.SeedSize {
		log.Fatal("invalid key or format %v", err)
	}
	privateKey = ed25519.NewKeyFromSeed(keyRaw)
	// derive public key for server-side verification
	publicKey = privateKey.Public().(ed25519.PublicKey)

	user = js.Global().Get("_wasm_user").String()
	addr = js.Global().Get("_wasm_addr").String()
	log.Println("User:", user, "Addr:", addr)
}

// signChallenge signs the given challenge, decoding from Base64 if needed
func signChallenge(data string) string {
   // try to decode Base64; if fails, treat as raw string
   msg, err := base64.StdEncoding.DecodeString(data)
   if err != nil {
       msg = []byte(data)
   }
   sig := ed25519.Sign(privateKey, msg)
   return base64.StdEncoding.EncodeToString(sig)
}

func handleChallenge(challenge string) {
	signature := signChallenge(challenge)
	sendJSON(map[string]any{
		"type": "signature",
		"data": signature,
	})
}

func main() {
	loadKeyFromJS()

	termInput := js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) > 0 {
			data := args[0].String()
			sendJSON(map[string]any{
				"type": "input",
				"data": data,
			})
		}
		return nil
	})
	js.Global().Set("goHandleTermInput", termInput)

   ws = js.Global().Get("WebSocket").New("ws://localhost:8080/ws")
   // send init (including authorized_keys-style public key) once connection opens
   ws.Set("onopen", js.FuncOf(func(this js.Value, args []js.Value) any {
       // convert raw ed25519 public key into SSH wire format
       sshPub, err := ssh.NewPublicKey(publicKey)
       if err != nil {
           log.Println("error creating ssh public key:", err)
           return nil
       }
       auth := ssh.MarshalAuthorizedKey(sshPub)
       authLine := strings.TrimSpace(string(auth))
       sendJSON(map[string]any{
           "type":    "init",
           "session": "browser-client",
           "user":    user,
           "addr":    addr,
           "pubkey":  authLine,
       })
       return nil
   }))

	ws.Set("onmessage", js.FuncOf(func(this js.Value, args []js.Value) any {
		msg := args[0].Get("data").String()
		var parsed map[string]any
		if err := json.Unmarshal([]byte(msg), &parsed); err == nil {
			typ, ok := parsed["type"].(string)
			if !ok {
				return nil
			}

			switch typ {
			case "output":
				text, _ := parsed["data"].(string)
				js.Global().Call("goWriteToTerminal", text)
			case "challenge":
				// server requests signature over challenge
				challenge, _ := parsed["data"].(string)
				handleChallenge(challenge)
			}
		}
		return nil
	}))

	select {}
}
