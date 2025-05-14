package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func main() {
	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("failed to generate host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		log.Fatalf("ssh.NewSignerFromKey: %v", err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fmt.Printf("Usuário '%s' autenticado com chave pública:\n%s\n",
				conn.User(),
				ssh.MarshalAuthorizedKey(key),
			)
			// Aceita qualquer chave pública
			return nil, nil
		},
	}
	config.AddHostKey(hostSigner)

	listener, err := net.Listen("tcp", ":2221")
	if err != nil {
		log.Fatalf("Falha ao escutar na porta 2221: %v", err)
	}
	log.Println("Servidor SSH ouvindo na porta 2221...")

	for {
		nConn, err := listener.Accept()
		if err != nil {
			log.Printf("Falha ao aceitar conexão: %v", err)
			continue
		}

		go func(nConn net.Conn) {
			sshConn, chans, reqs, err := ssh.NewServerConn(nConn, config)
			if err != nil {
				log.Printf("Falha no handshake SSH: %v", err)
				return
			}
			defer sshConn.Close()
			log.Printf("Nova conexão SSH de %s (%s)", sshConn.RemoteAddr(), sshConn.ClientVersion())

			// Ignora requisições globais
			go ssh.DiscardRequests(reqs)

			for newChannel := range chans {
				if newChannel.ChannelType() != "session" {
					newChannel.Reject(ssh.UnknownChannelType, "tipo de canal não suportado")
					continue
				}

				channel, requests, err := newChannel.Accept()
				if err != nil {
					log.Printf("Erro ao aceitar canal: %v", err)
					continue
				}

				go func(in <-chan *ssh.Request) {
					for req := range in {
						switch req.Type {
						case "shell":
							req.Reply(true, nil)
						default:
							req.Reply(false, nil)
						}
					}
				}(requests)

				io.WriteString(channel, fmt.Sprintf("Bem-vindo, %s!\n", sshConn.User()))
				channel.Close()
			}
		}(nConn)
	}
}
