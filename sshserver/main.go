package main

import (
	"fmt"
	"io"
	"log"

	gliderssh "github.com/gliderlabs/ssh"
	"golang.org/x/crypto/ssh"
)

func main() {
	sshServer := gliderssh.Server{
		Addr: ":2221", // Porta do servidor

		PublicKeyHandler: func(ctx gliderssh.Context, key gliderssh.PublicKey) bool {
			fmt.Printf("Usuário '%s' autenticado com chave pública:\n%s\n",
				ctx.User(),
				ssh.MarshalAuthorizedKey(key),
			)
			return true // Permitir todos os usuários com qualquer chave pública
		},

		Handler: func(s gliderssh.Session) {
			io.WriteString(s, fmt.Sprintf("Bem-vindo, %s!\n", s.User()))
		},
	}

	log.Println("Servidor SSH ouvindo na porta 2222...")
	log.Fatal(sshServer.ListenAndServe())
}
