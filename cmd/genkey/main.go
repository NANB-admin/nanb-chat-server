// Generates a fresh Ed25519 private key suitable for NANB_JWT_PRIV_KEY_B64.
// Prints the standard-base64-encoded 64-byte private key to stdout, nothing else.
//
//	go run ./cmd/genkey
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
)

func main() {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatalf("generate: %v", err)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(priv))
}
