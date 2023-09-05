package main

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen()
		return
	}

	pk := os.Getenv("PRIVATE_KEY_PATH")
	if pk == "" {
		pk = "./private.pem"
	}
	b, err := os.ReadFile(pk)
	if err != nil {
		log.Fatalf("Error reading file: %v", err)
	}
	block, _ := pem.Decode(b)
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}
	pub, err := priv.PublicKey.ECDH()
	if err != nil {
		log.Fatalf("Error generating ECDH public key: %v", err)
	}

	http.HandleFunc("/pubkey", pubkey(pub))
	http.HandleFunc("/register", register())
	http.Handle("/", http.FileServer(http.Dir(os.Getenv("KO_DATA_PATH"))))
	http.ListenAndServe(":8080", nil)
}

func pubkey(pub *ecdh.PublicKey) http.HandlerFunc {
	s := base64.URLEncoding.EncodeToString(pub.Bytes())
	log.Printf("Public key: %q", s)
	return func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, s) }
}

func register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Endpoint string `json:"endpoint"`
		}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Fatalf("Error decoding request: %v", err)
		}
		log.Println("Endpoint:", req.Endpoint)
	}
}

func keygen() {
	pk := os.Getenv("PRIVATE_KEY_PATH")
	if pk == "" {
		pk = "./private.pem"
	}
	if _, err := os.Stat(pk); err == nil {
		log.Fatalf("Private key already exists: %s", pk)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Error marshaling private key: %v", err)
	}
	f, err := os.Create(pk)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		log.Fatalf("Encoding PEM: %v", err)
	}
	log.Println("wrote private key to", pk)
}
