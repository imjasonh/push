package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

// Generate generates a local ECDSA private key for backward compatibility
func Generate() {
	log.Println("NOTE: This tool generates local keys, but the application now uses Google Cloud KMS.")
	log.Println("The generated key will not be used by the application unless you configure it to use local keys.")
	log.Println()
	
	const pk = "./private.pem"
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
	log.Println()
	log.Println("To use this key with the application, you would need to modify the configuration")
	log.Println("to load the key locally instead of using KMS.")
}