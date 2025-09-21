package keygen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

func TestKeyGeneration(t *testing.T) {
	// Test key generation logic (without file operations)
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Error generating private key: %v", err)
	}

	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Error marshaling private key: %v", err)
	}

	// Test parsing
	block := &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	pemData := pem.EncodeToMemory(block)

	block2, _ := pem.Decode(pemData)
	priv2, err := x509.ParseECPrivateKey(block2.Bytes)
	if err != nil {
		t.Fatalf("Error parsing private key: %v", err)
	}

	// Compare keys
	if !privateKey.Equal(priv2) {
		t.Error("Keys do not match after encoding/decoding")
	}
}