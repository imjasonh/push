package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// PublicKeyHandler creates an HTTP handler that returns the public key from KMS
func PublicKeyHandler(ctx context.Context, kmsClient *kms.KeyManagementClient, keyName string) http.HandlerFunc {
	// Get the public key from KMS
	req := &kmspb.GetPublicKeyRequest{Name: keyName}
	pubKeyResp, err := kmsClient.GetPublicKey(ctx, req)
	if err != nil {
		log.Fatalf("Error getting public key from KMS: %v", err)
	}

	// Parse the public key
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		log.Fatalf("Error decoding public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public key is not ECDSA")
	}

	// Convert to ECDH format for Web Push
	ecdhKey, err := ecdsaKey.ECDH()
	if err != nil {
		log.Fatalf("Error converting to ECDH: %v", err)
	}

	s := base64.URLEncoding.EncodeToString(ecdhKey.Bytes())
	log.Printf("Public key: %q", s)
	return func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, s) }
}

// GenerateVAPIDToken creates a VAPID JWT token using KMS for signing
func GenerateVAPIDToken(ctx context.Context, kmsClient *kms.KeyManagementClient, keyName, audience string) (string, error) {
	// Create JWT header
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}

	// Create JWT payload
	now := time.Now()
	payload := map[string]interface{}{
		"aud": audience,
		"exp": now.Add(12 * time.Hour).Unix(),
		"sub": "mailto:push@example.com", // Should be your email
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	// Create the message to sign
	message := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Hash the message
	hasher := sha256.New()
	hasher.Write([]byte(message))
	digest := hasher.Sum(nil)

	// Sign with KMS
	req := &kmspb.AsymmetricSignRequest{
		Name:   keyName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
	}

	result, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		return "", fmt.Errorf("signing with KMS: %w", err)
	}

	// Parse the signature
	signature, err := parseECDSASignature(result.Signature)
	if err != nil {
		return "", fmt.Errorf("parsing signature: %w", err)
	}

	// Complete the JWT
	jwt := message + "." + base64.RawURLEncoding.EncodeToString(signature)
	return jwt, nil
}

// parseECDSASignature converts DER-encoded ECDSA signature to the format expected by JWT
func parseECDSASignature(derSig []byte) ([]byte, error) {
	var sig struct {
		R *big.Int
		S *big.Int
	}

	_, err := asn1.Unmarshal(derSig, &sig)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling signature: %w", err)
	}

	// Convert to 64-byte format (32 bytes each for r and s)
	rBytes := sig.R.FillBytes(make([]byte, 32))
	sBytes := sig.S.FillBytes(make([]byte, 32))

	signature := append(rBytes, sBytes...)
	return signature, nil
}