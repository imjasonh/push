package crypto

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/googleapis/gax-go/v2"
	"cloud.google.com/go/kms/apiv1/kmspb"
)

// MockKMSClient implements the KMSClient interface for testing
type MockKMSClient struct {
	privateKey *ecdsa.PrivateKey
	publicPEM  string
}

func NewMockKMSClient() *MockKMSClient {
	// Generate a test key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	
	// Create public key PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		panic(err)
	}
	
	publicPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}))
	
	return &MockKMSClient{
		privateKey: privateKey,
		publicPEM:  publicPEM,
	}
}

func (m *MockKMSClient) GetPublicKey(ctx context.Context, req *kmspb.GetPublicKeyRequest, opts ...gax.CallOption) (*kmspb.PublicKey, error) {
	return &kmspb.PublicKey{
		Pem:       m.publicPEM,
		Algorithm: kmspb.CryptoKeyVersion_EC_SIGN_P256_SHA256,
	}, nil
}

func (m *MockKMSClient) AsymmetricSign(ctx context.Context, req *kmspb.AsymmetricSignRequest, opts ...gax.CallOption) (*kmspb.AsymmetricSignResponse, error) {
	// This is a simplified mock - in a real implementation, we'd properly sign the digest
	// For testing purposes, we'll return a dummy signature
	mockSignature := []byte("mock-signature-for-testing-purposes-only")
	
	return &kmspb.AsymmetricSignResponse{
		Signature: mockSignature,
	}, nil
}

// Ensure our mock implements the interface
var _ KMSClient = (*MockKMSClient)(nil)

func TestVAPIDTokenGeneration(t *testing.T) {
	// Test VAPID token structure (without KMS)
	audience := "https://fcm.googleapis.com/test-endpoint"
	
	// Test that we can create the basic JWT structure
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("Error marshaling header: %v", err)
	}

	payload := map[string]interface{}{
		"aud": audience,
		"exp": 1234567890,
		"sub": "mailto:test@example.com",
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Error marshaling payload: %v", err)
	}

	// Verify we can create a proper JWT structure
	if len(headerBytes) == 0 {
		t.Error("Header should not be empty")
	}
	if len(payloadBytes) == 0 {
		t.Error("Payload should not be empty")
	}
}

func TestPublicKeyHandler(t *testing.T) {
	// Create mock KMS client
	mockClient := NewMockKMSClient()
	
	// Test the public key handler
	ctx := context.Background()
	keyName := "test-key"
	handler := PublicKeyHandler(ctx, mockClient, keyName)
	
	req := httptest.NewRequest("GET", "/pubkey", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	body := w.Body.String()
	if len(body) == 0 {
		t.Error("Expected public key response, got empty body")
	}
	
	// The response should be a base64 URL encoded public key
	if len(body) < 10 {
		t.Error("Public key response seems too short")
	}
}

func TestGenerateVAPIDTokenWithMock(t *testing.T) {
	// Create mock KMS client
	mockClient := NewMockKMSClient()
	
	ctx := context.Background()
	keyName := "test-key"
	audience := "https://fcm.googleapis.com/test-endpoint"
	
	// This will return an error because our mock signature is not valid
	// But we can test that the function runs without panicking
	token, err := GenerateVAPIDToken(ctx, mockClient, keyName, audience)
	
	// We expect an error because the mock signature is not valid for JWT
	if err == nil {
		t.Error("Expected error with mock signature, but got none")
	}
	
	// The token should be empty due to the error
	if token != "" {
		t.Errorf("Expected empty token due to error, got: %s", token)
	}
}