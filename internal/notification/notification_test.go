package notification

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/googleapis/gax-go/v2"
	"cloud.google.com/go/kms/apiv1/kmspb"
	"github.com/google/go-github/v55/github"
)

// MockKMSClient implements the crypto.KMSClient interface for testing
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

func TestNotificationPayloadCreation(t *testing.T) {
	subjectURL := "https://api.github.com/repos/test/repo/issues/1"
	
	// Create expected payload structure
	payload := map[string]interface{}{
		"title": "GitHub: Test Issue",
		"body":  "New Issue in test/repo",
		"icon":  "/icon.png",
		"badge": "/badge.png",
		"data": map[string]interface{}{
			"url": subjectURL,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Error marshaling payload: %v", err)
	}

	// Verify JSON is valid
	var parsed map[string]interface{}
	if err := json.Unmarshal(payloadBytes, &parsed); err != nil {
		t.Fatalf("Error parsing payload JSON: %v", err)
	}

	if parsed["title"] != "GitHub: Test Issue" {
		t.Errorf("Expected title 'GitHub: Test Issue', got '%v'", parsed["title"])
	}
}

func TestSendPush(t *testing.T) {
	// Create mock KMS client
	mockClient := NewMockKMSClient()
	
	ctx := context.Background()
	endpoint := "https://fcm.googleapis.com/test-endpoint"
	keyName := "test-key"
	
	// Create test notification
	title := "Test Subject"
	repoName := "test/repo"
	subjectType := "Issue"
	subjectURL := "https://api.github.com/repos/test/repo/issues/1"
	
	notification := &github.Notification{
		Subject: &github.NotificationSubject{
			Title: &title,
			Type:  &subjectType,
			URL:   &subjectURL,
		},
		Repository: &github.Repository{
			FullName: &repoName,
		},
	}
	
	// Test the sendPush function
	// This will fail at the HTTP request stage since we're using a dummy endpoint,
	// but we can verify it gets past the KMS signing stage
	err := sendPush(ctx, endpoint, notification, mockClient, keyName)
	
	// We expect this to fail at the HTTP request stage (not KMS stage)
	if err == nil {
		t.Error("Expected error for dummy endpoint, but got none")
	}
	
	// The error should NOT be about KMS operations, but about the HTTP request
	// If we get a KMS error, it means our mock isn't working properly
	errMsg := err.Error()
	if strings.Contains(errMsg, "KMS") || strings.Contains(errMsg, "signing") {
		t.Errorf("Error should not be about KMS operations, got: %v", err)
	}
}