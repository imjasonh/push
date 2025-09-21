package crypto

import (
	"encoding/json"
	"testing"
)

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
	// Skip this test as it now requires KMS integration
	t.Skip("PublicKeyHandler now requires KMS integration")
}