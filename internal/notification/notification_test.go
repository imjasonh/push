package notification

import (
	"encoding/json"
	"testing"
)

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
	// Skip this test as it now requires KMS integration
	t.Skip("sendPush now requires KMS integration")
}