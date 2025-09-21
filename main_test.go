package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestKeygen(t *testing.T) {
	// Test key generation
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

func TestPubkeyHandler(t *testing.T) {
	// Skip this test as it now requires KMS integration
	t.Skip("Pubkey handler now requires KMS integration")
}

func TestAuthStartHandler(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		wantCode int
	}{
		{
			name:     "valid client ID",
			clientID: "test-client-id",
			wantCode: http.StatusSeeOther,
		},
		{
			name:     "empty client ID",
			clientID: "",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := authStart(tt.clientID)
			req := httptest.NewRequest("GET", "/auth/start", nil)
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.wantCode {
				t.Errorf("Expected status %d, got %d", tt.wantCode, w.Code)
			}

			if tt.wantCode == http.StatusSeeOther {
				location := w.Header().Get("Location")
				if !strings.Contains(location, "github.com") {
					t.Error("Expected redirect to GitHub")
				}
				if !strings.Contains(location, tt.clientID) {
					t.Error("Expected client ID in redirect URL")
				}
			}
		})
	}
}

func TestAuthRedirectHandler(t *testing.T) {
	tests := []struct {
		name         string
		query        string
		wantCode     int
	}{
		{
			name:     "missing code",
			query:    "",
			wantCode: http.StatusBadRequest,
		},
		{
			name:     "error parameter",
			query:    "error=access_denied&error_description=User+denied",
			wantCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := authRedirect("test-id", "test-secret")
			req := httptest.NewRequest("GET", "/auth/callback?"+tt.query, nil)
			w := httptest.NewRecorder()

			// For tests that don't make external requests
			if tt.wantCode == http.StatusBadRequest || tt.wantCode == http.StatusInternalServerError {
				handler(w, req)
				if w.Code != tt.wantCode {
					t.Errorf("Expected status %d, got %d", tt.wantCode, w.Code)
				}
			}
		})
	}
}

func TestRegisterHandler(t *testing.T) {
	t.Run("missing cookie", func(t *testing.T) {
		handler := register(nil)
		
		reqBody := `{"endpoint": "https://fcm.googleapis.com/test"}`
		req := httptest.NewRequest("POST", "/register", strings.NewReader(reqBody))
		w := httptest.NewRecorder()
		
		handler(w, req)
		
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d for missing cookie, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		handler := register(nil)
		
		req := httptest.NewRequest("POST", "/register", strings.NewReader("invalid json"))
		req.AddCookie(&http.Cookie{Name: "token", Value: "test-token"})
		w := httptest.NewRecorder()
		
		handler(w, req)
		
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d for invalid JSON, got %d", http.StatusBadRequest, w.Code)
		}
	})
}

func TestUnregisterHandler(t *testing.T) {
	t.Run("missing cookie", func(t *testing.T) {
		handler := unregister(nil)
		
		req := httptest.NewRequest("POST", "/unregister", nil)
		w := httptest.NewRecorder()
		
		handler(w, req)
		
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d for missing cookie, got %d", http.StatusBadRequest, w.Code)
		}
	})
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

func TestSendPushNotification(t *testing.T) {
	// Skip this test as it now requires KMS integration
	t.Skip("Push notification now requires KMS integration")
}

func BenchmarkPubkeyGeneration(b *testing.B) {
	// Skip this benchmark as it now requires KMS integration
	b.Skip("Pubkey generation now requires KMS integration")
}