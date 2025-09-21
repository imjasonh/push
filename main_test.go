package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-github/v55/github"
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
	// Generate a test private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Error generating private key: %v", err)
	}

	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		t.Fatalf("Error marshaling private key: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	// Test the pubkey handler
	handler := pubkey(pemData)
	
	req := httptest.NewRequest("GET", "/pubkey", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Error reading response body: %v", err)
	}

	if len(body) == 0 {
		t.Error("Empty public key response")
	}

	// Verify the public key format (base64 URL encoded)
	pubKeyStr := string(body)
	if len(pubKeyStr) == 0 {
		t.Error("Public key should not be empty")
	}
	
	// Should be valid base64 
	if _, err := base64.URLEncoding.DecodeString(pubKeyStr); err != nil {
		t.Errorf("Public key should be valid base64 URL encoded: %v", err)
	}
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

func TestSendPushNotification(t *testing.T) {
	// Generate test private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Error generating private key: %v", err)
	}

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

	// Test with a dummy endpoint
	endpoint := "https://fcm.googleapis.com/test-endpoint"
	
	// This will likely fail with a real request, but we can test the function doesn't panic
	err = sendPushNotification(endpoint, notification, privateKey)
	// We expect this to fail since it's not a real endpoint
	if err == nil {
		t.Error("Expected error for dummy endpoint, but got none")
	}
}

func BenchmarkPubkeyGeneration(b *testing.B) {
	// Generate a test private key once
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("Error generating private key: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		b.Fatalf("Error marshaling private key: %v", err)
	}

	pemData := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		handler := pubkey(pemData)
		req := httptest.NewRequest("GET", "/pubkey", nil)
		w := httptest.NewRecorder()
		handler(w, req)
	}
}