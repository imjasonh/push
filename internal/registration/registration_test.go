package registration

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterHandler(t *testing.T) {
	t.Run("missing cookie", func(t *testing.T) {
		handler := RegisterHandler(nil)
		
		reqBody := `{"endpoint": "https://fcm.googleapis.com/test"}`
		req := httptest.NewRequest("POST", "/register", strings.NewReader(reqBody))
		w := httptest.NewRecorder()
		
		handler(w, req)
		
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d for missing cookie, got %d", http.StatusBadRequest, w.Code)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		handler := RegisterHandler(nil)
		
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
		handler := UnregisterHandler(nil)
		
		req := httptest.NewRequest("POST", "/unregister", nil)
		w := httptest.NewRecorder()
		
		handler(w, req)
		
		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d for missing cookie, got %d", http.StatusBadRequest, w.Code)
		}
	})
}