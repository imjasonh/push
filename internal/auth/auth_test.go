package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStartHandler(t *testing.T) {
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
			handler := StartHandler(tt.clientID)
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

func TestRedirectHandler(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantCode int
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
			handler := RedirectHandler("test-id", "test-secret")
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