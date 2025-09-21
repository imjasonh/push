package auth

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
)

// StartHandler creates an HTTP handler for GitHub OAuth initiation
func StartHandler(clientID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL)

		if clientID == "" {
			http.Error(w, "Missing client ID", http.StatusInternalServerError)
			return
		}

		url := (&url.URL{
			Scheme: "https",
			Host:   "github.com",
			Path:   "/login/oauth/authorize",
			RawQuery: (&url.Values{
				"client_id": {strings.TrimSpace(clientID)},
				"scope":     {"notifications"},
			}).Encode(),
		}).String()
		log.Println("redirecting to", url)
		http.Redirect(w, r, url, http.StatusSeeOther)
	}
}

// RedirectHandler creates an HTTP handler for GitHub OAuth callback
func RedirectHandler(clientID, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL)

		if r.URL.Query().Get("error") != "" {
			http.Error(w, "Error: "+r.URL.Query().Get("error_description"), http.StatusInternalServerError)
			return
		}

		code := r.URL.Query().Get("code")
		if code == "" {
			http.Error(w, "Missing code", http.StatusBadRequest)
			return
		}

		url := (&url.URL{
			Scheme: "https",
			Host:   "github.com",
			Path:   "/login/oauth/access_token",
			RawQuery: (&url.Values{
				"code":          {code},
				"client_id":     {strings.TrimSpace(clientID)},
				"client_secret": {strings.TrimSpace(secret)},
			}).Encode(),
		}).String()
		req, err := http.NewRequest(http.MethodPost, url, nil)
		if err != nil {
			log.Fatalf("Error creating request: %v", err)
		}
		req.Header.Set("Accept", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			log.Fatalf("Error making request: %v", err)
		}
		defer resp.Body.Close()
		var token struct {
			Token string `json:"access_token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
			log.Fatalf("Error decoding response: %v", err)
		}
		log.Println("token:", token.Token)
		http.SetCookie(w, &http.Cookie{
			Name:  "token",
			Value: token.Token,
			Path:  "/",
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}