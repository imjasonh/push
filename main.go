package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/kelseyhightower/envconfig"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "keygen" {
		keygen()
		return
	}

	var env struct {
		PrivateKey     []byte `envconfig:"PRIVATE_KEY" required:"true"`
		GitHubClientID string `envconfig:"GH_CLIENT_ID" required:"false" default:""`
		GitHubSecret   string `envconfig:"GH_SECRET" required:"false" default:""`
	}
	if err := envconfig.Process("", &env); err != nil {
		log.Fatalf("Processing env: %v", err)
	}

	http.HandleFunc("/pubkey", pubkey(env.PrivateKey))
	http.HandleFunc("/register", register())
	http.HandleFunc("/auth/start", authStart(env.GitHubClientID))
	http.HandleFunc("/auth/callback", authRedirect(env.GitHubClientID, env.GitHubSecret))
	http.Handle("/", http.FileServer(http.Dir(os.Getenv("KO_DATA_PATH"))))
	http.ListenAndServe(":8080", nil)
}

func pubkey(privateKey []byte) http.HandlerFunc {
	block, _ := pem.Decode(privateKey)
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}
	pub, err := priv.PublicKey.ECDH()
	if err != nil {
		log.Fatalf("Error generating ECDH public key: %v", err)
	}
	s := base64.URLEncoding.EncodeToString(pub.Bytes())
	log.Printf("Public key: %q", s)
	return func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, s) }
}

func register() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL)
		var req struct {
			Endpoint string `json:"endpoint"`
		}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Fatalf("Error decoding request: %v", err)
		}
		log.Println("Endpoint:", req.Endpoint)
	}
}

func authStart(clientID string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL)

		if clientID == "" {
			http.Error(w, "Missing client ID", http.StatusInternalServerError)
			return
		}

		// TODO: local redirect uri

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

func authRedirect(clientID, secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Method, r.URL)

		if r.URL.Query().Get("error") != "" {
			fmt.Fprintln(w, "Error:", r.URL.Query().Get("error_description"))
			http.Error(w, "Error", http.StatusInternalServerError)
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

		fmt.Fprintln(w, "Access token:", token.Token)
	}
}

func keygen() {
	const pk = "./private.pem"
	if _, err := os.Stat(pk); err == nil {
		log.Fatalf("Private key already exists: %s", pk)
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("Error generating private key: %v", err)
	}
	b, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		log.Fatalf("Error marshaling private key: %v", err)
	}
	f, err := os.Create(pk)
	if err != nil {
		log.Fatalf("Error opening file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}); err != nil {
		log.Fatalf("Encoding PEM: %v", err)
	}
	log.Println("wrote private key to", pk)
}
