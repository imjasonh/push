package main

import (
	"context"
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

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/firestore"
	"github.com/google/go-github/v55/github"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var projectID string

func init() {
	var err error
	projectID, err = metadata.ProjectID()
	if err != nil {
		log.Fatalf("Failed to get project ID: %v", err)
	}
}

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

	ctx := context.Background()
	client, err := firestore.NewClient(ctx, projectID)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()

	if _, err := client.Collection("users").Doc("test").Get(ctx); err != nil && status.Code(err) != codes.NotFound {
		log.Fatalf("failed to query users: %v", err)
	}

	http.HandleFunc("/pubkey", pubkey(env.PrivateKey))
	http.HandleFunc("/register", register(client))
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

type doc struct {
	Endpoint string `firestore:"endpoint"`
	GHID     string `firestore:"ghid"`
}

func register(client *firestore.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log.Println(r.Method, r.URL)

		var req struct {
			Endpoint string `json:"endpoint"`
		}
		defer r.Body.Close()
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			log.Printf("Error decoding request: %v", err)
			http.Error(w, "Bad request", http.StatusBadRequest)
		}
		log.Println("Endpoint:", req.Endpoint)

		ghtoken, err := r.Cookie("token")
		if err != nil {
			log.Printf("getting GH cookie: %v", err)
			http.Error(w, "Missing GH token cookie", http.StatusBadRequest)
		}
		log.Println("Token:", ghtoken)

		u, _, err := github.NewClient(nil).WithAuthToken(ghtoken.Value).Users.Get(ctx, "")
		if err != nil {
			log.Printf("getting current GH user: %v", err)
			http.Error(w, "Error getting user", http.StatusInternalServerError)
		}

		// Create or update the document.
		if _, err := client.Collection("users").Doc(ghtoken.Value).Set(ctx, doc{
			Endpoint: req.Endpoint,
			GHID:     fmt.Sprintf("%d", *u.ID),
		}); err != nil {
			log.Fatalf("Error adding document: %v", err)
			http.Error(w, "Error", http.StatusInternalServerError)
		}
	}
}

func authStart(clientID string) http.HandlerFunc {
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
		log.Println("token:", token.Token) // TODO: save it
		http.SetCookie(w, &http.Cookie{
			Name:  "token",
			Value: token.Token,
			Path:  "/",
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
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
