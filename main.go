package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/firestore"
	kms "cloud.google.com/go/kms/apiv1"
	"cloud.google.com/go/kms/apiv1/kmspb"
	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/google/go-github/v55/github"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var projectID string

func init() {
	// Skip in test environment
	if os.Getenv("GO_ENV") == "test" {
		projectID = "test-project"
		return
	}
	
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
		GitHubClientID string `envconfig:"GH_CLIENT_ID" required:"false" default:""`
		GitHubSecret   string `envconfig:"GH_SECRET" required:"false" default:""`
		KMSKeyName     string `envconfig:"KMS_KEY_NAME" required:"true"`
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

	// Create KMS client
	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		log.Fatalf("Failed to create KMS client: %v", err)
	}
	defer kmsClient.Close()

	http.HandleFunc("/pubkey", pubkey(ctx, kmsClient, env.KMSKeyName))
	http.HandleFunc("/register", register(client))
	http.HandleFunc("/unregister", unregister(client))
	http.HandleFunc("/auth/start", authStart(env.GitHubClientID))
	http.HandleFunc("/auth/callback", authRedirect(env.GitHubClientID, env.GitHubSecret))
	http.Handle("/", http.FileServer(http.Dir(os.Getenv("KO_DATA_PATH"))))
	
	// Start notification polling in background
	go startNotificationPoller(client, ctx, kmsClient, env.KMSKeyName)
	
	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}

func pubkey(ctx context.Context, kmsClient *kms.KeyManagementClient, keyName string) http.HandlerFunc {
	// Get the public key from KMS
	req := &kmspb.GetPublicKeyRequest{Name: keyName}
	pubKeyResp, err := kmsClient.GetPublicKey(ctx, req)
	if err != nil {
		log.Fatalf("Error getting public key from KMS: %v", err)
	}

	// Parse the public key
	block, _ := pem.Decode([]byte(pubKeyResp.Pem))
	if block == nil {
		log.Fatalf("Error decoding public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}

	ecdsaKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		log.Fatalf("Public key is not ECDSA")
	}

	// Convert to ECDH format for Web Push
	ecdhKey, err := ecdsaKey.ECDH()
	if err != nil {
		log.Fatalf("Error converting to ECDH: %v", err)
	}

	s := base64.URLEncoding.EncodeToString(ecdhKey.Bytes())
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
			return
		}
		log.Println("Endpoint:", req.Endpoint)

		ghtoken, err := r.Cookie("token")
		if err != nil {
			log.Printf("getting GH cookie: %v", err)
			http.Error(w, "Missing GH token cookie", http.StatusBadRequest)
			return
		}
		log.Println("Token:", ghtoken)

		u, _, err := github.NewClient(nil).WithAuthToken(ghtoken.Value).Users.Get(ctx, "")
		if err != nil {
			log.Printf("getting current GH user: %v", err)
			http.Error(w, "Error getting user", http.StatusInternalServerError)
			return
		}

		// Create or update the document.
		if _, err := client.Collection("users").Doc(ghtoken.Value).Set(ctx, doc{
			Endpoint: req.Endpoint,
			GHID:     fmt.Sprintf("%d", *u.ID),
		}); err != nil {
			log.Printf("Error adding document: %v", err)
			http.Error(w, "Error", http.StatusInternalServerError)
			return
		}
		
		log.Printf("Successfully registered user %d with endpoint %s", *u.ID, req.Endpoint)
		w.WriteHeader(http.StatusOK)
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
	log.Println("NOTE: This tool generates local keys, but the application now uses Google Cloud KMS.")
	log.Println("The generated key will not be used by the application unless you configure it to use local keys.")
	log.Println()
	
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
	log.Println()
	log.Println("To use this key with the application, you would need to modify the configuration")
	log.Println("to load the key locally instead of using KMS.")
}

func unregister(client *firestore.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		log.Println(r.Method, r.URL)

		ghtoken, err := r.Cookie("token")
		if err != nil {
			log.Printf("getting GH cookie: %v", err)
			http.Error(w, "Missing GH token cookie", http.StatusBadRequest)
			return
		}

		// Delete the user document
		if _, err := client.Collection("users").Doc(ghtoken.Value).Delete(ctx); err != nil {
			log.Printf("Error deleting document: %v", err)
			http.Error(w, "Error unregistering", http.StatusInternalServerError)
			return
		}

		log.Printf("Successfully unregistered user with token %s", ghtoken.Value[:8]+"...")
		w.WriteHeader(http.StatusOK)
	}
}

func startNotificationPoller(client *firestore.Client, ctx context.Context, kmsClient *kms.KeyManagementClient, keyName string) {
	log.Println("Starting notification poller...")

	ticker := time.NewTicker(30 * time.Second) // Poll every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := pollAndSendNotifications(client, ctx, kmsClient, keyName); err != nil {
				log.Printf("Error polling notifications: %v", err)
			}
		}
	}
}

func pollAndSendNotifications(client *firestore.Client, ctx context.Context, kmsClient *kms.KeyManagementClient, keyName string) error {
	// Get all registered users
	users, err := client.Collection("users").Documents(ctx).GetAll()
	if err != nil {
		return fmt.Errorf("getting users: %w", err)
	}

	log.Printf("Polling notifications for %d registered users", len(users))

	for _, userDoc := range users {
		var userData doc
		if err := userDoc.DataTo(&userData); err != nil {
			log.Printf("Error parsing user data: %v", err)
			continue
		}

		ghToken := userDoc.Ref.ID
		if err := processUserNotifications(ctx, ghToken, userData, kmsClient, keyName); err != nil {
			log.Printf("Error processing notifications for user %s: %v", userData.GHID, err)
		}
	}

	return nil
}

func processUserNotifications(ctx context.Context, ghToken string, userData doc, kmsClient *kms.KeyManagementClient, keyName string) error {
	// Create GitHub client with user's token
	ghClient := github.NewClient(nil).WithAuthToken(ghToken)
	
	// Get notifications (only unread ones)
	notifications, _, err := ghClient.Activity.ListNotifications(ctx, &github.NotificationListOptions{
		All: false, // Only unread
		ListOptions: github.ListOptions{
			PerPage: 10, // Limit to avoid overwhelming
		},
	})
	if err != nil {
		return fmt.Errorf("getting GitHub notifications: %w", err)
	}

	if len(notifications) == 0 {
		return nil // No new notifications
	}

	log.Printf("Found %d notifications for user %s", len(notifications), userData.GHID)

	// Send push notification for each GitHub notification
	for _, notification := range notifications {
		if err := sendPushNotification(ctx, userData.Endpoint, notification, kmsClient, keyName); err != nil {
			log.Printf("Error sending push notification: %v", err)
		}
	}

	return nil
}

func sendPushNotification(ctx context.Context, endpoint string, notification *github.Notification, kmsClient *kms.KeyManagementClient, keyName string) error {
	// Prepare notification payload
	payload := map[string]interface{}{
		"title": fmt.Sprintf("GitHub: %s", *notification.Subject.Title),
		"body":  fmt.Sprintf("New %s in %s", *notification.Subject.Type, *notification.Repository.FullName),
		"icon":  "/icon.png",
		"badge": "/badge.png",
		"data": map[string]interface{}{
			"url": *notification.Subject.URL,
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	// Create Web Push subscription
	subscription := &webpush.Subscription{
		Endpoint: endpoint,
		Keys: webpush.Keys{
			// These would normally come from the subscription, but for demo purposes
			// we'll use empty values since the endpoint contains the key info
		},
	}

	// For now, we'll use a simple implementation that generates the VAPID token manually
	// This is a simplified version - in production you'd want to use the full VAPID spec
	vapidToken, err := generateVAPIDToken(ctx, kmsClient, keyName, endpoint)
	if err != nil {
		return fmt.Errorf("generating VAPID token: %w", err)
	}

	// Set the authorization header manually
	headers := map[string]string{
		"Authorization": "vapid t=" + vapidToken,
		"TTL":           "30",
	}

	// Send the push notification with custom headers
	resp, err := sendWebPushWithHeaders(payloadBytes, subscription, headers)
	if err != nil {
		return fmt.Errorf("sending push notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("push service responded with status %d", resp.StatusCode)
	}

	log.Printf("Push notification sent successfully for: %s", *notification.Subject.Title)
	return nil
}

// KMSSigner implements signing using Google Cloud KMS
type KMSSigner struct {
	client  *kms.KeyManagementClient
	keyName string
	ctx     context.Context
}

// generateVAPIDToken creates a VAPID JWT token using KMS for signing
func generateVAPIDToken(ctx context.Context, kmsClient *kms.KeyManagementClient, keyName, audience string) (string, error) {
	// Create JWT header
	header := map[string]interface{}{
		"alg": "ES256",
		"typ": "JWT",
	}

	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("marshaling header: %w", err)
	}

	// Create JWT payload
	now := time.Now()
	payload := map[string]interface{}{
		"aud": audience,
		"exp": now.Add(12 * time.Hour).Unix(),
		"sub": "mailto:push@example.com", // Should be your email
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	// Create the message to sign
	message := base64.RawURLEncoding.EncodeToString(headerBytes) + "." + base64.RawURLEncoding.EncodeToString(payloadBytes)

	// Hash the message
	hasher := sha256.New()
	hasher.Write([]byte(message))
	digest := hasher.Sum(nil)

	// Sign with KMS
	req := &kmspb.AsymmetricSignRequest{
		Name:   keyName,
		Digest: &kmspb.Digest{Digest: &kmspb.Digest_Sha256{Sha256: digest}},
	}

	result, err := kmsClient.AsymmetricSign(ctx, req)
	if err != nil {
		return "", fmt.Errorf("signing with KMS: %w", err)
	}

	// Parse the signature
	signature, err := parseECDSASignature(result.Signature)
	if err != nil {
		return "", fmt.Errorf("parsing signature: %w", err)
	}

	// Complete the JWT
	jwt := message + "." + base64.RawURLEncoding.EncodeToString(signature)
	return jwt, nil
}

// parseECDSASignature converts DER-encoded ECDSA signature to the format expected by JWT
func parseECDSASignature(derSig []byte) ([]byte, error) {
	var sig struct {
		R *big.Int
		S *big.Int
	}

	_, err := asn1.Unmarshal(derSig, &sig)
	if err != nil {
		return nil, fmt.Errorf("unmarshaling signature: %w", err)
	}

	// Convert to 64-byte format (32 bytes each for r and s)
	rBytes := sig.R.FillBytes(make([]byte, 32))
	sBytes := sig.S.FillBytes(make([]byte, 32))

	signature := append(rBytes, sBytes...)
	return signature, nil
}

// sendWebPushWithHeaders is a simplified version of webpush.SendNotification with custom headers
func sendWebPushWithHeaders(payload []byte, subscription *webpush.Subscription, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest("POST", subscription.Endpoint, strings.NewReader(string(payload)))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	// Set content type
	req.Header.Set("Content-Type", "application/octet-stream")

	// Set custom headers
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}
