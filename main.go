package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/firestore"
	kms "cloud.google.com/go/kms/apiv1"
	"github.com/kelseyhightower/envconfig"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"push/internal/auth"
	"push/internal/crypto"
	"push/internal/keygen"
	"push/internal/notification"
	"push/internal/registration"
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
		keygen.Generate()
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

	http.HandleFunc("/pubkey", crypto.PublicKeyHandler(ctx, kmsClient, env.KMSKeyName))
	http.HandleFunc("/register", registration.RegisterHandler(client))
	http.HandleFunc("/unregister", registration.UnregisterHandler(client))
	http.HandleFunc("/auth/start", auth.StartHandler(env.GitHubClientID))
	http.HandleFunc("/auth/callback", auth.RedirectHandler(env.GitHubClientID, env.GitHubSecret))
	http.Handle("/", http.FileServer(http.Dir(os.Getenv("KO_DATA_PATH"))))
	
	// Start notification polling in background
	go notification.StartPoller(client, ctx, kmsClient, env.KMSKeyName)
	
	log.Println("Server starting on :8080")
	http.ListenAndServe(":8080", nil)
}