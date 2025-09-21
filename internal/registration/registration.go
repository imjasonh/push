package registration

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"cloud.google.com/go/firestore"
	"github.com/google/go-github/v55/github"
)

// Doc represents a user document in Firestore
type Doc struct {
	Endpoint string `firestore:"endpoint"`
	GHID     string `firestore:"ghid"`
}

// RegisterHandler creates an HTTP handler for user registration
func RegisterHandler(client *firestore.Client) http.HandlerFunc {
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
		if _, err := client.Collection("users").Doc(ghtoken.Value).Set(ctx, Doc{
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

// UnregisterHandler creates an HTTP handler for user unregistration
func UnregisterHandler(client *firestore.Client) http.HandlerFunc {
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