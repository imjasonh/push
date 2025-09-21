package notification

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/firestore"
	kms "cloud.google.com/go/kms/apiv1"
	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/google/go-github/v55/github"

	"push/internal/crypto"
	"push/internal/registration"
)

// StartPoller starts the background notification polling goroutine
func StartPoller(client *firestore.Client, ctx context.Context, kmsClient *kms.KeyManagementClient, keyName string) {
	log.Println("Starting notification poller...")

	ticker := time.NewTicker(30 * time.Second) // Poll every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := pollAndSend(client, ctx, kmsClient, keyName); err != nil {
				log.Printf("Error polling notifications: %v", err)
			}
		}
	}
}

// pollAndSend polls GitHub notifications and sends push notifications
func pollAndSend(client *firestore.Client, ctx context.Context, kmsClient *kms.KeyManagementClient, keyName string) error {
	// Get all registered users
	users, err := client.Collection("users").Documents(ctx).GetAll()
	if err != nil {
		return fmt.Errorf("getting users: %w", err)
	}

	log.Printf("Polling notifications for %d registered users", len(users))

	for _, userDoc := range users {
		var userData registration.Doc
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

// processUserNotifications processes GitHub notifications for a single user
func processUserNotifications(ctx context.Context, ghToken string, userData registration.Doc, kmsClient *kms.KeyManagementClient, keyName string) error {
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
		if err := sendPush(ctx, userData.Endpoint, notification, kmsClient, keyName); err != nil {
			log.Printf("Error sending push notification: %v", err)
		}
	}

	return nil
}

// sendPush sends a Web Push notification using KMS-signed VAPID
func sendPush(ctx context.Context, endpoint string, notification *github.Notification, kmsClient *kms.KeyManagementClient, keyName string) error {
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

	// Generate VAPID token using KMS
	vapidToken, err := crypto.GenerateVAPIDToken(ctx, kmsClient, keyName, endpoint)
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