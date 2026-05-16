package foil

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestLiveSmoke(t *testing.T) {
	if os.Getenv("FOIL_LIVE_SMOKE") != "1" {
		t.Skip("set FOIL_LIVE_SMOKE=1 to run live smoke tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := NewClient(
		WithSecretKey(requireEnv(t, "FOIL_SMOKE_SECRET_KEY")),
		WithBaseURL(envOrDefault("FOIL_SMOKE_BASE_URL", defaultBaseURL)),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	organizationID := requireEnv(t, "FOIL_SMOKE_ORGANIZATION_ID")

	var createdKeyID string
	var rotatedKeyID string
	defer func() {
		bestEffortRevoke(t, ctx, client, organizationID, rotatedKeyID)
		if createdKeyID != "" && createdKeyID != rotatedKeyID {
			bestEffortRevoke(t, ctx, client, organizationID, createdKeyID)
		}
	}()

	sessions, err := client.Sessions.List(ctx, SessionListParams{Limit: 1})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions.Items) == 0 {
		t.Fatal("smoke organization must have at least one session for the live smoke suite")
	}
	session, err := client.Sessions.Get(ctx, sessions.Items[0].ID)
	if err != nil {
		t.Fatalf("get session: %v", err)
	}
	if session.ID != sessions.Items[0].ID {
		t.Fatalf("unexpected session id %q", session.ID)
	}

	fingerprints, err := client.Fingerprints.List(ctx, FingerprintListParams{Limit: 1})
	if err != nil {
		t.Fatalf("list fingerprints: %v", err)
	}
	if len(fingerprints.Items) == 0 {
		t.Fatal("smoke organization must have at least one fingerprint for the live smoke suite")
	}
	fingerprint, err := client.Fingerprints.Get(ctx, fingerprints.Items[0].ID)
	if err != nil {
		t.Fatalf("get fingerprint: %v", err)
	}
	if fingerprint.ID != fingerprints.Items[0].ID {
		t.Fatalf("unexpected fingerprint id %q", fingerprint.ID)
	}

	organization, err := client.Organizations.Get(ctx, organizationID)
	if err != nil {
		t.Fatalf("get organization: %v", err)
	}
	updatedOrganization, err := client.Organizations.Update(ctx, organizationID, UpdateOrganizationParams{Name: organization.Name, Status: organization.Status})
	if err != nil {
		t.Fatalf("update organization: %v", err)
	}
	if updatedOrganization.Name != organization.Name || updatedOrganization.Status != organization.Status {
		t.Fatalf("unexpected updated organization state %#v", updatedOrganization)
	}

	createdKey, err := client.Organizations.APIKeys.Create(ctx, organizationID, CreateAPIKeyParams{
		Name:        fmt.Sprintf("sdk-smoke-%x", time.Now().UnixMilli()),
		Environment: "test",
	})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	createdKeyID = createdKey.ID
	if len(createdKey.RevealedKey) < 3 || createdKey.RevealedKey[:3] != "sk_" {
		t.Fatalf("unexpected created secret key %q", createdKey.RevealedKey)
	}

	listedKey, err := findAPIKey(ctx, client, organizationID, createdKey.ID)
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	if listedKey == nil || listedKey.ID != createdKey.ID {
		t.Fatalf("created key %q not found in api key list", createdKey.ID)
	}

	rotatedKey, err := client.Organizations.APIKeys.Rotate(ctx, organizationID, createdKey.ID)
	if err != nil {
		t.Fatalf("rotate api key: %v", err)
	}
	rotatedKeyID = rotatedKey.ID
	if len(rotatedKey.RevealedKey) < 3 || rotatedKey.RevealedKey[:3] != "sk_" {
		t.Fatalf("unexpected rotated secret key %q", rotatedKey.RevealedKey)
	}

	fixture := loadFixture[struct {
		Token     string         `json:"token"`
		SecretKey string         `json:"secretKey"`
		Payload   map[string]any `json:"payload"`
	}](t, "sealed-token/vector.v1.json")

	result := SafeVerifyFoilToken(fixture.Token, fixture.SecretKey)
	if !result.OK || result.Data == nil {
		t.Fatalf("verify sealed token fixture: %v", result.Error)
	}
	decisionRaw, ok := fixture.Payload["decision"].(map[string]any)
	if !ok || result.Data.Decision.EventID != decisionRaw["event_id"] {
		t.Fatalf("unexpected verified event id %#v", result.Data.Decision.EventID)
	}
}

func requireEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required for the live smoke suite", name)
	}
	return value
}

func envOrDefault(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func findAPIKey(ctx context.Context, client *Client, organizationID string, keyID string) (*APIKey, error) {
	cursor := ""
	for {
		page, err := client.Organizations.APIKeys.List(ctx, organizationID, APIKeyListParams{Limit: 100, Cursor: cursor})
		if err != nil {
			return nil, err
		}
		for _, item := range page.Items {
			if item.ID == keyID {
				copied := item
				return &copied, nil
			}
		}
		if !page.HasMore || page.NextCursor == "" {
			return nil, nil
		}
		cursor = page.NextCursor
	}
}

func bestEffortRevoke(t *testing.T, ctx context.Context, client *Client, organizationID string, keyID string) {
	t.Helper()
	if keyID == "" {
		return
	}
	if _, err := client.Organizations.APIKeys.Revoke(ctx, organizationID, keyID); err != nil {
		if apiError, ok := err.(*APIError); ok && (apiError.Status == 404 || apiError.Code == "request.not_found") {
			return
		}
		t.Fatalf("revoke api key %s: %v", keyID, err)
	}
}
