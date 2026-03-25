package tripwire

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestLiveSmoke(t *testing.T) {
	if os.Getenv("TRIPWIRE_LIVE_SMOKE") != "1" {
		t.Skip("set TRIPWIRE_LIVE_SMOKE=1 to run live smoke tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	client, err := NewClient(
		WithSecretKey(requireEnv(t, "TRIPWIRE_SMOKE_SECRET_KEY")),
		WithBaseURL(envOrDefault("TRIPWIRE_SMOKE_BASE_URL", defaultBaseURL)),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	teamID := requireEnv(t, "TRIPWIRE_SMOKE_TEAM_ID")

	var createdKeyID string
	var rotatedKeyID string
	defer func() {
		bestEffortRevoke(t, ctx, client, teamID, rotatedKeyID)
		if createdKeyID != "" && createdKeyID != rotatedKeyID {
			bestEffortRevoke(t, ctx, client, teamID, createdKeyID)
		}
	}()

	sessions, err := client.Sessions.List(ctx, SessionListParams{Limit: 1})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(sessions.Items) == 0 {
		t.Fatal("smoke team must have at least one session for the live smoke suite")
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
		t.Fatal("smoke team must have at least one fingerprint for the live smoke suite")
	}
	fingerprint, err := client.Fingerprints.Get(ctx, fingerprints.Items[0].ID)
	if err != nil {
		t.Fatalf("get fingerprint: %v", err)
	}
	if fingerprint.ID != fingerprints.Items[0].ID {
		t.Fatalf("unexpected fingerprint id %q", fingerprint.ID)
	}

	team, err := client.Teams.Get(ctx, teamID)
	if err != nil {
		t.Fatalf("get team: %v", err)
	}
	updatedTeam, err := client.Teams.Update(ctx, teamID, UpdateTeamParams{Name: team.Name, Status: team.Status})
	if err != nil {
		t.Fatalf("update team: %v", err)
	}
	if updatedTeam.Name != team.Name || updatedTeam.Status != team.Status {
		t.Fatalf("unexpected updated team state %#v", updatedTeam)
	}

	isTest := true
	createdKey, err := client.Teams.APIKeys.Create(ctx, teamID, CreateAPIKeyParams{
		Name:   fmt.Sprintf("sdk-smoke-%x", time.Now().UnixMilli()),
		IsTest: &isTest,
	})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	createdKeyID = createdKey.ID
	if len(createdKey.SecretKey) < 3 || createdKey.SecretKey[:3] != "sk_" {
		t.Fatalf("unexpected created secret key %q", createdKey.SecretKey)
	}

	listedKey, err := findAPIKey(ctx, client, teamID, createdKey.ID)
	if err != nil {
		t.Fatalf("list api keys: %v", err)
	}
	if listedKey == nil || listedKey.ID != createdKey.ID {
		t.Fatalf("created key %q not found in api key list", createdKey.ID)
	}

	rotatedKey, err := client.Teams.APIKeys.Rotate(ctx, teamID, createdKey.ID)
	if err != nil {
		t.Fatalf("rotate api key: %v", err)
	}
	rotatedKeyID = rotatedKey.ID
	if len(rotatedKey.SecretKey) < 3 || rotatedKey.SecretKey[:3] != "sk_" {
		t.Fatalf("unexpected rotated secret key %q", rotatedKey.SecretKey)
	}

	fixture := loadFixture[struct {
		Token     string         `json:"token"`
		SecretKey string         `json:"secretKey"`
		Payload   map[string]any `json:"payload"`
	}](t, "sealed-token/vector.v1.json")

	result := SafeVerifyTripwireToken(fixture.Token, fixture.SecretKey)
	if !result.OK || result.Data == nil {
		t.Fatalf("verify sealed token fixture: %v", result.Error)
	}
	if result.Data.EventID != fixture.Payload["eventId"] {
		t.Fatalf("unexpected verified event id %#v", result.Data.EventID)
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

func findAPIKey(ctx context.Context, client *Client, teamID string, keyID string) (*APIKey, error) {
	cursor := ""
	for {
		page, err := client.Teams.APIKeys.List(ctx, teamID, APIKeyListParams{Limit: 100, Cursor: cursor})
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

func bestEffortRevoke(t *testing.T, ctx context.Context, client *Client, teamID string, keyID string) {
	t.Helper()
	if keyID == "" {
		return
	}
	if err := client.Teams.APIKeys.Revoke(ctx, teamID, keyID); err != nil {
		if apiError, ok := err.(*APIError); ok && (apiError.Status == 404 || apiError.Code == "request.not_found") {
			return
		}
		t.Fatalf("revoke api key %s: %v", keyID, err)
	}
}
