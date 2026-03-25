package tripwire

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func writeJSON(t *testing.T, writer http.ResponseWriter, status int, body any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if body != nil {
		if err := json.NewEncoder(writer).Encode(body); err != nil {
			t.Fatalf("encode response: %v", err)
		}
	}
}

func TestClientUsesEnvSecretFallback(t *testing.T) {
	original := os.Getenv("TRIPWIRE_SECRET_KEY")
	defer os.Setenv("TRIPWIRE_SECRET_KEY", original)
	if err := os.Setenv("TRIPWIRE_SECRET_KEY", "sk_env_default"); err != nil {
		t.Fatal(err)
	}

	fixture := loadFixture[resourceListEnvelope[SessionSummary]](t, "public-api/sessions/list.json")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeJSON(t, writer, http.StatusOK, fixture)
	}))
	defer server.Close()

	client, err := NewClient(WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	page, err := client.Sessions.List(context.Background(), SessionListParams{})
	if err != nil {
		t.Fatalf("list sessions: %v", err)
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected one session, got %d", len(page.Items))
	}
}

func TestClientMissingSecretFails(t *testing.T) {
	original := os.Getenv("TRIPWIRE_SECRET_KEY")
	defer os.Setenv("TRIPWIRE_SECRET_KEY", original)
	_ = os.Unsetenv("TRIPWIRE_SECRET_KEY")

	if _, err := NewClient(); err == nil {
		t.Fatal("expected missing secret error")
	}
}

func TestClientAppliesBaseURLTimeoutAndHeaders(t *testing.T) {
	fixture := loadFixture[resourceListEnvelope[SessionSummary]](t, "public-api/sessions/list.json")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.String() != "/v1/sessions?limit=5" {
			t.Fatalf("unexpected path %s", request.URL.String())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer sk_live_test" {
			t.Fatalf("unexpected auth header %s", got)
		}
		if got := request.Header.Get("X-Tripwire-Client"); got != "tripwire-server-go/0.1.0" {
			t.Fatalf("unexpected client header %s", got)
		}
		if got := request.Header.Get("User-Agent"); got != "custom-tripwire-go" {
			t.Fatalf("unexpected user agent %s", got)
		}
		writeJSON(t, writer, http.StatusOK, fixture)
	}))
	defer server.Close()

	client, err := NewClient(
		WithSecretKey("sk_live_test"),
		WithBaseURL(server.URL),
		WithHTTPClient(server.Client()),
		WithTimeout(5*time.Second),
		WithUserAgent("custom-tripwire-go"),
	)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if client.httpClient.Timeout != 5*time.Second {
		t.Fatalf("expected 5s timeout, got %s", client.httpClient.Timeout)
	}

	if _, err := client.Sessions.List(context.Background(), SessionListParams{Limit: 5}); err != nil {
		t.Fatalf("list sessions: %v", err)
	}
}

func TestSessionsFingerprintsTeamsAndAPIKeys(t *testing.T) {
	sessionList := loadFixture[resourceListEnvelope[SessionSummary]](t, "public-api/sessions/list.json")
	sessionDetail := loadFixture[resourceEnvelope[SessionDetail]](t, "public-api/sessions/detail.json")
	fingerprintList := loadFixture[resourceListEnvelope[FingerprintSummary]](t, "public-api/fingerprints/list.json")
	fingerprintDetail := loadFixture[resourceEnvelope[FingerprintDetail]](t, "public-api/fingerprints/detail.json")
	teamGet := loadFixture[resourceEnvelope[Team]](t, "public-api/teams/team.json")
	teamCreate := loadFixture[resourceEnvelope[Team]](t, "public-api/teams/team-create.json")
	teamUpdate := loadFixture[resourceEnvelope[Team]](t, "public-api/teams/team-update.json")
	apiKeyCreate := loadFixture[resourceEnvelope[IssuedAPIKey]](t, "public-api/teams/api-key-create.json")
	apiKeyList := loadFixture[resourceListEnvelope[APIKey]](t, "public-api/teams/api-key-list.json")
	apiKeyRotate := loadFixture[resourceEnvelope[IssuedAPIKey]](t, "public-api/teams/api-key-rotate.json")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.URL.Path == "/v1/sessions":
			if request.URL.Query().Get("cursor") == "" {
				writeJSON(t, writer, http.StatusOK, sessionList)
				return
			}
			secondPage := resourceListEnvelope[SessionSummary]{
				Data: []SessionSummary{
					{
						Object:        "session",
						ID:            "sid_123456789abcdefghjkmnpqrst",
						LatestEventID: "evt_3456789abcdefghjkmnpqrstvw",
						LatestResult:  sessionList.Data[0].LatestResult,
						LastScoredAt:  "2026-03-24T20:01:05.000Z",
					},
				},
				Pagination: pagination{Limit: 50, HasMore: false},
			}
			writeJSON(t, writer, http.StatusOK, secondPage)
		case request.URL.Path == "/v1/sessions/sid_0123456789abcdefghjkmnpqrs":
			writeJSON(t, writer, http.StatusOK, sessionDetail)
		case request.URL.Path == "/v1/fingerprints":
			writeJSON(t, writer, http.StatusOK, fingerprintList)
		case request.URL.Path == "/v1/fingerprints/vid_456789abcdefghjkmnpqrstvwx":
			writeJSON(t, writer, http.StatusOK, fingerprintDetail)
		case request.URL.Path == "/v1/teams" && request.Method == http.MethodPost:
			writeJSON(t, writer, http.StatusCreated, teamCreate)
		case request.URL.Path == "/v1/teams/team_56789abcdefghjkmnpqrstvwxy" && request.Method == http.MethodGet:
			writeJSON(t, writer, http.StatusOK, teamGet)
		case request.URL.Path == "/v1/teams/team_56789abcdefghjkmnpqrstvwxy" && request.Method == http.MethodPatch:
			writeJSON(t, writer, http.StatusOK, teamUpdate)
		case request.URL.Path == "/v1/teams/team_56789abcdefghjkmnpqrstvwxy/api-keys" && request.Method == http.MethodPost:
			writeJSON(t, writer, http.StatusCreated, apiKeyCreate)
		case request.URL.Path == "/v1/teams/team_56789abcdefghjkmnpqrstvwxy/api-keys" && request.Method == http.MethodGet:
			writeJSON(t, writer, http.StatusOK, apiKeyList)
		case request.URL.Path == "/v1/teams/team_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz/rotations":
			writeJSON(t, writer, http.StatusCreated, apiKeyRotate)
		case request.URL.Path == "/v1/teams/team_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz":
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(WithSecretKey("sk_live_test"), WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	page, err := client.Sessions.List(context.Background(), SessionListParams{Verdict: "bot", Limit: 25})
	if err != nil || page.NextCursor == "" || !page.HasMore {
		t.Fatalf("unexpected session list result: %#v, err=%v", page, err)
	}

	var sessionIDs []string
	err = client.Sessions.Iter(context.Background(), SessionListParams{}, func(item SessionSummary) error {
		sessionIDs = append(sessionIDs, item.ID)
		return nil
	})
	if err != nil {
		t.Fatalf("iterate sessions: %v", err)
	}
	if len(sessionIDs) != 2 {
		t.Fatalf("expected 2 session ids, got %d", len(sessionIDs))
	}

	session, err := client.Sessions.Get(context.Background(), "sid_0123456789abcdefghjkmnpqrs")
	if err != nil || session.ID != "sid_0123456789abcdefghjkmnpqrs" {
		t.Fatalf("unexpected session detail %#v err=%v", session, err)
	}

	fingerprints, err := client.Fingerprints.List(context.Background(), FingerprintListParams{})
	if err != nil || len(fingerprints.Items) != 1 {
		t.Fatalf("unexpected fingerprint list %#v err=%v", fingerprints, err)
	}
	fingerprint, err := client.Fingerprints.Get(context.Background(), "vid_456789abcdefghjkmnpqrstvwx")
	if err != nil || fingerprint.ID != "vid_456789abcdefghjkmnpqrstvwx" {
		t.Fatalf("unexpected fingerprint detail %#v err=%v", fingerprint, err)
	}

	team, err := client.Teams.Get(context.Background(), "team_56789abcdefghjkmnpqrstvwxy")
	if err != nil || team.ID != "team_56789abcdefghjkmnpqrstvwxy" {
		t.Fatalf("unexpected team %#v err=%v", team, err)
	}
	createdTeam, err := client.Teams.Create(context.Background(), CreateTeamParams{Name: "Example Team", Slug: "example-team"})
	if err != nil || createdTeam.ID != "team_56789abcdefghjkmnpqrstvwxy" {
		t.Fatalf("unexpected created team %#v err=%v", createdTeam, err)
	}
	updatedTeam, err := client.Teams.Update(context.Background(), "team_56789abcdefghjkmnpqrstvwxy", UpdateTeamParams{Name: "Updated Example Team"})
	if err != nil || updatedTeam.Name != "Updated Example Team" {
		t.Fatalf("unexpected updated team %#v err=%v", updatedTeam, err)
	}
	createdKey, err := client.Teams.APIKeys.Create(context.Background(), "team_56789abcdefghjkmnpqrstvwxy", CreateAPIKeyParams{Name: "Production"})
	if err != nil || createdKey.SecretKey != "sk_live_example" {
		t.Fatalf("unexpected created api key %#v err=%v", createdKey, err)
	}
	keys, err := client.Teams.APIKeys.List(context.Background(), "team_56789abcdefghjkmnpqrstvwxy", APIKeyListParams{})
	if err != nil || len(keys.Items) != 1 {
		t.Fatalf("unexpected api key list %#v err=%v", keys, err)
	}
	if err := client.Teams.APIKeys.Revoke(context.Background(), "team_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz"); err != nil {
		t.Fatalf("revoke api key: %v", err)
	}
	rotatedKey, err := client.Teams.APIKeys.Rotate(context.Background(), "team_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz")
	if err != nil || rotatedKey.SecretKey != "sk_live_rotated" {
		t.Fatalf("unexpected rotated api key %#v err=%v", rotatedKey, err)
	}
}

func TestAPIErrorsAreParsed(t *testing.T) {
	fixtures := []string{
		"errors/missing-api-key.json",
		"errors/invalid-api-key.json",
		"errors/validation-error.json",
		"errors/not-found.json",
	}

	for _, fixturePath := range fixtures {
		t.Run(fixturePath, func(t *testing.T) {
			fixture := loadFixture[publicErrorEnvelope](t, fixturePath)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("x-request-id", fixture.Error.RequestID)
				writeJSON(t, writer, fixture.Error.Status, fixture)
			}))
			defer server.Close()

			client, err := NewClient(WithSecretKey("sk_live_test"), WithBaseURL(server.URL), WithHTTPClient(server.Client()))
			if err != nil {
				t.Fatalf("new client: %v", err)
			}

			_, err = client.Sessions.List(context.Background(), SessionListParams{Limit: 999})
			apiErr, ok := err.(*APIError)
			if !ok {
				t.Fatalf("expected APIError, got %T", err)
			}
			if apiErr.Code != fixture.Error.Code || apiErr.RequestID != fixture.Error.RequestID {
				t.Fatalf("unexpected api error %#v", apiErr)
			}
		})
	}
}
