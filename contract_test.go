package tripwire

import (
	"encoding/json"
	"os"
	"testing"
)

func TestOnlySupportedPublicPathsAreExposed(t *testing.T) {
	body, err := os.ReadFile("spec/openapi.json")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	var spec struct {
		Paths map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("decode spec: %v", err)
	}
	expected := []string{
		"/v1/fingerprints",
		"/v1/fingerprints/{visitorId}",
		"/v1/sessions",
		"/v1/sessions/{sessionId}",
		"/v1/teams",
		"/v1/teams/{teamId}",
		"/v1/teams/{teamId}/api-keys",
		"/v1/teams/{teamId}/api-keys/{keyId}",
		"/v1/teams/{teamId}/api-keys/{keyId}/rotations",
	}
	if len(spec.Paths) != len(expected) {
		t.Fatalf("unexpected path count %d", len(spec.Paths))
	}
	for _, path := range expected {
		if _, ok := spec.Paths[path]; !ok {
			t.Fatalf("missing expected path %s", path)
		}
	}
}

func TestExpectedSuccessFixturesExist(t *testing.T) {
	paths := []string{
		"spec/fixtures/public-api/sessions/list.json",
		"spec/fixtures/public-api/sessions/detail.json",
		"spec/fixtures/public-api/fingerprints/list.json",
		"spec/fixtures/public-api/fingerprints/detail.json",
		"spec/fixtures/public-api/teams/team.json",
		"spec/fixtures/public-api/teams/team-create.json",
		"spec/fixtures/public-api/teams/team-update.json",
		"spec/fixtures/public-api/teams/api-key-create.json",
		"spec/fixtures/public-api/teams/api-key-list.json",
		"spec/fixtures/public-api/teams/api-key-rotate.json",
		"spec/fixtures/public-api/teams/api-key-revoke.json",
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("fixture missing %s: %v", path, err)
		}
	}
}
