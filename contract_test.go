package tripwire

import (
	"encoding/json"
	"os"
	"testing"
)

func readContractSpec(t *testing.T) map[string]any {
	t.Helper()

	body, err := os.ReadFile("spec/openapi.json")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}

	var spec map[string]any
	if err := json.Unmarshal(body, &spec); err != nil {
		t.Fatalf("decode spec: %v", err)
	}
	return spec
}

func nestedMap(t *testing.T, value any, path string) map[string]any {
	t.Helper()

	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is not an object", path)
	}
	return result
}

func nestedStringSlice(t *testing.T, value any, path string) []string {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is not an array", path)
	}

	result := make([]string, 0, len(items))
	for _, item := range items {
		text, ok := item.(string)
		if !ok {
			t.Fatalf("%s contains a non-string item", path)
		}
		result = append(result, text)
	}
	return result
}

func TestOnlySupportedPublicPathsAreExposed(t *testing.T) {
	spec := readContractSpec(t)
	paths := nestedMap(t, spec["paths"], "paths")
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
	if len(paths) != len(expected) {
		t.Fatalf("unexpected path count %d", len(paths))
	}
	for _, path := range expected {
		if _, ok := paths[path]; !ok {
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

func TestCriticalSchemaConstraintsAreTightened(t *testing.T) {
	spec := readContractSpec(t)
	schemas := nestedMap(t, nestedMap(t, spec["components"], "components")["schemas"], "components.schemas")

	sessionID := nestedMap(t, schemas["SessionId"], "SessionId")
	if sessionID["pattern"] != "^sid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$" {
		t.Fatalf("unexpected SessionId pattern: %v", sessionID["pattern"])
	}
	fingerprintID := nestedMap(t, schemas["FingerprintId"], "FingerprintId")
	if fingerprintID["pattern"] != "^vid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$" {
		t.Fatalf("unexpected FingerprintId pattern: %v", fingerprintID["pattern"])
	}
	teamID := nestedMap(t, schemas["TeamId"], "TeamId")
	if teamID["pattern"] != "^team_[0123456789abcdefghjkmnpqrstvwxyz]{26}$" {
		t.Fatalf("unexpected TeamId pattern: %v", teamID["pattern"])
	}
	apiKeyID := nestedMap(t, schemas["ApiKeyId"], "ApiKeyId")
	if apiKeyID["pattern"] != "^key_[0123456789abcdefghjkmnpqrstvwxyz]{26}$" {
		t.Fatalf("unexpected ApiKeyId pattern: %v", apiKeyID["pattern"])
	}

	sessionSummaryID := nestedMap(t, nestedMap(t, schemas["SessionSummary"], "SessionSummary")["properties"], "SessionSummary.properties")["id"]
	if nestedMap(t, sessionSummaryID, "SessionSummary.properties.id")["$ref"] != "#/components/schemas/SessionId" {
		t.Fatalf("SessionSummary.id should reference SessionId")
	}
	teamStatus := nestedMap(t, nestedMap(t, schemas["Team"], "Team")["properties"], "Team.properties")["status"]
	if nestedMap(t, teamStatus, "Team.properties.status")["$ref"] != "#/components/schemas/TeamStatus" {
		t.Fatalf("Team.status should reference TeamStatus")
	}
	apiKeyStatus := nestedMap(t, nestedMap(t, schemas["ApiKey"], "ApiKey")["properties"], "ApiKey.properties")["status"]
	if nestedMap(t, apiKeyStatus, "ApiKey.properties.status")["$ref"] != "#/components/schemas/ApiKeyStatus" {
		t.Fatalf("ApiKey.status should reference ApiKeyStatus")
	}
	publicErrorCode := nestedMap(t, nestedMap(t, schemas["PublicError"], "PublicError")["properties"], "PublicError.properties")["code"]
	if nestedMap(t, publicErrorCode, "PublicError.properties.code")["x-tripwire-known-values-ref"] != "#/components/schemas/KnownPublicErrorCode" {
		t.Fatalf("PublicError.code should expose x-tripwire-known-values-ref")
	}
	if _, ok := schemas["CollectBatchResponse"]; ok {
		t.Fatalf("CollectBatchResponse should be pruned from the public SDK spec")
	}

	if got := nestedStringSlice(t, nestedMap(t, schemas["TeamStatus"], "TeamStatus")["enum"], "TeamStatus.enum"); len(got) != 3 || got[0] != "active" || got[1] != "suspended" || got[2] != "deleted" {
		t.Fatalf("unexpected TeamStatus enum: %v", got)
	}
	if got := nestedStringSlice(t, nestedMap(t, schemas["ApiKeyStatus"], "ApiKeyStatus")["enum"], "ApiKeyStatus.enum"); len(got) != 3 || got[0] != "active" || got[1] != "revoked" || got[2] != "rotated" {
		t.Fatalf("unexpected ApiKeyStatus enum: %v", got)
	}

	sessionDetailRequired := nestedStringSlice(t, nestedMap(t, schemas["SessionDetail"], "SessionDetail")["required"], "SessionDetail.required")
	requiredSet := map[string]bool{}
	for _, item := range sessionDetailRequired {
		requiredSet[item] = true
	}
	if !requiredSet["ipIntel"] {
		t.Fatalf("SessionDetail.required should include ipIntel")
	}

	apiKeyRequired := nestedStringSlice(t, nestedMap(t, schemas["ApiKey"], "ApiKey")["required"], "ApiKey.required")
	requiredSet = map[string]bool{}
	for _, item := range apiKeyRequired {
		requiredSet[item] = true
	}
	for _, field := range []string{"allowedOrigins", "rateLimit", "rotatedAt", "revokedAt"} {
		if !requiredSet[field] {
			t.Fatalf("ApiKey.required should include %s", field)
		}
	}
}

func TestPublicOperationsHaveStableIDsAndTags(t *testing.T) {
	spec := readContractSpec(t)
	paths := nestedMap(t, spec["paths"], "paths")

	assertOperation := func(pathKey string, method string, operationID string, tag string) {
		t.Helper()
		operation := nestedMap(t, nestedMap(t, paths[pathKey], pathKey)[method], pathKey+"."+method)
		if operation["operationId"] != operationID {
			t.Fatalf("%s %s operationId = %v, want %s", method, pathKey, operation["operationId"], operationID)
		}
		tags := nestedStringSlice(t, operation["tags"], pathKey+"."+method+".tags")
		if len(tags) != 1 || tags[0] != tag {
			t.Fatalf("%s %s tags = %v, want [%s]", method, pathKey, tags, tag)
		}
	}

	assertOperation("/v1/sessions", "get", "listSessions", "Sessions")
	assertOperation("/v1/fingerprints/{visitorId}", "get", "getFingerprint", "Fingerprints")
	assertOperation("/v1/teams/{teamId}", "patch", "updateTeam", "Teams")
	assertOperation("/v1/teams/{teamId}/api-keys/{keyId}/rotations", "post", "rotateTeamApiKey", "API Keys")
}
