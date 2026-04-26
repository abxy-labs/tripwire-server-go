package tripwire

import (
	"encoding/json"
	"os"
	"reflect"
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

func nestedSlice(t *testing.T, value any, path string) []any {
	t.Helper()

	items, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is not an array", path)
	}
	return items
}

func stripExamples(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(typed))
		for key, item := range typed {
			if key == "example" {
				continue
			}
			result[key] = stripExamples(item)
		}
		return result
	case []any:
		result := make([]any, len(typed))
		for index, item := range typed {
			result[index] = stripExamples(item)
		}
		return result
	default:
		return value
	}
}

func TestOnlySupportedPublicPathsAreExposed(t *testing.T) {
	spec := readContractSpec(t)
	paths := nestedMap(t, spec["paths"], "paths")
	expected := []string{
		"/v1/fingerprints",
		"/v1/fingerprints/{visitorId}",
		"/v1/gate/agent-tokens/revoke",
		"/v1/gate/agent-tokens/verify",
		"/v1/gate/login-sessions",
		"/v1/gate/login-sessions/consume",
		"/v1/gate/registry",
		"/v1/gate/registry/{serviceId}",
		"/v1/gate/services",
		"/v1/gate/services/{serviceId}",
		"/v1/gate/sessions",
		"/v1/gate/sessions/{gateSessionId}",
		"/v1/gate/sessions/{gateSessionId}/ack",
		"/v1/organizations",
		"/v1/organizations/{organizationId}",
		"/v1/organizations/{organizationId}/api-keys",
		"/v1/organizations/{organizationId}/api-keys/{keyId}",
		"/v1/organizations/{organizationId}/api-keys/{keyId}/rotations",
		"/v1/organizations/{organizationId}/events",
		"/v1/organizations/{organizationId}/events/{eventId}",
		"/v1/organizations/{organizationId}/webhooks/endpoints",
		"/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}",
		"/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}/rotations",
		"/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}/test",
		"/v1/sessions",
		"/v1/sessions/{sessionId}",
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
		"spec/fixtures/api/sessions/list.json",
		"spec/fixtures/api/sessions/detail.json",
		"spec/fixtures/api/fingerprints/list.json",
		"spec/fixtures/api/fingerprints/detail.json",
		"spec/fixtures/api/gate/registry-list.json",
		"spec/fixtures/api/gate/registry-detail.json",
		"spec/fixtures/api/gate/services-list.json",
		"spec/fixtures/api/gate/service-detail.json",
		"spec/fixtures/api/gate/service-create.json",
		"spec/fixtures/api/gate/service-update.json",
		"spec/fixtures/api/gate/service-disable.json",
		"spec/fixtures/api/gate/session-create.json",
		"spec/fixtures/api/gate/session-poll.json",
		"spec/fixtures/api/gate/session-ack.json",
		"spec/fixtures/api/gate/login-session-create.json",
		"spec/fixtures/api/gate/login-session-consume.json",
		"spec/fixtures/api/gate/agent-token-verify.json",
		"spec/fixtures/api/gate/agent-token-revoke.json",
		"spec/fixtures/api/organizations/organization.json",
		"spec/fixtures/api/organizations/organization-create.json",
		"spec/fixtures/api/organizations/organization-update.json",
		"spec/fixtures/api/organizations/api-key-create.json",
		"spec/fixtures/api/organizations/api-key-list.json",
		"spec/fixtures/api/organizations/api-key-update.json",
		"spec/fixtures/api/organizations/api-key-rotate.json",
		"spec/fixtures/api/organizations/api-key-revoke.json",
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
	organizationID := nestedMap(t, schemas["OrganizationId"], "OrganizationId")
	if organizationID["pattern"] != "^org_[0123456789abcdefghjkmnpqrstvwxyz]{26}$" {
		t.Fatalf("unexpected OrganizationId pattern: %v", organizationID["pattern"])
	}
	apiKeyID := nestedMap(t, schemas["ApiKeyId"], "ApiKeyId")
	if apiKeyID["pattern"] != "^key_[0123456789abcdefghjkmnpqrstvwxyz]{26}$" {
		t.Fatalf("unexpected ApiKeyId pattern: %v", apiKeyID["pattern"])
	}

	sessionSummaryID := nestedMap(t, nestedMap(t, schemas["SessionSummary"], "SessionSummary")["properties"], "SessionSummary.properties")["id"]
	if nestedMap(t, sessionSummaryID, "SessionSummary.properties.id")["$ref"] != "#/components/schemas/SessionId" {
		t.Fatalf("SessionSummary.id should reference SessionId")
	}
	teamStatus := nestedMap(t, nestedMap(t, schemas["Organization"], "Organization")["properties"], "Organization.properties")["status"]
	if nestedMap(t, teamStatus, "Organization.properties.status")["$ref"] != "#/components/schemas/OrganizationStatus" {
		t.Fatalf("Organization.status should reference OrganizationStatus")
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

	if got := nestedStringSlice(t, nestedMap(t, schemas["OrganizationStatus"], "OrganizationStatus")["enum"], "OrganizationStatus.enum"); len(got) != 3 || got[0] != "active" || got[1] != "suspended" || got[2] != "deleted" {
		t.Fatalf("unexpected OrganizationStatus enum: %v", got)
	}
	if got := nestedStringSlice(t, nestedMap(t, schemas["ApiKeyStatus"], "ApiKeyStatus")["enum"], "ApiKeyStatus.enum"); len(got) != 3 || got[0] != "active" || got[1] != "rotating" || got[2] != "revoked" {
		t.Fatalf("unexpected ApiKeyStatus enum: %v", got)
	}

	sessionDetailRequired := nestedStringSlice(t, nestedMap(t, schemas["SessionDetail"], "SessionDetail")["required"], "SessionDetail.required")
	requiredSet := map[string]bool{}
	for _, item := range sessionDetailRequired {
		requiredSet[item] = true
	}
	for _, field := range []string{"decision", "highlights", "automation", "web_bot_auth", "network", "runtime_integrity", "visitor_fingerprint", "connection_fingerprint", "previous_decisions", "request", "browser", "device", "analysis_coverage", "signals_fired", "client_telemetry"} {
		if !requiredSet[field] {
			t.Fatalf("SessionDetail.required should include %s", field)
		}
	}
	if got := nestedMap(t, nestedMap(t, schemas["SessionDetail"], "SessionDetail")["properties"], "SessionDetail.properties")["request"]; !reflect.DeepEqual(stripExamples(got), map[string]any{"$ref": "#/components/schemas/SessionDetailRequest"}) {
		t.Fatalf("SessionDetail.request should reference SessionDetailRequest, got %#v", got)
	}
	if got := nestedMap(t, nestedMap(t, schemas["SessionDetail"], "SessionDetail")["properties"], "SessionDetail.properties")["client_telemetry"]; !reflect.DeepEqual(stripExamples(got), map[string]any{"$ref": "#/components/schemas/SessionClientTelemetry"}) {
		t.Fatalf("SessionDetail.client_telemetry should reference SessionClientTelemetry, got %#v", got)
	}
	if got := nestedMap(t, nestedMap(t, schemas["SessionDetail"], "SessionDetail")["properties"], "SessionDetail.properties")["automation"]; !reflect.DeepEqual(stripExamples(got), map[string]any{
		"anyOf": []any{
			map[string]any{"$ref": "#/components/schemas/SessionAutomation"},
			map[string]any{"type": "null"},
		},
	}) {
		t.Fatalf("SessionDetail.automation should allow SessionAutomation or null, got %#v", got)
	}
	if got := nestedMap(t, nestedMap(t, schemas["SessionDetail"], "SessionDetail")["properties"], "SessionDetail.properties")["signals_fired"]; !reflect.DeepEqual(stripExamples(got), map[string]any{
		"type":  "array",
		"items": map[string]any{"$ref": "#/components/schemas/SessionSignalFired"},
	}) {
		t.Fatalf("SessionDetail.signals_fired should reference SessionSignalFired items, got %#v", got)
	}
	if got := nestedMap(t, nestedMap(t, schemas["SessionSignalFired"], "SessionSignalFired")["properties"], "SessionSignalFired.properties")["signal"]; nestedMap(t, got, "SessionSignalFired.properties.signal")["type"] != "string" {
		t.Fatalf("SessionSignalFired.signal should be a string, got %#v", got)
	}
	if properties := nestedMap(t, schemas["GateManagedService"], "GateManagedService")["properties"]; nestedMap(t, properties, "GateManagedService.properties")["team_id"] != nil {
		t.Fatalf("GateManagedService should not expose team_id")
	}
	if properties := nestedMap(t, schemas["GateManagedService"], "GateManagedService")["properties"]; nestedMap(t, properties, "GateManagedService.properties")["webhook_secret"] != nil {
		t.Fatalf("GateManagedService should not expose webhook_secret")
	}

	apiKeyRequired := nestedStringSlice(t, nestedMap(t, schemas["ApiKey"], "ApiKey")["required"], "ApiKey.required")
	requiredSet = map[string]bool{}
	for _, item := range apiKeyRequired {
		requiredSet[item] = true
	}
	for _, field := range []string{"type", "allowed_origins", "scopes", "key_preview", "last_used_at", "rate_limit", "rotated_at", "revoked_at", "grace_expires_at"} {
		if !requiredSet[field] {
			t.Fatalf("ApiKey.required should include %s", field)
		}
	}
	issuedAPIKeyRequired := nestedStringSlice(t, nestedMap(t, schemas["IssuedApiKey"], "IssuedApiKey")["required"], "IssuedApiKey.required")
	issuedRequiredSet := map[string]bool{}
	for _, item := range issuedAPIKeyRequired {
		issuedRequiredSet[item] = true
	}
	if !issuedRequiredSet["revealed_key"] {
		t.Fatalf("IssuedApiKey.required should include revealed_key")
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
	assertOperation("/v1/fingerprints/{visitorId}", "get", "getVisitorFingerprint", "Visitor fingerprints")
	assertOperation("/v1/organizations/{organizationId}", "patch", "updateOrganization", "Organizations")
	assertOperation("/v1/organizations/{organizationId}/api-keys/{keyId}", "patch", "updateOrganizationApiKey", "API Keys")
	assertOperation("/v1/organizations/{organizationId}/api-keys/{keyId}/rotations", "post", "rotateOrganizationApiKey", "API Keys")
	assertOperation("/v1/gate/services", "post", "createManagedGateService", "Gate")
	assertOperation("/v1/gate/sessions/{gateSessionId}", "get", "pollGateSession", "Gate")
	assertOperation("/v1/gate/agent-tokens/revoke", "post", "revokeGateAgentToken", "Gate")
}
