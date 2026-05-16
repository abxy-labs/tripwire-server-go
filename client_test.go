package foil

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

func ptr[T any](value T) *T {
	return &value
}

func TestClientUsesEnvSecretFallback(t *testing.T) {
	original := os.Getenv("FOIL_SECRET_KEY")
	defer os.Setenv("FOIL_SECRET_KEY", original)
	if err := os.Setenv("FOIL_SECRET_KEY", "sk_env_default"); err != nil {
		t.Fatal(err)
	}

	fixture := loadFixture[resourceListEnvelope[SessionSummary]](t, "api/sessions/list.json")
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
	original := os.Getenv("FOIL_SECRET_KEY")
	defer os.Setenv("FOIL_SECRET_KEY", original)
	_ = os.Unsetenv("FOIL_SECRET_KEY")

	client, err := NewClient()
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if client.Gate == nil || client.Gate.Registry == nil {
		t.Fatal("expected gate resources to be initialized")
	}
}

func TestSecretEndpointsFailAtRequestTimeWhenNoSecretIsConfigured(t *testing.T) {
	original := os.Getenv("FOIL_SECRET_KEY")
	defer os.Setenv("FOIL_SECRET_KEY", original)
	_ = os.Unsetenv("FOIL_SECRET_KEY")

	client, err := NewClient()
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	if _, err := client.Sessions.List(context.Background(), SessionListParams{}); err == nil {
		t.Fatal("expected missing secret error")
	}
}

func TestClientAppliesBaseURLTimeoutAndHeaders(t *testing.T) {
	fixture := loadFixture[resourceListEnvelope[SessionSummary]](t, "api/sessions/list.json")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.String() != "/v1/sessions?limit=5" {
			t.Fatalf("unexpected path %s", request.URL.String())
		}
		if got := request.Header.Get("Authorization"); got != "Bearer sk_live_test" {
			t.Fatalf("unexpected auth header %s", got)
		}
		if got := request.Header.Get("X-Foil-Client"); got != "foil-server-go/0.1.0" {
			t.Fatalf("unexpected client header %s", got)
		}
		if got := request.Header.Get("User-Agent"); got != "custom-foil-go" {
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
		WithUserAgent("custom-foil-go"),
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

func TestSessionsFingerprintsOrganizationsAndAPIKeys(t *testing.T) {
	sessionList := loadFixture[resourceListEnvelope[SessionSummary]](t, "api/sessions/list.json")
	sessionDetail := loadFixture[resourceEnvelope[SessionDetail]](t, "api/sessions/detail.json")
	fingerprintList := loadFixture[resourceListEnvelope[VisitorFingerprintSummary]](t, "api/fingerprints/list.json")
	fingerprintDetail := loadFixture[resourceEnvelope[VisitorFingerprintDetail]](t, "api/fingerprints/detail.json")
	organizationGet := loadFixture[resourceEnvelope[Organization]](t, "api/organizations/organization.json")
	organizationCreate := loadFixture[resourceEnvelope[Organization]](t, "api/organizations/organization-create.json")
	organizationUpdate := loadFixture[resourceEnvelope[Organization]](t, "api/organizations/organization-update.json")
	apiKeyCreate := loadFixture[resourceEnvelope[IssuedAPIKey]](t, "api/organizations/api-key-create.json")
	apiKeyList := loadFixture[resourceListEnvelope[APIKey]](t, "api/organizations/api-key-list.json")
	apiKeyUpdate := loadFixture[resourceEnvelope[APIKey]](t, "api/organizations/api-key-update.json")
	apiKeyRotate := loadFixture[resourceEnvelope[IssuedAPIKey]](t, "api/organizations/api-key-rotate.json")

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
						Object:    "session",
						ID:        "sid_123456789abcdefghjkmnpqrst",
						CreatedAt: sessionList.Data[0].CreatedAt,
						LatestDecision: Decision{
							EventID:              "evt_3456789abcdefghjkmnpqrstvw",
							Verdict:              sessionList.Data[0].LatestDecision.Verdict,
							RiskScore:            sessionList.Data[0].LatestDecision.RiskScore,
							Phase:                sessionList.Data[0].LatestDecision.Phase,
							IsProvisional:        sessionList.Data[0].LatestDecision.IsProvisional,
							Manipulation:         sessionList.Data[0].LatestDecision.Manipulation,
							EvaluationDurationMS: sessionList.Data[0].LatestDecision.EvaluationDurationMS,
							EvaluatedAt:          "2026-03-24T20:01:05.000Z",
						},
						VisitorFingerprint: sessionList.Data[0].VisitorFingerprint,
					},
				},
				Pagination: pagination{Limit: 50, HasMore: false},
				Meta:       meta{RequestID: "req_0123456789abcdef0123456789abcdef"},
			}
			writeJSON(t, writer, http.StatusOK, secondPage)
		case request.URL.Path == "/v1/sessions/sid_0123456789abcdefghjkmnpqrs":
			writeJSON(t, writer, http.StatusOK, sessionDetail)
		case request.URL.Path == "/v1/fingerprints":
			writeJSON(t, writer, http.StatusOK, fingerprintList)
		case request.URL.Path == "/v1/fingerprints/vid_456789abcdefghjkmnpqrstvwx":
			writeJSON(t, writer, http.StatusOK, fingerprintDetail)
		case request.URL.Path == "/v1/organizations" && request.Method == http.MethodPost:
			writeJSON(t, writer, http.StatusCreated, organizationCreate)
		case request.URL.Path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy" && request.Method == http.MethodGet:
			writeJSON(t, writer, http.StatusOK, organizationGet)
		case request.URL.Path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy" && request.Method == http.MethodPatch:
			writeJSON(t, writer, http.StatusOK, organizationUpdate)
		case request.URL.Path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys" && request.Method == http.MethodPost:
			writeJSON(t, writer, http.StatusCreated, apiKeyCreate)
		case request.URL.Path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys" && request.Method == http.MethodGet:
			writeJSON(t, writer, http.StatusOK, apiKeyList)
		case request.URL.Path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz/rotations":
			writeJSON(t, writer, http.StatusCreated, apiKeyRotate)
		case request.URL.Path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz" && request.Method == http.MethodPatch:
			writeJSON(t, writer, http.StatusOK, apiKeyUpdate)
		case request.URL.Path == "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/api-keys/key_6789abcdefghjkmnpqrstvwxyz":
			revokeFixture := loadFixture[resourceEnvelope[APIKey]](t, "api/organizations/api-key-revoke.json")
			writeJSON(t, writer, http.StatusOK, revokeFixture)
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
	if session.NativeRuntimeIntegrity != nil || session.NativeApp != nil || session.NativeCarrier != nil || session.NativeMotionPrint != nil || session.DeviceIdentity != nil || session.InstallID != nil {
		t.Fatalf("expected null native session fields, got %#v", session)
	}

	fingerprints, err := client.Fingerprints.List(context.Background(), FingerprintListParams{})
	if err != nil || len(fingerprints.Items) != 1 {
		t.Fatalf("unexpected fingerprint list %#v err=%v", fingerprints, err)
	}
	fingerprint, err := client.Fingerprints.Get(context.Background(), "vid_456789abcdefghjkmnpqrstvwx")
	if err != nil || fingerprint.ID != "vid_456789abcdefghjkmnpqrstvwx" {
		t.Fatalf("unexpected fingerprint detail %#v err=%v", fingerprint, err)
	}

	organization, err := client.Organizations.Get(context.Background(), "org_56789abcdefghjkmnpqrstvwxy")
	if err != nil || organization.ID != "org_56789abcdefghjkmnpqrstvwxy" {
		t.Fatalf("unexpected organization %#v err=%v", organization, err)
	}
	createdOrganization, err := client.Organizations.Create(context.Background(), CreateOrganizationParams{Name: "Example Organization", Slug: "example-organization"})
	if err != nil || createdOrganization.ID != "org_56789abcdefghjkmnpqrstvwxy" {
		t.Fatalf("unexpected created organization %#v err=%v", createdOrganization, err)
	}
	updatedOrganization, err := client.Organizations.Update(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", UpdateOrganizationParams{Name: "Updated Example Organization"})
	if err != nil || updatedOrganization.Name != "Example Organization" {
		t.Fatalf("unexpected updated organization %#v err=%v", updatedOrganization, err)
	}
	createdKey, err := client.Organizations.APIKeys.Create(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", CreateAPIKeyParams{Name: "Production Backend"})
	if err != nil || createdKey.RevealedKey != "sk_live_[example_secret_key]" {
		t.Fatalf("unexpected created api key %#v err=%v", createdKey, err)
	}
	keys, err := client.Organizations.APIKeys.List(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", APIKeyListParams{})
	if err != nil || len(keys.Items) != 1 {
		t.Fatalf("unexpected api key list %#v err=%v", keys, err)
	}
	updatedKey, err := client.Organizations.APIKeys.Update(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz", UpdateAPIKeyParams{Name: "Updated Web App"})
	if err != nil || updatedKey.Name != "Updated Web App" {
		t.Fatalf("unexpected updated api key %#v err=%v", updatedKey, err)
	}
	revokedKey, err := client.Organizations.APIKeys.Revoke(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz")
	if err != nil || revokedKey.ID != "key_6789abcdefghjkmnpqrstvwxyz" {
		t.Fatalf("unexpected revoked api key %#v err=%v", revokedKey, err)
	}
	rotatedKey, err := client.Organizations.APIKeys.Rotate(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", "key_6789abcdefghjkmnpqrstvwxyz")
	if err != nil || rotatedKey.RevealedKey != "sk_live_[rotated_example_secret_key]" {
		t.Fatalf("unexpected rotated api key %#v err=%v", rotatedKey, err)
	}
}

func TestWebhooksUseEventHistoryEndpoints(t *testing.T) {
	delivery := WebhookDelivery{
		Object:         "webhook_delivery",
		ID:             "wdlv_0123456789abcdef0123456789abcdef",
		EventID:        "wevt_0123456789abcdef0123456789abcdef",
		EndpointID:     "we_0123456789abcdef0123456789abcdef",
		EventType:      "session.fingerprint.calculated",
		Status:         "succeeded",
		Attempts:       1,
		ResponseStatus: ptr(200),
		ResponseBody:   ptr("{}"),
		CreatedAt:      "2026-03-24T20:00:00.000Z",
		UpdatedAt:      "2026-03-24T20:00:05.000Z",
	}
	event := Event{
		Object:            "event",
		ID:                "wevt_0123456789abcdef0123456789abcdef",
		Type:              "session.fingerprint.calculated",
		Subject:           EventSubject{Type: "session", ID: "sid_0123456789abcdefghjkmnpqrs"},
		Data:              map[string]any{"source": "waitForFingerprint"},
		WebhookDeliveries: []WebhookDelivery{delivery},
		CreatedAt:         "2026-03-24T20:00:00.000Z",
	}
	listResponse := resourceListEnvelope[Event]{
		Data:       []Event{event},
		Pagination: pagination{Limit: 25, HasMore: false},
		Meta:       meta{RequestID: "req_0123456789abcdef0123456789abcdef"},
	}
	detailResponse := resourceEnvelope[Event]{
		Data: event,
		Meta: meta{RequestID: "req_0123456789abcdef0123456789abcdef"},
	}

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Authorization"); got != "Bearer sk_live_test" {
			t.Fatalf("unexpected auth header %q", got)
		}
		switch request.URL.Path {
		case "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events":
			if got := request.URL.Query().Get("endpoint_id"); got != "we_0123456789abcdef0123456789abcdef" {
				t.Fatalf("unexpected endpoint_id %q", got)
			}
			if got := request.URL.Query().Get("type"); got != "session.fingerprint.calculated" {
				t.Fatalf("unexpected type %q", got)
			}
			writeJSON(t, writer, http.StatusOK, listResponse)
		case "/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events/wevt_0123456789abcdef0123456789abcdef":
			writeJSON(t, writer, http.StatusOK, detailResponse)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClient(WithSecretKey("sk_live_test"), WithBaseURL(server.URL), WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	events, err := client.Webhooks.ListEvents(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", EventListParams{
		EndpointID: "we_0123456789abcdef0123456789abcdef",
		Type:       "session.fingerprint.calculated",
		Limit:      25,
	})
	if err != nil || len(events.Items) != 1 || events.Items[0].Subject.ID != "sid_0123456789abcdefghjkmnpqrs" {
		t.Fatalf("unexpected events %#v err=%v", events, err)
	}
	if events.Items[0].WebhookDeliveries[0].Status != "succeeded" {
		t.Fatalf("unexpected delivery status %q", events.Items[0].WebhookDeliveries[0].Status)
	}

	fetched, err := client.Webhooks.RetrieveEvent(context.Background(), "org_56789abcdefghjkmnpqrstvwxy", "wevt_0123456789abcdef0123456789abcdef")
	if err != nil || fetched.Type != "session.fingerprint.calculated" {
		t.Fatalf("unexpected event %#v err=%v", fetched, err)
	}
}

func TestGateNamespaceSupportsPublicBearerAndSecretFlows(t *testing.T) {
	registryList := loadFixture[resourceEnvelope[[]GateRegistryEntry]](t, "api/gate/registry-list.json")
	registryDetail := loadFixture[resourceEnvelope[GateRegistryEntry]](t, "api/gate/registry-detail.json")
	servicesList := loadFixture[resourceEnvelope[[]GateManagedService]](t, "api/gate/services-list.json")
	serviceDetail := loadFixture[resourceEnvelope[GateManagedService]](t, "api/gate/service-detail.json")
	serviceCreate := loadFixture[resourceEnvelope[GateManagedService]](t, "api/gate/service-create.json")
	serviceUpdate := loadFixture[resourceEnvelope[GateManagedService]](t, "api/gate/service-update.json")
	serviceDisable := loadFixture[resourceEnvelope[GateManagedService]](t, "api/gate/service-disable.json")
	sessionCreate := loadFixture[resourceEnvelope[GateSessionCreate]](t, "api/gate/session-create.json")
	sessionPoll := loadFixture[resourceEnvelope[GateSessionPollData]](t, "api/gate/session-poll.json")
	sessionAck := loadFixture[resourceEnvelope[GateSessionDeliveryAcknowledgement]](t, "api/gate/session-ack.json")
	loginCreate := loadFixture[resourceEnvelope[GateLoginSession]](t, "api/gate/login-session-create.json")
	loginConsume := loadFixture[resourceEnvelope[GateDashboardLogin]](t, "api/gate/login-session-consume.json")
	agentVerify := loadFixture[resourceEnvelope[AgentTokenVerification]](t, "api/gate/agent-token-verify.json")

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		auth := request.Header.Get("Authorization")
		switch {
		case request.URL.Path == "/v1/gate/registry":
			if auth != "" {
				t.Fatalf("expected no auth header for registry list, got %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, registryList)
		case request.URL.Path == "/v1/gate/registry/foil":
			if auth != "" {
				t.Fatalf("expected no auth header for registry get, got %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, registryDetail)
		case request.URL.Path == "/v1/gate/services" && request.Method == http.MethodGet:
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, servicesList)
		case request.URL.Path == "/v1/gate/services/foil" && request.Method == http.MethodGet:
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, serviceDetail)
		case request.URL.Path == "/v1/gate/services" && request.Method == http.MethodPost:
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusCreated, serviceCreate)
		case request.URL.Path == "/v1/gate/services/acme_prod" && request.Method == http.MethodPatch:
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, serviceUpdate)
		case request.URL.Path == "/v1/gate/services/acme_prod" && request.Method == http.MethodDelete:
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, serviceDisable)
		case request.URL.Path == "/v1/gate/sessions" && request.Method == http.MethodPost:
			if auth != "" {
				t.Fatalf("expected no auth header for session create, got %q", auth)
			}
			writeJSON(t, writer, http.StatusCreated, sessionCreate)
		case request.URL.Path == "/v1/gate/sessions/gate_0123456789abcdefghjkmnpqrs" && request.Method == http.MethodGet:
			if auth != "Bearer gtpoll_0123456789abcdefghjkmnpqrs" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, sessionPoll)
		case request.URL.Path == "/v1/gate/sessions/gate_0123456789abcdefghjkmnpqrs/ack":
			if auth != "Bearer gtpoll_0123456789abcdefghjkmnpqrs" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, sessionAck)
		case request.URL.Path == "/v1/gate/login-sessions":
			if auth != "Bearer agt_0123456789abcdefghjkmnpqrs" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusCreated, loginCreate)
		case request.URL.Path == "/v1/gate/login-sessions/consume":
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, loginConsume)
		case request.URL.Path == "/v1/gate/agent-tokens/verify":
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
			writeJSON(t, writer, http.StatusOK, agentVerify)
		case request.URL.Path == "/v1/gate/agent-tokens/revoke":
			if auth != "Bearer sk_live_test" {
				t.Fatalf("unexpected auth header %q", auth)
			}
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

	if items, err := client.Gate.Registry.List(context.Background()); err != nil || len(items) != 1 || items[0].ID != "foil" {
		t.Fatalf("unexpected gate registry list %#v err=%v", items, err)
	}
	if item, err := client.Gate.Registry.Get(context.Background(), "foil"); err != nil || item.ID != "foil" {
		t.Fatalf("unexpected gate registry detail %#v err=%v", item, err)
	}
	if items, err := client.Gate.Services.List(context.Background()); err != nil || len(items) != 1 || items[0].ID != "acme_prod" {
		t.Fatalf("unexpected gate services list %#v err=%v", items, err)
	}
	if item, err := client.Gate.Services.Get(context.Background(), "foil"); err != nil || item.ID != "acme_prod" {
		t.Fatalf("unexpected gate service detail %#v err=%v", item, err)
	}
	if item, err := client.Gate.Services.Create(context.Background(), CreateGateServiceParams{
		ID:                "acme_prod",
		Name:              "Acme Production",
		Description:       "Acme production signup flow",
		Website:           "https://acme.example.com",
		WebhookEndpointID: "we_0123456789abcdef0123456789abcdef",
	}); err != nil || item.ID != "acme_prod" {
		t.Fatalf("unexpected created gate service %#v err=%v", item, err)
	}
	discoverable := true
	if item, err := client.Gate.Services.Update(context.Background(), "acme_prod", UpdateGateServiceParams{Discoverable: &discoverable}); err != nil || !item.Discoverable {
		t.Fatalf("unexpected updated gate service %#v err=%v", item, err)
	}
	if item, err := client.Gate.Services.Disable(context.Background(), "acme_prod"); err != nil || item.Status != GateServiceStatusDisabled {
		t.Fatalf("unexpected disabled gate service %#v err=%v", item, err)
	}
	if item, err := client.Gate.Sessions.Create(context.Background(), CreateGateSessionParams{
		ServiceID:   "foil",
		AccountName: "my-project",
		Delivery: GateDeliveryRequest{
			Version:   1,
			Algorithm: "x25519-hkdf-sha256/aes-256-gcm",
			KeyID:     "kid_integrator_0123456789abcdefgh",
			PublicKey: "public_key_integrator",
		},
	}); err != nil || item.ID != "gate_0123456789abcdefghjkmnpqrs" {
		t.Fatalf("unexpected created gate session %#v err=%v", item, err)
	}
	if item, err := client.Gate.Sessions.Poll(context.Background(), "gate_0123456789abcdefghjkmnpqrs", "gtpoll_0123456789abcdefghjkmnpqrs"); err != nil || item.Status != "approved" {
		t.Fatalf("unexpected polled gate session %#v err=%v", item, err)
	}
	if item, err := client.Gate.Sessions.Acknowledge(context.Background(), "gate_0123456789abcdefghjkmnpqrs", AcknowledgeGateSessionDeliveryParams{
		PollToken: "gtpoll_0123456789abcdefghjkmnpqrs",
		AckToken:  "gtack_0123456789abcdefghjkmnpqrs",
	}); err != nil || item.Status != "acknowledged" {
		t.Fatalf("unexpected gate ack %#v err=%v", item, err)
	}
	if item, err := client.Gate.LoginSessions.Create(context.Background(), CreateGateLoginSessionParams{
		ServiceID:  "foil",
		AgentToken: "agt_0123456789abcdefghjkmnpqrs",
	}); err != nil || item.ID == "" {
		t.Fatalf("unexpected gate login session %#v err=%v", item, err)
	}
	if item, err := client.Gate.LoginSessions.Consume(context.Background(), ConsumeGateLoginSessionParams{
		Code: "gate_code_0123456789abcdefghjkm",
	}); err != nil || item.Object != "gate_dashboard_login" {
		t.Fatalf("unexpected gate dashboard login %#v err=%v", item, err)
	}
	if item, err := client.Gate.AgentTokens.Verify(context.Background(), VerifyGateAgentTokenParams{
		AgentToken: "agt_0123456789abcdefghjkmnpqrs",
	}); err != nil || !item.Valid {
		t.Fatalf("unexpected gate agent verification %#v err=%v", item, err)
	}
	if err := client.Gate.AgentTokens.Revoke(context.Background(), RevokeGateAgentTokenParams{
		AgentToken: "agt_0123456789abcdefghjkmnpqrs",
	}); err != nil {
		t.Fatalf("unexpected gate revoke error %v", err)
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
			fixture := loadFixture[apiErrorEnvelope](t, fixturePath)
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
