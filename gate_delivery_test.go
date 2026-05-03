package tripwire

import (
	"encoding/json"
	"os"
	"testing"
)

func TestGateDeliveryFixturesRoundtrip(t *testing.T) {
	var deliveryRequestFixture struct {
		Delivery     GateDeliveryRequest `json:"delivery"`
		DerivedKeyID string              `json:"derived_key_id"`
	}
	loadFixtureJSON(t, "spec/fixtures/gate-delivery/delivery-request.json", &deliveryRequestFixture)

	validatedDelivery, err := ValidateGateDeliveryRequest(deliveryRequestFixture.Delivery)
	if err != nil {
		t.Fatalf("validate delivery request: %v", err)
	}
	if validatedDelivery.KeyID != deliveryRequestFixture.DerivedKeyID {
		t.Fatalf("derived key id mismatch: got %s want %s", validatedDelivery.KeyID, deliveryRequestFixture.DerivedKeyID)
	}

	var vectorFixture struct {
		PrivateKeyPKCS8 string               `json:"private_key_pkcs8"`
		Payload         GateDeliveryPayload  `json:"payload"`
		Envelope        GateDeliveryEnvelope `json:"envelope"`
	}
	loadFixtureJSON(t, "spec/fixtures/gate-delivery/vector.v1.json", &vectorFixture)

	privateKey, err := ImportDeliveryPrivateKeyPKCS8(vectorFixture.PrivateKeyPKCS8)
	if err != nil {
		t.Fatalf("import private key: %v", err)
	}
	decrypted, err := DecryptGateDeliveryEnvelope(privateKey, vectorFixture.Envelope)
	if err != nil {
		t.Fatalf("decrypt envelope: %v", err)
	}
	if got, want := toJSON(t, decrypted), toJSON(t, &vectorFixture.Payload); got != want {
		t.Fatalf("decrypted payload mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestGateWebhookAndEnvFixtures(t *testing.T) {
	var payload GateApprovedWebhookPayload
	loadFixtureJSON(t, "spec/fixtures/gate-delivery/approved-webhook-payload.valid.json", &payload)
	validatedPayload, err := ValidateGateApprovedWebhookPayload(payload)
	if err != nil {
		t.Fatalf("validate approved webhook payload: %v", err)
	}
	if got, want := toJSON(t, validatedPayload), toJSON(t, &payload); got != want {
		t.Fatalf("approved webhook payload mismatch\n got: %s\nwant: %s", got, want)
	}

	var signatureFixture struct {
		Secret           string `json:"secret"`
		Timestamp        string `json:"timestamp"`
		ExpiredTimestamp string `json:"expired_timestamp"`
		NowSeconds       int64  `json:"now_seconds"`
		RawBody          string `json:"raw_body"`
		Signature        string `json:"signature"`
		InvalidSignature string `json:"invalid_signature"`
	}
	loadFixtureJSON(t, "spec/fixtures/gate-delivery/webhook-signature.json", &signatureFixture)

	envelope, parsedPayload, err := ParseWebhookEvent([]byte(signatureFixture.RawBody))
	if err != nil {
		t.Fatalf("parse webhook event: %v", err)
	}
	if envelope.Type != "gate.session.approved" {
		t.Fatalf("webhook event type mismatch: got %s", envelope.Type)
	}
	gatePayload, ok := parsedPayload.(GateApprovedWebhookPayload)
	if !ok {
		t.Fatalf("parsed webhook payload type mismatch: got %T", parsedPayload)
	}
	if gatePayload.ServiceID != payload.ServiceID || gatePayload.GateSessionID != payload.GateSessionID {
		t.Fatalf("parsed webhook payload mismatch: got %s/%s", gatePayload.ServiceID, gatePayload.GateSessionID)
	}
	if _, _, err := VerifyAndParseWebhookEvent(VerifyGateWebhookSignatureInput{
		Secret:     signatureFixture.Secret,
		Timestamp:  signatureFixture.Timestamp,
		RawBody:    signatureFixture.RawBody,
		Signature:  signatureFixture.Signature,
		NowSeconds: signatureFixture.NowSeconds,
	}); err != nil {
		t.Fatalf("verify and parse webhook event: %v", err)
	}

	if !VerifyGateWebhookSignature(VerifyGateWebhookSignatureInput{
		Secret:     signatureFixture.Secret,
		Timestamp:  signatureFixture.Timestamp,
		RawBody:    signatureFixture.RawBody,
		Signature:  signatureFixture.Signature,
		NowSeconds: signatureFixture.NowSeconds,
	}) {
		t.Fatal("expected valid signature fixture to verify")
	}
	if VerifyGateWebhookSignature(VerifyGateWebhookSignatureInput{
		Secret:     signatureFixture.Secret,
		Timestamp:  signatureFixture.Timestamp,
		RawBody:    signatureFixture.RawBody,
		Signature:  signatureFixture.InvalidSignature,
		NowSeconds: signatureFixture.NowSeconds,
	}) {
		t.Fatal("expected invalid signature fixture to fail")
	}
	if VerifyGateWebhookSignature(VerifyGateWebhookSignatureInput{
		Secret:     signatureFixture.Secret,
		Timestamp:  signatureFixture.ExpiredTimestamp,
		RawBody:    signatureFixture.RawBody,
		Signature:  signatureFixture.Signature,
		NowSeconds: signatureFixture.NowSeconds,
	}) {
		t.Fatal("expected expired signature fixture to fail")
	}
	envelope, parsedUnknownPayload, err := ParseWebhookEvent([]byte(`{"id":"wevt_0123456789abcdefghjkmnpqrs","object":"webhook_event","type":"unknown.event","created":"2026-04-27T00:00:00.000Z","data":{"future":true}}`))
	if err != nil {
		t.Fatalf("parse unknown webhook event type: %v", err)
	}
	if envelope.Type != "unknown.event" {
		t.Fatalf("unknown webhook event type mismatch: got %s", envelope.Type)
	}
	unknownPayload, ok := parsedUnknownPayload.(map[string]any)
	if !ok || unknownPayload["future"] != true {
		t.Fatalf("unknown webhook event payload mismatch: got %#v", parsedUnknownPayload)
	}

	var envPolicyFixture struct {
		DeriveAgentTokenEnvKey []struct {
			ServiceID string `json:"service_id"`
			Expected  string `json:"expected"`
		} `json:"derive_agent_token_env_key"`
		IsGateManagedEnvVarKey []struct {
			Key     string `json:"key"`
			Managed bool   `json:"managed"`
		} `json:"is_gate_managed_env_var_key"`
		IsBlockedGateEnvVarKey []struct {
			Key     string `json:"key"`
			Blocked bool   `json:"blocked"`
		} `json:"is_blocked_gate_env_var_key"`
	}
	loadFixtureJSON(t, "spec/fixtures/gate-delivery/env-policy.json", &envPolicyFixture)

	for _, entry := range envPolicyFixture.DeriveAgentTokenEnvKey {
		actual, err := DeriveGateAgentTokenEnvKey(entry.ServiceID)
		if err != nil {
			t.Fatalf("derive env key for %s: %v", entry.ServiceID, err)
		}
		if actual != entry.Expected {
			t.Fatalf("derive env key mismatch for %s: got %s want %s", entry.ServiceID, actual, entry.Expected)
		}
	}
	for _, entry := range envPolicyFixture.IsGateManagedEnvVarKey {
		if actual := IsGateManagedEnvVarKey(entry.Key); actual != entry.Managed {
			t.Fatalf("managed env key mismatch for %s: got %t want %t", entry.Key, actual, entry.Managed)
		}
	}
	for _, entry := range envPolicyFixture.IsBlockedGateEnvVarKey {
		if actual := IsBlockedGateEnvVarKey(entry.Key); actual != entry.Blocked {
			t.Fatalf("blocked env key mismatch for %s: got %t want %t", entry.Key, actual, entry.Blocked)
		}
	}
}

func TestCreateGateApprovedWebhookResponseRoundtrip(t *testing.T) {
	keyPair, err := CreateDeliveryKeyPair()
	if err != nil {
		t.Fatalf("create key pair: %v", err)
	}
	response, err := CreateGateApprovedWebhookResponse(GateDeliveryHelperInput{
		Delivery: keyPair.Delivery,
		Outputs: map[string]string{
			"TRIPWIRE_PUBLISHABLE_KEY": "pk_live_bundle",
			"TRIPWIRE_SECRET_KEY":      "sk_live_bundle",
		},
	})
	if err != nil {
		t.Fatalf("create gate approved webhook response: %v", err)
	}
	payload, err := DecryptGateDeliveryEnvelope(keyPair.PrivateKey, response.EncryptedDelivery)
	if err != nil {
		t.Fatalf("decrypt created response: %v", err)
	}
	if got, want := toJSON(t, payload.Outputs), `{"TRIPWIRE_PUBLISHABLE_KEY":"pk_live_bundle","TRIPWIRE_SECRET_KEY":"sk_live_bundle"}`; got != want {
		t.Fatalf("response outputs mismatch\n got: %s\nwant: %s", got, want)
	}
}

func loadFixtureJSON(t *testing.T, path string, target any) {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture %s: %v", path, err)
	}
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode fixture %s: %v", path, err)
	}
}

func toJSON(t *testing.T, value any) string {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal json: %v", err)
	}
	return string(body)
}
