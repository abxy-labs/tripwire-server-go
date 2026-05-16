package tripwire

import (
	"os"
	"testing"
)

func TestVerifyTripwireTokenFixture(t *testing.T) {
	fixture := loadFixture[struct {
		Token      string         `json:"token"`
		SecretKey  string         `json:"secretKey"`
		SecretHash string         `json:"secretHash"`
		Payload    map[string]any `json:"payload"`
	}](t, "sealed-token/vector.v1.json")

	verified, err := VerifyTripwireToken(fixture.Token, fixture.SecretKey)
	if err != nil {
		t.Fatalf("verify token with secret key: %v", err)
	}
	if verified.SessionID != fixture.Payload["session_id"] {
		t.Fatalf("unexpected session id %#v", verified.SessionID)
	}

	verified, err = VerifyTripwireToken(fixture.Token, fixture.SecretHash)
	if err != nil {
		t.Fatalf("verify token with secret hash: %v", err)
	}
	decisionRaw, ok := fixture.Payload["decision"].(map[string]any)
	if !ok || verified.Decision.EventID != decisionRaw["event_id"] {
		t.Fatalf("unexpected decision event id %#v", verified.Decision.EventID)
	}
}

func TestSafeVerifyTripwireTokenInvalidFixture(t *testing.T) {
	fixture := loadFixture[struct {
		Token string `json:"token"`
	}](t, "sealed-token/invalid.json")

	result := SafeVerifyTripwireToken(fixture.Token, "sk_live_fixture_secret")
	if result.OK || result.Error == nil {
		t.Fatal("expected invalid token failure result")
	}
}

func TestVerifyTripwireTokenMissingSecret(t *testing.T) {
	fixture := loadFixture[struct {
		Token string `json:"token"`
	}](t, "sealed-token/vector.v1.json")

	original := os.Getenv("FOIL_SECRET_KEY")
	defer os.Setenv("FOIL_SECRET_KEY", original)
	_ = os.Unsetenv("FOIL_SECRET_KEY")

	if _, err := VerifyTripwireToken(fixture.Token, ""); err == nil {
		t.Fatal("expected missing secret error")
	}
}
