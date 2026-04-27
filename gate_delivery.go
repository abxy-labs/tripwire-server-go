package tripwire

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	GateDeliveryVersion     = 1
	GateDeliveryAlgorithm   = "x25519-hkdf-sha256/aes-256-gcm"
	GateAgentTokenEnvSuffix = "_GATE_AGENT_TOKEN"
)

var (
	gateDeliveryHKDFInfo  = []byte("tripwire-gate-delivery:v1")
	blockedGateEnvVarKeys = map[string]struct{}{
		"BASH_ENV":              {},
		"BROWSER":               {},
		"CDPATH":                {},
		"DYLD_INSERT_LIBRARIES": {},
		"DYLD_LIBRARY_PATH":     {},
		"EDITOR":                {},
		"ENV":                   {},
		"GIT_ASKPASS":           {},
		"GIT_SSH_COMMAND":       {},
		"HOME":                  {},
		"LD_LIBRARY_PATH":       {},
		"LD_PRELOAD":            {},
		"NODE_OPTIONS":          {},
		"NODE_PATH":             {},
		"PATH":                  {},
		"PERL5OPT":              {},
		"PERLLIB":               {},
		"PROMPT_COMMAND":        {},
		"PYTHONHOME":            {},
		"PYTHONPATH":            {},
		"PYTHONSTARTUP":         {},
		"RUBYLIB":               {},
		"RUBYOPT":               {},
		"SHELLOPTS":             {},
		"SSH_ASKPASS":           {},
		"VISUAL":                {},
		"XDG_CONFIG_HOME":       {},
	}
	blockedGateEnvVarPrefixes = []string{
		"NPM_CONFIG_",
		"BUN_CONFIG_",
		"GIT_CONFIG_",
	}
	webhookEventTypes = map[string]struct{}{
		"session.fingerprint.calculated": {},
		"session.result.persisted":       {},
		"gate.session.approved":          {},
		"webhook.test":                   {},
	}
)

func DeriveGateAgentTokenEnvKey(serviceID string) (string, error) {
	normalized := strings.TrimSpace(serviceID)
	normalized = strings.ToUpper(strings.Trim(normalizeEnvKeyToken(normalized), "_"))
	if normalized == "" {
		return "", errors.New("service_id is required to derive a Gate agent token env key")
	}
	return normalized + GateAgentTokenEnvSuffix, nil
}

func IsGateManagedEnvVarKey(key string) bool {
	return key == "TRIPWIRE_AGENT_TOKEN" || strings.HasSuffix(key, GateAgentTokenEnvSuffix)
}

func IsBlockedGateEnvVarKey(key string) bool {
	normalized := strings.ToUpper(strings.TrimSpace(key))
	if _, ok := blockedGateEnvVarKeys[normalized]; ok {
		return true
	}
	for _, prefix := range blockedGateEnvVarPrefixes {
		if strings.HasPrefix(normalized, prefix) {
			return true
		}
	}
	return false
}

func KeyIDForRawX25519PublicKey(rawPublicKey []byte) (string, error) {
	if len(rawPublicKey) != 32 {
		return "", errors.New("X25519 public key must be 32 bytes")
	}
	sum := sha256.Sum256(rawPublicKey)
	return b64urlEncode(sum[:]), nil
}

func CreateDeliveryKeyPair() (*GeneratedDeliveryKeyPair, error) {
	curve := ecdh.X25519()
	privateKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	keyID, err := KeyIDForRawX25519PublicKey(privateKey.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	return &GeneratedDeliveryKeyPair{
		Delivery: GateDeliveryRequest{
			Version:   GateDeliveryVersion,
			Algorithm: GateDeliveryAlgorithm,
			KeyID:     keyID,
			PublicKey: b64urlEncode(privateKey.PublicKey().Bytes()),
		},
		PrivateKey: privateKey,
	}, nil
}

func ExportDeliveryPrivateKeyPKCS8(privateKey any) (string, error) {
	typedKey, ok := privateKey.(*ecdh.PrivateKey)
	if !ok {
		return "", errors.New("delivery private key must be an X25519 private key")
	}
	encoded, err := x509.MarshalPKCS8PrivateKey(typedKey)
	if err != nil {
		return "", err
	}
	return b64urlEncode(encoded), nil
}

func ImportDeliveryPrivateKeyPKCS8(value string) (*ecdh.PrivateKey, error) {
	decoded, err := b64urlDecode(value, "delivery.private_key_pkcs8")
	if err != nil {
		return nil, err
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(decoded)
	if err != nil {
		return nil, err
	}
	typedKey, ok := privateKey.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("delivery.private_key_pkcs8 must contain an X25519 private key")
	}
	return typedKey, nil
}

func ValidateGateDeliveryRequest(value GateDeliveryRequest) (*GateDeliveryRequest, error) {
	if value.Version != GateDeliveryVersion {
		return nil, errors.New("delivery.version must be 1")
	}
	if value.Algorithm != GateDeliveryAlgorithm {
		return nil, fmt.Errorf("delivery.algorithm must be %s", GateDeliveryAlgorithm)
	}
	if value.PublicKey == "" {
		return nil, errors.New("delivery.public_key is required")
	}
	if value.KeyID == "" {
		return nil, errors.New("delivery.key_id is required")
	}
	rawPublicKey, err := b64urlDecode(value.PublicKey, "delivery.public_key")
	if err != nil {
		return nil, err
	}
	if len(rawPublicKey) != 32 {
		return nil, errors.New("delivery.public_key must be a raw X25519 public key")
	}
	keyID, err := KeyIDForRawX25519PublicKey(rawPublicKey)
	if err != nil {
		return nil, err
	}
	if keyID != value.KeyID {
		return nil, errors.New("delivery.key_id does not match delivery.public_key")
	}
	return &GateDeliveryRequest{
		Version:   GateDeliveryVersion,
		Algorithm: GateDeliveryAlgorithm,
		KeyID:     value.KeyID,
		PublicKey: value.PublicKey,
	}, nil
}

func CreateEncryptedDeliveryResponse(input GateDeliveryHelperInput) (*GateEncryptedDeliveryResponse, error) {
	envelope, err := EncryptGateDeliveryPayload(input.Delivery, GateDeliveryPayload{
		Version: GateDeliveryVersion,
		Outputs: input.Outputs,
	})
	if err != nil {
		return nil, err
	}
	return &GateEncryptedDeliveryResponse{EncryptedDelivery: *envelope}, nil
}

func CreateGateApprovedWebhookResponse(input GateDeliveryHelperInput) (*GateEncryptedDeliveryResponse, error) {
	return CreateEncryptedDeliveryResponse(input)
}

func ValidateGateApprovedWebhookPayload(value GateApprovedWebhookPayload) (*GateApprovedWebhookPayload, error) {
	if value.ServiceID == "" {
		return nil, errors.New("service_id is required")
	}
	if value.GateSessionID == "" {
		return nil, errors.New("gate_session_id is required")
	}
	if value.GateAccountID == "" {
		return nil, errors.New("gate_account_id is required")
	}
	if value.AccountName == "" {
		return nil, errors.New("account_name is required")
	}
	if value.Tripwire.Verdict != "bot" && value.Tripwire.Verdict != "human" && value.Tripwire.Verdict != "inconclusive" {
		return nil, errors.New("tripwire.verdict is invalid")
	}
	delivery, err := ValidateGateDeliveryRequest(value.Delivery)
	if err != nil {
		return nil, err
	}
	validated := value
	validated.Delivery = *delivery
	if validated.Metadata == nil {
		validated.Metadata = nil
	}
	return &validated, nil
}

func VerifyGateWebhookSignature(input VerifyGateWebhookSignatureInput) bool {
	parsedTimestamp, err := time.Parse(time.RFC3339, "")
	_ = parsedTimestamp
	_ = err
	timestamp, convErr := parseUnixTimestamp(input.Timestamp)
	if convErr != nil {
		return false
	}
	nowSeconds := input.NowSeconds
	if nowSeconds == 0 {
		nowSeconds = time.Now().Unix()
	}
	maxAgeSeconds := input.MaxAgeSeconds
	if maxAgeSeconds == 0 {
		maxAgeSeconds = 5 * 60
	}
	if absInt64(nowSeconds-timestamp) > maxAgeSeconds {
		return false
	}
	expected := hmac.New(sha256.New, []byte(input.Secret))
	expected.Write([]byte(input.Timestamp))
	expected.Write([]byte("."))
	expected.Write([]byte(input.RawBody))
	return subtle.ConstantTimeCompare(
		[]byte(fmt.Sprintf("%x", expected.Sum(nil))),
		[]byte(input.Signature),
	) == 1
}

type WebhookEventEnvelope struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Type    string          `json:"type"`
	Created string          `json:"created"`
	Data    json.RawMessage `json:"data"`
}

func ParseWebhookEvent(rawBody []byte) (*WebhookEventEnvelope, any, error) {
	var envelope WebhookEventEnvelope
	if err := json.Unmarshal(rawBody, &envelope); err != nil {
		return nil, nil, err
	}
	if envelope.Object != "webhook_event" {
		return nil, nil, errors.New("webhook event object must be webhook_event")
	}
	if envelope.ID == "" {
		return nil, nil, errors.New("webhook event id is required")
	}
	if envelope.Type == "" {
		return nil, nil, errors.New("webhook event type is required")
	}
	if _, ok := webhookEventTypes[envelope.Type]; !ok {
		return nil, nil, fmt.Errorf("unsupported webhook event type: %s", envelope.Type)
	}
	if envelope.Created == "" {
		return nil, nil, errors.New("webhook event created timestamp is required")
	}
	if len(envelope.Data) == 0 {
		return nil, nil, errors.New("webhook event data is required")
	}
	if envelope.Type == "gate.session.approved" {
		var rawPayload map[string]any
		if err := json.Unmarshal(envelope.Data, &rawPayload); err != nil {
			return nil, nil, err
		}
		if _, ok := rawPayload["event"]; ok {
			return nil, nil, errors.New("webhook payload must not include event; use the webhook event envelope type")
		}
		var payload GateApprovedWebhookPayload
		if err := json.Unmarshal(envelope.Data, &payload); err != nil {
			return nil, nil, err
		}
		validated, err := ValidateGateApprovedWebhookPayload(payload)
		if err != nil {
			return nil, nil, err
		}
		return &envelope, *validated, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(envelope.Data, &payload); err != nil {
		return nil, nil, err
	}
	return &envelope, payload, nil
}

func VerifyAndParseWebhookEvent(input VerifyGateWebhookSignatureInput) (*WebhookEventEnvelope, any, error) {
	if !VerifyGateWebhookSignature(input) {
		return nil, nil, errors.New("invalid Tripwire webhook signature")
	}
	return ParseWebhookEvent([]byte(input.RawBody))
}

func EncryptGateDeliveryPayload(delivery GateDeliveryRequest, payload GateDeliveryPayload) (*GateDeliveryEnvelope, error) {
	validatedDelivery, err := ValidateGateDeliveryRequest(delivery)
	if err != nil {
		return nil, err
	}
	if payload.Version != GateDeliveryVersion {
		return nil, errors.New("Gate delivery payload version must be 1")
	}
	recipientRawPublicKey, err := b64urlDecode(validatedDelivery.PublicKey, "delivery.public_key")
	if err != nil {
		return nil, err
	}
	recipientPublicKey, err := ecdh.X25519().NewPublicKey(recipientRawPublicKey)
	if err != nil {
		return nil, err
	}
	ephemeralPrivateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := ephemeralPrivateKey.ECDH(recipientPublicKey)
	if err != nil {
		return nil, err
	}
	salt, err := randomBytes(32)
	if err != nil {
		return nil, err
	}
	iv, err := randomBytes(12)
	if err != nil {
		return nil, err
	}
	key, err := deriveGateDeliveryKey(sharedSecret, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, iv, plaintext, nil)
	tagLength := gcm.Overhead()
	ciphertext := sealed[:len(sealed)-tagLength]
	tag := sealed[len(sealed)-tagLength:]
	return &GateDeliveryEnvelope{
		Version:            GateDeliveryVersion,
		Algorithm:          GateDeliveryAlgorithm,
		KeyID:              validatedDelivery.KeyID,
		EphemeralPublicKey: b64urlEncode(ephemeralPrivateKey.PublicKey().Bytes()),
		Salt:               b64urlEncode(salt),
		IV:                 b64urlEncode(iv),
		Ciphertext:         b64urlEncode(ciphertext),
		Tag:                b64urlEncode(tag),
	}, nil
}

func ValidateEncryptedGateDeliveryEnvelope(value GateDeliveryEnvelope) (*GateDeliveryEnvelope, error) {
	if value.Version != GateDeliveryVersion {
		return nil, errors.New("encrypted_delivery.version must be 1")
	}
	if value.Algorithm != GateDeliveryAlgorithm {
		return nil, fmt.Errorf("encrypted_delivery.algorithm must be %s", GateDeliveryAlgorithm)
	}
	if value.KeyID == "" || value.EphemeralPublicKey == "" || value.Salt == "" || value.IV == "" || value.Ciphertext == "" || value.Tag == "" {
		return nil, errors.New("encrypted delivery fields are required")
	}
	if decoded, err := b64urlDecode(value.EphemeralPublicKey, "encrypted_delivery.ephemeral_public_key"); err != nil || len(decoded) != 32 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("encrypted_delivery.ephemeral_public_key must be 32 bytes")
	}
	if decoded, err := b64urlDecode(value.Salt, "encrypted_delivery.salt"); err != nil || len(decoded) != 32 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("encrypted_delivery.salt must be 32 bytes")
	}
	if decoded, err := b64urlDecode(value.IV, "encrypted_delivery.iv"); err != nil || len(decoded) != 12 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("encrypted_delivery.iv must be 12 bytes")
	}
	if decoded, err := b64urlDecode(value.Tag, "encrypted_delivery.tag"); err != nil || len(decoded) != 16 {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("encrypted_delivery.tag must be 16 bytes")
	}
	return &value, nil
}

func DecryptGateDeliveryEnvelope(privateKey any, envelope GateDeliveryEnvelope) (*GateDeliveryPayload, error) {
	typedKey, ok := privateKey.(*ecdh.PrivateKey)
	if !ok {
		return nil, errors.New("delivery private key must be an X25519 private key")
	}
	validatedEnvelope, err := ValidateEncryptedGateDeliveryEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	ephemeralPublicKeyRaw, err := b64urlDecode(validatedEnvelope.EphemeralPublicKey, "encrypted_delivery.ephemeral_public_key")
	if err != nil {
		return nil, err
	}
	ephemeralPublicKey, err := ecdh.X25519().NewPublicKey(ephemeralPublicKeyRaw)
	if err != nil {
		return nil, err
	}
	sharedSecret, err := typedKey.ECDH(ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	salt, err := b64urlDecode(validatedEnvelope.Salt, "encrypted_delivery.salt")
	if err != nil {
		return nil, err
	}
	key, err := deriveGateDeliveryKey(sharedSecret, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	iv, err := b64urlDecode(validatedEnvelope.IV, "encrypted_delivery.iv")
	if err != nil {
		return nil, err
	}
	ciphertext, err := b64urlDecode(validatedEnvelope.Ciphertext, "encrypted_delivery.ciphertext")
	if err != nil {
		return nil, err
	}
	tag, err := b64urlDecode(validatedEnvelope.Tag, "encrypted_delivery.tag")
	if err != nil {
		return nil, err
	}
	plaintext, err := gcm.Open(nil, iv, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, err
	}
	var payload GateDeliveryPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, errors.New("encrypted_delivery decrypted to invalid JSON")
	}
	if payload.Version != GateDeliveryVersion {
		return nil, errors.New("encrypted_delivery payload version must be 1")
	}
	if payload.Outputs == nil {
		return nil, errors.New("encrypted_delivery payload outputs must be an object")
	}
	return &payload, nil
}

func b64urlEncode(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func deriveGateDeliveryKey(sharedSecret []byte, salt []byte) ([]byte, error) {
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(sharedSecret)
	prk := extract.Sum(nil)

	expand := hmac.New(sha256.New, prk)
	expand.Write(gateDeliveryHKDFInfo)
	expand.Write([]byte{1})
	return expand.Sum(nil), nil
}

func b64urlDecode(value string, label string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("invalid %s", label)
	}
	return decoded, nil
}

func randomBytes(length int) ([]byte, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func normalizeEnvKeyToken(value string) string {
	var builder strings.Builder
	lastUnderscore := false
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			builder.WriteRune(r)
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			builder.WriteByte('_')
			lastUnderscore = true
		}
	}
	return builder.String()
}

func parseUnixTimestamp(value string) (int64, error) {
	var timestamp int64
	if _, err := fmt.Sscanf(value, "%d", &timestamp); err != nil {
		return 0, err
	}
	return timestamp, nil
}

func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}
