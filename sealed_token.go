package tripwire

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"regexp"
)

const tokenVersion = byte(0x01)

var hexSecretPattern = regexp.MustCompile(`\A[0-9a-fA-F]{64}\z`)

func resolveSecret(secretKey string) (string, error) {
	if secretKey != "" {
		return secretKey, nil
	}
	if envSecret := os.Getenv("FOIL_SECRET_KEY"); envSecret != "" {
		return envSecret, nil
	}
	return "", &ConfigurationError{
		Message: "Missing Tripwire secret key. Pass WithSecretKey or set FOIL_SECRET_KEY.",
	}
}

func normalizeSecretMaterial(secretKeyOrHash string) string {
	if hexSecretPattern.MatchString(secretKeyOrHash) {
		return string(bytes.ToLower([]byte(secretKeyOrHash)))
	}
	sum := sha256.Sum256([]byte(secretKeyOrHash))
	return hex.EncodeToString(sum[:])
}

func deriveTokenKey(secretKeyOrHash string) []byte {
	sum := sha256.Sum256([]byte(normalizeSecretMaterial(secretKeyOrHash) + "\x00sealed-results"))
	return sum[:]
}

func VerifyTripwireToken(sealedToken string, secretKey string) (*VerifiedTripwireToken, error) {
	resolvedSecret, err := resolveSecret(secretKey)
	if err != nil {
		return nil, err
	}

	raw, err := base64.StdEncoding.DecodeString(sealedToken)
	if err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}
	if len(raw) < 29 {
		return nil, &TokenVerificationError{Message: "Tripwire token is too short."}
	}
	if raw[0] != tokenVersion {
		return nil, &TokenVerificationError{Message: "Unsupported Tripwire token version."}
	}

	nonce := raw[1:13]
	ciphertext := raw[13 : len(raw)-16]
	tag := raw[len(raw)-16:]

	block, err := aes.NewCipher(deriveTokenKey(resolvedSecret))
	if err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}

	compressed, err := aead.Open(nil, nonce, append(ciphertext, tag...), nil)
	if err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}

	reader, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}
	defer reader.Close()

	payloadBytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}

	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}

	verified := &VerifiedTripwireToken{}
	if err := json.Unmarshal(payloadBytes, verified); err != nil {
		return nil, &TokenVerificationError{Message: "Failed to verify Tripwire token.", Err: err}
	}
	verified.Raw = payload
	return verified, nil
}

func SafeVerifyTripwireToken(sealedToken string, secretKey string) VerificationResult {
	verified, err := VerifyTripwireToken(sealedToken, secretKey)
	if err != nil {
		return VerificationResult{OK: false, Error: err}
	}
	return VerificationResult{OK: true, Data: verified}
}
