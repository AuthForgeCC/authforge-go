package authforge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func deriveKey(appSecret, nonce string) []byte {
	h := sha256.Sum256([]byte(appSecret + nonce))
	return h[:]
}

func signPayload(payload string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifySignature(payload, signature, appSecret, nonce string) bool {
	key := deriveKey(appSecret, nonce)
	expected := signPayload(payload, key)
	return hmac.Equal([]byte(expected), []byte(strings.ToLower(strings.TrimSpace(signature))))
}

func decodePayload(payloadB64 string) (map[string]interface{}, error) {
	decoded, err := base64.StdEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, err
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(decoded, &payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func extractExpiresFromSessionToken(sessionToken string) (int64, bool) {
	parts := strings.Split(sessionToken, ".")
	if len(parts) < 2 {
		return 0, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}

	var body map[string]interface{}
	if err := json.Unmarshal(decoded, &body); err != nil {
		return 0, false
	}

	if expiresValue, ok := numberToInt64(body["expiresIn"]); ok {
		return expiresValue, true
	}
	if expiresValue, ok := numberToInt64(body["exp"]); ok {
		return expiresValue, true
	}
	return 0, false
}

func numberToInt64(value interface{}) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case float32:
		return int64(typed), true
	case int:
		return int64(typed), true
	case int64:
		return typed, true
	case int32:
		return int64(typed), true
	case json.Number:
		v, err := typed.Int64()
		if err == nil {
			return v, true
		}
		return 0, false
	default:
		return 0, false
	}
}
