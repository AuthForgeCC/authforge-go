package authforge

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
)

func deriveValidateKey(appSecret, nonce string) []byte {
	h := sha256.Sum256([]byte(appSecret + nonce))
	return h[:]
}

func deriveHeartbeatKey(sigKey, nonce string) []byte {
	h := sha256.Sum256([]byte(sigKey + nonce))
	return h[:]
}

func signPayload(payload string, key []byte) string {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func verifySignature(payload, signature string, key []byte) bool {
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

func decodeSessionTokenBody(sessionToken string) (map[string]interface{}, bool) {
	parts := strings.SplitN(sessionToken, ".", 2)
	if len(parts) < 2 {
		return nil, false
	}

	decoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}

	var body map[string]interface{}
	if err := json.Unmarshal(decoded, &body); err != nil {
		return nil, false
	}
	return body, true
}

func extractExpiresFromSessionToken(sessionToken string) (int64, bool) {
	body, ok := decodeSessionTokenBody(sessionToken)
	if !ok {
		return 0, false
	}
	if value, ok := numberToInt64(body["expiresIn"]); ok {
		return value, true
	}
	if value, ok := numberToInt64(body["exp"]); ok {
		return value, true
	}
	return 0, false
}

func extractSigKeyFromSessionToken(sessionToken string) (string, bool) {
	body, ok := decodeSessionTokenBody(sessionToken)
	if !ok {
		return "", false
	}
	value, ok := body["sigKey"].(string)
	if !ok || value == "" {
		return "", false
	}
	return value, true
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
