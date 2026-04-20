package authforge

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
)

func verifySignature(payload, signature string, publicKey []byte) bool {
	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(publicKey), []byte(payload), signatureBytes)
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
