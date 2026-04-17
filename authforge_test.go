package authforge

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type vectorBlock struct {
	Inputs struct {
		AppSecret string `json:"appSecret,omitempty"`
		SigKey    string `json:"sigKey,omitempty"`
		Nonce     string `json:"nonce"`
		Payload   string `json:"payload"`
	} `json:"inputs"`
	Outputs struct {
		DerivedKeyHex string `json:"derivedKeyHex"`
		SignatureHex  string `json:"signatureHex"`
	} `json:"outputs"`
}

type vectorFile struct {
	Validate  vectorBlock `json:"validate"`
	Heartbeat vectorBlock `json:"heartbeat"`
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("test_vectors.json")
	if err != nil {
		t.Fatalf("read test vectors: %v", err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse test vectors: %v", err)
	}
	return vectors
}

func TestValidateCryptoVectorsMatchReference(t *testing.T) {
	t.Parallel()
	v := loadVectors(t).Validate

	derived := deriveValidateKey(v.Inputs.AppSecret, v.Inputs.Nonce)
	derivedHex := hex.EncodeToString(derived)
	if !strings.EqualFold(derivedHex, v.Outputs.DerivedKeyHex) {
		t.Fatalf("derived key mismatch: got %s want %s", derivedHex, v.Outputs.DerivedKeyHex)
	}

	signature := signPayload(v.Inputs.Payload, derived)
	if !strings.EqualFold(signature, v.Outputs.SignatureHex) {
		t.Fatalf("signature mismatch: got %s want %s", signature, v.Outputs.SignatureHex)
	}

	if !verifySignature(v.Inputs.Payload, v.Outputs.SignatureHex, derived) {
		t.Fatal("verifySignature returned false for known-good validate vector")
	}
}

func TestHeartbeatCryptoVectorsMatchReference(t *testing.T) {
	t.Parallel()
	h := loadVectors(t).Heartbeat

	derived := deriveHeartbeatKey(h.Inputs.SigKey, h.Inputs.Nonce)
	derivedHex := hex.EncodeToString(derived)
	if !strings.EqualFold(derivedHex, h.Outputs.DerivedKeyHex) {
		t.Fatalf("derived key mismatch: got %s want %s", derivedHex, h.Outputs.DerivedKeyHex)
	}

	signature := signPayload(h.Inputs.Payload, derived)
	if !strings.EqualFold(signature, h.Outputs.SignatureHex) {
		t.Fatalf("signature mismatch: got %s want %s", signature, h.Outputs.SignatureHex)
	}

	if !verifySignature(h.Inputs.Payload, h.Outputs.SignatureHex, derived) {
		t.Fatal("verifySignature returned false for known-good heartbeat vector")
	}
}

func TestValidateAndHeartbeatKeysDiffer(t *testing.T) {
	t.Parallel()
	vectors := loadVectors(t)
	if strings.EqualFold(vectors.Validate.Outputs.DerivedKeyHex, vectors.Heartbeat.Outputs.DerivedKeyHex) {
		t.Fatal("validate and heartbeat derived keys should differ")
	}
}

func TestExtractSigKeyFromSessionToken(t *testing.T) {
	t.Parallel()
	vectors := loadVectors(t)
	payload, err := decodePayload(vectors.Validate.Inputs.Payload)
	if err != nil {
		t.Fatalf("decodePayload: %v", err)
	}
	sessionToken, ok := payload["sessionToken"].(string)
	if !ok || sessionToken == "" {
		t.Fatal("expected sessionToken in vector payload")
	}
	sigKey, ok := extractSigKeyFromSessionToken(sessionToken)
	if !ok {
		t.Fatal("expected sigKey to be extracted from session token")
	}
	if sigKey != vectors.Heartbeat.Inputs.SigKey {
		t.Fatalf("sigKey mismatch: got %s want %s", sigKey, vectors.Heartbeat.Inputs.SigKey)
	}
}

func TestHWIDStableAcrossCalls(t *testing.T) {
	t.Parallel()

	first := generateHWID()
	second := generateHWID()

	if first == "" || second == "" {
		t.Fatal("hwid should not be empty")
	}
	if first != second {
		t.Fatalf("hwid must be stable: first=%s second=%s", first, second)
	}
}

func TestServerErrorMappingSentinels(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		target error
	}{
		{name: "invalid app", input: "invalid_app", target: ErrInvalidApp},
		{name: "invalid key", input: "invalid_key", target: ErrInvalidKey},
		{name: "expired", input: "expired", target: ErrExpired},
		{name: "revoked", input: "revoked", target: ErrRevoked},
		{name: "hwid mismatch", input: "hwid_mismatch", target: ErrHwidMismatch},
		{name: "no credits", input: "no_credits", target: ErrNoCredits},
		{name: "blocked", input: "blocked", target: ErrBlocked},
		{name: "rate limited", input: "rate_limited", target: ErrRateLimited},
		{name: "replay detected", input: "replay_detected", target: ErrReplayDetected},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			err := mapServerError(tc.input)
			if !errors.Is(err, tc.target) {
				t.Fatalf("expected errors.Is(%v, %v) to be true", err, tc.target)
			}
		})
	}
}
