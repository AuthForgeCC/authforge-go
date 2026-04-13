package authforge

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type vectorFile struct {
	Inputs struct {
		AppSecret string `json:"appSecret"`
		Nonce     string `json:"nonce"`
		Payload   string `json:"payload"`
	} `json:"inputs"`
	Outputs struct {
		DerivedKeyHex string `json:"derivedKeyHex"`
		SignatureHex  string `json:"signatureHex"`
	} `json:"outputs"`
}

func TestCryptoVectorsMatchReference(t *testing.T) {
	t.Parallel()

	vectorPath := "test_vectors.json"
	raw, err := os.ReadFile(vectorPath)
	if err != nil {
		t.Fatalf("read test vectors: %v", err)
	}

	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse test vectors: %v", err)
	}

	derived := deriveKey(vectors.Inputs.AppSecret, vectors.Inputs.Nonce)
	derivedHex := hex.EncodeToString(derived)
	if !strings.EqualFold(derivedHex, vectors.Outputs.DerivedKeyHex) {
		t.Fatalf("derived key mismatch: got %s want %s", derivedHex, vectors.Outputs.DerivedKeyHex)
	}

	signature := signPayload(vectors.Inputs.Payload, derived)
	if !strings.EqualFold(signature, vectors.Outputs.SignatureHex) {
		t.Fatalf("signature mismatch: got %s want %s", signature, vectors.Outputs.SignatureHex)
	}

	if !verifySignature(vectors.Inputs.Payload, vectors.Outputs.SignatureHex, vectors.Inputs.AppSecret, vectors.Inputs.Nonce) {
		t.Fatal("verifySignature returned false for known-good vector")
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
