package authforge

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

type vectorCase struct {
	ID           string `json:"id"`
	Payload      string `json:"payload"`
	Signature    string `json:"signature"`
	ShouldVerify bool   `json:"shouldVerify"`
}

type vectorFile struct {
	Algorithm string       `json:"algorithm"`
	PublicKey string       `json:"publicKey"`
	Cases     []vectorCase `json:"cases"`
}

func decodeBase64PublicKey(publicKey string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(publicKey)
}

func loadVectors(t *testing.T) vectorFile {
	t.Helper()
	raw, err := os.ReadFile("test_vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vectors vectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return vectors
}

func TestEd25519Vectors(t *testing.T) {
	vectors := loadVectors(t)
	publicKey, err := decodeBase64PublicKey(vectors.PublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	for _, testCase := range vectors.Cases {
		valid := verifySignature(testCase.Payload, testCase.Signature, [][]byte{publicKey})
		if valid != testCase.ShouldVerify {
			t.Fatalf("vector %s validity mismatch: got %v want %v", testCase.ID, valid, testCase.ShouldVerify)
		}
	}
}

// During a server-side rotation a client may be configured with the
// previous and the current public key. Verification has to walk every
// entry instead of bailing on the first miss.
func TestEd25519MultiKeyAcceptsAny(t *testing.T) {
	vectors := loadVectors(t)
	realKey, err := decodeBase64PublicKey(vectors.PublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	decoy := make([]byte, 32)
	for _, c := range vectors.Cases {
		if !c.ShouldVerify {
			continue
		}
		if !verifySignature(c.Payload, c.Signature, [][]byte{decoy, realKey}) {
			t.Fatalf("multi-key verify rejected vector %s", c.ID)
		}
	}
}

func TestConfigAcceptsCommaSeparatedPublicKey(t *testing.T) {
	vectors := loadVectors(t)
	const decoy = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	client, err := New(Config{
		AppID:         "app",
		AppSecret:     "secret",
		PublicKey:     decoy + "," + vectors.PublicKey,
		HeartbeatMode: "local",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.publicKeys) != 2 {
		t.Fatalf("expected 2 trusted keys, got %d", len(client.publicKeys))
	}
}

func TestConfigPublicKeysFieldRotationSet(t *testing.T) {
	vectors := loadVectors(t)
	const decoy = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	client, err := New(Config{
		AppID:         "app",
		AppSecret:     "secret",
		PublicKeys:    []string{decoy, vectors.PublicKey},
		HeartbeatMode: "local",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(client.publicKeys) != 2 {
		t.Fatalf("expected 2 trusted keys, got %d", len(client.publicKeys))
	}
}

func TestConfigRequiresPublicKey(t *testing.T) {
	_, err := New(Config{
		AppID:         "app-1",
		AppSecret:     "secret-1",
		HeartbeatMode: "local",
	})
	if err == nil {
		t.Fatal("expected missing public key validation error")
	}
}

func TestValidateLicenseSuccessDoesNotStartHeartbeat(t *testing.T) {
	t.Setenv("AUTHFORGE_SDK_TEST_NONCE", "nonce-validate-001")
	vectors := loadVectors(t)
	var successCase vectorCase
	for _, c := range vectors.Cases {
		if c.ID == "validate_success" {
			successCase = c
			break
		}
	}
	if successCase.ID == "" {
		t.Fatal("missing validate_success vector")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/auth/validate") {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status":    "ok",
			"payload":   successCase.Payload,
			"signature": successCase.Signature,
			"keyId":     "signing-key-1",
		})
	}))
	t.Cleanup(srv.Close)

	client, err := New(Config{
		AppID:         "app",
		AppSecret:     "secret",
		PublicKey:     vectors.PublicKey,
		HeartbeatMode: "local",
		APIBaseURL:    srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	res, err := client.ValidateLicense("license-key")
	if err != nil {
		t.Fatal(err)
	}
	if res.SessionToken != "session.validate.token" {
		t.Fatalf("token %q", res.SessionToken)
	}
	client.mu.Lock()
	cancel := client.heartbeatCancel
	auth := client.authenticated
	client.mu.Unlock()
	if cancel != nil {
		t.Fatal("heartbeat should not start for ValidateLicense")
	}
	if auth {
		t.Fatal("ValidateLicense should not persist session")
	}
}

func TestValidateLicenseInvalidKeyNoHeartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "invalid_key",
			"error":  "invalid_key",
		})
	}))
	t.Cleanup(srv.Close)

	client, err := New(Config{
		AppID:         "app",
		AppSecret:     "secret",
		PublicKey:     "0wRcYWn44wk9tHOisXgso1wbtUqpFdy0IeMk4HXDiNc=",
		HeartbeatMode: "local",
		APIBaseURL:    srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.ValidateLicense("bad")
	if err == nil {
		t.Fatal("expected error")
	}
	client.mu.Lock()
	cancel := client.heartbeatCancel
	client.mu.Unlock()
	if cancel != nil {
		t.Fatal("heartbeat should not start")
	}
}
