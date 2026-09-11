package authforge

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type offlineVectorCase struct {
	Name            string                 `json:"name"`
	AppID           string                 `json:"appId"`
	PublicKey       string                 `json:"publicKey"`
	HWID            string                 `json:"hwid"`
	Now             string                 `json:"now"`
	File            string                 `json:"file"`
	Expect          string                 `json:"expect"`
	PayloadBase64   string                 `json:"payloadBase64"`
	SignatureBase64 string                 `json:"signatureBase64"`
	Payload         map[string]interface{} `json:"payload"`
}

type offlineVectorFile struct {
	Version int `json:"version"`
	Keys    struct {
		SigningPublicKey string `json:"signingPublicKey"`
		WrongPublicKey   string `json:"wrongPublicKey"`
	} `json:"keys"`
	Cases []offlineVectorCase `json:"cases"`
}

func loadOfflineVectors(t *testing.T) offlineVectorFile {
	t.Helper()
	raw, err := os.ReadFile("offline_license_vectors.json")
	if err != nil {
		t.Fatalf("read offline vectors: %v", err)
	}
	var vectors offlineVectorFile
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("parse offline vectors: %v", err)
	}
	if len(vectors.Cases) < 15 {
		t.Fatalf("expected at least 15 offline vector cases, got %d", len(vectors.Cases))
	}
	return vectors
}

func offlineCase(t *testing.T, vectors offlineVectorFile, name string) offlineVectorCase {
	t.Helper()
	for _, c := range vectors.Cases {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("offline vector case %q not found", name)
	return offlineVectorCase{}
}

func parseVectorTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t.Fatalf("parse time %q: %v", value, err)
	}
	return parsed
}

func TestOfflineVectorsMatchExpectedResults(t *testing.T) {
	vectors := loadOfflineVectors(t)
	for _, c := range vectors.Cases {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			lic, err := VerifyLicenseFile(c.File, VerifyLicenseFileOptions{
				AppID:     c.AppID,
				PublicKey: c.PublicKey,
				HWID:      c.HWID,
				Now:       parseVectorTime(t, c.Now),
			})
			got := "ok"
			if err != nil {
				got = OfflineErrorCode(err)
				if got == "" {
					t.Fatalf("non-sentinel error: %v", err)
				}
			}
			if got != c.Expect {
				t.Fatalf("expected %s, got %s (err=%v)", c.Expect, got, err)
			}
			if err == nil && c.Payload != nil {
				if !reflect.DeepEqual(lic.Payload, c.Payload) {
					t.Fatalf("payload mismatch:\n got %v\nwant %v", lic.Payload, c.Payload)
				}
				if lic.PayloadBase64 != c.PayloadBase64 || lic.SignatureBase64 != c.SignatureBase64 {
					t.Fatalf("canonical strings mismatch")
				}
			}
		})
	}
}

func TestParseLicenseFileRecoversCanonicalString(t *testing.T) {
	vectors := loadOfflineVectors(t)
	good := offlineCase(t, vectors, "good_bound")
	parsed, err := ParseLicenseFile(good.File)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.PayloadBase64 != good.PayloadBase64 || parsed.SignatureBase64 != good.SignatureBase64 {
		t.Fatalf("canonical strings mismatch")
	}
	if parsed.Headers["Version"] != "1" || parsed.Headers["App-Id"] != good.AppID {
		t.Fatalf("unexpected headers: %v", parsed.Headers)
	}
	if _, err := ParseLicenseFile("nope"); !errors.Is(err, ErrOfflineBadArmor) {
		t.Fatalf("expected ErrOfflineBadArmor, got %v", err)
	}
}

func TestGoodFileExposesEntitlements(t *testing.T) {
	vectors := loadOfflineVectors(t)
	good := offlineCase(t, vectors, "good_bound")
	lic, err := VerifyLicenseFile(good.File, VerifyLicenseFileOptions{
		AppID: good.AppID, PublicKey: good.PublicKey, HWID: good.HWID, Now: parseVectorTime(t, good.Now),
	})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if lic.LicenseKey != "TEST-KEY0-0000-0000" || lic.KeyID != "kid-test-0001" {
		t.Fatalf("unexpected identity: %+v", lic)
	}
	if lic.HwidPolicy.Mode != "bound" || !reflect.DeepEqual(lic.HwidPolicy.Hwids, []string{"testhwid", "second-machine"}) {
		t.Fatalf("unexpected hwid policy: %+v", lic.HwidPolicy)
	}
	if lic.LicenseVariables["tier"] != "pro" || lic.AppVariables["theme"] != "dark" {
		t.Fatalf("unexpected variables: %v / %v", lic.LicenseVariables, lic.AppVariables)
	}
	if lic.Label == nil || *lic.Label != "Vector license" {
		t.Fatalf("unexpected label: %v", lic.Label)
	}
	if lic.ExpiresAt == nil || *lic.ExpiresAt != "2027-01-01T00:00:00.000Z" {
		t.Fatalf("unexpected expiry: %v", lic.ExpiresAt)
	}
}

func newOfflineTestClient(t *testing.T, good offlineVectorCase, mutate func(*Config)) (*Client, *[]string) {
	t.Helper()
	failures := []string{}
	cfg := Config{
		AppID:        good.AppID,
		AppSecret:    "unused-offline",
		PublicKey:    good.PublicKey,
		HWIDOverride: good.HWID,
		// Any network call would hit a closed port and fail loudly.
		APIBaseURL: "http://127.0.0.1:9",
		OnFailure:  func(msg string) { failures = append(failures, msg) },
	}
	if mutate != nil {
		mutate(&cfg)
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	return client, &failures
}

func TestLoginFromFileIsOfflineAndStartsNoHeartbeat(t *testing.T) {
	vectors := loadOfflineVectors(t)
	good := offlineCase(t, vectors, "good_lifetime")
	client, failures := newOfflineTestClient(t, good, nil)

	if client.HWID() != good.HWID {
		t.Fatalf("HWID() = %q", client.HWID())
	}
	lic, err := client.LoginFromFile(good.File)
	if err != nil {
		t.Fatalf("LoginFromFile: %v", err)
	}
	if !client.IsAuthenticated() {
		t.Fatal("expected authenticated")
	}
	if client.GetSessionKind() != SessionKindOffline {
		t.Fatalf("GetSessionKind() = %v, want offline", client.GetSessionKind())
	}
	client.mu.Lock()
	heartbeatRunning := client.heartbeatCancel != nil
	token := client.sessionToken
	client.mu.Unlock()
	if heartbeatRunning {
		t.Fatal("offline login must not start the heartbeat goroutine")
	}
	// No token sentinel: an offline session has no server session at all.
	if token != "" {
		t.Fatalf("offline session must not hold a session token, got %q", token)
	}
	if client.LicenseVariables()["tier"] != "pro" || client.AppVariables()["theme"] != "dark" {
		t.Fatalf("variables not populated")
	}
	if client.SessionData()["licenseKey"] != "TEST-KEY0-0000-0000" {
		t.Fatalf("session data not populated")
	}
	offline := client.OfflineLicense()
	if offline == nil || offline.JTI != lic.JTI || offline.JTI != "00000000-0000-4000-8000-000000000003" {
		t.Fatalf("unexpected OfflineLicense(): %+v", offline)
	}
	if len(*failures) != 0 {
		t.Fatalf("unexpected failures: %v", *failures)
	}

	client.Logout()
	if client.IsAuthenticated() || client.OfflineLicense() != nil {
		t.Fatal("logout must clear offline state")
	}
	if client.GetSessionKind() != SessionKindNone {
		t.Fatalf("GetSessionKind() after logout = %v", client.GetSessionKind())
	}
}

func TestOfflineSelfBanIsLocalErrorAndNeverPosts(t *testing.T) {
	vectors := loadOfflineVectors(t)
	good := offlineCase(t, vectors, "good_lifetime")

	var posts int32
	var lastBody map[string]interface{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&posts, 1)
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &lastBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer srv.Close()

	client, _ := newOfflineTestClient(t, good, func(c *Config) { c.APIBaseURL = srv.URL })
	if _, err := client.LoginFromFile(good.File); err != nil {
		t.Fatalf("LoginFromFile: %v", err)
	}

	for _, revoke := range []bool{true, false} {
		if _, err := client.SelfBan("", "", revoke, false, false); !errors.Is(err, ErrOfflineSession) {
			t.Fatalf("SelfBan on offline session: err = %v, want ErrOfflineSession", err)
		}
	}
	if n := atomic.LoadInt32(&posts); n != 0 {
		t.Fatalf("offline SelfBan must not contact the server, saw %d request(s)", n)
	}
	// Still authenticated offline afterwards; nothing was torn down.
	if !client.IsAuthenticated() {
		t.Fatal("offline session must survive a refused SelfBan")
	}

	// An explicit licenseKey is a request about a different credential and
	// legitimately takes the pre-session path with a fresh nonce.
	if _, err := client.SelfBan("OTHER-KEY0-0000-0000", "", true, true, true); err != nil {
		t.Fatalf("SelfBan(explicit license): %v", err)
	}
	if n := atomic.LoadInt32(&posts); n != 1 {
		t.Fatalf("expected exactly one request, saw %d", n)
	}
	if lastBody["licenseKey"] != "OTHER-KEY0-0000-0000" || lastBody["revokeLicense"] != false {
		t.Fatalf("unexpected pre-session body: %v", lastBody)
	}
	if _, has := lastBody["sessionToken"]; has {
		t.Fatalf("pre-session self-ban must not carry a session token: %v", lastBody)
	}
	if nonce, _ := lastBody["nonce"].(string); nonce == "" {
		t.Fatalf("pre-session self-ban must carry a nonce: %v", lastBody)
	}
}

func TestOfflineHeartbeatEntryPointIsNoOp(t *testing.T) {
	vectors := loadOfflineVectors(t)
	good := offlineCase(t, vectors, "good_lifetime")
	client, failures := newOfflineTestClient(t, good, func(c *Config) { c.OnlineHeartbeat = true })
	if _, err := client.LoginFromFile(good.File); err != nil {
		t.Fatalf("LoginFromFile: %v", err)
	}
	// Shrink the interval below the constructor minimum so a ticker, if one
	// were ever started, would fire during this test.
	client.heartbeatInterval = 10 * time.Millisecond

	// Even if something calls the internal entry point, an offline session
	// never starts the goroutine, never checks in and never runs the grace
	// check - so the closed-port API base URL is never hit.
	client.startHeartbeat()
	client.mu.Lock()
	running := client.heartbeatCancel != nil
	client.mu.Unlock()
	if running {
		t.Fatal("startHeartbeat must be a no-op for an offline session")
	}
	time.Sleep(50 * time.Millisecond)
	if !client.IsAuthenticated() || client.GetSessionKind() != SessionKindOffline {
		t.Fatal("offline session must be untouched")
	}
	if len(*failures) != 0 {
		t.Fatalf("unexpected failures: %v", *failures)
	}
}

func TestLoginFromFileRejectsWithSentinelErrors(t *testing.T) {
	vectors := loadOfflineVectors(t)
	good := offlineCase(t, vectors, "good_lifetime")

	cases := []struct {
		name   string
		mutate func(*Config)
		file   string
		want   error
		code   string
	}{
		{"tampered", nil, offlineCase(t, vectors, "bad_signature_tampered_body").File, ErrOfflineBadSignature, "bad_signature"},
		{"wrong key", func(c *Config) { c.PublicKey = vectors.Keys.WrongPublicKey }, good.File, ErrOfflineBadSignature, "bad_signature"},
		{"expired", nil, offlineCase(t, vectors, "expired").File, ErrOfflineExpired, "expired"},
		{"hwid mismatch", func(c *Config) { c.HWIDOverride = "otherhwid" }, good.File, ErrOfflineHwidMismatch, "hwid_mismatch"},
		{"wrong app", func(c *Config) { c.AppID = "other-app" }, good.File, ErrOfflineWrongApp, "wrong_app"},
		{"unsupported version", nil, offlineCase(t, vectors, "unsupported_version").File, ErrOfflineUnsupportedVersion, "unsupported_version"},
		{"bad armor", nil, offlineCase(t, vectors, "bad_armor_garbage").File + "\n-----BEGIN AUTHFORGE LICENSE-----", ErrOfflineBadArmor, "bad_armor"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			client, failures := newOfflineTestClient(t, good, tc.mutate)
			lic, err := client.LoginFromFile(tc.file)
			if lic != nil || !errors.Is(err, tc.want) {
				t.Fatalf("expected %v, got lic=%v err=%v", tc.want, lic, err)
			}
			if client.IsAuthenticated() {
				t.Fatal("must not be authenticated after a rejected file")
			}
			if len(*failures) != 1 || !strings.HasSuffix((*failures)[0], "offline_login_failed: "+tc.code) {
				t.Fatalf("unexpected OnFailure calls: %v", *failures)
			}
		})
	}
}

func TestLoginFromFileReadsFromDiskAndVerifyIsSideEffectFree(t *testing.T) {
	vectors := loadOfflineVectors(t)
	good := offlineCase(t, vectors, "good_lifetime")
	client, _ := newOfflineTestClient(t, good, nil)

	path := filepath.Join(t.TempDir(), "license.authforge")
	if err := os.WriteFile(path, []byte(good.File), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := client.VerifyLicenseFile(path); err != nil {
		t.Fatalf("VerifyLicenseFile: %v", err)
	}
	if client.IsAuthenticated() {
		t.Fatal("VerifyLicenseFile must not authenticate")
	}
	if _, err := client.LoginFromFile(path); err != nil {
		t.Fatalf("LoginFromFile(path): %v", err)
	}
	if !client.IsAuthenticated() {
		t.Fatal("expected authenticated")
	}
	if _, err := client.LoginFromFile(filepath.Join(t.TempDir(), "missing.authforge")); err == nil {
		t.Fatal("expected read error for missing file")
	}
}
