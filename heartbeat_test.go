package authforge

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type heartbeatReply struct {
	status int
	body   string
}

func failedBody(code string) string {
	return `{"status":"failed","error":"` + code + `"}`
}

func signedBody(vector vectorCase) string {
	return `{"status":"ok","payload":"` + vector.Payload + `","signature":"` + vector.Signature + `"}`
}

func vectorByID(t *testing.T, id string) vectorCase {
	t.Helper()
	for _, c := range loadVectors(t).Cases {
		if c.ID == id {
			return c
		}
	}
	t.Fatalf("missing %s vector", id)
	return vectorCase{}
}

// heartbeatServer answers /auth/heartbeat with replies in order, repeating
// the last one, and counts requests.
func heartbeatServer(t *testing.T, replies ...heartbeatReply) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/auth/heartbeat") {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		n := int(atomic.AddInt32(&calls, 1)) - 1
		if n >= len(replies) {
			n = len(replies) - 1
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(replies[n].status)
		_, _ = w.Write([]byte(replies[n].body))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

type heartbeatHarness struct {
	client *Client
	ctx    context.Context
	mu     sync.Mutex
	errs   []*Error
	sleeps []time.Duration
}

// newHeartbeatHarness returns a client holding a live online session, as if
// Login had succeeded, with the background loop's context registered.
func newHeartbeatHarness(t *testing.T, baseURL string) *heartbeatHarness {
	t.Helper()
	vectors := loadVectors(t)
	validate := vectorByID(t, "validate_success")
	h := &heartbeatHarness{}
	client, err := New(Config{
		AppID:           "app",
		AppSecret:       "secret",
		PublicKey:       vectors.PublicKey,
		APIBaseURL:      baseURL,
		OnlineHeartbeat: true,
		OnHeartbeatFailure: func(err *Error) {
			h.mu.Lock()
			h.errs = append(h.errs, err)
			h.mu.Unlock()
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	client.sleep = func(d time.Duration) {
		h.mu.Lock()
		h.sleeps = append(h.sleeps, d)
		h.mu.Unlock()
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	client.mu.Lock()
	client.licenseKey = "license-key"
	client.sessionToken = "session.validate.token"
	client.sessionKind = SessionKindOnline
	client.sessionExpiresIn = time.Now().Add(time.Hour).Unix()
	client.rawPayloadB64 = validate.Payload
	client.signature = validate.Signature
	client.authenticated = true
	client.heartbeatCtx = ctx
	client.heartbeatCancel = cancel
	client.mu.Unlock()
	h.client = client
	h.ctx = ctx
	return h
}

func (h *heartbeatHarness) onlyFailure(t *testing.T) *Error {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.errs) != 1 {
		t.Fatalf("expected exactly one heartbeat failure, got %d: %v", len(h.errs), h.errs)
	}
	return h.errs[0]
}

func (h *heartbeatHarness) recordedSleeps() []time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]time.Duration(nil), h.sleeps...)
}

func (h *heartbeatHarness) assertInvalidated(t *testing.T) {
	t.Helper()
	if h.client.IsAuthenticated() {
		t.Fatal("fatal heartbeat failure must invalidate the session")
	}
	h.client.mu.Lock()
	token, payload, cancel := h.client.sessionToken, h.client.rawPayloadB64, h.client.heartbeatCancel
	h.client.mu.Unlock()
	if token != "" || payload != "" {
		t.Fatalf("session state not cleared: token=%q payload=%q", token, payload)
	}
	if cancel != nil {
		t.Fatal("background checks should be detached")
	}
	if h.ctx.Err() == nil {
		t.Fatal("background check context should be cancelled")
	}
}

func (h *heartbeatHarness) assertStillAuthenticated(t *testing.T) {
	t.Helper()
	if !h.client.IsAuthenticated() {
		t.Fatal("transient heartbeat failure must keep the session")
	}
	if h.ctx.Err() != nil {
		t.Fatal("transient heartbeat failure must not stop background checks")
	}
}

func (h *heartbeatHarness) assertTransient(t *testing.T, keepGoing bool, wantCode string) *Error {
	t.Helper()
	if !keepGoing {
		t.Fatal("background checks should continue after a transient failure")
	}
	failure := h.onlyFailure(t)
	if failure.Code != wantCode {
		t.Fatalf("code = %q, want %q (%v)", failure.Code, wantCode, failure)
	}
	if !failure.IsTransient() || failure.IsFatal() || !IsTransient(failure) {
		t.Fatalf("%s should be transient", wantCode)
	}
	h.assertStillAuthenticated(t)
	return failure
}

// newLoopClient returns a client with a live online session whose background
// loop has not been started yet.
func newLoopClient(t *testing.T, baseURL string, onFailure func(*Error)) *Client {
	t.Helper()
	client, err := New(Config{
		AppID:              "app",
		AppSecret:          "secret",
		PublicKey:          loadVectors(t).PublicKey,
		APIBaseURL:         baseURL,
		OnlineHeartbeat:    true,
		OnHeartbeatFailure: onFailure,
	})
	if err != nil {
		t.Fatal(err)
	}
	client.heartbeatInterval = 10 * time.Millisecond
	client.mu.Lock()
	client.sessionToken = "session.validate.token"
	client.sessionKind = SessionKindOnline
	client.sessionExpiresIn = time.Now().Add(time.Hour).Unix()
	client.authenticated = true
	client.mu.Unlock()
	return client
}

func waitOrFail(t *testing.T, done <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func waitForLoopExit(t *testing.T, client *Client) {
	t.Helper()
	exited := make(chan struct{})
	go func() {
		client.heartbeatWg.Wait()
		close(exited)
	}()
	waitOrFail(t, exited, "the background loop to exit")
}

func TestHeartbeatDefinitiveCodesInvalidateSession(t *testing.T) {
	cases := []struct {
		code     string
		status   int
		sentinel error
	}{
		{"revoked", 410, ErrRevoked},
		{"expired", 410, ErrExpired},
		{"hwid_mismatch", 403, ErrHwidMismatch},
		{"blocked", 403, ErrBlocked},
		{"app_disabled", 403, ErrAppDisabled},
		{"session_expired", 401, ErrSessionExpired},
		{"invalid_app", 401, ErrInvalidApp},
		{"malformed_request", 400, ErrBadRequest},
	}
	for _, tc := range cases {
		for _, status := range []int{tc.status, 200} {
			t.Run(tc.code+"/"+strconv.Itoa(status), func(t *testing.T) {
				srv, calls := heartbeatServer(t, heartbeatReply{status, failedBody(tc.code)})
				h := newHeartbeatHarness(t, srv.URL)

				if h.client.heartbeatTick(h.ctx, true) {
					t.Fatal("background checks should stop after a definitive failure")
				}

				failure := h.onlyFailure(t)
				if failure.Code != tc.code {
					t.Fatalf("code = %q, want %q", failure.Code, tc.code)
				}
				if !failure.IsFatal() || failure.IsTransient() || IsTransient(failure) {
					t.Fatalf("%s should be fatal", tc.code)
				}
				if !strings.Contains(failure.Error(), tc.code) {
					t.Fatalf("message %q should contain the code", failure.Error())
				}
				if !errors.Is(failure, tc.sentinel) {
					t.Fatalf("errors.Is(%v, %v) = false", failure, tc.sentinel)
				}
				if got := atomic.LoadInt32(calls); got != 1 {
					t.Fatalf("definitive answers must not be retried; %d requests", got)
				}
				if sleeps := h.recordedSleeps(); len(sleeps) != 0 {
					t.Fatalf("definitive answers must not sleep; sleeps = %v", sleeps)
				}
				h.assertInvalidated(t)
			})
		}
	}
}

func TestHeartbeatSignatureMismatchIsDefinitive(t *testing.T) {
	t.Setenv("AUTHFORGE_SDK_TEST_NONCE", "nonce-validate-001")
	srv, calls := heartbeatServer(t, heartbeatReply{200, signedBody(vectorByID(t, "wrong_app_key"))})
	h := newHeartbeatHarness(t, srv.URL)

	if h.client.heartbeatTick(h.ctx, true) {
		t.Fatal("expected checks to stop")
	}
	failure := h.onlyFailure(t)
	if failure.Code != "signature_mismatch" || !failure.IsFatal() || !errors.Is(failure, ErrSignatureMismatch) {
		t.Fatalf("unexpected failure %#v", failure)
	}
	if got := atomic.LoadInt32(calls); got != 1 {
		t.Fatalf("%d requests, want 1", got)
	}
	h.assertInvalidated(t)
}

func TestHeartbeatTransientCodesKeepSession(t *testing.T) {
	cases := []struct {
		code       string
		status     int
		wantCalls  int32
		wantSleeps []time.Duration
		sentinel   error
	}{
		{"rate_limited", 429, 3, []time.Duration{2 * time.Second, 5 * time.Second}, ErrRateLimited},
		{"system_error", 500, 1, nil, ErrServerError},
		{"server_error", 500, 1, nil, ErrServerError},
		{"no_credits", 429, 1, nil, ErrNoCredits},
		{"demo_quota_exceeded", 429, 1, nil, nil},
		{"app_burn_cap_reached", 429, 1, nil, ErrAppBurnCapReached},
		{"bad_request", 400, 1, nil, ErrBadRequest},
		{"invalid_key", 401, 1, nil, ErrInvalidKey},
		{"some_future_code", 403, 1, nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			srv, calls := heartbeatServer(t, heartbeatReply{tc.status, failedBody(tc.code)})
			h := newHeartbeatHarness(t, srv.URL)

			failure := h.assertTransient(t, h.client.heartbeatTick(h.ctx, true), tc.code)
			if tc.sentinel != nil && !errors.Is(failure, tc.sentinel) {
				t.Fatalf("errors.Is(%v, %v) = false", failure, tc.sentinel)
			}
			if got := atomic.LoadInt32(calls); got != tc.wantCalls {
				t.Fatalf("%d requests, want %d", got, tc.wantCalls)
			}
			sleeps := h.recordedSleeps()
			if len(sleeps) != len(tc.wantSleeps) {
				t.Fatalf("sleeps = %v, want %v", sleeps, tc.wantSleeps)
			}
			for i := range sleeps {
				if sleeps[i] != tc.wantSleeps[i] {
					t.Fatalf("sleeps = %v, want %v", sleeps, tc.wantSleeps)
				}
			}
		})
	}
}

func TestHeartbeatUnparseableBodiesAreTransient(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		code   string
	}{
		{"html_403", 403, "<html>forbidden</html>", "http_error_403"},
		{"html_500", 500, "<html>error</html>", "http_error_500"},
		{"html_502", 502, "<html>gateway</html>", "http_error_502"},
		{"empty_200", 200, "", "invalid_json_response"},
		{"empty_503", 503, "", "http_error_503"},
		{"array_200", 200, `["revoked"]`, "invalid_json_response"},
		{"string_200", 200, `"revoked"`, "invalid_json_response"},
		{"array_410", 410, `["revoked"]`, "http_error_410"},
		{"null_200", 200, `null`, "unexpected_response"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := heartbeatServer(t, heartbeatReply{tc.status, tc.body})
			h := newHeartbeatHarness(t, srv.URL)

			h.assertTransient(t, h.client.heartbeatTick(h.ctx, true), tc.code)
			if got := atomic.LoadInt32(calls); got != 1 {
				t.Fatalf("%d requests, want 1", got)
			}
		})
	}
}

// Only {"status":"failed","error":"<code>"} is an AuthForge verdict; a
// definitive-looking code in any other shape must not log the user out.
func TestHeartbeatMalformedFailureBodiesAreUnexpected(t *testing.T) {
	cases := []struct {
		name    string
		status  int
		body    string
		wantMsg string
	}{
		{"error_without_status", 410, `{"error":"revoked"}`, `status=<missing> error="revoked"`},
		{"code_in_status", 410, `{"status":"revoked"}`, `status="revoked" error=<missing>`},
		{"failed_without_error", 403, `{"status":"failed"}`, `status="failed" error=<missing>`},
		{"failed_empty_error", 200, `{"status":"failed","error":"  "}`, `status="failed" error="  "`},
		{"failed_non_string_error", 200, `{"status":"failed","error":7}`, `status="failed" error=7`},
		{"error_without_status_200", 200, `{"error":"hwid_mismatch"}`, `status=<missing> error="hwid_mismatch"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := heartbeatServer(t, heartbeatReply{tc.status, tc.body})
			h := newHeartbeatHarness(t, srv.URL)

			failure := h.assertTransient(t, h.client.heartbeatTick(h.ctx, true), "unexpected_response")
			if !strings.Contains(failure.Error(), tc.wantMsg) {
				t.Fatalf("message %q should contain %q", failure.Error(), tc.wantMsg)
			}
			if got := atomic.LoadInt32(calls); got != 1 {
				t.Fatalf("%d requests, want 1", got)
			}
		})
	}
}

func TestHeartbeatFailedStatusIsCaseInsensitive(t *testing.T) {
	srv, _ := heartbeatServer(t, heartbeatReply{410, `{"status":" Failed ","error":"revoked"}`})
	h := newHeartbeatHarness(t, srv.URL)

	if h.client.heartbeatTick(h.ctx, true) {
		t.Fatal("expected checks to stop")
	}
	if failure := h.onlyFailure(t); failure.Code != "revoked" {
		t.Fatalf("unexpected failure %#v", failure)
	}
	h.assertInvalidated(t)
}

func TestHeartbeatNetworkErrorIsTransient(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	h := newHeartbeatHarness(t, url)

	h.assertTransient(t, h.client.heartbeatTick(h.ctx, true), "network_error")
	if sleeps := h.recordedSleeps(); len(sleeps) != 1 || sleeps[0] != 2*time.Second {
		t.Fatalf("network failures retry once after 2s; sleeps = %v", sleeps)
	}
}

func TestHeartbeatTimeoutIsTransient(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	h := newHeartbeatHarness(t, srv.URL)
	h.client.httpClient.Timeout = 50 * time.Millisecond

	h.assertTransient(t, h.client.heartbeatTick(h.ctx, true), "timeout")
}

func TestHeartbeatTransientFailureAfterTTLBecomesSessionExpired(t *testing.T) {
	srv, _ := heartbeatServer(t, heartbeatReply{500, failedBody("system_error")})
	h := newHeartbeatHarness(t, srv.URL)
	h.client.mu.Lock()
	h.client.sessionExpiresIn = time.Now().Add(-time.Second).Unix()
	h.client.mu.Unlock()

	if h.client.heartbeatTick(h.ctx, true) {
		t.Fatal("expected checks to stop")
	}
	failure := h.onlyFailure(t)
	if failure.Code != "session_expired" || !failure.IsFatal() || !errors.Is(failure, ErrSessionExpired) {
		t.Fatalf("unexpected failure %#v", failure)
	}
	if !errors.Is(failure, ErrServerError) {
		t.Fatal("the promoted failure should keep the transient cause")
	}
	h.assertInvalidated(t)
}

func TestHeartbeatSuccessAfterTransientFailureRefreshesSession(t *testing.T) {
	t.Setenv("AUTHFORGE_SDK_TEST_NONCE", "nonce-heartbeat-001")
	srv, _ := heartbeatServer(t,
		heartbeatReply{500, failedBody("system_error")},
		heartbeatReply{200, signedBody(vectorByID(t, "heartbeat_success"))},
	)
	h := newHeartbeatHarness(t, srv.URL)

	if !h.client.heartbeatTick(h.ctx, true) {
		t.Fatal("expected checks to continue after system_error")
	}
	if !h.client.heartbeatTick(h.ctx, true) {
		t.Fatal("expected checks to continue after success")
	}
	h.onlyFailure(t)
	h.client.mu.Lock()
	token := h.client.sessionToken
	h.client.mu.Unlock()
	if token != "session.heartbeat.token" {
		t.Fatalf("session not refreshed: %q", token)
	}
	h.assertStillAuthenticated(t)
}

func TestGracePeriodExpiryInvalidatesSession(t *testing.T) {
	h := newHeartbeatHarness(t, "http://127.0.0.1:9")
	h.client.mu.Lock()
	h.client.sessionExpiresIn = time.Now().Add(-time.Second).Unix()
	h.client.mu.Unlock()

	if h.client.heartbeatTick(h.ctx, false) {
		t.Fatal("expected checks to stop")
	}
	failure := h.onlyFailure(t)
	if failure.Code != "session_expired" || !failure.IsFatal() || !errors.Is(failure, ErrSessionExpired) {
		t.Fatalf("unexpected failure %#v", failure)
	}
	h.assertInvalidated(t)
}

func TestGracePeriodTamperedSessionIsFatal(t *testing.T) {
	tampered := vectorByID(t, "tampered_payload")
	h := newHeartbeatHarness(t, "http://127.0.0.1:9")
	h.client.mu.Lock()
	h.client.rawPayloadB64 = tampered.Payload
	h.client.signature = tampered.Signature
	h.client.mu.Unlock()

	if h.client.heartbeatTick(h.ctx, false) {
		t.Fatal("expected checks to stop")
	}
	if failure := h.onlyFailure(t); failure.Code != "signature_mismatch" || !errors.Is(failure, ErrSignatureMismatch) {
		t.Fatalf("unexpected failure %#v", failure)
	}
	h.assertInvalidated(t)
}

// Without OnHeartbeatFailure the string callback keeps its old contract:
// one call per failure carrying the error message.
func TestHeartbeatLegacyOnFailureGetsMessageOnce(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	h := newHeartbeatHarness(t, url)
	var messages []string
	h.client.onHeartbeatFailure = nil
	h.client.onFailure = func(msg string) { messages = append(messages, msg) }

	h.client.heartbeatTick(h.ctx, true)
	if len(messages) != 1 || !strings.HasPrefix(messages[0], "authforge: request failed:") {
		t.Fatalf("messages = %q", messages)
	}

	revokedSrv, _ := heartbeatServer(t, heartbeatReply{410, failedBody("revoked")})
	h.client.apiBaseURL = revokedSrv.URL
	h.client.heartbeatTick(h.ctx, true)
	if len(messages) != 2 || messages[1] != "authforge: license revoked: revoked" {
		t.Fatalf("messages = %q", messages)
	}
	h.assertInvalidated(t)
}

// End to end through the background goroutine: transient failures (including
// unknown codes) keep it running, the first definitive one clears the session
// and stops it.
func TestHeartbeatLoopStopsOnlyOnDefinitive(t *testing.T) {
	srv, calls := heartbeatServer(t,
		heartbeatReply{500, failedBody("system_error")},
		heartbeatReply{403, failedBody("some_future_code")},
		heartbeatReply{429, failedBody("no_credits")},
		heartbeatReply{403, failedBody("blocked")},
	)
	failures := make(chan *Error, 8)
	client := newLoopClient(t, srv.URL, func(err *Error) { failures <- err })

	client.startHeartbeat()
	var codes []string
	for len(codes) < 4 {
		select {
		case failure := <-failures:
			codes = append(codes, failure.Code)
		case <-time.After(5 * time.Second):
			t.Fatalf("timed out; codes so far %v", codes)
		}
	}
	waitForLoopExit(t, client)

	if strings.Join(codes, ",") != "system_error,some_future_code,no_credits,blocked" {
		t.Fatalf("codes = %v", codes)
	}
	if got := atomic.LoadInt32(calls); got != 4 {
		t.Fatalf("loop should stop after the definitive failure; %d requests", got)
	}
	if client.IsAuthenticated() {
		t.Fatal("blocked must invalidate the session")
	}
	client.Logout()
}

// Callbacks run on the heartbeat goroutine with no SDK lock held, so they
// can query and log out the client.
func TestHeartbeatCallbackCanLogoutAndQueryAuth(t *testing.T) {
	cases := []struct {
		name           string
		reply          heartbeatReply
		authInCallback bool
	}{
		{"transient", heartbeatReply{500, failedBody("system_error")}, true},
		{"fatal", heartbeatReply{410, failedBody("revoked")}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, calls := heartbeatServer(t, tc.reply)
			done := make(chan struct{})
			var authBefore, authAfter bool
			var client *Client
			client = newLoopClient(t, srv.URL, func(err *Error) {
				authBefore = client.IsAuthenticated()
				client.Logout()
				authAfter = client.IsAuthenticated()
				close(done)
			})

			client.startHeartbeat()
			waitOrFail(t, done, "the failure callback (deadlock?)")
			waitForLoopExit(t, client)

			if authBefore != tc.authInCallback {
				t.Fatalf("IsAuthenticated() in callback = %v, want %v", authBefore, tc.authInCallback)
			}
			if authAfter || client.IsAuthenticated() {
				t.Fatal("Logout should clear the session")
			}
			if got := atomic.LoadInt32(calls); got != 1 {
				t.Fatalf("checks should stop after Logout; %d requests", got)
			}
		})
	}
}

// A check-in that succeeds after Logout must not write the session back.
func TestLogoutDuringInFlightHeartbeatStaysLoggedOut(t *testing.T) {
	t.Setenv("AUTHFORGE_SDK_TEST_NONCE", "nonce-heartbeat-001")
	body := signedBody(vectorByID(t, "heartbeat_success"))
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt32(&calls, 1) == 1 {
			close(entered)
			<-release
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	var failures int32
	client := newLoopClient(t, srv.URL, func(err *Error) { atomic.AddInt32(&failures, 1) })

	client.startHeartbeat()
	waitOrFail(t, entered, "the check-in request")
	loggedOut := make(chan struct{})
	go func() {
		client.Logout()
		close(loggedOut)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for client.IsAuthenticated() {
		if time.Now().After(deadline) {
			t.Fatal("Logout did not clear the session")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	waitOrFail(t, loggedOut, "Logout to return")

	if client.IsAuthenticated() {
		t.Fatal("late check-in response resurrected the session")
	}
	client.mu.Lock()
	token := client.sessionToken
	client.mu.Unlock()
	if token != "" {
		t.Fatalf("session token written back: %q", token)
	}
	if got := atomic.LoadInt32(&failures); got != 0 {
		t.Fatalf("a discarded check-in must not report a failure; %d callbacks", got)
	}
}

// A failure for a session that was replaced mid-request is dropped instead of
// clearing the new session.
func TestHeartbeatFailureForReplacedSessionIsDropped(t *testing.T) {
	var h *heartbeatHarness
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.client.mu.Lock()
		h.client.sessionGeneration++
		h.client.sessionToken = "session.replaced.token"
		h.client.mu.Unlock()
		w.WriteHeader(410)
		_, _ = w.Write([]byte(failedBody("revoked")))
	}))
	t.Cleanup(srv.Close)
	h = newHeartbeatHarness(t, srv.URL)

	if !h.client.heartbeatTick(h.ctx, true) {
		t.Fatal("checks should continue for the replacement session")
	}
	h.mu.Lock()
	reported := len(h.errs)
	h.mu.Unlock()
	if reported != 0 {
		t.Fatalf("stale failure reported %d times", reported)
	}
	h.assertStillAuthenticated(t)
}

func TestIsTransientClassification(t *testing.T) {
	definitive := []string{"revoked", "expired", "hwid_mismatch", "blocked", "session_expired", "malformed_request", "app_disabled", "invalid_app", "signature_mismatch"}
	transient := []string{
		"network_error", "timeout", "rate_limited", "system_error", "server_error",
		"no_credits", "demo_quota_exceeded", "app_burn_cap_reached", "bad_request", "invalid_key",
		"replay_detected", "revoke_requires_session", "unexpected_response", "invalid_json_response",
		"http_error_400", "http_error_403", "http_error_404", "http_error_408", "http_error_429",
		"http_error_500", "http_error_502", "http_error_503", "missing_session_token", "nonce_mismatch",
		"invalid_payload", "unknown_error", "some_future_code", "",
	}
	for _, code := range definitive {
		if err := newError(code, code); !err.IsFatal() || err.IsTransient() {
			t.Errorf("%q should be definitive", code)
		}
	}
	for _, code := range transient {
		if err := newError(code, code); !err.IsTransient() || err.IsFatal() {
			t.Errorf("%q should be transient", code)
		}
	}
	if IsTransient(nil) || IsTransient(errors.New("plain")) {
		t.Error("non-AuthForge errors are not transient")
	}
	wrapped := errors.Join(errors.New("context"), mapServerError("rate_limited"))
	if !IsTransient(wrapped) || ErrorCode(wrapped) != "rate_limited" {
		t.Error("IsTransient / ErrorCode should see through wrapping")
	}
}

func TestLoginErrorsExposeCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		_, _ = w.Write([]byte(failedBody("hwid_mismatch")))
	}))
	t.Cleanup(srv.Close)
	client, err := New(Config{AppID: "app", AppSecret: "secret", PublicKey: loadVectors(t).PublicKey, APIBaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.ValidateLicense("key")
	if !errors.Is(err, ErrHwidMismatch) || ErrorCode(err) != "hwid_mismatch" || IsTransient(err) {
		t.Fatalf("unexpected error %v (code %q)", err, ErrorCode(err))
	}
	if err.Error() != "authforge: HWID slots full: hwid_mismatch" {
		t.Fatalf("message changed: %q", err.Error())
	}
}
