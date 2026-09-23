package authforge

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultAPIBaseURL = "https://auth.authforge.cc"

var (
	ErrInvalidApp            = errors.New("authforge: invalid app credentials")
	ErrInvalidKey            = errors.New("authforge: invalid license key")
	ErrExpired               = errors.New("authforge: license expired")
	ErrRevoked               = errors.New("authforge: license revoked")
	ErrHwidMismatch          = errors.New("authforge: HWID slots full")
	ErrNoCredits             = errors.New("authforge: no credits")
	ErrAppBurnCapReached     = errors.New("authforge: app credit burn cap reached")
	ErrBlocked               = errors.New("authforge: blocked")
	ErrRateLimited           = errors.New("authforge: rate limited")
	ErrReplayDetected        = errors.New("authforge: replay detected")
	ErrAppDisabled           = errors.New("authforge: app disabled")
	ErrSessionExpired        = errors.New("authforge: session expired")
	ErrRevokeRequiresSession = errors.New("authforge: revoke requires session-authenticated self-ban")
	ErrBadRequest            = errors.New("authforge: bad request")
	ErrServerError           = errors.New("authforge: server error")
	ErrSignatureMismatch     = errors.New("authforge: signature verification failed")
	// ErrOfflineSession is returned by SelfBan when the client authenticated
	// with LoginFromFile and no explicit license key / session token was
	// given: an offline session has no server session and never phones home.
	ErrOfflineSession = errors.New("authforge: offline_session")
)

var serverErrorSentinels = map[string]error{
	"invalid_app":             ErrInvalidApp,
	"invalid_key":             ErrInvalidKey,
	"expired":                 ErrExpired,
	"revoked":                 ErrRevoked,
	"hwid_mismatch":           ErrHwidMismatch,
	"no_credits":              ErrNoCredits,
	"app_burn_cap_reached":    ErrAppBurnCapReached,
	"blocked":                 ErrBlocked,
	"rate_limited":            ErrRateLimited,
	"replay_detected":         ErrReplayDetected,
	"app_disabled":            ErrAppDisabled,
	"session_expired":         ErrSessionExpired,
	"revoke_requires_session": ErrRevokeRequiresSession,
	"bad_request":             ErrBadRequest,
	"malformed_request":       ErrBadRequest,
	"demo_quota_exceeded":     nil,
	"server_error":            ErrServerError,
	"system_error":            ErrServerError,
}

// Codes where AuthForge definitively rejected the session or license. Every
// other code is transient: network_error, timeout, rate_limited,
// system_error, server_error, no_credits, demo_quota_exceeded,
// app_burn_cap_reached, bad_request, invalid_key, every http_error_<status>,
// invalid_json_response, unexpected_response, SDK-local codes such as
// nonce_mismatch, and codes this SDK version doesn't know yet.
var definitiveErrorCodes = map[string]struct{}{
	"revoked":            {},
	"expired":            {},
	"hwid_mismatch":      {},
	"blocked":            {},
	"session_expired":    {},
	"malformed_request":  {},
	"app_disabled":       {},
	"invalid_app":        {},
	"signature_mismatch": {},
}

// errSessionReplaced reports a check-in whose session was logged out or
// replaced while the request was in flight; its result is discarded.
var errSessionReplaced = errors.New("authforge: session replaced during check-in")

var serverErrorCodeRE = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// Error is a failure with a machine-readable Code: the server's error code
// ("revoked", "hwid_mismatch", ...) or an SDK code ("network_error",
// "timeout", "http_error_502", "signature_mismatch", ...). errors.Is still
// matches the sentinel errors (ErrRevoked, ErrHwidMismatch, ...) and the
// underlying transport error.
type Error struct {
	Code     string
	message  string
	sentinel error
	cause    error
}

func (e *Error) Error() string {
	return e.message
}

func (e *Error) Unwrap() []error {
	out := make([]error, 0, 2)
	if e.sentinel != nil {
		out = append(out, e.sentinel)
	}
	if e.cause != nil {
		out = append(out, e.cause)
	}
	return out
}

// IsTransient reports whether retrying later can succeed: every code except
// the definitive revoked, expired, hwid_mismatch, blocked, session_expired,
// malformed_request, app_disabled, invalid_app and signature_mismatch.
// Unknown codes are transient.
func (e *Error) IsTransient() bool {
	return isTransientCode(e.Code)
}

// IsFatal reports whether AuthForge definitively rejected the session or
// license (revoked, expired, hwid_mismatch, blocked, session_expired,
// malformed_request, app_disabled, invalid_app, signature_mismatch).
func (e *Error) IsFatal() bool {
	return !e.IsTransient()
}

// IsTransient reports whether err is an AuthForge failure worth retrying.
func IsTransient(err error) bool {
	var afErr *Error
	return errors.As(err, &afErr) && afErr.IsTransient()
}

// ErrorCode returns the machine-readable code of an AuthForge failure, or ""
// when err is not one.
func ErrorCode(err error) string {
	var afErr *Error
	if errors.As(err, &afErr) {
		return afErr.Code
	}
	return ""
}

func isTransientCode(code string) bool {
	_, definitive := definitiveErrorCodes[code]
	return !definitive
}

func newError(code string, message string) *Error {
	return &Error{Code: code, message: message}
}

// SessionKind says how the client authenticated.
type SessionKind int

const (
	// SessionKindNone means the client is not authenticated.
	SessionKindNone SessionKind = iota
	// SessionKindOnline is a server session from Login / ValidateLicense.
	SessionKindOnline
	// SessionKindOffline is a locally verified .authforge file from LoginFromFile.
	SessionKindOffline
)

func (k SessionKind) String() string {
	switch k {
	case SessionKindNone:
		return "none"
	case SessionKindOnline:
		return "online"
	case SessionKindOffline:
		return "offline"
	default:
		return fmt.Sprintf("SessionKind(%d)", int(k))
	}
}

type Config struct {
	AppID string
	// AppSecret authenticates online APIs (Login, ValidateLicense, SelfBan).
	// Leave empty for offline-only clients (LoginFromFile). Air-gapped
	// builds should not ship the secret.
	AppSecret string
	// PublicKey is the trusted Ed25519 public key (base64-encoded). For the
	// common single-key case set this directly; during a server-side rotation
	// pass the previous and current keys via PublicKeys instead so the SDK
	// trusts both for the duration of the cutover.
	PublicKey string
	// PublicKeys is the optional rotation set; when non-empty it takes
	// precedence over PublicKey. The first entry is treated as the primary
	// (current) key for telemetry/logging purposes; verification accepts a
	// signature that matches any entry.
	PublicKeys []string

	// OnlineHeartbeat enables the optional online check-ins policy: the SDK
	// periodically calls POST /auth/heartbeat so revocation and
	// concurrent-use detection take effect quickly. When false (the
	// default), the SDK relies on the grace period instead: after a
	// successful activation the app keeps running on the signed session,
	// re-verified locally, until the session TTL expires, with no further
	// network calls.
	OnlineHeartbeat bool

	// Deprecated: HeartbeatMode is deprecated. Leave it empty for the default grace period behavior, or set OnlineHeartbeat to true for online check-ins ("server" maps to OnlineHeartbeat, "local" maps to the default).
	HeartbeatMode     string
	HeartbeatInterval time.Duration
	APIBaseURL        string
	OnFailure         func(error string)
	// OnHeartbeatFailure, when set, receives background check failures
	// instead of OnFailure, as an *Error carrying the code and its
	// transient/fatal classification. Fatal failures have already cleared
	// the session when it runs; transient ones keep checking in. It runs on
	// the background goroutine with no SDK lock held, so it may call Logout.
	// With neither callback set, a transient failure prints a one-line
	// warning to stderr and a fatal one clears the session silently.
	OnHeartbeatFailure func(err *Error)
	RequestTimeout     time.Duration
	HWIDOverride       string

	// SessionTTL sets the grace period duration: how long the app keeps
	// running on the signed session without contacting AuthForge. It is
	// the session token lifetime requested from the server on Login. Zero
	// means "use the server default" (24h today). Server clamps to
	// [1h, 7d]; out-of-range values are silently clamped.
	SessionTTL time.Duration
}

type LoginResult struct {
	SessionToken     string                 `json:"sessionToken"`
	ExpiresIn        int64                  `json:"expiresIn"`
	SessionExpiresAt string                 `json:"sessionExpiresAt,omitempty"`
	LicenseExpiresAt *string                `json:"licenseExpiresAt,omitempty"`
	MaxHwidSlots     *int                   `json:"maxHwidSlots,omitempty"`
	HwidCount        *int                   `json:"hwidCount,omitempty"`
	LicenseLabel     *string                `json:"licenseLabel,omitempty"`
	AppVariables     map[string]interface{} `json:"appVariables,omitempty"`
	LicenseVariables map[string]interface{} `json:"licenseVariables,omitempty"`
	RequestID        string                 `json:"requestId,omitempty"`
}

type Client struct {
	appID              string
	appSecret          string
	onlineHeartbeat    bool
	heartbeatInterval  time.Duration
	apiBaseURL         string
	onFailure          func(error string)
	onHeartbeatFailure func(err *Error)
	httpClient         *http.Client
	sleep              func(time.Duration)
	stderr             io.Writer
	// sessionTTLSeconds is the SDK-requested session TTL sent to /auth/validate.
	// Zero means "let the server pick its default".
	sessionTTLSeconds int

	hwid string

	mu           sync.Mutex
	licenseKey   string
	sessionToken string
	// sessionKind drives IsAuthenticated, SelfBan and the heartbeat guard so
	// an offline file session can never be mistaken for a server session.
	sessionKind      SessionKind
	publicKeys       [][]byte
	sessionExpiresIn int64
	lastNonce        string
	rawPayloadB64    string
	signature        string
	sessionData      map[string]interface{}
	appVariables     map[string]interface{}
	licenseVariables map[string]interface{}
	authenticated    bool
	// offlineLicense is set when the client authenticated via LoginFromFile.
	offlineLicense *OfflineLicense
	// sessionGeneration changes on every Login and session reset, so a
	// check-in that was in flight across one never writes its result back.
	sessionGeneration uint64

	heartbeatCtx    context.Context
	heartbeatCancel context.CancelFunc
	heartbeatWg     sync.WaitGroup
	// inHeartbeatCallback lets Logout run from a failure callback, which
	// executes on the goroutine Logout would otherwise wait for.
	inHeartbeatCallback atomic.Bool
}

// collectPublicKeyStrings returns the canonical (de-duplicated, trimmed)
// list of base64 public keys configured on cfg. Both PublicKeys and
// PublicKey are honoured to keep callers that pre-date the rotation API
// working unchanged. Callers may also pass a comma-separated string in
// PublicKey for environment-variable convenience.
func collectPublicKeyStrings(cfg Config) []string {
	out := make([]string, 0, len(cfg.PublicKeys)+1)
	seen := make(map[string]struct{})
	add := func(value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		if _, exists := seen[trimmed]; exists {
			return
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	for _, key := range cfg.PublicKeys {
		add(key)
	}
	if strings.Contains(cfg.PublicKey, ",") {
		for _, segment := range strings.Split(cfg.PublicKey, ",") {
			add(segment)
		}
	} else {
		add(cfg.PublicKey)
	}
	return out
}

func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.AppID) == "" {
		return nil, fmt.Errorf("authforge: app id is required")
	}
	publicKeyStrings := collectPublicKeyStrings(cfg)
	if len(publicKeyStrings) == 0 {
		return nil, fmt.Errorf("authforge: public key is required")
	}
	publicKeys := make([][]byte, 0, len(publicKeyStrings))
	for _, raw := range publicKeyStrings {
		decoded, err := base64.StdEncoding.DecodeString(raw)
		if err != nil || len(decoded) != 32 {
			return nil, fmt.Errorf("authforge: invalid public key")
		}
		publicKeys = append(publicKeys, decoded)
	}

	mode := strings.ToLower(strings.TrimSpace(cfg.HeartbeatMode))
	if mode != "" && mode != "local" && mode != "server" {
		return nil, fmt.Errorf("authforge: heartbeat mode must be \"local\" or \"server\" (deprecated; use OnlineHeartbeat instead)")
	}
	onlineHeartbeat := cfg.OnlineHeartbeat || mode == "server"

	interval := cfg.HeartbeatInterval
	if interval <= 0 {
		interval = 15 * time.Minute
	} else if interval < 10*time.Second {
		return nil, fmt.Errorf("authforge: heartbeat interval must be >= 10s")
	}

	baseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if baseURL == "" {
		baseURL = defaultAPIBaseURL
	}

	timeout := cfg.RequestTimeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	sessionTTLSeconds := 0
	if cfg.SessionTTL > 0 {
		sessionTTLSeconds = int(cfg.SessionTTL / time.Second)
		if sessionTTLSeconds < 1 {
			sessionTTLSeconds = 1
		}
	}

	resolvedHWID := strings.TrimSpace(cfg.HWIDOverride)
	if resolvedHWID == "" {
		resolvedHWID = generateHWID()
	}

	client := &Client{
		appID:              strings.TrimSpace(cfg.AppID),
		appSecret:          strings.TrimSpace(cfg.AppSecret),
		publicKeys:         publicKeys,
		onlineHeartbeat:    onlineHeartbeat,
		heartbeatInterval:  interval,
		apiBaseURL:         baseURL,
		onFailure:          cfg.OnFailure,
		onHeartbeatFailure: cfg.OnHeartbeatFailure,
		sessionTTLSeconds:  sessionTTLSeconds,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		sleep:            time.Sleep,
		stderr:           os.Stderr,
		hwid:             resolvedHWID,
		sessionData:      map[string]interface{}{},
		appVariables:     map[string]interface{}{},
		licenseVariables: map[string]interface{}{},
	}

	return client, nil
}

func (c *Client) requireAppSecret() error {
	if strings.TrimSpace(c.appSecret) == "" {
		return fmt.Errorf("authforge: app secret is required for online APIs; omit it only for LoginFromFile")
	}
	return nil
}

func (c *Client) Login(licenseKey string) (*LoginResult, error) {
	trimmedLicense := strings.TrimSpace(licenseKey)
	if trimmedLicense == "" {
		return nil, fmt.Errorf("authforge: license key is required")
	}

	result, err := c.validateWithRateLimitRetry(trimmedLicense)
	if err != nil {
		return nil, err
	}

	c.startHeartbeat()
	return result, nil
}

// ValidateLicense performs the same /auth/validate request and signature checks as Login,
// without updating client session state or starting the heartbeat goroutine.
func (c *Client) ValidateLicense(licenseKey string) (*LoginResult, error) {
	trimmedLicense := strings.TrimSpace(licenseKey)
	if trimmedLicense == "" {
		return nil, fmt.Errorf("authforge: license key is required")
	}

	return c.validateOnce(trimmedLicense, false, false)
}

func (c *Client) SelfBan(
	licenseKey string,
	sessionToken string,
	revokeLicense bool,
	blacklistHwid bool,
	blacklistIP bool,
) (map[string]interface{}, error) {
	c.mu.Lock()
	currentSession := c.sessionToken
	currentLicense := c.licenseKey
	currentKind := c.sessionKind
	hwid := c.hwid
	c.mu.Unlock()

	resolvedSession := strings.TrimSpace(sessionToken)
	explicitLicense := strings.TrimSpace(licenseKey)

	// An offline session has no server session and must never phone home on
	// its own. Callers who pass an explicit licenseKey/sessionToken are asking
	// about a *different* credential and still get the normal paths.
	if currentKind == SessionKindOffline && resolvedSession == "" && explicitLicense == "" {
		return nil, ErrOfflineSession
	}

	if resolvedSession == "" {
		resolvedSession = strings.TrimSpace(currentSession)
	}
	if resolvedSession != "" {
		body := map[string]interface{}{
			"appId":         c.appID,
			"sessionToken":  resolvedSession,
			"hwid":          hwid,
			"revokeLicense": revokeLicense,
			"blacklistHwid": blacklistHwid,
			"blacklistIp":   blacklistIP,
		}
		response, err := c.postJSON("/auth/selfban", body, true)
		if err != nil {
			return nil, err
		}
		if !isSuccessStatus(response["status"]) {
			return nil, mapServerError(valueAsString(response["error"]))
		}
		return response, nil
	}

	resolvedLicense := explicitLicense
	if resolvedLicense == "" {
		resolvedLicense = strings.TrimSpace(currentLicense)
	}
	if resolvedLicense == "" {
		return nil, fmt.Errorf("authforge: missing license key")
	}
	if err := c.requireAppSecret(); err != nil {
		return nil, err
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}
	body := map[string]interface{}{
		"appId":         c.appID,
		"appSecret":     c.appSecret,
		"licenseKey":    resolvedLicense,
		"hwid":          hwid,
		"nonce":         nonce,
		"revokeLicense": false,
		"blacklistHwid": blacklistHwid,
		"blacklistIp":   blacklistIP,
	}
	response, err := c.postJSON("/auth/selfban", body, true)
	if err != nil {
		return nil, err
	}
	if !isSuccessStatus(response["status"]) {
		return nil, mapServerError(valueAsString(response["error"]))
	}
	return response, nil
}

func (c *Client) Logout() {
	c.mu.Lock()
	cancel := c.resetSessionLocked()
	c.mu.Unlock()

	if cancel != nil {
		cancel()
		if !c.inHeartbeatCallback.Load() {
			c.heartbeatWg.Wait()
		}
	}
}

// resetSessionLocked clears all session state and detaches the background
// check loop, returning its cancel func. Callers hold c.mu.
func (c *Client) resetSessionLocked() context.CancelFunc {
	cancel := c.heartbeatCancel
	c.heartbeatCancel = nil
	c.heartbeatCtx = nil
	c.licenseKey = ""
	c.sessionToken = ""
	c.sessionKind = SessionKindNone
	c.sessionExpiresIn = 0
	c.lastNonce = ""
	c.rawPayloadB64 = ""
	c.signature = ""
	c.sessionData = map[string]interface{}{}
	c.appVariables = map[string]interface{}{}
	c.licenseVariables = map[string]interface{}{}
	c.authenticated = false
	c.offlineLicense = nil
	c.sessionGeneration++
	return cancel
}

// IsAuthenticated is true for an online session (Login) or an offline one
// (LoginFromFile).
func (c *Client) IsAuthenticated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.authenticated {
		return false
	}
	switch c.sessionKind {
	case SessionKindOnline:
		return c.sessionToken != ""
	case SessionKindOffline:
		return true
	case SessionKindNone:
		return false
	default:
		return false
	}
}

// GetSessionKind reports how the client authenticated: SessionKindOnline
// after Login, SessionKindOffline after LoginFromFile, SessionKindNone when
// logged out.
func (c *Client) GetSessionKind() SessionKind {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sessionKind
}

func (c *Client) SessionData() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneMap(c.sessionData)
}

func (c *Client) GetSessionData() map[string]interface{} {
	return c.SessionData()
}

func (c *Client) AppVariables() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneMap(c.appVariables)
}

func (c *Client) GetAppVariables() map[string]interface{} {
	return c.AppVariables()
}

func (c *Client) LicenseVariables() map[string]interface{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	return cloneMap(c.licenseVariables)
}

func (c *Client) GetLicenseVariables() map[string]interface{} {
	return c.LicenseVariables()
}

func (c *Client) validateWithRateLimitRetry(licenseKey string) (*LoginResult, error) {
	return c.validateOnce(licenseKey, true, true)
}

func (c *Client) validateOnce(licenseKey string, persistSession bool, invokeOnNetworkFailure bool) (*LoginResult, error) {
	if err := c.requireAppSecret(); err != nil {
		return nil, err
	}
	nonce, err := generateNonce()
	if err != nil {
		return nil, err
	}

	body := map[string]interface{}{
		"appId":      c.appID,
		"appSecret":  c.appSecret,
		"licenseKey": licenseKey,
		"hwid":       c.hwid,
		"nonce":      nonce,
	}
	if c.sessionTTLSeconds > 0 {
		body["ttlSeconds"] = c.sessionTTLSeconds
	}

	response, err := c.postJSON("/auth/validate", body, invokeOnNetworkFailure)
	if err != nil {
		return nil, err
	}

	return c.applySignedResponse(response, nonce, licenseKey, persistSession, true, "validate", 0)
}

func (c *Client) startHeartbeat() {
	c.mu.Lock()
	// Offline sessions have no grace period and no online check-ins: the
	// file's own expiresAt is the only clock. Never start a goroutine for them.
	if c.heartbeatCancel != nil || c.sessionKind == SessionKindOffline {
		c.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.heartbeatCtx = ctx
	c.heartbeatCancel = cancel
	onlineHeartbeat := c.onlineHeartbeat
	interval := c.heartbeatInterval
	c.heartbeatWg.Add(1)
	c.mu.Unlock()

	go func() {
		defer c.heartbeatWg.Done()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !c.heartbeatTick(ctx, onlineHeartbeat) {
					return
				}
			}
		}
	}()
}

// heartbeatTick runs one background check and reports whether checks should
// continue. Transient failures keep the session and check in again next
// interval; with no callback set they print a one-line warning to stderr.
// Definitive failures clear the session before the callback runs,
// so neither the grace period nor IsAuthenticated keeps the app running on
// it, and the callback may call Login again. Callbacks run with c.mu
// released.
func (c *Client) heartbeatTick(ctx context.Context, onlineHeartbeat bool) bool {
	c.mu.Lock()
	generation := c.sessionGeneration
	c.mu.Unlock()

	var err error
	if onlineHeartbeat {
		err = c.serverHeartbeat(generation)
	} else {
		err = c.gracePeriodCheck()
	}
	if err == nil {
		return true
	}
	if ctx.Err() != nil {
		return false
	}

	c.mu.Lock()
	if c.sessionGeneration != generation {
		// The failure belongs to a session that has since been replaced.
		c.mu.Unlock()
		return ctx.Err() == nil
	}
	failure := c.heartbeatErrorLocked(err)
	var cancel context.CancelFunc
	if failure.IsFatal() {
		cancel = c.resetSessionLocked()
	}
	c.mu.Unlock()
	if cancel != nil {
		cancel()
	}

	c.inHeartbeatCallback.Store(true)
	if c.onHeartbeatFailure != nil {
		c.onHeartbeatFailure(failure)
	} else if c.onFailure != nil {
		c.onFailure(failure.Error())
	} else if failure.IsTransient() {
		fmt.Fprintf(c.stderr, "AuthForge: background check failed (%s); retrying next interval\n", failure.Code)
	}
	c.inHeartbeatCallback.Store(false)
	return failure.IsTransient() && ctx.Err() == nil
}

// heartbeatErrorLocked normalizes a background check failure. Callers hold
// c.mu.
func (c *Client) heartbeatErrorLocked(err error) *Error {
	var failure *Error
	if !errors.As(err, &failure) {
		switch {
		case errors.Is(err, ErrSessionExpired):
			failure = &Error{Code: "session_expired", message: err.Error(), sentinel: ErrSessionExpired}
		case errors.Is(err, ErrSignatureMismatch):
			failure = &Error{Code: "signature_mismatch", message: err.Error(), sentinel: ErrSignatureMismatch}
		default:
			failure = &Error{Code: "unknown_error", message: err.Error(), cause: err}
		}
	}
	// A transient failure can't extend the session past its signed TTL.
	if failure.IsTransient() && c.sessionExpiresIn > 0 && time.Now().Unix() >= c.sessionExpiresIn {
		return &Error{
			Code:     "session_expired",
			message:  ErrSessionExpired.Error(),
			sentinel: ErrSessionExpired,
			cause:    failure,
		}
	}
	return failure
}

func (c *Client) serverHeartbeat(generation uint64) error {
	c.mu.Lock()
	sessionToken := c.sessionToken
	c.mu.Unlock()

	if strings.TrimSpace(sessionToken) == "" {
		return newError("missing_session_token", "authforge: missing session token")
	}

	nonce, err := generateNonce()
	if err != nil {
		return err
	}

	body := map[string]interface{}{
		"appId":        c.appID,
		"sessionToken": sessionToken,
		"nonce":        nonce,
		"hwid":         c.hwid,
	}

	// Network failures surface once, through the heartbeat failure callback.
	response, err := c.postJSON("/auth/heartbeat", body, false)
	if err != nil {
		return err
	}
	if err := checkHeartbeatVerdict(response); err != nil {
		return err
	}

	_, err = c.applySignedResponse(response, nonce, "", true, false, "heartbeat", generation)
	return err
}

// checkHeartbeatVerdict accepts a non-success check-in response as an
// AuthForge verdict only when it is {"status":"failed","error":"<code>"};
// anything else (proxy pages, partial bodies) is unexpected_response, which
// is transient.
func checkHeartbeatVerdict(response map[string]interface{}) error {
	if isSuccessStatus(response["status"]) {
		return nil
	}
	status, statusIsString := response["status"].(string)
	code, codeIsString := response["error"].(string)
	if statusIsString && strings.EqualFold(strings.TrimSpace(status), "failed") && codeIsString && strings.TrimSpace(code) != "" {
		return nil
	}
	return newError("unexpected_response", fmt.Sprintf(
		"authforge: unexpected_response: status=%s error=%s",
		rawJSONField(response, "status"),
		rawJSONField(response, "error"),
	))
}

func rawJSONField(response map[string]interface{}, key string) string {
	value, ok := response[key]
	if !ok {
		return "<missing>"
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return fmt.Sprintf("%v", value)
	}
	return string(encoded)
}

// gracePeriodCheck enforces the grace period: it re-verifies the signed
// session obtained at activation and fails with ErrSessionExpired once the
// session TTL has elapsed. It makes no network calls.
func (c *Client) gracePeriodCheck() error {
	c.mu.Lock()
	payload := c.rawPayloadB64
	signature := c.signature
	expiresIn := c.sessionExpiresIn
	c.mu.Unlock()

	if payload == "" || signature == "" {
		return newError("missing_session_state", "authforge: missing local verification state")
	}

	if !verifySignature(payload, signature, c.publicKeys) {
		return ErrSignatureMismatch
	}

	if time.Now().Unix() < expiresIn {
		return nil
	}
	return ErrSessionExpired
}

// applySignedResponse verifies a signed response and, when persistSession is
// set, stores it. A login starts a new session generation; a check-in stores
// its result only while the session is still the one at generation.
func (c *Client) applySignedResponse(
	response map[string]interface{},
	expectedNonce string,
	licenseKey string,
	persistSession bool,
	isLogin bool,
	signingContext string,
	generation uint64,
) (*LoginResult, error) {
	_ = signingContext
	status := response["status"]
	if !isSuccessStatus(status) {
		serverError := extractServerError(response)
		if serverError == "" {
			serverError = "unknown_error"
		}
		return nil, mapServerError(serverError)
	}

	payloadB64 := valueAsString(response["payload"])
	if payloadB64 == "" {
		return nil, newError("missing_payload", "authforge: missing payload")
	}

	signature := valueAsString(response["signature"])
	if signature == "" {
		return nil, newError("missing_signature", "authforge: missing signature")
	}

	payload, err := decodePayload(payloadB64)
	if err != nil {
		return nil, &Error{Code: "invalid_payload", message: fmt.Sprintf("authforge: invalid payload: %v", err), cause: err}
	}

	nonce := valueAsString(payload["nonce"])
	if nonce != expectedNonce {
		return nil, newError("nonce_mismatch", "authforge: nonce mismatch")
	}

	if !verifySignature(payloadB64, signature, c.publicKeys) {
		return nil, ErrSignatureMismatch
	}

	sessionToken := valueAsString(payload["sessionToken"])
	if sessionToken == "" {
		return nil, newError("missing_session_token", "authforge: missing session token")
	}

	expiresIn, hasTokenExpiry := extractExpiresFromSessionToken(sessionToken)
	if !hasTokenExpiry {
		value, ok := numberToInt64(payload["expiresIn"])
		if !ok {
			return nil, newError("missing_expires_in", "authforge: missing expiresIn")
		}
		expiresIn = value
	}

	appVars := extractVariables(payload["appVariables"])
	licenseVars := extractVariables(payload["licenseVariables"])
	requestID := valueAsString(payload["requestId"])
	sessionExpiresAt := valueAsString(payload["sessionExpiresAt"])
	var licenseExpiresAt *string
	if raw, has := payload["licenseExpiresAt"]; has {
		switch typed := raw.(type) {
		case nil:
			empty := ""
			licenseExpiresAt = &empty
		case string:
			licenseExpiresAt = &typed
		}
	}
	maxHwidSlots := extractIntPtr(payload["maxHwidSlots"])
	hwidCount := extractIntPtr(payload["hwidCount"])
	licenseLabel := extractStringPtr(payload["licenseLabel"])

	if !persistSession {
		return &LoginResult{
			SessionToken:     sessionToken,
			ExpiresIn:        expiresIn,
			SessionExpiresAt: sessionExpiresAt,
			LicenseExpiresAt: licenseExpiresAt,
			MaxHwidSlots:     maxHwidSlots,
			HwidCount:        hwidCount,
			LicenseLabel:     licenseLabel,
			AppVariables:     cloneMap(appVars),
			LicenseVariables: cloneMap(licenseVars),
			RequestID:        requestID,
		}, nil
	}

	c.mu.Lock()
	if isLogin {
		c.sessionGeneration++
	} else if c.sessionGeneration != generation {
		c.mu.Unlock()
		return nil, errSessionReplaced
	}
	if licenseKey != "" {
		c.licenseKey = licenseKey
	}
	c.sessionToken = sessionToken
	c.sessionKind = SessionKindOnline
	c.sessionExpiresIn = expiresIn
	c.lastNonce = expectedNonce
	c.rawPayloadB64 = payloadB64
	c.signature = strings.ToLower(strings.TrimSpace(signature))
	c.sessionData = cloneMap(payload)
	if appVars != nil || isLogin {
		c.appVariables = cloneMap(appVars)
	}
	if licenseVars != nil || isLogin {
		c.licenseVariables = cloneMap(licenseVars)
	}
	c.authenticated = true
	appVarsCopy := cloneMap(c.appVariables)
	licenseVarsCopy := cloneMap(c.licenseVariables)
	c.mu.Unlock()

	return &LoginResult{
		SessionToken:     sessionToken,
		ExpiresIn:        expiresIn,
		SessionExpiresAt: sessionExpiresAt,
		LicenseExpiresAt: licenseExpiresAt,
		MaxHwidSlots:     maxHwidSlots,
		HwidCount:        hwidCount,
		LicenseLabel:     licenseLabel,
		AppVariables:     appVarsCopy,
		LicenseVariables: licenseVarsCopy,
		RequestID:        requestID,
	}, nil
}

func (c *Client) postJSON(path string, body map[string]interface{}, invokeOnNetworkFailure bool) (map[string]interface{}, error) {
	rateRetryDelays := []time.Duration{0, 2 * time.Second, 5 * time.Second}
	mutableBody := cloneMap(body)
	var lastRateErr error

	for attempt := 0; attempt < len(rateRetryDelays); attempt++ {
		if rateRetryDelays[attempt] > 0 {
			c.sleep(rateRetryDelays[attempt])
			if _, ok := mutableBody["nonce"]; ok {
				nonce, nonceErr := generateNonce()
				if nonceErr != nil {
					return nil, nonceErr
				}
				mutableBody["nonce"] = nonce
				body["nonce"] = nonce
			}
		}

		requestBody, err := json.Marshal(mutableBody)
		if err != nil {
			return nil, fmt.Errorf("authforge: encode request failed: %w", err)
		}

		request, err := http.NewRequest(http.MethodPost, c.apiBaseURL+path, bytes.NewReader(requestBody))
		if err != nil {
			return nil, fmt.Errorf("authforge: create request failed: %w", err)
		}
		request.Header.Set("Content-Type", "application/json")

		var response *http.Response
		networkRetried := false
		for {
			response, err = c.httpClient.Do(request)
			if err == nil {
				break
			}
			if !networkRetried {
				networkRetried = true
				c.sleep(2 * time.Second)
				request, err = http.NewRequest(http.MethodPost, c.apiBaseURL+path, bytes.NewReader(requestBody))
				if err != nil {
					return nil, fmt.Errorf("authforge: create request failed: %w", err)
				}
				request.Header.Set("Content-Type", "application/json")
				continue
			}
			if invokeOnNetworkFailure && c.onFailure != nil {
				c.onFailure("network_error")
			}
			return nil, &Error{
				Code:    transportErrorCode(err),
				message: fmt.Sprintf("authforge: request failed: %v", err),
				cause:   err,
			}
		}

		rawBody, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, &Error{
				Code:    transportErrorCode(err),
				message: fmt.Sprintf("authforge: read response failed: %v", err),
				cause:   err,
			}
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return nil, &Error{
					Code:    fmt.Sprintf("http_error_%d", response.StatusCode),
					message: fmt.Sprintf("authforge: http error %d", response.StatusCode),
					cause:   err,
				}
			}
			return nil, &Error{
				Code:    "invalid_json_response",
				message: fmt.Sprintf("authforge: invalid json response: %v", err),
				cause:   err,
			}
		}

		// no_credits / app_burn_cap_reached / demo_quota_exceeded also use
		// HTTP 429 but are not worth retrying; only retry a genuine rate limit.
		serverError := extractServerError(parsed)
		if serverError == "rate_limited" || (response.StatusCode == http.StatusTooManyRequests && serverError == "") {
			lastRateErr = mapServerError("rate_limited")
			continue
		}

		return parsed, nil
	}

	if lastRateErr != nil {
		return nil, lastRateErr
	}
	return nil, mapServerError("rate_limited")
}

func transportErrorCode(err error) string {
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return "timeout"
	}
	return "network_error"
}

func mapServerError(serverError string) error {
	sentinel := serverErrorSentinels[serverError]
	message := "authforge: " + serverError
	if sentinel != nil {
		message = sentinel.Error() + ": " + serverError
	}
	return &Error{Code: serverError, message: message, sentinel: sentinel}
}

// extractServerError returns the response's error code. Codes this SDK
// version doesn't know yet pass through instead of being dropped.
func extractServerError(response map[string]interface{}) string {
	errorCode := strings.ToLower(valueAsString(response["error"]))
	if _, known := serverErrorSentinels[errorCode]; known || serverErrorCodeRE.MatchString(errorCode) {
		return errorCode
	}

	statusCode := strings.ToLower(valueAsString(response["status"]))
	if _, known := serverErrorSentinels[statusCode]; known {
		return statusCode
	}
	return ""
}

func isSuccessStatus(status interface{}) bool {
	switch typed := status.(type) {
	case bool:
		return typed
	case string:
		switch strings.ToLower(strings.TrimSpace(typed)) {
		case "ok", "success", "valid", "true", "1":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func valueAsString(value interface{}) string {
	switch typed := value.(type) {
	case string:
		return strings.TrimSpace(typed)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprintf("%v", value))
	}
}

func extractVariables(value interface{}) map[string]interface{} {
	raw, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}
	return cloneMap(raw)
}

func cloneMap(value map[string]interface{}) map[string]interface{} {
	if value == nil {
		return map[string]interface{}{}
	}

	cloned := make(map[string]interface{}, len(value))
	for key, item := range value {
		cloned[key] = item
	}
	return cloned
}

func generateNonce() (string, error) {
	if v := strings.TrimSpace(os.Getenv("AUTHFORGE_SDK_TEST_NONCE")); v != "" {
		return v, nil
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("authforge: nonce generation failed: %w", err)
	}
	return hex.EncodeToString(nonce), nil
}
