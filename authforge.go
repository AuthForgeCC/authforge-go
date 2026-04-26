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
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const defaultAPIBaseURL = "https://auth.authforge.cc"

var (
	ErrInvalidApp        = errors.New("authforge: invalid app credentials")
	ErrInvalidKey        = errors.New("authforge: invalid license key")
	ErrExpired           = errors.New("authforge: license expired")
	ErrRevoked           = errors.New("authforge: license revoked")
	ErrHwidMismatch      = errors.New("authforge: HWID slots full")
	ErrNoCredits         = errors.New("authforge: no credits")
	ErrAppBurnCapReached = errors.New("authforge: app credit burn cap reached")
	ErrBlocked           = errors.New("authforge: blocked")
	ErrRateLimited       = errors.New("authforge: rate limited")
	ErrReplayDetected    = errors.New("authforge: replay detected")
	ErrAppDisabled       = errors.New("authforge: app disabled")
	ErrSessionExpired    = errors.New("authforge: session expired")
	ErrRevokeRequiresSession = errors.New("authforge: revoke requires session-authenticated self-ban")
	ErrBadRequest        = errors.New("authforge: bad request")
	ErrServerError       = errors.New("authforge: server error")
	ErrSignatureMismatch = errors.New("authforge: signature verification failed")
)

type Config struct {
	AppID     string
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
	PublicKeys        []string
	HeartbeatMode     string
	HeartbeatInterval time.Duration
	APIBaseURL        string
	OnFailure         func(error string)
	RequestTimeout    time.Duration
	HWIDOverride      string

	// SessionTTL overrides the session token lifetime requested from the
	// server on Login. Zero means "use the server default" (24h today).
	// Server clamps to [1h, 7d]; out-of-range values are silently clamped.
	SessionTTL time.Duration
}

type LoginResult struct {
	SessionToken     string                 `json:"sessionToken"`
	ExpiresIn        int64                  `json:"expiresIn"`
	AppVariables     map[string]interface{} `json:"appVariables,omitempty"`
	LicenseVariables map[string]interface{} `json:"licenseVariables,omitempty"`
	RequestID        string                 `json:"requestId"`
}

type Client struct {
	appID             string
	appSecret         string
	heartbeatMode     string
	heartbeatInterval time.Duration
	apiBaseURL        string
	onFailure         func(error string)
	httpClient        *http.Client
	// sessionTTLSeconds is the SDK-requested session TTL sent to /auth/validate.
	// Zero means "let the server pick its default".
	sessionTTLSeconds int

	hwid string

	mu               sync.Mutex
	licenseKey       string
	sessionToken     string
	publicKeys       [][]byte
	sessionExpiresIn int64
	lastNonce        string
	rawPayloadB64    string
	signature        string
	sessionData      map[string]interface{}
	appVariables     map[string]interface{}
	licenseVariables map[string]interface{}
	authenticated    bool

	heartbeatCtx    context.Context
	heartbeatCancel context.CancelFunc
	heartbeatWg     sync.WaitGroup
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
	if strings.TrimSpace(cfg.AppSecret) == "" {
		return nil, fmt.Errorf("authforge: app secret is required")
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
	if mode != "local" && mode != "server" {
		return nil, fmt.Errorf("authforge: heartbeat mode must be \"local\" or \"server\"")
	}

	interval := cfg.HeartbeatInterval
	if interval <= 0 {
		interval = 15 * time.Minute
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
		appID:             strings.TrimSpace(cfg.AppID),
		appSecret:         strings.TrimSpace(cfg.AppSecret),
		publicKeys:        publicKeys,
		heartbeatMode:     mode,
		heartbeatInterval: interval,
		apiBaseURL:        baseURL,
		onFailure:         cfg.OnFailure,
		sessionTTLSeconds: sessionTTLSeconds,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		hwid:             resolvedHWID,
		sessionData:      map[string]interface{}{},
		appVariables:     map[string]interface{}{},
		licenseVariables: map[string]interface{}{},
	}

	return client, nil
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
	hwid := c.hwid
	c.mu.Unlock()

	resolvedSession := strings.TrimSpace(sessionToken)
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

	resolvedLicense := strings.TrimSpace(licenseKey)
	if resolvedLicense == "" {
		resolvedLicense = strings.TrimSpace(currentLicense)
	}
	if resolvedLicense == "" {
		return nil, fmt.Errorf("authforge: missing license key")
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
	cancel := c.heartbeatCancel
	c.heartbeatCancel = nil
	c.heartbeatCtx = nil
	c.licenseKey = ""
	c.sessionToken = ""
	c.sessionExpiresIn = 0
	c.lastNonce = ""
	c.rawPayloadB64 = ""
	c.signature = ""
	c.sessionData = map[string]interface{}{}
	c.appVariables = map[string]interface{}{}
	c.licenseVariables = map[string]interface{}{}
	c.authenticated = false
	c.mu.Unlock()

	if cancel != nil {
		cancel()
		c.heartbeatWg.Wait()
	}
}

func (c *Client) IsAuthenticated() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.authenticated && c.sessionToken != ""
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

	return c.applySignedResponse(response, nonce, licenseKey, persistSession, true, "validate")
}

func (c *Client) startHeartbeat() {
	c.mu.Lock()
	if c.heartbeatCancel != nil {
		c.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.heartbeatCtx = ctx
	c.heartbeatCancel = cancel
	mode := c.heartbeatMode
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
				var err error
				if mode == "server" {
					err = c.serverHeartbeat()
				} else {
					err = c.localHeartbeat()
				}
				if err != nil {
					if c.onFailure != nil {
						c.onFailure(err.Error())
					}
					return
				}
			}
		}
	}()
}

func (c *Client) serverHeartbeat() error {
	c.mu.Lock()
	sessionToken := c.sessionToken
	c.mu.Unlock()

	if strings.TrimSpace(sessionToken) == "" {
		return fmt.Errorf("authforge: missing session token")
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

	response, err := c.postJSON("/auth/heartbeat", body, true)
	if err != nil {
		return err
	}

	_, err = c.applySignedResponse(response, nonce, "", true, false, "heartbeat")
	return err
}

func (c *Client) localHeartbeat() error {
	c.mu.Lock()
	payload := c.rawPayloadB64
	signature := c.signature
	expiresIn := c.sessionExpiresIn
	c.mu.Unlock()

	if payload == "" || signature == "" {
		return fmt.Errorf("authforge: missing local verification state")
	}

	if !verifySignature(payload, signature, c.publicKeys) {
		return ErrSignatureMismatch
	}

	if time.Now().Unix() < expiresIn {
		return nil
	}
	return ErrSessionExpired
}

func (c *Client) applySignedResponse(
	response map[string]interface{},
	expectedNonce string,
	licenseKey string,
	persistSession bool,
	isLogin bool,
	signingContext string,
) (*LoginResult, error) {
	_ = signingContext
	status := response["status"]
	if !isSuccessStatus(status) {
		serverError := valueAsString(response["error"])
		if serverError == "" {
			serverError = "unknown_error"
		}
		return nil, mapServerError(serverError)
	}

	payloadB64 := valueAsString(response["payload"])
	if payloadB64 == "" {
		return nil, fmt.Errorf("authforge: missing payload")
	}

	signature := valueAsString(response["signature"])
	if signature == "" {
		return nil, fmt.Errorf("authforge: missing signature")
	}

	payload, err := decodePayload(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("authforge: invalid payload: %w", err)
	}

	nonce := valueAsString(payload["nonce"])
	if nonce != expectedNonce {
		return nil, fmt.Errorf("authforge: nonce mismatch")
	}

	if !verifySignature(payloadB64, signature, c.publicKeys) {
		return nil, ErrSignatureMismatch
	}

	sessionToken := valueAsString(payload["sessionToken"])
	if sessionToken == "" {
		return nil, fmt.Errorf("authforge: missing session token")
	}

	expiresIn, hasTokenExpiry := extractExpiresFromSessionToken(sessionToken)
	if !hasTokenExpiry {
		value, ok := numberToInt64(payload["expiresIn"])
		if !ok {
			return nil, fmt.Errorf("authforge: missing expiresIn")
		}
		expiresIn = value
	}

	appVars := extractVariables(payload["appVariables"])
	licenseVars := extractVariables(payload["licenseVariables"])
	requestID := valueAsString(payload["requestId"])

	if !persistSession {
		return &LoginResult{
			SessionToken:     sessionToken,
			ExpiresIn:        expiresIn,
			AppVariables:     cloneMap(appVars),
			LicenseVariables: cloneMap(licenseVars),
			RequestID:        requestID,
		}, nil
	}

	c.mu.Lock()
	if licenseKey != "" {
		c.licenseKey = licenseKey
	}
	c.sessionToken = sessionToken
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
			time.Sleep(rateRetryDelays[attempt])
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
				time.Sleep(2 * time.Second)
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
			return nil, fmt.Errorf("authforge: request failed: %w", err)
		}

		rawBody, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("authforge: read response failed: %w", err)
		}

		var parsed map[string]interface{}
		if err := json.Unmarshal(rawBody, &parsed); err != nil {
			if response.StatusCode < 200 || response.StatusCode >= 300 {
				return nil, fmt.Errorf("authforge: http error %d", response.StatusCode)
			}
			return nil, fmt.Errorf("authforge: invalid json response: %w", err)
		}

		serverError := extractServerError(parsed)
		if response.StatusCode == 429 || serverError == "rate_limited" {
			lastRateErr = mapServerError("rate_limited")
			continue
		}

		return parsed, nil
	}

	if lastRateErr != nil {
		return nil, lastRateErr
	}
	return nil, ErrRateLimited
}

func mapServerError(serverError string) error {
	switch serverError {
	case "invalid_app":
		return fmt.Errorf("%w: %s", ErrInvalidApp, serverError)
	case "invalid_key":
		return fmt.Errorf("%w: %s", ErrInvalidKey, serverError)
	case "expired":
		return fmt.Errorf("%w: %s", ErrExpired, serverError)
	case "revoked":
		return fmt.Errorf("%w: %s", ErrRevoked, serverError)
	case "hwid_mismatch":
		return fmt.Errorf("%w: %s", ErrHwidMismatch, serverError)
	case "no_credits":
		return fmt.Errorf("%w: %s", ErrNoCredits, serverError)
	case "app_burn_cap_reached":
		return fmt.Errorf("%w: %s", ErrAppBurnCapReached, serverError)
	case "blocked":
		return fmt.Errorf("%w: %s", ErrBlocked, serverError)
	case "rate_limited":
		return fmt.Errorf("%w: %s", ErrRateLimited, serverError)
	case "replay_detected":
		return fmt.Errorf("%w: %s", ErrReplayDetected, serverError)
	case "app_disabled":
		return fmt.Errorf("%w: %s", ErrAppDisabled, serverError)
	case "session_expired":
		return fmt.Errorf("%w: %s", ErrSessionExpired, serverError)
	case "revoke_requires_session":
		return fmt.Errorf("%w: %s", ErrRevokeRequiresSession, serverError)
	case "bad_request":
		return fmt.Errorf("%w: %s", ErrBadRequest, serverError)
	case "server_error", "system_error":
		return fmt.Errorf("%w: %s", ErrServerError, serverError)
	default:
		return fmt.Errorf("authforge: %s", serverError)
	}
}

func extractServerError(response map[string]interface{}) string {
	errorCode := strings.ToLower(valueAsString(response["error"]))
	switch errorCode {
	case "invalid_app", "invalid_key", "expired", "revoked", "hwid_mismatch", "no_credits", "app_burn_cap_reached", "blocked", "rate_limited", "replay_detected", "app_disabled", "session_expired", "revoke_requires_session", "bad_request", "server_error", "system_error":
		return errorCode
	}

	statusCode := strings.ToLower(valueAsString(response["status"]))
	switch statusCode {
	case "invalid_app", "invalid_key", "expired", "revoked", "hwid_mismatch", "no_credits", "app_burn_cap_reached", "blocked", "rate_limited", "replay_detected", "app_disabled", "session_expired", "revoke_requires_session", "bad_request", "server_error", "system_error":
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
