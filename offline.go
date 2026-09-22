package authforge

// Offline license files (`.authforge`).
//
// A cloud-minted, Ed25519-signed document for machines that never phone home.
// This is a SEPARATE mode from the grace period: the grace period continues a
// signed session after one online activation, while an offline file is
// verified locally with only the app public key and the machine HWID. Nothing
// in this file performs network I/O or starts online check-ins.
//
// Format (version 1):
//
//	-----BEGIN AUTHFORGE LICENSE-----
//	Version: 1
//	App-Id: <appId>
//	License: <licenseKey>
//	Key-Id: <kid>
//	Expires-At: <ISO-8601 | never>
//
//	<base64 JSON payload, wrapped at 64 columns>
//	-----END AUTHFORGE LICENSE-----
//	-----BEGIN AUTHFORGE SIGNATURE-----
//	<base64 Ed25519 signature>
//	-----END AUTHFORGE SIGNATURE-----
//
// Signed bytes: the UTF-8 bytes of the base64 payload string (body lines
// joined, whitespace removed) - the same contract as /auth/validate.

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// OfflineLicenseFileVersion is the only `.authforge` format version this SDK accepts.
const OfflineLicenseFileVersion = 1

const (
	offlineBeginLicense   = "-----BEGIN AUTHFORGE LICENSE-----"
	offlineEndLicense     = "-----END AUTHFORGE LICENSE-----"
	offlineBeginSignature = "-----BEGIN AUTHFORGE SIGNATURE-----"
	offlineEndSignature   = "-----END AUTHFORGE SIGNATURE-----"
)

var (
	offlineBase64Re     = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	offlineWhitespaceRe = regexp.MustCompile(`\s+`)
)

// Offline license file errors. Compare with errors.Is. Check order is fixed
// across every SDK: bad armor -> bad signature -> unsupported version ->
// malformed payload -> wrong app -> expired -> HWID mismatch.
var (
	ErrOfflineBadArmor           = errors.New("authforge: offline license file: bad armor")
	ErrOfflineBadSignature       = errors.New("authforge: offline license file: bad signature")
	ErrOfflineUnsupportedVersion = errors.New("authforge: offline license file: unsupported version")
	ErrOfflineMalformedPayload   = errors.New("authforge: offline license file: malformed payload")
	ErrOfflineWrongApp           = errors.New("authforge: offline license file: wrong app")
	ErrOfflineExpired            = errors.New("authforge: offline license file: expired")
	ErrOfflineHwidMismatch       = errors.New("authforge: offline license file: HWID mismatch")
)

// OfflineErrorCode returns the cross-SDK error code ("bad_armor",
// "bad_signature", "unsupported_version", "malformed_payload", "wrong_app",
// "expired", "hwid_mismatch") for an offline verification error, or "" when
// err is not one of the ErrOffline* sentinels.
func OfflineErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrOfflineBadArmor):
		return "bad_armor"
	case errors.Is(err, ErrOfflineBadSignature):
		return "bad_signature"
	case errors.Is(err, ErrOfflineUnsupportedVersion):
		return "unsupported_version"
	case errors.Is(err, ErrOfflineMalformedPayload):
		return "malformed_payload"
	case errors.Is(err, ErrOfflineWrongApp):
		return "wrong_app"
	case errors.Is(err, ErrOfflineExpired):
		return "expired"
	case errors.Is(err, ErrOfflineHwidMismatch):
		return "hwid_mismatch"
	default:
		return ""
	}
}

// OfflineHwidPolicy is the HWID binding policy embedded in a file.
// Mode is "bound" (verify only when the local HWID is in Hwids) or "any".
type OfflineHwidPolicy struct {
	Mode  string   `json:"mode"`
	Hwids []string `json:"hwids,omitempty"`
}

// OfflineLicense is the verified content of a `.authforge` file.
type OfflineLicense struct {
	AppID      string `json:"appId"`
	LicenseKey string `json:"licenseKey"`
	// JTI uniquely identifies this minted file.
	JTI string `json:"jti"`
	// KeyID is the app signing key id that signed the file.
	KeyID    string `json:"kid"`
	IssuedAt string `json:"issuedAt"`
	// ExpiresAt is nil for a lifetime file.
	ExpiresAt        *string                `json:"expiresAt"`
	HwidPolicy       OfflineHwidPolicy      `json:"hwid"`
	Label            *string                `json:"label,omitempty"`
	LicenseExpiresAt *string                `json:"licenseExpiresAt,omitempty"`
	LicenseVariables map[string]interface{} `json:"licenseVariables,omitempty"`
	AppVariables     map[string]interface{} `json:"appVariables,omitempty"`
	// Payload is the full decoded payload (unknown fields preserved).
	Payload map[string]interface{} `json:"-"`
	// PayloadBase64 / SignatureBase64 are the canonical signed string and its signature.
	PayloadBase64   string `json:"-"`
	SignatureBase64 string `json:"-"`
}

// ParsedLicenseFile is the raw armor split into its parts.
type ParsedLicenseFile struct {
	Headers         map[string]string
	PayloadBase64   string
	SignatureBase64 string
}

// ParseLicenseFile splits armored `.authforge` text into headers, the
// canonical base64 payload string and the base64 signature. It tolerates
// CRLF, a UTF-8 BOM, arbitrary re-wrapping of the base64 body and text
// before/after the armor. Returns ErrOfflineBadArmor for anything else.
func ParseLicenseFile(text string) (*ParsedLicenseFile, error) {
	normalized := strings.TrimPrefix(text, "\uFEFF")
	normalized = strings.ReplaceAll(normalized, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	lines := strings.Split(normalized, "\n")

	find := func(marker string, start int) int {
		for i := start; i < len(lines); i++ {
			if strings.TrimSpace(lines[i]) == marker {
				return i
			}
		}
		return -1
	}

	beginIdx := find(offlineBeginLicense, 0)
	if beginIdx == -1 {
		return nil, ErrOfflineBadArmor
	}
	endIdx := find(offlineEndLicense, beginIdx+1)
	if endIdx == -1 {
		return nil, ErrOfflineBadArmor
	}
	sigBeginIdx := find(offlineBeginSignature, endIdx+1)
	if sigBeginIdx == -1 {
		return nil, ErrOfflineBadArmor
	}
	sigEndIdx := find(offlineEndSignature, sigBeginIdx+1)
	if sigEndIdx == -1 {
		return nil, ErrOfflineBadArmor
	}

	block := lines[beginIdx+1 : endIdx]
	blankIdx := -1
	for i, line := range block {
		if strings.TrimSpace(line) == "" {
			blankIdx = i
			break
		}
	}
	if blankIdx == -1 {
		return nil, ErrOfflineBadArmor
	}

	headers := make(map[string]string, blankIdx)
	for _, raw := range block[:blankIdx] {
		line := strings.TrimSpace(raw)
		colon := strings.Index(line, ":")
		if colon <= 0 {
			return nil, ErrOfflineBadArmor
		}
		headers[strings.TrimSpace(line[:colon])] = strings.TrimSpace(line[colon+1:])
	}

	payloadBase64 := offlineWhitespaceRe.ReplaceAllString(strings.Join(block[blankIdx+1:], ""), "")
	signatureBase64 := offlineWhitespaceRe.ReplaceAllString(strings.Join(lines[sigBeginIdx+1:sigEndIdx], ""), "")
	if payloadBase64 == "" || !offlineBase64Re.MatchString(payloadBase64) {
		return nil, ErrOfflineBadArmor
	}
	if signatureBase64 == "" || !offlineBase64Re.MatchString(signatureBase64) {
		return nil, ErrOfflineBadArmor
	}
	return &ParsedLicenseFile{Headers: headers, PayloadBase64: payloadBase64, SignatureBase64: signatureBase64}, nil
}

// VerifyLicenseFileOptions configures VerifyLicenseFile.
type VerifyLicenseFileOptions struct {
	// AppID must equal the payload appId.
	AppID string
	// PublicKey / PublicKeys: trusted raw-32-byte Ed25519 keys, standard
	// base64 (same forms as Config). A signature matching any key is accepted.
	PublicKey  string
	PublicKeys []string
	// HWID is the local machine id; required for mode:"bound" files.
	HWID string
	// Now overrides the clock (tests). Zero means time.Now().
	Now time.Time
}

// VerifyLicenseFile verifies armored `.authforge` text with NO network
// access. The signature is checked before the payload JSON is decoded so a
// forged file never reaches the parser.
func VerifyLicenseFile(file string, opts VerifyLicenseFileOptions) (*OfflineLicense, error) {
	parsed, err := ParseLicenseFile(file)
	if err != nil {
		return nil, err
	}

	keyStrings := collectPublicKeyStrings(Config{PublicKey: opts.PublicKey, PublicKeys: opts.PublicKeys})
	keys := make([][]byte, 0, len(keyStrings))
	for _, raw := range keyStrings {
		decoded, decodeErr := base64.StdEncoding.DecodeString(raw)
		if decodeErr != nil || len(decoded) != 32 {
			continue
		}
		keys = append(keys, decoded)
	}
	if len(keys) == 0 || !verifySignature(parsed.PayloadBase64, parsed.SignatureBase64, keys) {
		return nil, ErrOfflineBadSignature
	}

	decoded, err := base64.StdEncoding.DecodeString(parsed.PayloadBase64)
	if err != nil {
		return nil, ErrOfflineMalformedPayload
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(decoded, &raw); err != nil || raw == nil {
		return nil, ErrOfflineMalformedPayload
	}
	if version, ok := numberToInt64(raw["v"]); !ok || version != OfflineLicenseFileVersion {
		return nil, fmt.Errorf("%w: v=%v", ErrOfflineUnsupportedVersion, raw["v"])
	}

	var lic OfflineLicense
	if err := json.Unmarshal(decoded, &lic); err != nil {
		return nil, ErrOfflineMalformedPayload
	}
	if typ, _ := raw["typ"].(string); typ != "authforge-license" {
		return nil, ErrOfflineMalformedPayload
	}
	if lic.AppID == "" || lic.LicenseKey == "" || lic.JTI == "" || lic.KeyID == "" || lic.IssuedAt == "" {
		return nil, ErrOfflineMalformedPayload
	}
	if _, present := raw["expiresAt"]; !present {
		return nil, ErrOfflineMalformedPayload
	}
	if lic.ExpiresAt != nil && *lic.ExpiresAt == "" {
		return nil, ErrOfflineMalformedPayload
	}
	switch lic.HwidPolicy.Mode {
	case "bound":
		if len(lic.HwidPolicy.Hwids) == 0 {
			return nil, ErrOfflineMalformedPayload
		}
		for _, h := range lic.HwidPolicy.Hwids {
			if h == "" {
				return nil, ErrOfflineMalformedPayload
			}
		}
	case "any":
		lic.HwidPolicy.Hwids = nil
	default:
		return nil, ErrOfflineMalformedPayload
	}

	if lic.AppID != strings.TrimSpace(opts.AppID) {
		return nil, ErrOfflineWrongApp
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	if lic.ExpiresAt != nil {
		exp, parseErr := time.Parse(time.RFC3339Nano, *lic.ExpiresAt)
		if parseErr != nil || !exp.After(now) {
			return nil, ErrOfflineExpired
		}
	}

	if lic.HwidPolicy.Mode == "bound" {
		local := strings.TrimSpace(opts.HWID)
		matched := false
		for _, h := range lic.HwidPolicy.Hwids {
			if local != "" && h == local {
				matched = true
				break
			}
		}
		if !matched {
			return nil, ErrOfflineHwidMismatch
		}
	}

	lic.Payload = raw
	lic.PayloadBase64 = parsed.PayloadBase64
	lic.SignatureBase64 = parsed.SignatureBase64
	return &lic, nil
}

// HWID returns the hardware id this client sends to AuthForge (or the
// configured HWIDOverride). Customers on air-gapped machines report this
// value to the operator so an offline `.authforge` file can be bound to it.
func (c *Client) HWID() string {
	return c.hwid
}

// VerifyLicenseFile verifies a `.authforge` file (filesystem path or armored
// text) with this client's app id, public key(s) and HWID, without touching
// session state.
func (c *Client) VerifyLicenseFile(pathOrText string) (*OfflineLicense, error) {
	text, err := readLicenseFileInput(pathOrText)
	if err != nil {
		return nil, err
	}
	return c.verifyLicenseFileText(text, time.Time{})
}

// LoginFromFile authorizes from a cloud-minted offline license file
// (`.authforge`) with NO network access. Accepts a filesystem path or the
// armored text itself.
//
// On success the client is authenticated (IsAuthenticated, SessionData,
// AppVariables, LicenseVariables work) and OfflineLicense() describes the
// file. No grace-period goroutine and no online check-ins are started - the
// file's own expiry is the only clock. Online Login is untouched.
//
// Failures are returned (compare with errors.Is against the ErrOffline*
// sentinels) and also reported through Config.OnFailure with the code from
// OfflineErrorCode.
func (c *Client) LoginFromFile(pathOrText string) (*OfflineLicense, error) {
	text, err := readLicenseFileInput(pathOrText)
	if err != nil {
		c.notifyFailure("offline_login_failed: " + err.Error())
		return nil, err
	}
	lic, err := c.verifyLicenseFileText(text, time.Time{})
	if err != nil {
		code := OfflineErrorCode(err)
		if code == "" {
			code = err.Error()
		}
		c.notifyFailure("offline_login_failed: " + code)
		return nil, err
	}
	c.applyOfflineLicense(lic)
	return lic, nil
}

// OfflineLicense returns the offline file the client authenticated with, or nil.
func (c *Client) OfflineLicense() *OfflineLicense {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.offlineLicense == nil {
		return nil
	}
	copied := *c.offlineLicense
	copied.Payload = cloneMap(c.offlineLicense.Payload)
	return &copied
}

func (c *Client) verifyLicenseFileText(text string, now time.Time) (*OfflineLicense, error) {
	keys := make([]string, 0, len(c.publicKeys))
	for _, key := range c.publicKeys {
		keys = append(keys, base64.StdEncoding.EncodeToString(key))
	}
	return VerifyLicenseFile(text, VerifyLicenseFileOptions{
		AppID:      c.appID,
		PublicKeys: keys,
		HWID:       c.hwid,
		Now:        now,
	})
}

func (c *Client) applyOfflineLicense(lic *OfflineLicense) {
	// Stop any online session first so the two modes never overlap.
	c.Logout()

	var expiresIn int64
	if lic.ExpiresAt != nil {
		if exp, err := time.Parse(time.RFC3339Nano, *lic.ExpiresAt); err == nil {
			expiresIn = exp.Unix()
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.licenseKey = lic.LicenseKey
	// Offline files carry no server session token. The explicit session kind
	// (not a token sentinel) is what makes IsAuthenticated true and keeps
	// SelfBan/heartbeats from ever contacting the server for this session.
	c.sessionToken = ""
	c.sessionKind = SessionKindOffline
	c.sessionExpiresIn = expiresIn
	c.rawPayloadB64 = lic.PayloadBase64
	c.signature = lic.SignatureBase64
	c.sessionData = cloneMap(lic.Payload)
	c.appVariables = cloneMap(lic.AppVariables)
	c.licenseVariables = cloneMap(lic.LicenseVariables)
	c.offlineLicense = lic
	c.authenticated = true
}

func (c *Client) notifyFailure(message string) {
	if c.onFailure != nil {
		c.onFailure(message)
	}
}

func readLicenseFileInput(pathOrText string) (string, error) {
	if strings.TrimSpace(pathOrText) == "" {
		return "", fmt.Errorf("authforge: license file must be a path or the armored text")
	}
	if strings.Contains(pathOrText, offlineBeginLicense) {
		return pathOrText, nil
	}
	data, err := os.ReadFile(pathOrText)
	if err != nil {
		return "", fmt.Errorf("authforge: read license file: %w", err)
	}
	return string(data), nil
}

// ---------------------------------------------------------------------------
// Activation requests (`.authforge-request`)
//
// Unsigned transport for a HWID so the operator can mint a bound `.authforge`
// file without the customer pasting a raw string. Distinct markers from
// BEGIN AUTHFORGE LICENSE. Not signed; the Checksum header is the only
// integrity check. Keep activationRequestSDKTag in sync with the release tag.
// ---------------------------------------------------------------------------

const (
	activationRequestVersion = 1
	activationRequestTyp     = "authforge-activation-request"
	beginActivationRequest   = "-----BEGIN AUTHFORGE ACTIVATION REQUEST-----"
	endActivationRequest     = "-----END AUTHFORGE ACTIVATION REQUEST-----"
	activationRequestSDKTag  = "go/1.4.0"
	armorLineWidth           = 64
	maxRequestHWID           = 256
	maxRequestMachineName    = 128
	maxRequestOS             = 64
	maxRequestSDK            = 64
	maxRequestLicenseKey     = 64
)

// ActivationRequestOptions controls optional fields on CreateActivationRequest.
// MachineName is omitted unless IncludeMachineName is true.
type ActivationRequestOptions struct {
	IncludeMachineName bool
	MachineName        string
	OS                 string
	OmitOS             bool
	SDK                string
	OmitSDK            bool
	LicenseKey         string
	CreatedAt          string
}

func clipRequestField(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func jsonEscapeRequest(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				b.WriteString(fmt.Sprintf(`\u00%02x`, r))
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
	return b.String()
}

func wrapArmor64(value string) string {
	var lines []string
	for i := 0; i < len(value); i += armorLineWidth {
		end := i + armorLineWidth
		if end > len(value) {
			end = len(value)
		}
		lines = append(lines, value[i:end])
	}
	return strings.Join(lines, "\n")
}

func detectOSLabel() string {
	switch runtime.GOOS {
	case "windows":
		return clipRequestField("Windows", maxRequestOS)
	case "darwin":
		return clipRequestField("macOS", maxRequestOS)
	case "linux":
		return clipRequestField("Linux", maxRequestOS)
	default:
		return clipRequestField(runtime.GOOS, maxRequestOS)
	}
}

func canonicalActivationRequestJSON(appID, hwid, createdAt, machineName, osName, sdk, licenseKey string) string {
	parts := []string{
		fmt.Sprintf(`"v":%d`, activationRequestVersion),
		`"typ":` + jsonEscapeRequest(activationRequestTyp),
		`"appId":` + jsonEscapeRequest(appID),
		`"hwid":` + jsonEscapeRequest(clipRequestField(hwid, maxRequestHWID)),
		`"createdAt":` + jsonEscapeRequest(createdAt),
	}
	if machineName != "" {
		parts = append(parts, `"machineName":`+jsonEscapeRequest(clipRequestField(machineName, maxRequestMachineName)))
	}
	if osName != "" {
		parts = append(parts, `"os":`+jsonEscapeRequest(clipRequestField(osName, maxRequestOS)))
	}
	if sdk != "" {
		parts = append(parts, `"sdk":`+jsonEscapeRequest(clipRequestField(sdk, maxRequestSDK)))
	}
	if licenseKey != "" {
		parts = append(parts, `"licenseKey":`+jsonEscapeRequest(clipRequestField(licenseKey, maxRequestLicenseKey)))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// FormatActivationRequest builds armored `.authforge-request` text from explicit fields.
func FormatActivationRequest(appID, hwid, createdAt, machineName, osName, sdk, licenseKey string) string {
	jsonBody := canonicalActivationRequestJSON(appID, hwid, createdAt, machineName, osName, sdk, licenseKey)
	payloadB64 := base64.StdEncoding.EncodeToString([]byte(jsonBody))
	sum := sha256.Sum256([]byte(payloadB64))
	checksum := fmt.Sprintf("%x", sum)[:16]
	clean := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(appID, "\r", " "), "\n", " "))
	return strings.Join([]string{
		beginActivationRequest,
		fmt.Sprintf("Version: %d", activationRequestVersion),
		"App-Id: " + clean,
		"Checksum: " + checksum,
		"",
		wrapArmor64(payloadB64),
		endActivationRequest,
		"",
	}, "\n")
}

// CreateActivationRequest builds an activation request for this machine.
// No network, no session, no app secret. machineName is omitted unless
// opts.IncludeMachineName is true.
func (c *Client) CreateActivationRequest(opts ActivationRequestOptions) string {
	createdAt := opts.CreatedAt
	if createdAt == "" {
		createdAt = time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z"
	}
	var machineName string
	if opts.IncludeMachineName {
		machineName = opts.MachineName
		if machineName == "" {
			machineName, _ = os.Hostname()
		}
	}
	osName := ""
	if !opts.OmitOS {
		if opts.OS != "" {
			osName = opts.OS
		} else {
			osName = detectOSLabel()
		}
	}
	sdk := ""
	if !opts.OmitSDK {
		if opts.SDK != "" {
			sdk = opts.SDK
		} else {
			sdk = activationRequestSDKTag
		}
	}
	licenseKey := opts.LicenseKey
	if licenseKey == "" {
		c.mu.Lock()
		licenseKey = c.licenseKey
		c.mu.Unlock()
	}
	return FormatActivationRequest(c.appID, c.hwid, createdAt, machineName, osName, sdk, licenseKey)
}
