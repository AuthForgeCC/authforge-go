# AuthForge SDK: AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app activates (validates) a license key online: it sends the key + hardware ID to `POST /auth/validate`, and the server checks revocation, expiry, HWID slots, and credits, then returns an Ed25519-signed session with a TTL.

After activation there are two policies:

- **Grace period (the default).** The app keeps running on the signed session without contacting AuthForge. The SDK re-verifies the signed session locally in the background and fails when the session TTL expires. The grace period equals the session TTL: default 24h, server clamps requested values to 1h to 7d (set with `SessionTTL`). No network traffic after activation.
- **Online check-ins (opt-in, `OnlineHeartbeat: true`).** The SDK periodically calls `POST /auth/heartbeat` for fast revocation and concurrent-use detection. A revoked license fails on the very next check-in, and each successful check-in refreshes the session.

When a background check fails (revocation on a check-in, or the grace period ending), `OnFailure` is invoked and you handle it (typically exit the app).

## Billing model (so you can pick sensible settings)

- **1 activation = 1 credit** (`Login` or `ValidateLicense` call).
- **10 online check-ins = 1 credit** (billed on every 10th successful check-in, per license). The grace period costs nothing after activation.
- Keep `HeartbeatInterval` at `>= 10s` (`15m` is the common desktop default). `/auth/heartbeat` is limited to 6 requests/minute per license key; billing still scales with check-in count.
- With online check-ins, revocation takes effect on the **very next check-in** regardless of interval. With the grace period only, a revocation takes effect at the next online activation.

## Installation

Use **`go get github.com/AuthForgeCC/authforge-go@<tag>`** with a published semver tag (for example `@v1.0.2`). For a local checkout or vendored sources, use a `replace` directive or copy the `.go` files as described in the repository README.

## Minimal working integration

This activates online once, then runs through the grace period (no further network calls). Add `OnlineHeartbeat: true` to enable online check-ins.

```go
package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/AuthForgeCC/authforge-go"
)

func main() {
	client, err := authforge.New(authforge.Config{
		AppID:     "YOUR_APP_ID",
		AppSecret: "YOUR_APP_SECRET",
		PublicKey: "YOUR_PUBLIC_KEY", // required: base64 Ed25519 key from the dashboard
		OnFailure: func(msg string) {
			fmt.Fprintf(os.Stderr, "AuthForge: %s\n", msg)
			os.Exit(1)
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	fmt.Print("Enter license key: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		fmt.Fprintf(os.Stderr, "input: %v\n", err)
		os.Exit(1)
	}
	licenseKey := strings.TrimSpace(line)

	result, err := client.Login(licenseKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Authenticated; expiresIn=%d\n", result.ExpiresIn)

	// --- Your application code starts here ---
	fmt.Println("Running with a valid license.")
	// --- Your application code ends here ---

	client.Logout()
}
```

## Constructor parameters (`Config`)

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| `AppID` | `string` | yes | (none) | Application ID |
| `AppSecret` | `string` | yes | (none) | Application secret |
| `PublicKey` | `string` | yes* | (none) | Base64 Ed25519 public key from the dashboard. Accepts a comma-separated trust list. *Required unless `PublicKeys` is set |
| `PublicKeys` | `[]string` | no | `nil` | Rotation set; when non-empty it takes precedence over `PublicKey`. The SDK trusts a signature matching **any** entry |
| `OnlineHeartbeat` | `bool` | no | `false` | `true` enables online check-ins (periodic `POST /auth/heartbeat`). `false` means grace period only |
| `HeartbeatMode` | `string` | no | `""` | Deprecated (see migration section). Empty is valid and means the default grace period behavior; `"server"` maps to `OnlineHeartbeat: true`; `"local"` maps to the default. Case-insensitive |
| `HeartbeatInterval` | `time.Duration` | no | `15m` | Interval between background checks (minimum `10s`) |
| `APIBaseURL` | `string` | no | `https://auth.authforge.cc` | API base URL |
| `OnFailure` | `func(error string)` | no | `nil` | Background check failures; `Login` network failures after retry. Not invoked by `ValidateLicense` |
| `RequestTimeout` | `time.Duration` | no | `15s` | Per-request HTTP timeout |
| `SessionTTL` | `time.Duration` | no | `0` (server default: 24h) | The grace period duration: requested session token lifetime. Server clamps to `[1h, 7d]`; out-of-range values are silently clamped. Online check-ins refresh the token while preserving this lifetime. |
| `HWIDOverride` | `string` | no | `""` | Optional custom HWID/subject string. When non-empty (for example `tg:123456789`), the SDK sends it instead of generating a machine fingerprint. |

For Telegram/Discord bot flows, prefer immutable IDs (`tg:<user_id>`, `discord:<user_id>`) instead of usernames.

## Migrating from HeartbeatMode

`HeartbeatMode` is deprecated but still works; no wire-protocol change is involved.

- `HeartbeatMode: "local"` maps to the default grace period behavior: remove the field.
- `HeartbeatMode: "server"` maps to online check-ins: replace it with `OnlineHeartbeat: true`.
- Empty `HeartbeatMode` is valid and means the default grace period behavior.
- Any other value makes `New` return an error.

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `New(Config)` | `(*Client, error)` | Validates config, constructs client |
| `Login(licenseKey string)` | `(*LoginResult, error)` | Activates the license online and starts the background check loop |
| `ValidateLicense(licenseKey string)` | `(*LoginResult, error)` | Same validate + signatures as `Login`; no session persistence or background checks; does not call `OnFailure` |
| `Logout()` | (none) | Stops background checks and clears state |
| `IsAuthenticated()` | `bool` | Whether authenticated |
| `GetSessionData()` / `SessionData()` | `map[string]interface{}` | Payload map |
| `GetAppVariables()` / `AppVariables()` | `map[string]interface{}` | App variables |
| `GetLicenseVariables()` / `LicenseVariables()` | `map[string]interface{}` | License variables |

## Error codes the server can return

Full set: invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, app_burn_cap_reached, blocked, rate_limited, replay_detected, app_disabled, session_expired, revoke_requires_session, bad_request, malformed_request, system_error

These map to the exported sentinel errors (`ErrInvalidApp`, `ErrInvalidKey`, `ErrAppBurnCapReached`, `ErrRevokeRequiresSession`, `ErrServerError`, and so on); use `errors.Is` to match them. `bad_request`/`malformed_request` both map to `ErrBadRequest`, and `system_error`/`server_error` both map to `ErrServerError`.

Notes:
- `replay_detected` is validate-only. `rate_limited` can be returned by `/auth/validate` and `/auth/heartbeat` (heartbeat is license-limited at 6/min and has no app-layer IP limit).
- When the grace period ends, the background check reports `ErrSessionExpired` through `OnFailure`.

## Common patterns

### Reading license variables (feature gating)

```go
vars := client.GetLicenseVariables()
if tier, ok := vars["tier"]; ok {
	_ = tier
}
```

### Graceful shutdown

```go
client.Logout()
```

### Custom error handling

Use `errors.Is` with `authforge.ErrInvalidKey`, `authforge.ErrExpired`, etc. on `Login` errors. `OnFailure` receives background check error strings (and `network_error` on some transport failures).

## Do NOT

- Do not hardcode the app secret as a plain string literal in source: use environment variables or encrypted config
- Do not skip `OnFailure`: it is invoked when a background check fails (revocation on an online check-in, or the grace period ending)
- Do not call `Login` on every app action: call once at startup; the grace period or online check-ins handle the rest
- Do not set the deprecated `HeartbeatMode` in new code: leave it empty for the default grace period, or set `OnlineHeartbeat: true` for online check-ins
