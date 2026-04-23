# AuthForge Go SDK

Official Go SDK for [AuthForge](https://authforge.cc) with Ed25519-verified license validation and background heartbeats.

**Zero external dependencies.** Uses only the Go standard library.

## Installation

The module is **`github.com/AuthForgeCC/authforge-go`**. With a released version tag on GitHub, add it like any other public module:

```bash
go get github.com/AuthForgeCC/authforge-go@v1.0.2
```

Pin a **`v1.x.y` tag you have pushed** (for example **`@v1.0.2`**). Without an `@` suffix, `go get` resolves **`@latest`** once the proxy has indexed the tag.

### Local module with `replace` (forks, air-gapped builds, or hacking on the SDK)

1. Clone this repository somewhere on your machine (for example next to your application).
2. In your applicationâ€™s `go.mod`, require the module path and add a `replace` to your local checkout:

```go
module example.com/myapp

go 1.21

require github.com/AuthForgeCC/authforge-go v0.0.0

replace github.com/AuthForgeCC/authforge-go => ../path/to/authforge-go
```

Adjust `../path/to/authforge-go` to the real path, then run `go mod tidy`.

### Copy source into your project

You can vendor `authforge.go`, `hwid.go`, `crypto.go`, and related files into your tree (for example under `internal/authforge/`) and adjust import paths if you change the module path. Prefer `go get` when possible.

## Quick start

The quick start below assumes `go get` (or a `replace` pointing at a local clone) is configured as in **Installation**.

```go
package main

import (
	"fmt"
	"os"

	"github.com/AuthForgeCC/authforge-go"
)

func main() {
	client, err := authforge.New(authforge.Config{
		AppID:         "YOUR_APP_ID",
		AppSecret:     "YOUR_APP_SECRET",
		PublicKey:     "YOUR_PUBLIC_KEY",
		HeartbeatMode: "server",
		OnFailure: func(errMsg string) {
			fmt.Fprintf(os.Stderr, "Auth failed: %s\n", errMsg)
			os.Exit(1)
		},
	})
	if err != nil {
		panic(err)
	}

	result, err := client.Login("XXXX-XXXX-XXXX-XXXX")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Authenticated! Expires: %d\n", result.ExpiresIn)
	select {}
}
```

## Config

| Field | Type | Default | Description |
|---|---|---|---|
| `AppID` | `string` | required | App ID from dashboard |
| `AppSecret` | `string` | required | App secret from dashboard |
| `PublicKey` | `string` | required | App Ed25519 public key (base64) from dashboard |
| `HeartbeatMode` | `string` | required | `"server"` or `"local"` |
| `HeartbeatInterval` | `time.Duration` | `15 * time.Minute` | Interval between heartbeat checks. Any interval from `1 * time.Second` up is supported; pick based on how fast you want revocations to propagate. |
| `APIBaseURL` | `string` | `https://auth.authforge.cc` | API base URL override |
| `OnFailure` | `func(error string)` | `nil` | Called when background heartbeat fails |
| `RequestTimeout` | `time.Duration` | `15 * time.Second` | HTTP timeout per request |
| `SessionTTL` | `time.Duration` | `0` (server default: 24h) | Requested session token lifetime. Server clamps to `[1h, 7d]`; out-of-range values are silently clamped. Heartbeats refresh the session while preserving the requested TTL. |
| `HWIDOverride` | `string` | `""` | Optional custom hardware/subject identifier. When non-empty, the SDK sends this value instead of generated device fingerprint data. |

### Identity-based binding example (Telegram/Discord)

```go
client, err := authforge.New(authforge.Config{
    AppID:         "YOUR_APP_ID",
    AppSecret:     "YOUR_APP_SECRET",
    PublicKey:     "YOUR_PUBLIC_KEY",
    HeartbeatMode: "server",
    HWIDOverride:  fmt.Sprintf("tg:%d", telegramUserID), // or fmt.Sprintf("discord:%d", discordUserID)
})
```

## Billing

- **1 `Login` call = 1 credit** (one `/auth/validate` debit).
- **10 heartbeats on the same license = 1 credit** (debited every 10th successful heartbeat).

This means a session-style app running for 6 hours at a 15-minute interval burns ~1 validation + ~24 heartbeats = ~3.4 credits/day. A server app running 24/7 with a 1-minute interval burns ~145 credits/day per license â€” choose your interval based on how quickly you need revocations to take effect (they always land on the **next** heartbeat, regardless of interval).

## Methods

| Method | Returns | Description |
|---|---|---|
| `Login(licenseKey string)` | `(*LoginResult, error)` | Validates key and stores signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `SelfBan(...)` | `(map[string]interface{}, error)` | Requests `/auth/selfban` to blacklist HWID/IP and optionally revoke (session-authenticated only) |
| `Logout()` | `void` | Stops heartbeat and clears all session/auth state |
| `IsAuthenticated()` | `bool` | True when an active authenticated session exists |
| `GetSessionData()` / `SessionData()` | `map[string]interface{}` | Full decoded payload map |
| `GetAppVariables()` / `AppVariables()` | `map[string]interface{}` | App-scoped variables map |
| `GetLicenseVariables()` / `LicenseVariables()` | `map[string]interface{}` | License-scoped variables map |

## Heartbeat modes

- `server`: sends `POST /auth/heartbeat` on every interval.
- `local`: verifies stored signature and expiry timestamp locally without heartbeat network calls; expires with `ErrSessionExpired`.

## Error handling

The SDK returns errors instead of panicking. Common failure cases are exposed as sentinel errors:

```go
if err != nil {
	switch {
	case errors.Is(err, authforge.ErrInvalidApp):
		// app credentials are invalid
	case errors.Is(err, authforge.ErrInvalidKey):
		// license key is invalid
	case errors.Is(err, authforge.ErrExpired):
		// license expired
	case errors.Is(err, authforge.ErrRevoked):
		// license revoked
	case errors.Is(err, authforge.ErrHwidMismatch):
		// HWID slots full
	case errors.Is(err, authforge.ErrNoCredits):
		// account has no credits
	case errors.Is(err, authforge.ErrBlocked):
		// blocked by security rules
	case errors.Is(err, authforge.ErrRateLimited):
		// request was rate limited
	case errors.Is(err, authforge.ErrReplayDetected):
		// nonce replay detected
	case errors.Is(err, authforge.ErrAppDisabled):
		// app disabled
	case errors.Is(err, authforge.ErrSessionExpired):
		// session expired
	case errors.Is(err, authforge.ErrRevokeRequiresSession):
		// attempted pre-session revoke
	case errors.Is(err, authforge.ErrBadRequest):
		// malformed request
	case errors.Is(err, authforge.ErrSignatureMismatch):
		// response signature mismatch
	default:
		// transport or unknown error
	}
}
```

Internal request retries are automatic:
- `rate_limited`: retry after 2s, then 5s (max 3 attempts total)
- network failure: retry once after 2s
- retry attempts always use a fresh nonce

## Self-ban (tamper response)

Use `SelfBan(...)` when anti-tamper checks trigger:

```go
// Post-session (authenticated): defaults are typically all true in caller logic.
_, err = client.SelfBan("", "", true, true, true)

// Pre-session: pass license key, SDK automatically forces revokeLicense=false.
_, err = client.SelfBan("AF-XXXX-XXXX-XXXX", "", true, true, true)

// Explicit flags:
_, err = client.SelfBan("", "", false, true, true)
```

`SelfBan(...)` selects mode automatically:
- Uses post-session mode when a session token is available (`sessionToken` argument or current SDK session).
- Falls back to pre-session mode with `licenseKey` + nonce + app secret.
- In pre-session mode, revoke is always disabled client-side to avoid unsafe key revocations.

## License

MIT
