# AuthForge SDK — AI Agent Reference

> This file is optimized for AI coding agents (Cursor, Copilot, Claude Code, etc.).
> It contains everything needed to correctly integrate AuthForge licensing into a project.

## What AuthForge does

AuthForge is a license key validation service. Your app sends a license key + hardware ID to the AuthForge API, gets back a cryptographically signed response, and runs background heartbeats to maintain the session. If the license is revoked or expired, the heartbeat fails and you handle it (typically exit the app).

## Installation

The module is not available via remote `go get` yet. Clone or copy this repository, then use a `replace` directive in your app’s `go.mod` pointing at the local SDK folder (see README), or vendor the `.go` files into your module.

## Minimal working integration

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
		AppID:         "YOUR_APP_ID",
		AppSecret:     "YOUR_APP_SECRET",
		HeartbeatMode: "server",
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
| `AppID` | `string` | yes | — | Application ID |
| `AppSecret` | `string` | yes | — | Application secret |
| `HeartbeatMode` | `string` | yes | — | `"server"` or `"local"` (case-insensitive) |
| `HeartbeatInterval` | `time.Duration` | no | `15m` | Interval between heartbeats |
| `APIBaseURL` | `string` | no | `https://auth.authforge.cc` | API base URL |
| `OnFailure` | `func(error string)` | no | `nil` | Background heartbeat failures; login errors return from `Login` |
| `RequestTimeout` | `time.Duration` | no | `15s` | Per-request HTTP timeout |

## Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `New(Config)` | `(*Client, error)` | Validates config, constructs client |
| `Login(licenseKey string)` | `(*LoginResult, error)` | Validates license and starts heartbeat |
| `Logout()` | — | Stops heartbeat and clears state |
| `IsAuthenticated()` | `bool` | Whether authenticated |
| `GetSessionData()` / `SessionData()` | `map[string]interface{}` | Payload map |
| `GetAppVariables()` / `AppVariables()` | `map[string]interface{}` | App variables |
| `GetLicenseVariables()` / `LicenseVariables()` | `map[string]interface{}` | License variables |

## Error codes the server can return

invalid_app, invalid_key, expired, revoked, hwid_mismatch, no_credits, blocked, rate_limited, replay_detected, checksum_required, checksum_mismatch, session_expired, app_disabled

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

Use `errors.Is` with `authforge.ErrInvalidKey`, `authforge.ErrExpired`, etc. on `Login` errors. `OnFailure` receives heartbeat error strings (and `network_error` on some transport failures).

## Do NOT

- Do not hardcode the app secret as a plain string literal in source — use environment variables or encrypted config
- Do not skip `OnFailure` when you rely on heartbeats — it is invoked on heartbeat failure
- Do not call `Login` on every app action — call once at startup; heartbeats handle the rest
- Do not use `HeartbeatMode: "local"` unless the app has no internet after initial auth
