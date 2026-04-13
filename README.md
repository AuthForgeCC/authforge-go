# AuthForge Go SDK

Official Go SDK for [AuthForge](https://authforge.cc) with HMAC-verified license validation and background heartbeats.

**Zero external dependencies.** Uses only the Go standard library.

## Installation

```bash
go get github.com/AuthForgeCC/authforge-go
```

## Quick start

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
| `HeartbeatMode` | `string` | required | `"server"` or `"local"` |
| `HeartbeatInterval` | `time.Duration` | `15 * time.Minute` | Interval between heartbeat checks |
| `APIBaseURL` | `string` | `https://auth.authforge.cc` | API base URL override |
| `OnFailure` | `func(error string)` | `nil` | Called when background heartbeat fails |
| `RequestTimeout` | `time.Duration` | `15 * time.Second` | HTTP timeout per request |

## Methods

| Method | Returns | Description |
|---|---|---|
| `Login(licenseKey string)` | `(*LoginResult, error)` | Validates key and stores signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
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
    case errors.Is(err, authforge.ErrBadRequest):
        // malformed request
    case errors.Is(err, authforge.ErrChecksumRequired):
        // checksum required by server
    case errors.Is(err, authforge.ErrChecksumMismatch):
        // checksum mismatch
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

## License

MIT
