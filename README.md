# AuthForge Go SDK

Official Go SDK for [AuthForge](https://authforge.cc). Activate a license online with an Ed25519-verified response, then run through the grace period by default (no further network calls), or opt in to online check-ins for fast revocation.

**Zero external dependencies.** Uses only the Go standard library.

## How licensing works

1. **Activate (validate) online.** `Login` calls `POST /auth/validate`. The server checks revocation, expiry, HWID slots, and credits, and returns an Ed25519-signed session with a TTL.
2. **Grace period (the default).** After activation, the app keeps running on the signed session without contacting AuthForge. The SDK periodically re-verifies the signed session locally and fails with `ErrSessionExpired` when the TTL expires. The grace period equals the session TTL: default 24h, and the server clamps requested values to `[1h, 7d]` (set it with `SessionTTL`).
3. **Online check-ins (optional).** Set `OnlineHeartbeat: true` to call `POST /auth/heartbeat` periodically. This gives you fast revocation and concurrent-use detection: a revoked license fails on the very next check-in instead of at the end of the grace period.

Separately, for machines that can **never** reach the internet, an operator can mint a signed **offline license file (`.authforge`)** in the AuthForge dashboard or Developer API. The SDK verifies it locally with your app public key: see [Offline license files](#offline-license-files-authforge).

## Features

Everything in this list ships in `authforge.go`, `crypto.go`, `hwid.go`, and `offline.go` today:

- **License activation** via `POST /auth/validate`, returning a signed `LoginResult`.
- **Ed25519 signature verification** on every `/auth/validate` and `/auth/heartbeat` response; tampered or unsigned responses are rejected.
- **Key rotation**: configure `PublicKey` (single key or comma-separated string) and/or `PublicKeys` (rotation set). The SDK trusts a signature that matches **any** configured key, so you can roll the server-side signing key without breaking deployed clients.
- **Nonce anti-replay**: a fresh 128-bit nonce is sent on every request and the echoed nonce in the signed payload is checked before the response is accepted.
- **HWID fingerprinting**: deterministic device hash from hostname + OS + arch + MAC, with graceful fallback.
- **`HWIDOverride`**: bind to any identity instead of the machine (for example `tg:<id>`, `discord:<id>`).
- **Seat enforcement**: the server binds each HWID into a license's free slots up to `maxHwidSlots`; `HwidCount` / `MaxHwidSlots` are surfaced on `LoginResult`. A shared (unlimited-seat) key skips per-device binding.
- **Grace period by default, online check-ins opt-in** (see [Grace period and online check-ins](#grace-period-and-online-check-ins)).
- **Offline license files (`.authforge`)**: `LoginFromFile` / `VerifyLicenseFile` verify a cloud-minted, Ed25519-signed file with zero network access for air-gapped machines.
- **Self-ban** (`SelfBan(...)`) for anti-tamper response, both pre-session and post-session.
- **Grace period duration** control via `SessionTTL`, with server-side clamping to `[1h, 7d]`.
- **App variables / license variables** for feature flags and tiered licensing.
- **Automatic retries** for rate-limited and transient network failures, with a fresh nonce per retry.
- **Returns errors instead of exiting**: unlike the Python/Node/C#/C++ SDKs, the Go SDK never calls `os.Exit`; `Login`/`ValidateLicense` return errors and background failures are reported through `OnFailure` / `OnHeartbeatFailure`, classified as transient or fatal.

## Installation

The module is **`github.com/AuthForgeCC/authforge-go`**. With a released version tag on GitHub, add it like any other public module:

```bash
go get github.com/AuthForgeCC/authforge-go@v1.4.1
```

Pin a **`v1.x.y` tag you have pushed** (for example **`@v1.4.1`**). Without an `@` suffix, `go get` resolves **`@latest`** once the proxy has indexed the tag.

### Local module with `replace` (forks, air-gapped builds, or hacking on the SDK)

1. Clone this repository somewhere on your machine (for example next to your application).
2. In your application's `go.mod`, require the module path and add a `replace` to your local checkout:

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

The quick start below assumes `go get` (or a `replace` pointing at a local clone) is configured as in **Installation**. It activates online once, then runs through the grace period (no further network calls):

```go
package main

import (
	"fmt"
	"os"

	"github.com/AuthForgeCC/authforge-go"
)

func main() {
	licenseLost := make(chan *authforge.Error, 1)
	client, err := authforge.New(authforge.Config{
		AppID:     "YOUR_APP_ID",
		AppSecret: "YOUR_APP_SECRET",
		PublicKey: "YOUR_PUBLIC_KEY",
		OnHeartbeatFailure: func(err *authforge.Error) {
			if err.IsTransient() {
				return // network blip: the SDK checks in again next interval
			}
			select {
			case licenseLost <- err: // signal main instead of exiting on this goroutine
			default:
			}
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
	lost := <-licenseLost // your app's work runs elsewhere until this fires
	fmt.Fprintf(os.Stderr, "License check failed: %s\n", lost.Code)
	// Save the user's work here, then exit.
	os.Exit(1)
}
```

To enable online check-ins instead, add `OnlineHeartbeat: true` (and optionally tune `HeartbeatInterval`).

## Config

| Field | Type | Default | Description |
|---|---|---|---|
| `AppID` | `string` | required | App ID from dashboard |
| `AppSecret` | `string` | required for online APIs; empty for `LoginFromFile` only | App secret from dashboard. Do not ship it in air-gapped binaries. |
| `PublicKey` | `string` | required* | App Ed25519 public key (base64) from dashboard. Accepts a comma-separated trust list. *Required unless `PublicKeys` is set. |
| `PublicKeys` | `[]string` | optional | Rotation set of trusted Ed25519 public keys. When non-empty, takes precedence over `PublicKey`; the SDK trusts a signature matching **any** entry (see [Key rotation](#key-rotation)). |
| `OnlineHeartbeat` | `bool` | `false` | Enables online check-ins: periodic `POST /auth/heartbeat` for fast revocation and concurrent-use detection. When `false`, the SDK relies on the grace period. |
| `HeartbeatMode` | `string` | `""` | Deprecated, see [Migrating from HeartbeatMode](#migrating-from-heartbeatmode). Empty means the default grace period behavior; `"server"` maps to `OnlineHeartbeat: true`; `"local"` maps to the default. |
| `HeartbeatInterval` | `time.Duration` | `15 * time.Minute` | Interval between background checks (online check-ins or local grace period re-verification). Minimum supported interval is `10 * time.Second`; pick based on how fast you want revocations to propagate. |
| `APIBaseURL` | `string` | `https://auth.authforge.cc` | API base URL override |
| `OnFailure` | `func(error string)` | `nil` | Called when a background check fails (with the error message), unless `OnHeartbeatFailure` is set |
| `OnHeartbeatFailure` | `func(err *authforge.Error)` | `nil` | Receives background check failures instead of `OnFailure`, with `err.Code` and `err.IsTransient()` / `err.IsFatal()`. See [Background check failures](#background-check-failures) |
| `RequestTimeout` | `time.Duration` | `15 * time.Second` | HTTP timeout per request |
| `SessionTTL` | `time.Duration` | `0` (server default: 24h) | The grace period duration: requested session token lifetime. Server clamps to `[1h, 7d]`; out-of-range values are silently clamped. Online check-ins refresh the session while preserving the requested TTL. |
| `HWIDOverride` | `string` | `""` | Optional custom hardware/subject identifier. When non-empty, the SDK sends this value instead of generated device fingerprint data. |

### Identity-based binding example (Telegram/Discord)

```go
client, err := authforge.New(authforge.Config{
    AppID:           "YOUR_APP_ID",
    AppSecret:       "YOUR_APP_SECRET",
    PublicKey:       "YOUR_PUBLIC_KEY",
    OnlineHeartbeat: true,
    HWIDOverride:    fmt.Sprintf("tg:%d", telegramUserID), // or fmt.Sprintf("discord:%d", discordUserID)
})
```

### Key rotation

To rotate the server-side signing key without a flag-day, configure both the
**new** and **previous** keys; the SDK accepts a signature matching any entry:

```go
client, err := authforge.New(authforge.Config{
    AppID:      "YOUR_APP_ID",
    AppSecret:  "YOUR_APP_SECRET",
    PublicKeys: []string{"NEW_PUBLIC_KEY", "PREVIOUS_PUBLIC_KEY"},
})
```

A comma-separated `PublicKey` (`"NEW,PREVIOUS"`) works too, for env-var convenience.

## Grace period and online check-ins

**Grace period (the default).** After one successful online activation, the app keeps running on the signed session without contacting AuthForge. The SDK re-verifies the cached signed payload locally on every `HeartbeatInterval` tick and fails with `ErrSessionExpired` once the session TTL elapses. The grace period equals the session TTL: default 24h, server-clamped to `[1h, 7d]` (set with `SessionTTL`). This is session continuation, not persistent offline licensing: a mid-session revocation only takes effect at the next online activation.

**Online check-ins (`OnlineHeartbeat: true`).** The SDK sends `POST /auth/heartbeat` on every interval. Revocation and concurrent-use detection take effect on the very next check-in, and each successful check-in refreshes the session. A definitive rejection (`revoked`, `hwid_mismatch`, `blocked`, ...) clears the stored session immediately; every other failure (network, `rate_limited`, `system_error`, `no_credits`, unknown codes, ...) is transient and keeps it until the session TTL runs out. See [Background check failures](#background-check-failures).

## Offline license files (`.authforge`)

For machines that never connect to the internet, the operator mints a **signed offline license file** in the AuthForge dashboard (License page -> *Mint .authforge file*) or via `POST /v1/licenses/{licenseKey}/offline-files`. The file is a standalone Ed25519-signed document; the SDK verifies it with **only** your app public key and the machine HWID. It never contacts AuthForge and never starts online check-ins. Leave `AppSecret` empty so the air-gapped binary does not contain the App Secret.

| | Grace period (default) | Offline license file |
| --- | --- | --- |
| Needs network | Once, at `Login` | Never on the end machine |
| What is verified | Signed *session* from `/auth/validate` | Signed *document* minted in the cloud |
| Lifetime | Session TTL: 1h to 7d | Operator-chosen expiry or lifetime (perpetual licenses only) |
| Revocation | Picked up at the next online validate / check-in | **Not** reachable: the file stays valid until its own expiry |
| Cost | 1 credit per `Login` | 1 credit per mint; verifying is free |

```go
client, err := authforge.New(authforge.Config{
	AppID:     "YOUR_APP_ID",
	PublicKey: "YOUR_PUBLIC_KEY",
	OnFailure: func(msg string) { log.Println("authforge:", msg) },
})
if err != nil {
	log.Fatal(err)
}

// 1. Write an activation request the operator drops into the mint dialog:
request := client.CreateActivationRequest(authforge.ActivationRequestOptions{})

// 2. Later, authorize from the minted file (path or armored text). No network.
lic, err := client.LoginFromFile("license.authforge")
if err != nil {
	switch {
	case errors.Is(err, authforge.ErrOfflineExpired):
		log.Fatal("offline license expired - ask the operator for a new file")
	case errors.Is(err, authforge.ErrOfflineHwidMismatch):
		log.Fatal("this file is bound to a different machine")
	default:
		log.Fatal(err)
	}
}
fmt.Println("Offline license OK; expires:", lic.ExpiresAt) // nil pointer = lifetime
fmt.Println(client.LicenseVariables())
```

Collect the HWID from the same SDK build that will load the file: fingerprints are not portable across SDKs or languages. After `LoginFromFile`, `GetSessionKind()` returns `SessionKindOffline` (`SessionKindOnline` after `Login`, `SessionKindNone` when logged out).

`authforge.VerifyLicenseFile(text, opts)` (package function) and `client.VerifyLicenseFile(pathOrText)` perform the same checks without touching client state. Errors are sentinels for `errors.Is`, in check order: `ErrOfflineBadArmor`, `ErrOfflineBadSignature`, `ErrOfflineUnsupportedVersion`, `ErrOfflineMalformedPayload`, `ErrOfflineWrongApp`, `ErrOfflineExpired`, `ErrOfflineHwidMismatch`; `authforge.OfflineErrorCode(err)` maps them to the cross-SDK codes. `LoginFromFile` also reports `offline_login_failed: <code>` through `OnFailure`.

File format (version 1): PEM-style armor with informational headers, a base64 JSON payload (`v`, `appId`, `licenseKey`, `jti`, `kid`, `issuedAt`, `expiresAt`, `hwid` policy, optional label/variable snapshots) and a detached Ed25519 signature over the UTF-8 bytes of the base64 payload string - the same contract as `/auth/validate`. See `offline_license_vectors.json` for conformance vectors.

## Migrating from HeartbeatMode

`Config.HeartbeatMode` is deprecated but still works:

- `HeartbeatMode: "local"` maps to the default grace period behavior. Remove the field.
- `HeartbeatMode: "server"` maps to online check-ins. Replace it with `OnlineHeartbeat: true`.
- An empty `HeartbeatMode` is now valid and means the default grace period behavior.
- Any other value still returns an error from `New`.
- If both fields are set, either one enables online check-ins: `HeartbeatMode: "server"` is not overridden by `OnlineHeartbeat: false`.

```go
// Before:
authforge.Config{ /* ... */ HeartbeatMode: "server"}
// After:
authforge.Config{ /* ... */ OnlineHeartbeat: true}

// Before:
authforge.Config{ /* ... */ HeartbeatMode: "local"}
// After (grace period is the default):
authforge.Config{ /* ... */ }
```

## Billing

- **1 `Login` or `ValidateLicense` call = 1 credit** (one `/auth/validate` debit each).
- **10 online check-ins on the same license = 1 credit** (debited every 10th successful check-in). The grace period costs nothing after activation.

This means a session-style app running for 6 hours at a 15-minute check-in interval burns ~1 validation + ~24 check-ins = ~3.4 credits/day. `/auth/heartbeat` is limited to 6 requests/minute per license key, so keep intervals at 10 seconds or higher and choose cadence based on revocation speed needs (they always land on the **next** check-in).

## Methods

| Method | Returns | Description |
|---|---|---|
| `Login(licenseKey string)` | `(*LoginResult, error)` | Activates the key online and stores the signed session (`sessionToken`, `expiresIn`, `appVariables`, `licenseVariables`) |
| `ValidateLicense(licenseKey string)` | `(*LoginResult, error)` | Same `/auth/validate` + signatures as `Login`; does not persist session or start background checks; does not invoke `OnFailure` for validate or network errors |
| `SelfBan(...)` | `(map[string]interface{}, error)` | Requests `/auth/selfban` to blacklist HWID/IP and optionally revoke (session-authenticated only) |
| `LoginFromFile(pathOrText string)` | `(*OfflineLicense, error)` | Authorizes from an offline `.authforge` file with no network; never starts background checks; errors are `ErrOffline*` sentinels and are echoed to `OnFailure` as `offline_login_failed: <code>` |
| `VerifyLicenseFile(pathOrText string)` | `(*OfflineLicense, error)` | Verifies a `.authforge` file with this client's app id / keys / HWID without changing state |
| `OfflineLicense()` | `*OfflineLicense` | The offline file in use (`JTI`, `ExpiresAt`, `HwidPolicy`, …) or `nil` |
| `GetSessionKind()` | `SessionKind` | `SessionKindOnline`, `SessionKindOffline`, or `SessionKindNone` when logged out |
| `HWID()` | `string` | The HWID this client sends (or `HWIDOverride`); customers share it to receive a bound file |
| `CreateActivationRequest(opts ActivationRequestOptions)` | `string` | Unsigned `.authforge-request` for this machine. No network, no secret. Hostname omitted unless `IncludeMachineName` |
| `Logout()` | `void` | Stops background checks and clears all session/auth state |
| `IsAuthenticated()` | `bool` | True when an active authenticated session exists |
| `GetSessionData()` / `SessionData()` | `map[string]interface{}` | Full decoded payload map |
| `GetAppVariables()` / `AppVariables()` | `map[string]interface{}` | App-scoped variables map |
| `GetLicenseVariables()` / `LicenseVariables()` | `map[string]interface{}` | License-scoped variables map |

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
		// HWID slots full (Login) or HWID no longer bound (check-in)
	case errors.Is(err, authforge.ErrNoCredits):
		// account has no credits
	case errors.Is(err, authforge.ErrAppBurnCapReached):
		// app credit burn cap reached
	case errors.Is(err, authforge.ErrBlocked):
		// blocked by security rules
	case errors.Is(err, authforge.ErrRateLimited):
		// request was rate limited
	case errors.Is(err, authforge.ErrReplayDetected):
		// nonce replay detected
	case errors.Is(err, authforge.ErrAppDisabled):
		// app disabled
	case errors.Is(err, authforge.ErrSessionExpired):
		// session expired (grace period ended)
	case errors.Is(err, authforge.ErrRevokeRequiresSession):
		// attempted pre-session revoke
	case errors.Is(err, authforge.ErrBadRequest):
		// bad_request or malformed_request
	case errors.Is(err, authforge.ErrServerError):
		// system_error or server_error
	case errors.Is(err, authforge.ErrSignatureMismatch):
		// response signature mismatch
	default:
		// transport or unknown error
	}
}
```

`ValidateLicense` returns the same error types as `Login` but **does not** call `OnFailure` for failed validate or network errors (background checks still use `OnFailure` on failure).

Server and transport failures are `*authforge.Error` values: `authforge.ErrorCode(err)` returns the machine-readable code (`invalid_key`, `hwid_mismatch`, `network_error`, `http_error_502`, ...) and `authforge.IsTransient(err)` its classification. `errors.Is` against the sentinels above keeps working. Server codes this SDK version doesn't know yet are passed through unchanged.

Internal request retries are automatic:
- `rate_limited`, or HTTP 429 without an error code: retry after 2s, then 5s (max 3 attempts total). `no_credits`, `app_burn_cap_reached` and `demo_quota_exceeded` share HTTP 429 but are not retried; a background check reports them as transient and tries again at the next interval.
- network failure: retry once after 2s
- retry attempts always use a fresh nonce

### Background check failures

Each failed background check produces an `*authforge.Error`:

- `Code`: the server's error code (`revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `rate_limited`, `no_credits`, `system_error`, `malformed_request`, ...), or an SDK code: `network_error`, `timeout`, `http_error_<status>` (non-JSON error body), `invalid_json_response`, `unexpected_response`, `signature_mismatch`, `nonce_mismatch`, ...
- `IsTransient()` / `IsFatal()`: the classification.

A failed check-in counts as an AuthForge verdict only when the body is a JSON object with `"status": "failed"` and a non-empty string `error`. Any other failure body (for example `{"error":"revoked"}` without a status, or `{"status":"failed"}` without an error) is reported as `unexpected_response`, and the message keeps the raw `status` / `error` values.

| Kind | Codes | What the SDK does |
|---|---|---|
| Fatal | `revoked`, `expired`, `hwid_mismatch` (the HWID is no longer bound to the license, for example after an HWID reset), `blocked` (HWID/IP blacklisted or not whitelisted), `session_expired` (including the end of the grace period), `malformed_request`, `app_disabled`, `invalid_app`, `signature_mismatch` | Clears the stored session (as `Logout()` does) and stops background checks **before** the callback runs, so the grace period cannot keep the app running on it and `IsAuthenticated()` is `false`. The callback may call `Login` again. |
| Transient | Everything else: `network_error`, `timeout`, `rate_limited`, `system_error`, `server_error`, `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_<status>`, `invalid_json_response`, `unexpected_response`, and codes this SDK version doesn't know yet | Keeps the session and checks in again on the next `HeartbeatInterval`. Once the signed session's TTL has passed, the next transient failure is reported as a fatal `session_expired` instead. |

The error reaches `OnHeartbeatFailure` when it is set, otherwise `OnFailure` as `err.Error()` (the same message as earlier releases, for example `authforge: license revoked: revoked`). A heartbeat network failure is reported once, not as a separate `network_error` string first. Without a callback, a transient failure prints `AuthForge: background check failed (<code>); retrying next interval` to stderr and checks in again next interval; a fatal one clears the session and stops background checks without output (the SDK never exits the process, so check `IsAuthenticated()` or set a callback).

Callbacks run on the background check goroutine with no SDK lock held, so calling `Logout()`, `IsAuthenticated()` or any other client method from them is safe; `Logout()` there stops further checks. A check-in still in flight when `Logout()` or `Login` runs never writes its result back to the client.

To tolerate short outages but shut down on a definitive answer, have the callback signal your main goroutine and let it save and exit:

```go
licenseLost := make(chan *authforge.Error, 1)

client, err := authforge.New(authforge.Config{
	AppID:           "YOUR_APP_ID",
	AppSecret:       "YOUR_APP_SECRET",
	PublicKey:       "YOUR_PUBLIC_KEY",
	OnlineHeartbeat: true,
	SessionTTL:      time.Hour, // retry window for transient check-in failures
	OnHeartbeatFailure: func(err *authforge.Error) {
		if err.IsTransient() {
			// Connectivity problem or AuthForge overloaded: keep running. The SDK
			// retries every HeartbeatInterval and reports session_expired (fatal)
			// once the SessionTTL grace period is used up.
			log.Printf("AuthForge check-in failed (%s), retrying", err.Code)
			return
		}
		log.Printf("License check failed: %s", err.Code) // session already cleared
		select {
		case licenseLost <- err: // runs on the background goroutine: signal, don't exit here
		default:
		}
	},
})

// ... Login, then run your app's work on other goroutines ...

select {
case <-licenseLost:
	saveUserWork()
	client.Logout()
	os.Exit(1)
case <-appDone:
}
```

You can also pass a `context.Context` built with `context.WithCancelCause` and cancel it from the callback. Calling `os.Exit(1)` inside the callback is a last resort: deferred functions do not run, so save the user's work first.

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
- Not available after `LoginFromFile`: offline sessions have no server session, so `SelfBan` with no explicit `licenseKey` / `sessionToken` returns `ErrOfflineSession` without contacting the server.

## License

MIT
