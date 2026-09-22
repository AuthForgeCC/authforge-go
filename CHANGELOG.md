# Changelog

## 1.4.0

### Behavior changes for callers

- **Typed errors.** Server and transport failures are now `*authforge.Error` values with `Code`, `IsTransient()` and `IsFatal()`; `authforge.ErrorCode(err)` and `authforge.IsTransient(err)` work on wrapped errors. `errors.Is` against the existing sentinels (`ErrRevoked`, `ErrHwidMismatch`, ...) still works, and messages are unchanged.
- **`Config.OnHeartbeatFailure func(*authforge.Error)`.** Receives background check failures as a typed error. When it is set, `OnFailure` is not called for them; without it, `OnFailure` keeps receiving `err.Error()`.
- **Classification.** Only `revoked`, `expired`, `hwid_mismatch`, `blocked`, `session_expired`, `malformed_request`, `app_disabled`, `invalid_app` and the SDK-local `signature_mismatch` are definitive. Everything else is transient, including `no_credits`, `demo_quota_exceeded`, `app_burn_cap_reached`, `bad_request`, `invalid_key`, every `http_error_<status>` and unknown codes. Grace period expiry, and a transient failure after the session TTL has passed, report `session_expired`.
- **Transient check-in failures keep checking in.** Previously the background loop stopped on any failure. Now the session is kept and the next check happens at the next interval.
- **Definitive failures clear the session before the callback runs**, as `Logout()` does, and stop background checks; `IsAuthenticated()` is `false` inside the callback.
- **New `unexpected_response` code (transient).** A failed check-in counts as a verdict only when the body is a JSON object with `"status": "failed"` and a non-empty string `error`.
- **Rate-limit retry.** Only `rate_limited`, or HTTP 429 without an error code, is retried (after 2s, then 5s). HTTP 429 `no_credits`, `app_burn_cap_reached` and `demo_quota_exceeded` are no longer retried.
- **One callback per heartbeat network failure.** A check-in network failure no longer also fires `OnFailure("network_error")` before the heartbeat failure callback.
- **Unknown server codes are passed through** as `Code` instead of being dropped.
- **Callbacks run with no SDK lock held**, so calling `Logout()` or `IsAuthenticated()` from them is safe, and a check-in in flight across `Logout()` / `Login` no longer writes its result back.
