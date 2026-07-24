# Architecture

This document describes the technical design of go-pkceflow and its companion wrapper wails-pkceflow.

## Module Structure

Two separate Go modules in separate repositories:

```
go-pkceflow                         Core library (framework-agnostic)
  pkceflow.go                       Client, New(), Login, Logout, AccessToken, TokenFn
  config.go                         Config struct, validation, defaults
  interfaces.go                     AuthFlowHandler, TokenPersistence, EventEmitter
  errors.go                         Sentinel errors, AuthError type
  state.go                          TokenState, AuthStatusResult
  refresh.go                        Token refresh (single-shot + background loop)
  options.go                        Functional options (WithLogger, WithTokenPersistence, WithEventEmitter)
  claims.go                         ID token claims decoding (Claims, DecodeIDToken)
  desktopflow/                      Localhost callback broker + system browser (implements AuthFlowHandler, LogoutFlowHandler)
  mobileflow/                       Channel-based handler for deep link callbacks
  filestore/                        AES-256-GCM encrypted file (default TokenPersistence)
  eventbus/                         DeferredEventBus, NoopEventBus utilities
  oidctest/                         FakeIDPServer, test doubles, assertion helpers

An OS-keyring-backed TokenPersistence is a possible future backend. Because
storage is behind the TokenPersistence interface, adding it later is additive
and does not break the API.

wails-pkceflow                      Wails v3 wrapper (depends on go-pkceflow)
  wailspkceflow.go                  AuthService (Wails service lifecycle adapter)
  events.go                         WailsEventBus, DeferredWailsEventBus
  deeplink.go                       Deep link router for mobile callbacks
```

## Core Interfaces

The library is built around a small set of focused interfaces:

**AuthFlowHandler** -- Handles the platform-specific part of the OAuth flow (opening a browser, receiving the callback).
- `StartAuthFlow(ctx, authURL) (callbackURL, error)` -- Opens auth URL, returns the callback URL with code+state
- `RedirectURI() string` -- Returns the redirect URI registered with the IdP

**LogoutFlowHandler** (optional) -- Extends a handler to support RP-Initiated Logout with a separately registered post-logout redirect URI.
- `StartLogoutFlow(ctx, logoutURL) (callbackURL, error)` -- Opens the end-session URL, returns the post-logout callback URL
- `PostLogoutRedirectURI() string` -- Returns the post_logout_redirect_uri (empty means "reuse the login redirect URI")

When a handler does not implement this interface, `Logout` falls back to `StartAuthFlow` with the login `RedirectURI` and a fresh `state`, which covers IdPs that reuse one URI for both. The desktop handler implements it and lets callers set a distinct logout path via `SetLogoutURI` / `SetLogoutPath`.

**TokenPersistence** -- Stores and retrieves encrypted token state.
- `Save(TokenState) error`
- `Load() (TokenState, error)`
- `Delete() error`

**EventEmitter** -- Notifies the application of auth state changes.
- `Emit(event string, data any)`

## Desktop callback broker

The desktop handler does not spin up a fresh listener per flow. Instead a single
reference-counted **broker** binds the loopback port lazily on the first flow and
serves every in-flight flow from one mux. Each flow registers a one-shot waiter
keyed by `path + state`; an incoming callback is routed to the matching waiter,
so concurrent logins (or a login and a logout) never collide on the port and a
callback only resolves the flow that started it. Unmatched or stale callbacks get
the same success page as matched ones, so a local process cannot probe for live
flows. The port is released a short grace period after the last flow clears.

For `localhost`, the broker binds both `127.0.0.1` and `[::1]` (succeeding if at
least one binds) so a callback is captured regardless of how the OS resolves the
name. It never binds a wildcard address.

## Reading ID token claims

`Client.Claims()` decodes the current session's ID token into a `Claims` struct
(standard OIDC claims plus a `Raw` map for provider-specific fields). The
signature is not re-verified: go-oidc already verified it during the token
exchange, so this only inspects an already-trusted token. Access tokens are
never decoded because they are opaque to clients per RFC 6750.

## Auth Flow (PKCE S256)

1. Client generates PKCE verifier + S256 challenge
2. Client generates 32-byte random state and 32-byte random nonce (base64url)
3. Client builds authorization URL with challenge, state, nonce, scopes, extra params
4. AuthFlowHandler opens URL in system browser and waits for callback
5. Client validates state (constant-time compare), checks for error params
6. Client exchanges authorization code for tokens (with PKCE verifier)
7. Client validates ID token signature via OIDC discovery JWKS
8. Client validates the ID token nonce claim (constant-time compare)
9. Client persists token state and emits login event

## Token Lifecycle

```
[No Session] --Login()--> [Authenticated]
[Authenticated] --token expiring--> [Refreshing] --success--> [Authenticated]
[Refreshing] --failure (temporary)--> [Grace Mode] --retry--> [Refreshing]
[Refreshing] --failure (permanent)--> [Expired]
[Grace Mode] --grace period exceeded--> [Expired]
[Any state] --Logout()--> [No Session]
```

The background refresh loop uses DHCP-style adaptive timing:
- Sleep duration = max(time_remaining / 2, 10 seconds)
- On failure: halve the interval (faster retries)
- On permanent error (invalid_grant): stop loop, emit session-expired

## Platform Support

| Platform | AuthFlowHandler | TokenPersistence | Notes |
|----------|----------------|------------------|-------|
| Linux | desktopflow (localhost + xdg-open) | filestore | Encrypted file in user config dir |
| macOS | desktopflow (localhost + open) | filestore | Encrypted file in user config dir |
| Windows | desktopflow (localhost + start) | filestore | Encrypted file in user config dir |
| iOS | mobileflow (Universal Links) | filestore (app sandbox) | Consumer provides deep link wiring |
| Android | mobileflow (App Links) | filestore (app sandbox) | Kernel UID isolation |

An OS-native credential store (keyring/Keychain) may be added later as an
additional TokenPersistence implementation without changing the core API.

## Security Model

- PKCE S256 only (never plain)
- State parameter: 32 bytes from crypto/rand, compared with subtle.ConstantTimeCompare
- Nonce parameter: 32 bytes from crypto/rand, always sent and validated against the ID token nonce claim with subtle.ConstantTimeCompare (OIDC replay protection)
- Tokens never logged at any level
- Localhost server binds loopback only (127.0.0.1, and [::1] for the localhost host), never a wildcard address
- File-based token encryption: AES-256-GCM with random nonce per write
- Key derivation: SHA-256(appID + machineID); fallback to persisted random key file
- Redirect URIs: loopback IP literal per RFC 8252 (desktop), claimed HTTPS (mobile)

Token storage security model: the default filestore encrypts tokens with
AES-256-GCM and relies on per-user file permissions (desktop) or the application
sandbox (mobile). This is sufficient for typical OIDC tokens and keeps the
default dependency-free and CGo-free. Consumers needing stricter handling (an OS
keyring or Keychain, a hardware-backed keystore, or a secure enclave) implement
the `TokenPersistence` interface and inject it via `WithTokenPersistence`; no
other change is required. An OS-native store may also be added to the library as
an additional backend later without breaking the API.

## IdP Compatibility

Designed and tested for:
- Keycloak (primary, production-tested)
- Microsoft Entra ID (needs ExtraAuthParams for prompt/audience)
- Auth0 (needs audience parameter)
- Okta (standard OIDC)
- Google (needs access_type=offline instead of offline_access scope)

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Core has zero framework dependencies | Usable with any Go application, not just Wails |
| Separate repos for core and wrapper | Independent versioning, clear dependency direction |
| Interfaces over concrete types | Testability, platform flexibility |
| No mobile AuthFlowHandler in library | Deep link setup is app-specific; library provides the channel-based handler, consumer wires the platform bridge |
| Filestore as the default store | No external service or platform toolchain required; works headless and cross-compiles without CGo |
| OS keyring deferred to a future backend | The TokenPersistence interface allows adding it later without breaking changes |
| Random persistent key (not hostname) | Hostname changes don't invalidate tokens |
| DeferredEventBus pattern | Solves Wails startup ordering (services created before app is ready) |
