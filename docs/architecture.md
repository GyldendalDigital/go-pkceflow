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
  options.go                        Functional options (WithLogger, WithStore, etc.)
  desktopflow/                      Localhost callback + system browser (implements AuthFlowHandler)
  mobileflow/                       Channel-based handler for deep link callbacks
  keyringstore/                     OS credential manager via go-keyring (implements TokenPersistence)
  filestore/                        AES-256-GCM encrypted file (fallback TokenPersistence)
  keychainstore/                    iOS Keychain (build-tagged darwin/ios)
  eventbus/                         DeferredEventBus, NoopEventBus utilities
  oidctest/                         FakeIDPServer, test doubles, assertion helpers

wails-pkceflow                      Wails v3 wrapper (depends on go-pkceflow)
  wailspkceflow.go                  AuthService (Wails service lifecycle adapter)
  events.go                         WailsEventBus, DeferredWailsEventBus
  deeplink.go                       Deep link router for mobile callbacks
```

## Core Interfaces

The library is built around three focused interfaces:

**AuthFlowHandler** -- Handles the platform-specific part of the OAuth flow (opening a browser, receiving the callback).
- `StartAuthFlow(ctx, authURL) (callbackURL, error)` -- Opens auth URL, returns the callback URL with code+state
- `RedirectURI() string` -- Returns the redirect URI registered with the IdP

**TokenPersistence** -- Stores and retrieves encrypted token state.
- `Save(TokenState) error`
- `Load() (TokenState, error)`
- `Delete() error`

**EventEmitter** -- Notifies the application of auth state changes.
- `Emit(event string, data any)`

## Auth Flow (PKCE S256)

1. Client generates PKCE verifier + S256 challenge
2. Client generates 32-byte random state (base64url)
3. Client builds authorization URL with challenge, state, scopes, extra params
4. AuthFlowHandler opens URL in system browser and waits for callback
5. Client validates state (constant-time compare), checks for error params
6. Client exchanges authorization code for tokens (with PKCE verifier)
7. Client validates ID token signature via OIDC discovery JWKS
8. Client persists token state and emits login event

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
| Linux | desktopflow (localhost + xdg-open) | keyringstore (secret-service) | filestore fallback |
| macOS | desktopflow (localhost + open) | keyringstore (Keychain) | |
| Windows | desktopflow (localhost + start) | keyringstore (Credential Manager) | |
| iOS | mobileflow (Universal Links) | keychainstore | Consumer provides deep link wiring |
| Android | mobileflow (App Links) | filestore (app sandbox) | Kernel UID isolation |

## Security Model

- PKCE S256 only (never plain)
- State parameter: 32 bytes from crypto/rand, compared with subtle.ConstantTimeCompare
- Tokens never logged at any level
- Localhost server binds 127.0.0.1 only (not 0.0.0.0)
- File-based token encryption: AES-256-GCM with random nonce per write
- Key derivation: SHA-256(appID + machineID); fallback to persisted random key file
- Redirect URIs: loopback IP literal per RFC 8252 (desktop), claimed HTTPS (mobile)

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
| Keyring as default store (not file) | More secure, no key management needed, works on all desktop OS |
| File store as fallback | Headless/CI environments, Linux without secret-service |
| Random persistent key (not hostname) | Hostname changes don't invalidate tokens |
| DeferredEventBus pattern | Solves Wails startup ordering (services created before app is ready) |
