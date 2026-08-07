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
  options.go                        Functional options (WithLogger, WithTokenPersistence, WithEventEmitter, WithHTTPClient)
  claims.go                         ID token claims decoding (Claims, DecodeIDToken)
  desktopflow/                      Localhost callback broker + system browser (implements AuthFlowHandler, LogoutFlowHandler)
  mobileflow/                       Correlated handler for deep link callbacks
  filestore/                        Optional AES-256-GCM file persistence
  eventbus/                         DeferredEventBus, NoopEventBus utilities
  oidctest/                         FakeIDPServer, test doubles, assertion helpers

An OS-keyring-backed TokenPersistence is a possible future backend. Because
storage is behind the TokenPersistence interface, adding it later is additive
and does not break the API.

wails-pkceflow                      Wails v3 wrapper (depends on go-pkceflow)
  wailspkceflow.go                  Options, AuthService, lifecycle, deep-link subscription
  emitter.go                        Core EventEmitter -> Wails application events
  result.go                         Frontend-safe AuthResult mapping
  claims.go                         Frontend-safe ID token claims DTO
  examples/wails-desktop/           Runnable app with a safe bound delegator
```

## Core Interfaces

The library is built around a small set of focused interfaces:

**AuthFlowHandler** -- Handles the application-facing part of the OAuth flow
(opening a browser and returning the callback). On mobile, the OS/framework
bridge remains responsible for passing its launch URL to `mobileflow.DeliverURL`.
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

`Load` distinguishes absent or successfully retrieved malformed content (zero
state, nil) from operational storage failures (zero state, error).
`Client.RestoreSession` preserves that error boundary as `(restored, error)`;
an error never replaces the current in-memory generation. `restored` describes
non-zero state restoration, while `AuthStatus` decides validity and grace.

**EventEmitter** -- Notifies the application of auth state changes.
- `Emit(event string, data any)`

## Desktop callback broker

The desktop handler does not spin up a fresh listener per flow. Instead a single
reference-counted **broker** binds the loopback port lazily on the first flow and
serves every in-flight flow from one mux. Each flow registers a one-shot waiter
keyed by `path + state`; an incoming callback is routed to the matching waiter,
so concurrent handler users never collide on the port and a callback only
resolves the flow that started it. This concurrency remains available to
independent Clients and direct handler users; one Client applies the lifecycle
ordering described below. Unmatched or stale callbacks get the same success page
as matched ones, so a local process cannot probe for live flows. The port is
released a short grace period after the last flow clears.

For `localhost`, the broker binds both `127.0.0.1` and `[::1]` (succeeding if at
least one binds) so a callback is captured regardless of how the OS resolves the
name. It never binds a wildcard address.

## Client lifecycle ordering

Each Client also admits one current OIDC discovery operation. A newly admitted
`Init` cancels and supersedes the previous operation on that Client, while a
call whose context is already canceled is not admitted. Discovery network work
runs without Client locks. Before committing the provider, verifier, OAuth2
configuration, logout endpoint, and refresh wakeup as one snapshot, `Init`
rechecks both operation ownership and cancellation under the Init commit lock.
Only a discovery failure that is current and not canceled at its result fence
emits `oidcauth:init-failed`; calls that lose that fence leave the previous
snapshot and event stream unchanged.

Each Client admits one current login/logout operation identity. A newly admitted
Login or Logout cancels the previous operation; overlapping Logout calls are the
exception and coalesce. Login checks that identity and its context inside the
same critical section that commits token state, persistence, and
`oidcauth:logged-in`; a late callback or token response therefore cannot
resurrect a session after Logout. A pre-cancelled Login and a Login attempted
before successful discovery are rejected before admission and do not disturb an
active operation.

Logout is the local security boundary. It atomically supersedes an older Login,
clears memory, attempts persistent deletion, and queues `oidcauth:logged-out`
before any RP-Initiated Logout browser round trip. Concurrent Logout calls
coalesce so only one local event and one provider round trip are attempted. A
newer Login can cancel a pending RP callback wait, but it cannot recall a logout
page already opened at the provider.

A narrow, context-aware permit serializes only calls into one Client's flow
handler. This lets a cancelled mobile waiter unregister before its replacement
starts. Token exchange, persistence, event delivery, and local logout do not hold
that permit. Separate Clients have separate operation identities and permits.

Framework adapters can apply stricter UX rules. `wails-pkceflow`, for example,
rejects a second frontend command as `flow_in_progress`; core ordering remains
the correctness layer for direct Client calls and other integrations.

## Persistence durability and recovery

A successful Login or verified refresh first installs a new semantic
`stateRevision`, then calls `TokenPersistence.Save` while holding the state
commit lock. If Save reports an error, the in-memory generation remains
authoritative. Rolling back could restore a refresh token that a rotating
provider has already invalidated.

The failed revision is marked dirty without copying its tokens into retry
metadata. While `StartRefreshLoop` is active, a separate local supervisor
retries Save after 1, 2, 4, and later seconds, capped at one minute. Each retry
claims the exact revision, acquires the state commit lock, rechecks the claim,
and holds that lock through Save. A newer Login or refresh therefore persists
after an older in-flight retry, while Logout invalidates queued work and runs
Delete after any retry already in progress. Recovery never repeats a token
grant, advances the revision, or emits another auth event.

Save errors have an indeterminate publication outcome: a backend can fail
before writing, after publishing the replacement, or after removing an
unreadable old value. Until a retry returns nil, a new process may restore the
old state, the new state, or no state. An old rotated refresh token may be
rejected, after which normal grace and explicit Login policy apply. The
Client never compensates with Delete, never rolls memory back, and never forces
browser Login.

`StopRefreshLoop` pauses queued recovery but cannot interrupt a synchronous
TokenPersistence call already in progress. Pending state survives a later
Start. Persistence methods must be synchronous and idempotent; one Client's
locking does not order two active Clients sharing the same storage namespace.
Arbitrary backend errors are not included in logs because they may contain
credentials.

Logout also installs a private in-memory tombstone after clearing state and
invalidating Save recovery. `RestoreSession` cannot reload tokens into that
same Client, even when Delete failed and storage still contains them. The
tombstone cannot survive process restart, so failed Delete retains the
documented uncertain restart behavior.

## Reading ID token claims

`Client.Claims()` decodes the current session's ID token into a `Claims` struct
(standard OIDC claims plus a `Raw` map for provider-specific fields). The
signature is not re-verified by `Claims`: go-oidc already verified the token
during login or refresh, so this only inspects an already-trusted token. A
refresh response may omit `id_token`, in which case the previously verified
token is retained. If a refresh includes one, it is verified and must keep the
same non-empty `sub` claim. Access tokens are never decoded because they are
opaque to clients per RFC 6750.

## Auth Flow (PKCE S256)

1. Client generates PKCE verifier + S256 challenge
2. Client generates 32-byte random state and 32-byte random nonce (base64url)
3. Client builds authorization URL with challenge, state, nonce, scopes, extra params
4. AuthFlowHandler opens URL in system browser and waits for callback
5. Client validates state (constant-time compare), checks for error params
6. Client exchanges the authorization code with the PKCE verifier, sending the
   public `client_id` in the form body without a secret or HTTP Basic probe
7. Client validates the ID token issuer, audience, signature, and expiry via
   the discovery JWKS
8. Client validates the ID token nonce claim (constant-time compare)
9. Client persists token state and emits the logged-in event

## Token Lifecycle

`AuthStatus` is computed from the in-memory `TokenState`:

- `Valid` means the access token expires more than 30 seconds from now.
- `GraceMode` means the token is no longer valid but the configured grace
  period, measured from the last successful login or refresh, has not ended.
- `CanUseApp` is `Valid || GraceMode`. Grace controls application usability; it
  does not make an expired access token acceptable to an API.

`AccessToken` returns a valid token immediately. Inside the 30-second expiry
buffer it attempts one refresh when discovery is initialized and a refresh
token exists. If a normal refresh error occurs, it may return the previous
token while grace is active. A session-integrity failure always fails closed,
even during grace.

The background refresh supervisor uses the token's original lifetime
(`ExpiresAt - LastAuthAt`) as a DHCP-style schedule:

1. it makes no eager request merely because the loop started;
2. the first attempt occurs when 50% of the original lifetime remains;
3. temporary failures retry when 25%, 12.5%, and later halving fractions
   remain, with at least 10 seconds between failed attempts;
4. a successful refresh starts a new schedule from the returned token state;
5. no background request starts at or after the actual access-token expiry.

If the next legal retry would be at or after expiry, that token generation is
parked. The supervisor stays alive and waits for newer Login, RestoreSession,
or successful on-demand refresh state. Parking does not clear tokens, launch
Login, or emit `oidcauth:session-expired`; `AuthStatus` and the configured grace
period continue to decide whether the app is usable.

A permanent OAuth error also parks that generation immediately, because
retrying a revoked or invalid refresh token cannot help. The supervisor emits
`oidcauth:session-expired` once when grace is disabled or exhausted, without
making more network attempts while grace remains. A session-integrity failure
parks and emits immediately despite grace, and the affected generation fails
closed in `AccessToken` and `AuthStatus`.

Stopping and restarting the loop does not reset a generation's refresh retry
stage, terminal disposition, or pending persistence recovery. Token state with
missing or inconsistent lifetime timestamps has no safe background refresh
schedule; persistence recovery remains independent of token expiry metadata.

Every successful refresh emits `oidcauth:token-refreshed`, including a refresh
triggered synchronously by `AccessToken`. A later persistence retry emits no
duplicate event.

## Platform Integration Map

| Platform | AuthFlowHandler | TokenPersistence | Notes |
|----------|----------------|------------------|-------|
| Linux | desktopflow (localhost + xdg-open) | filestore | Encrypted file in user config dir |
| macOS | desktopflow (localhost + open) | filestore | Encrypted file in user config dir |
| Windows | desktopflow (localhost + start) | filestore | Encrypted file in user config dir |
| iOS | mobileflow (callback correlation) | filestore (app sandbox) | Application configures links/browser session; native host or completion handler delivers the URL |
| Android | mobileflow (callback correlation) | filestore (app sandbox) | Application configures links; native host delivers the intent URL; sandbox uses kernel UID isolation |

An OS-native credential store (keyring/Keychain) may be added later as an
additional TokenPersistence implementation without changing the core API.

## Security Model

- PKCE S256 only (never plain)
- State parameter: 32 bytes from crypto/rand, compared with subtle.ConstantTimeCompare
- Nonce parameter: 32 bytes from crypto/rand, always sent and validated against the ID token nonce claim with subtle.ConstantTimeCompare (OIDC replay protection)
- Tokens never logged at any level
- Public-client token requests send `client_id` in the form body and never send
  a client secret or probe HTTP Basic authentication
- Localhost server binds loopback only (127.0.0.1, and [::1] for the localhost host), never a wildcard address
- File-based token encryption: AES-256-GCM with random nonce per write
- Key derivation: SHA-256(appID + machineID); fallback to persisted random key file
- Redirect URIs: loopback on desktop; claimed HTTPS is preferred on mobile,
  with registered private-use schemes supported at weaker interception
  resistance
- Refreshed ID tokens are verified and cannot silently change the session subject
- Extra parameter maps cannot override library-owned OAuth/OIDC/PKCE fields or
  introduce a client secret

Token storage security model: the included filestore encrypts tokens with
AES-256-GCM and relies on verified POSIX mode bits, a caller-private inherited
Windows ACL, or the application sandbox on mobile. `NewDefault` uses the normal
per-user configuration tree; callers passing an explicit Windows directory to
`New` are responsible for its ACL because Go file modes do not configure DACLs.
Explicit store directories must support same-directory hard links for fallback
key publication and same-directory rename replacement for token saves.
This is sufficient for typical OIDC tokens and keeps the default dependency-free
and CGo-free. Consumers needing stricter handling (an OS keyring or Keychain, a
hardware-backed keystore, or a secure enclave) implement the
`TokenPersistence` interface and inject it via `WithTokenPersistence`; no other
change is required. An OS-native store may also be added to the library as an
additional backend later without breaking the API.

## Provider Status

| Provider | Project status | Notes |
|----------|----------------|-------|
| Keycloak | Manually validated | Linux: login, exchange, repeated refresh, logout. Windows: login, exchange, repeated refresh; logout not yet tested |
| Auth0 | Configuration guide | Native-app PKCE is expected to work; API audience and refresh policy are provider settings |
| Microsoft Entra ID | Configuration guide | Use a tenant-specific v2 issuer and a public native-app registration |
| Other OIDC providers | Compatibility checklist | Expected when discovery, PKCE S256, public token exchange, nonce-bearing ID tokens, and matching redirects are supported |

Only Keycloak has completed a project-owned live-provider run so far. Automated
tests use `oidctest.FakeIDPServer`; they do not prove a provider's console
configuration or operational quirks. See the
[generic OIDC checklist](idp-setup-generic-oidc.md) for the actual contract.

## Design Decisions

| Decision | Rationale |
|----------|-----------|
| Core has zero framework dependencies | Usable with any Go application, not just Wails |
| Separate repos for core and wrapper | Independent versioning, clear dependency direction |
| Interfaces over concrete types | Testability, platform flexibility |
| No OS-specific deep-link bridge in core | `mobileflow.Handler` validates delivered callbacks; the application owns OS registration, the framework host owns native event production, and an adapter may forward surfaced URLs |
| In-memory default; optional filestore | Minimal clients need no filesystem; persistent apps can inject the CGo-free encrypted store |
| OS keyring deferred to a future backend | The TokenPersistence interface allows adding it later without breaking changes |
| Random persistent key (not hostname) | Hostname changes don't invalidate tokens |
| DeferredEventBus pattern | Solves Wails startup ordering (services created before app is ready) |
