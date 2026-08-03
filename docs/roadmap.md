# Roadmap

Current status: **Pre-1.0 beta hardening**

## Milestones

### M1: Core Types and Interfaces ✓
> Foundation types that everything else depends on.

- [x] Initialize Go module
- [x] Core interfaces (AuthFlowHandler, TokenPersistence, EventEmitter)
- [x] Token state and auth status types
- [x] Configuration struct with validation
- [x] Error types and sentinels
- [x] Event name constants
- [x] Option type and constructors

### M2: Test Infrastructure ✓
> Enables TDD for the entire library.

- [x] FakeIDPServer (reusable fake OIDC provider, zero go-pkceflow imports)
- [x] Test doubles (MemoryStore, RecordingEmitter, FakeFlowHandler)

### M3: Client Core ✓
> The heart of the library.

- [x] Client struct and New() constructor
- [x] Init() and OIDC discovery
- [x] RestoreSession()
- [x] Login() flow (PKCE S256, state validation, token exchange)
- [x] Logout() flow (local + RP-initiated)
- [x] AccessToken() and TokenFn()
- [x] AuthStatus()
- [x] Token refresh (single-shot, double-check locking)

### M4: Desktop Flow Handler ✓
> Localhost callback server and system browser opener.

- [x] Localhost callback server with loopback validation
- [x] Default browser opener (Linux/macOS/Windows)

### M5: Token Persistence ✓
> Secure token storage.

- [x] Filestore (AES-256-GCM encrypted, machine-ID key derivation, pure Go)

### M6: Mobile Flow Handler ✓
> URI- and state-correlated handler for deep link callbacks.

- [x] Mobile flow handler (StartAuthFlow + DeliverURL)

### M7: Refresh Loop and Event Bus ✓
> Background token refresh and event utilities.

- [x] Event bus utilities (DeferredEventBus, NoopEventBus)
- [x] Background refresh loop with DHCP-style lifetime scheduling

### M8: Integration ✓
> First working end-to-end desktop login, hardened for real-world IdPs.

- [x] End-to-end integration test
- [x] Package documentation (doc.go files)
- [x] Integration example CLI
- [x] Logout state correlation + optional LogoutFlowHandler
- [x] Desktop shared callback broker (path+state routing, grace shutdown)
- [x] Desktop separate login/logout redirect URIs
- [x] ID token claims helper (Claims, DecodeIDToken, Client.Claims)
- [x] CLI logout flags + claims helper
- [x] Docs: how-it-works (ELI5), Keycloak POC, Auth0, mobile deep linking

### M8.5: Core Completion ✓
> Final core hardening and platform parity so the Wails wrapper builds against a frozen API.

- [x] Always-on OIDC nonce (send + constant-time validate against ID token claim)
- [x] Mobile logout parity (mobileflow implements LogoutFlowHandler)
- [x] Token storage security model + bring-your-own TokenPersistence guidance
- [x] Council review hardening: refresh errors classified as permanent (EventSessionExpired fires on revoked tokens), EventInitFailed emitted, unused API removed, Windows browser opener, config/URL validation

### M9: wails-pkceflow Wrapper ✓
> Wails v3 service adapter and event bridge.

- [x] Initialize wails-pkceflow module
- [x] Wails auth service adapter
- [x] Wails event bridge
- [x] Deep link router (mobile; real-device validation remains)

### M10: Documentation and Release (in progress)
> Examples, guides, and v1.0 release prep.

- [x] README examples and getting started
- [x] IdP setup guides: Keycloak, Auth0, Entra ID, generic OIDC provider
- [x] Wails integration guide
- [x] Example: CLI app
- [x] Example: Wails desktop app with Dockerized Keycloak
- [ ] Release v1.0.0
- [ ] v1.0.0-beta.1 release

## Before Dogfooding

- [x] Complete coverage and edge-path hardening
  ([#43](https://github.com/GyldendalDigital/go-pkceflow/issues/43)).
- [x] Correct the refresh scheduler so retries follow explicit 50%, 25%, 12.5%
  lifetime stages and stop at access-token expiry
  ([#55](https://github.com/GyldendalDigital/go-pkceflow/issues/55)).
- [x] Harden mobile callback filtering and active-flow handling.
- [x] Define deterministic overlapping Login/Logout semantics
  ([#58](https://github.com/GyldendalDigital/go-pkceflow/issues/58)).
- [ ] Define refresh durability when persistence fails
  ([#63](https://github.com/GyldendalDigital/go-pkceflow/issues/63)).
- [ ] Make native OS matrix failures gate protected merges
  ([#64](https://github.com/GyldendalDigital/go-pkceflow/issues/64)).
- [ ] Reconcile the wrapper dependency pin and stale completed issues.
- [ ] Validate mobile deep-link delivery on an emulator/device
  ([wrapper #8](https://github.com/GyldendalDigital/wails-pkceflow/issues/8)).

## Version Plan

- `v0.9.x-alpha/beta` -- Feature-complete core; Keycloak validated on Linux and
  Windows, with remaining hardening and platform/provider validation
- `v1.0.0-beta.x` -- Feature-complete, validated, seeking feedback
- `v1.0.0-rc.x` -- API frozen, bug fixes only
- `v1.0.0` -- Stable release

Docs are vendor- and consumer-agnostic: no migration guide tied to any specific
application. IdP guidance favours a generic OIDC guide plus a small set of
high-value provider walkthroughs to keep maintenance sustainable.

## Backlog

- OS-native credential store (keyring/Keychain) as an additional TokenPersistence
  backend. Additive behind the existing interface; no core API change required.
