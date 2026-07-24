# Roadmap

Current status: **Early development** (pre-release)

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
> Channel-based handler for deep link callbacks.

- [x] Mobile flow handler (StartAuthFlow + DeliverURL)

### M7: Refresh Loop and Event Bus (in progress)
> Background token refresh and event utilities.

- [x] Event bus utilities (DeferredEventBus, NoopEventBus)
- [x] Background refresh loop (DHCP-style timing)

### M8: Integration
> First working end-to-end desktop login, hardened for real-world IdPs.

- [x] End-to-end integration test
- [x] Package documentation (doc.go files)
- [x] Integration example CLI
- [x] Logout state correlation + optional LogoutFlowHandler
- [ ] Desktop shared callback broker (path+state routing, grace shutdown)
- [ ] Desktop separate login/logout redirect URIs
- [ ] Token claims helper (Claims, DecodeIDToken, Client.Claims)
- [ ] CLI logout flags + claims helper
- [ ] Docs: how-it-works (ELI5), Keycloak POC, Auth0, mobile deep linking

### M9: wails-pkceflow Wrapper
> Wails v3 service adapter and event bridge.

- [x] Initialize wails-pkceflow module
- [ ] Wails auth service adapter
- [ ] Wails event bridge
- [ ] Deep link router (mobile)

### M10: Documentation and Release
> Examples, guides, and v1.0 release prep.

- [ ] README examples and getting started
- [ ] IdP setup guides (Keycloak, Entra ID)
- [ ] Wails integration guide
- [ ] Release v1.0.0
- [ ] Migration guide (from custom implementations)
- [ ] Example: Wails desktop app
- [ ] Example: CLI app
- [ ] v1.0.0-beta.1 release

## Version Plan

- `v0.x` -- API exploration, breaking changes expected
- `v1.0.0-beta.x` -- Feature-complete, seeking feedback
- `v1.0.0-rc.x` -- API frozen, bug fixes only
- `v1.0.0` -- Stable release
