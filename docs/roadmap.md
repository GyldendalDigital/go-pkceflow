# Roadmap

Current status: **Early development** (pre-release)

## Milestones

### M1: Module Bootstrap and Core Types
> Foundation types that everything else depends on.

- [x] Initialize Go module
- [ ] Core interfaces (AuthFlowHandler, TokenPersistence, EventEmitter)
- [ ] Token state and auth status types
- [ ] Configuration struct with validation
- [ ] Error types and sentinels
- [ ] Event name constants
- [ ] Option type and constructors

### M2: Test Infrastructure
> Enables TDD for the entire library.

- [ ] FakeIDPServer (fake OIDC provider for tests)
- [ ] Test doubles (MemoryStore, RecordingEmitter, FakeFlowHandler)

### M3: Client Core
> The heart of the library.

- [ ] Client struct and New() constructor
- [ ] Init() and OIDC discovery
- [ ] RestoreSession()
- [ ] Login() flow (PKCE S256, state validation, token exchange)
- [ ] Logout() flow (local + RP-initiated)
- [ ] AccessToken() and TokenFn()
- [ ] AuthStatus()
- [ ] Token refresh (single-shot)

### M4: Desktop Flow Handler
> Localhost callback server and system browser opener.

- [ ] Localhost callback server with loopback validation
- [ ] Default browser opener (Linux/macOS/Windows)

### M5: Token Persistence
> Secure token storage implementations.

- [ ] Keyring store (OS credential manager via go-keyring)
- [ ] File store (AES-256-GCM encrypted, fallback)
- [ ] iOS Keychain store

### M6: Mobile Flow Handler
> Channel-based handler for deep link callbacks.

- [ ] Mobile flow handler (StartAuthFlow + DeliverURL)

### M7: Refresh Loop and Event Bus
> Background token refresh and event utilities.

- [ ] Event bus utilities (DeferredEventBus, NoopEventBus)
- [ ] Background refresh loop (DHCP-style timing)

### M8: Integration
> First working end-to-end desktop login.

- [ ] End-to-end integration test
- [ ] Package documentation (doc.go files)

### M9: wails-pkceflow Wrapper
> Wails v3 service adapter and event bridge.

- [ ] Initialize wails-pkceflow module
- [ ] Wails auth service adapter
- [ ] Wails event bridge
- [ ] Deep link router (mobile)

### M10: Documentation and Release
> Examples, guides, and v1.0 release prep.

- [ ] Getting started guide
- [ ] IdP setup guides (Keycloak, Entra ID, Auth0, Okta, Google)
- [ ] Desktop setup guide
- [ ] iOS / Android deep link setup guides
- [ ] Migration guide (from custom implementations)
- [ ] Example: Wails desktop app
- [ ] Example: CLI app
- [ ] v1.0.0-beta.1 release

## Version Plan

- `v0.x` -- API exploration, breaking changes expected
- `v1.0.0-beta.x` -- Feature-complete, seeking feedback
- `v1.0.0-rc.x` -- API frozen, bug fixes only
- `v1.0.0` -- Stable release
