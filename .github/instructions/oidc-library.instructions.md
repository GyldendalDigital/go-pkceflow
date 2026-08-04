---
applyTo: "**/go-pkceflow/**,**/wails-pkceflow/**,**/docs/oidc-library-*"
---

# OIDC Library Development Instructions

When working on go-pkceflow or wails-pkceflow code, follow these guidelines.

## Architecture

- **Core (`go-pkceflow`)**: Framework-agnostic Go OIDC PKCE library. Zero Wails imports. Ships desktop, mobile flow handlers and platform token storage.
- **Wrapper (`wails-pkceflow`)**: Thin Wails v3 adapter. Depends on core. Forwards Wails launch-URL events to mobileflow, bridges events, and provides a ready-to-use desktop service. Native Android/iOS event production is owned by Wails.
- **Separate repos**: Independent versioning and release cycles.
- **Platform boundary**: Desktop consumers use the included loopback handler.
  Mobile consumers configure OS link registration and pass launch URLs to
  `mobileflow.DeliverURL`, either directly or through a framework adapter.
  Wails v3.0.0-beta.2 does not yet produce those mobile launch-URL events.

## Design Principles

1. No framework dependencies in core (no Wails, no Fyne). No CGo; the library must cross-compile from any platform without platform toolchains.
2. Focused interfaces: AuthFlowHandler, TokenPersistence, EventEmitter (not a mega-interface)
3. Configuration via explicit struct with Validate() method and sensible defaults
4. All errors wrap with %w and include actionable context (what URL, what operation)
5. Named sentinel errors for typed checking: ErrNotInitialized, ErrFlowCancelled, ErrStateMismatch
6. No global state; everything constructed and injected
7. TokenFn pattern: `func() string` for injecting into HTTP clients

## Security Requirements

- PKCE S256 only (never plain)
- State parameter: 32 bytes, crypto/rand, base64url, compared with subtle.ConstantTimeCompare
- Never log access tokens, refresh tokens, ID tokens, or authorization codes
- Token storage: AES-256-GCM encrypted filestore with machine-ID derived key; fallback to persisted random key (not hostname)
- Mobile: app sandbox provides isolation (same security model as browser cookies); filestore works without additional platform code
- Desktop: encrypted file in the user config directory; verified `0600` mode
  on POSIX and a caller-private inherited ACL on Windows
- TokenPersistence interface enables test doubles and future alternative backends (e.g., OS keyring) without breaking changes
- Localhost server: bind loopback only (`127.0.0.1`, plus `[::1]` when the
  configured host is `localhost`), never a wildcard address

## Testing

- Core must be testable without a real IdP
- Use `oidctest.FakeIDPServer` for integration tests
- Use `oidctest.MemoryStore` for unit tests
- Use `oidctest.RecordingEmitter` to assert events
- All interfaces have test doubles in the oidctest package

## Standards Compliance

- RFC 8252 (OAuth 2.0 for Native Applications)
- RFC 7636 (Proof Key for Code Exchange)
- OpenID Connect Core 1.0
- OpenID Connect RP-Initiated Logout 1.0

## IdP Compatibility

Support these IdPs (test with FakeIDPServer, document quirks):
- Keycloak (primary; manually smoke-tested on Linux and Windows, with
  application dogfooding pending)
- Microsoft Entra ID (needs ExtraAuthParams for prompt, audience)
- Auth0 (needs audience param)
- Okta (standard)
- Google (needs access_type=offline instead of offline_access scope)
