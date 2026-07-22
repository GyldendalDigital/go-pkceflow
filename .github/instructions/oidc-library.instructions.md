---
applyTo: "**/go-pkceflow/**,**/wails-pkceflow/**,**/docs/oidc-library-*"
---

# OIDC Library Development Instructions

When working on go-pkceflow or wails-pkceflow code, follow these guidelines.

## Architecture

- **Core (`go-pkceflow`)**: Framework-agnostic Go OIDC PKCE library. Zero Wails imports. Ships desktop, mobile flow handlers and platform token storage.
- **Wrapper (`wails-pkceflow`)**: Thin Wails v3 adapter. Depends on core. Routes deep links to mobileflow, bridges events, provides ready-to-use service.
- **Separate repos**: Independent versioning and release cycles.
- **Developer writes zero platform auth code**: Install, configure, set up IdP/DNS/manifests, call Login().

## Design Principles

1. No framework dependencies in core (no Wails, no Fyne). Platform-native code (CGo) allowed behind build tags for OS-level integrations (Keychain).
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
- Desktop token storage: OS credential manager via `zalando/go-keyring` (macOS Keychain, Linux secret-service, Windows Credential Manager)
- iOS token storage: Keychain via `keybase/go-keychain` (hardware-backed, survives reinstall)
- Android token storage: filestore in app sandbox (kernel-enforced UID isolation, same security model as browser cookies). Interface allows EncryptedSharedPreferences upgrade for high-security apps.
- Fallback token storage: AES-256-GCM filestore with machine-ID derived key; fallback to persisted random key (not hostname)
- Localhost server: bind 127.0.0.1 only (never 0.0.0.0)

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
- RP-Initiated Logout (draft-ietf-connect-rpinitiated)

## IdP Compatibility

Support these IdPs (test with FakeIDPServer, document quirks):
- Keycloak (primary, production-tested in Ordnett Pluss)
- Microsoft Entra ID (needs ExtraAuthParams for prompt, audience)
- Auth0 (needs audience param)
- Okta (standard)
- Google (needs access_type=offline instead of offline_access scope)

## Reference

- Technical plan: `.agent-sessions/oidc-library-technical-plan.md`
- Mobile/storage revision: `.agent-sessions/plans/plan-mobile-implementations-in-library.md`
- Session context: `.agent-sessions/oidc-library-session-context.md`
- Reference implementation (external): `~/dev/ordnett_pluss_v4/lib/auth.go`, `lib/tokenstore.go`, `lib/platform.go`, `lib/eventbus.go`
