# Changelog

All notable changes to go-pkceflow are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `oidctest`: Strict native-client protocol enforcement (PKCE mandatory,
  redirect URI validation, code expiry, response_type and scope checks).
- `oidctest`: Adversarial ID token and JWKS testing (key rotation, forced
  issuer/audience/expiry, JWKS failure simulation).
- `oidctest`: Request/response scripting (per-endpoint hooks, request recorder,
  per-grant-type error injection).
- `oidctest`: `RecordingEmitter.WaitForEvent` for async test assertions.
- `oidctest`: `FailingStore` for testing persistence error paths.

## [v0.9.0-beta.7] - 2026-07-29

### Fixed
- Surface session restore persistence errors through the public API so callers
  can distinguish "no session" from "storage broken" (#74).

### Changed
- Clarified mobile boundaries and release gates in documentation (#73).

## [v0.9.0-beta.6] - 2026-07-25

### Fixed
- Recover failed token persistence saves without dropping the in-memory session (#69).
- Order overlapping client auth operations (Login/Logout serialization) (#68).
- Recheck refresh grace window after token refresh completes (#66).

### Added
- Native OS CI matrix gates protected branch merges (#70).
- Package-aware coverage policy enforcement (#67).
- Filestore persistence invariant hardening (#65).

## [v0.9.0-beta.5] - 2026-07-20

### Fixed
- Implement DHCP-style refresh scheduling with 50%/25%/12.5% lifetime stages
  stopping at access-token expiry (#62).
- Serialize refresh grants and session commits to prevent concurrent refresh
  races (#61).

## [v0.9.0-beta.4] - 2026-07-15

### Fixed
- Harden mobile callback correlation and active-flow filtering (#59).
- Harden refresh and OAuth parameter handling (#56).

### Added
- OS matrix CI with govulncheck (#54).
- Provider guides: Auth0, Entra ID, generic OIDC (#57).

## [v0.9.0-beta.3] - 2026-07-11

### Fixed
- Force `AuthStyleInParams` for public PKCE clients, preventing Keycloak
  single-use code invalidation when the oauth2 library probes Basic auth (#51).

## [v0.9.0-beta.2] - 2026-07-08

### Added
- `filestore.DefaultDir` and `filestore.NewDefault` helpers for standard
  XDG/AppData token storage paths (#50).
- `WithHTTPClient` option to route all library HTTP through a custom client (#49).

## [v0.9.0-beta.1] - 2026-07-04

### Added
- Initial feature-complete pre-release.
- OIDC Authorization Code + PKCE S256 login and RP-Initiated Logout.
- Token refresh with background DHCP-style scheduling.
- Desktop flow handler (loopback callback server + system browser).
- Mobile flow handler (URI-correlated deep-link handler).
- Encrypted filestore (AES-256-GCM, machine-ID key derivation).
- Event bus utilities (DeferredEventBus, NoopEventBus).
- Test infrastructure: FakeIDPServer, MemoryStore, RecordingEmitter,
  FakeFlowHandler.
- ID token claims helper.
- Example CLI application.
- Documentation: architecture, how-it-works, IdP setup guides, mobile
  deep-linking guide.

[Unreleased]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.7...HEAD
[v0.9.0-beta.7]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.6...v0.9.0-beta.7
[v0.9.0-beta.6]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.5...v0.9.0-beta.6
[v0.9.0-beta.5]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.4...v0.9.0-beta.5
[v0.9.0-beta.4]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.3...v0.9.0-beta.4
[v0.9.0-beta.3]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.2...v0.9.0-beta.3
[v0.9.0-beta.2]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.1...v0.9.0-beta.2
[v0.9.0-beta.1]: https://github.com/GyldendalDigital/go-pkceflow/releases/tag/v0.9.0-beta.1
