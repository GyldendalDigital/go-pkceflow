# Changelog

All notable changes to go-pkceflow are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- **Behaviour change:** the offline grace period no longer extends a session the
  provider has authoritatively refused. When a refresh fails with
  `invalid_grant` — the provider was reachable and rejected the refresh token as
  revoked or expired — the session now ends at once: `AccessToken` returns `""`,
  `AuthStatus` reports `GraceMode: false` and `CanUseApp: false`, and
  `oidcauth:session-expired` is emitted immediately instead of at
  `LastAuthAt + GracePeriod`. The refusal is persisted, so it also survives a
  restart; previously the block was in-memory only, so a revoked account regained
  a full grace window on every launch. Grace exists for "the app could not reach
  the provider", not for "the provider said no": before this change a
  deliberately revoked account kept working for the entire configured grace
  window, on a working network.

  Unchanged and still covered by grace: transport errors, timeouts, DNS
  failures, offline use, and any response that carries no OAuth error code
  (including 5xx and non-standard bodies) — classification is by error code, not
  by HTTP status. So are `invalid_client` / `unauthorized_client`, which refuse the client
  registration rather than the token, and a fresh `Login` would fail too, so
  ending grace there would strand the user. Also unchanged: a refusal is treated
  as inconclusive, and grace is kept, when an earlier refresh for the same
  generation was abandoned in flight (a cancelled request, `Pause`, or mobile
  backgrounding) or when stored state holds a demonstrably newer refresh token.
  Both indicate refresh-token rotation rather than revocation.

  The refused session keeps its ID token, so `Claims` still names the user a
  re-authentication prompt should address, and drops every credential and
  timestamp. Applications that relied on grace surviving revocation must treat
  `oidcauth:session-expired` and `AuthStatus().CanUseApp == false` as the
  authoritative signal to re-authenticate, and must not infer session state from
  resource-server status codes.
- `IsPermanentError` is unchanged in behaviour, but its documentation no longer
  claims a permanent error means the refresh token is invalid: only
  `invalid_grant` says that, and only that code ends grace.
- Refresh failures that permanently park a token generation, and
  session-integrity failures, are now logged at Warn rather than Debug on both
  the on-demand and background-loop paths, so a revocation leaves a trace under
  a default handler.
- Documentation: refreshed the stale pre-1.0 release gate status (#88) and
  aligned the logout callback examples with the CLI default (#89).

### Security
- ID token `azp` (authorized party) validation on both login and refresh, per
  OIDC Core 3.1.3.7. go-oidc only checks that the client ID appears in `aud`, so
  an ID token issued to a *different* client was previously accepted. A present
  `azp` must equal the configured client ID; an absent one is accepted for a
  single-audience token and rejected when the token carries more than one
  audience, where the spec requires it. A mismatch is logged at Warn with both
  client IDs so a provider misconfiguration is diagnosable in the field.

### Added
- `oidctest`: `SetForceAzp`, `SetForceAzpRawJSON`, and `SetForceAudiences` for
  adversarial authorized-party and multi-audience ID token testing.
- Best-effort RFC 7009 refresh-token revocation during `Logout`, when discovery
  advertises a `revocation_endpoint`. RP-Initiated Logout ends the browser
  session but does not necessarily invalidate an offline grant, and
  `offline_access` is requested by default, so previously a copy of the token
  store taken before logout could stay redeemable for the provider's whole
  offline-session window. The POST runs after the local commit and before the
  browser round trip, carries `token_type_hint=refresh_token` and the public
  `client_id`, is bounded by its own short timeout so it cannot starve the
  browser logout, and never follows redirects, so a discovery document cannot
  replay a refresh token to another host. Failures are logged without token or
  response-body text and never change what `Logout` returns. A logout superseded
  by a newer `Login` skips revocation, because session-bound refresh tokens make
  it possible to tear down the session that `Login` just established. Providers
  without RFC 7009 support, such as Microsoft Entra ID, are unaffected.
- `oidctest`: a `/revoke` endpoint that really invalidates the refresh token,
  `revocation_endpoint` in the discovery document,
  `Hooks.SetRevocationHook`, and `WithOmitRevocationEndpoint`.

## [v0.9.0-beta.10] - 2026-08-11

### Added
- `BearerTransport` for automatic access-token injection into an `http.Client`
  (#87).

### Changed
- `examples/cli`: `--logout-path` now defaults to `/logout-callback` instead of
  being empty (#86).
- Documentation: separated the desktop and mobile callback sections (#85).

## [v0.9.0-beta.9] - 2026-08-08

### Added
- `desktopflow`: `LogoutHTML` for a distinct logout callback page (#83).

### Changed
- Documentation: documented `LogoutHTML`, `SetLogoutPath`, and custom callback
  pages (#84).

## [v0.9.0-beta.8] - 2026-08-07

### Added
- `oidctest`: Strict native-client protocol enforcement (PKCE mandatory,
  redirect URI validation, code expiry, response_type and scope checks) (#77).
- `oidctest`: Adversarial ID token and JWKS testing (key rotation, forced
  issuer/audience/expiry, JWKS failure simulation) (#78).
- `oidctest`: Request/response scripting (per-endpoint hooks, request recorder,
  per-grant-type error injection) (#79).
- `oidctest`: `RecordingEmitter.WaitForEvent` for async test assertions (#80).
- `oidctest`: `FailingStore` for testing persistence error paths (#80).
- `CHANGELOG.md` (#81).

### Changed
- **Breaking:** `DefaultScopes` is now a function returning a fresh copy on each
  call, instead of a package-level variable. Callers that read or mutated the
  variable must call `DefaultScopes()` (#82).

### Fixed
- Fence canceled and stale `Init` generations so a superseded discovery call
  cannot commit its snapshot or emit `oidcauth:init-failed` (#76).

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

[Unreleased]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.10...HEAD
[v0.9.0-beta.10]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.9...v0.9.0-beta.10
[v0.9.0-beta.9]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.8...v0.9.0-beta.9
[v0.9.0-beta.8]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.7...v0.9.0-beta.8
[v0.9.0-beta.7]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.6...v0.9.0-beta.7
[v0.9.0-beta.6]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.5...v0.9.0-beta.6
[v0.9.0-beta.5]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.4...v0.9.0-beta.5
[v0.9.0-beta.4]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.3...v0.9.0-beta.4
[v0.9.0-beta.3]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.2...v0.9.0-beta.3
[v0.9.0-beta.2]: https://github.com/GyldendalDigital/go-pkceflow/compare/v0.9.0-beta.1...v0.9.0-beta.2
[v0.9.0-beta.1]: https://github.com/GyldendalDigital/go-pkceflow/releases/tag/v0.9.0-beta.1
