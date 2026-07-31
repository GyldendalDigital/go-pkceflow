# Agent Guidance for go-pkceflow and wails-pkceflow

This file is the canonical agent guidance for the paired PKCE libraries:

- `go-pkceflow`: framework-agnostic OIDC Authorization Code + PKCE core.
- `wails-pkceflow`: thin Wails v3 wrapper that depends on the core.

When working in the wrapper repository, also read its local `AGENTS.md` for
wrapper-specific constraints. Keep this file portable for contributors who clone
only the core repository.

## Project Shape

- Core repository: `github.com/GyldendalDigital/go-pkceflow`
- Wrapper repository: `github.com/GyldendalDigital/wails-pkceflow`
- Development workspace often has both repos as siblings under `go-pkceflow/`
  with a dev-only `go.work`.
- Core must have zero Wails, UI framework, or application-specific imports.
- Wrapper may depend on core and Wails v3, but must not reimplement OIDC logic.

## Current Architecture

Core owns:

- OIDC discovery and Authorization Code + PKCE S256.
- Login, logout, ID token verification, nonce/state validation.
- Token refresh, refresh loop, grace-period behavior, and auth events.
- Platform-neutral interfaces: `AuthFlowHandler`, `LogoutFlowHandler`,
  `TokenPersistence`, and `EventEmitter`.
- Desktop flow handler, mobile flow handler, encrypted filestore, event bus,
  and `oidctest` fake IdP/test doubles.

Wrapper owns:

- Wails v3 `AuthService` lifecycle glue.
- Wails event bridge for core `oidcauth:*` events.
- Frontend-safe DTOs and `AuthResult` values.
- Deep-link delivery from Wails launch URL events into `mobileflow`.

## Security and Protocol Rules

- PKCE S256 only. Never implement or enable PKCE `plain`.
- Use system browser based flows only. No embedded webview login.
- State and nonce must be generated with `crypto/rand` and compared with
  `subtle.ConstantTimeCompare`.
- Never log access tokens, refresh tokens, ID tokens, authorization codes, PKCE
  verifiers, client secrets, or raw token endpoint response bodies.
- Native apps are public clients. Do not introduce client-secret based flows.
- Access tokens are opaque to clients. Do not decode them in the library.
- ID token claims may be decoded only after the token was already verified
  during login/refresh.
- Desktop callback servers must bind loopback only. Never bind wildcard
  addresses.
- Token persistence must stay pluggable. Security-sensitive storage behavior
  belongs behind `TokenPersistence`.
- Default filestore encryption uses AES-256-GCM and per-user file permissions.
  Stronger storage backends should be additive.

## API and Go Design Rules

- Keep public interfaces small and focused.
- Prefer explicit config, functional options, and dependency injection over
  global state.
- Preserve framework independence in core.
- Use idiomatic Go errors with `%w` and actionable context.
- Preserve stable sentinel errors and event names where possible.
- Do not introduce CGo into core.
- Keep changes scoped to the task and surrounding ownership boundary.
- Public API changes require README/docs updates and focused tests.

## Testing and Verification

Core tests must not require a real IdP by default. Use:

- `oidctest.FakeIDPServer` for integration-like auth tests.
- `oidctest.MemoryStore` for persistence tests.
- `oidctest.RecordingEmitter` for event assertions.
- Injectable browser openers or URL openers for desktop/mobile flow tests.

Common checks:

```bash
go test ./...
go test -race -coverprofile=coverage.out ./...
go test ./.github/scripts/coveragecheck
go run ./.github/scripts/coveragecheck -profile coverage.out
go vet ./...
```

For security-sensitive or cross-platform work, also consider:

- race tests where relevant
- OS build/test matrix
- `govulncheck`
- real IdP smoke validation, documented separately from automated tests

## Git Workflow

- Branch from `master`.
- Use one branch per work package.
- Keep PRs focused.
- Do not combine unrelated refactors with feature, fix, or test work.
- Use conventional commit style: `feat`, `fix`, `test`, `docs`, `ci`, `chore`,
  or `refactor`.
- Do not rewrite, reset, or delete user work unless explicitly asked.
- After a PR is merged, fetch/prune, return to `master`, fast-forward, and
  delete stale local branches only when safe or explicitly confirmed.

## Session Continuity

Because long sessions may be interrupted, keep local handoff state current when
working in the maintainer workspace:

- Core handoff file: `.agent-sessions/session-state-2026-07-29.md`
- Plan directory: `.agent-sessions/plans/`

Update the handoff after material changes:

- branch or PR state
- decisions and rationale
- tests run and results
- blockers
- next actions

These files are local workflow notes and may be gitignored.

## Council Workflow

For non-trivial auth, security, API, cross-platform, persistence, release, or
documentation architecture work, use a council review style. If subagent tools
are available, delegate independent read-heavy review or validation tasks to
subagents. Keep write-heavy work coordinated by the main agent unless write
scopes are clearly disjoint.

Council lenses:

1. OIDC/OAuth protocol: RFC 8252, RFC 7636, OIDC Core, RP-Initiated Logout,
   IdP compatibility.
2. Security: threat model, token handling, logging, persistence, callback
   safety, replay/CSRF protections.
3. Desktop platform: loopback binding, browser opener behavior, port lifecycle,
   Windows/macOS/Linux differences.
4. Mobile platform: Universal Links, App Links, custom schemes, app lifecycle,
   callback delivery.
5. Go library design: API shape, package boundaries, interfaces, tests,
   dependency hygiene.
6. Wails integration: service lifecycle, bindings, event bridge, frontend-safe
   surface.
7. Developer experience: docs, examples, error messages, setup pitfalls, release
   readiness.

Council output should be concrete:

- findings with file references where possible
- risks and mitigations
- proposed scope boundaries
- tests or docs needed
- open questions for the maintainer

## Planning Expectations

Use a written plan for substantial or risky tasks, especially security,
protocol, public API, release, or cross-repo work. A good plan includes:

- goal and scope
- affected files
- council concerns
- chosen approach and alternatives rejected
- test strategy
- risks and rollback path

Small, clear edits can be implemented directly, but still verify and summarize
the result.

## Documentation Expectations

Docs should stay vendor- and consumer-agnostic unless they are explicitly IdP
setup guides. Keep provider guides practical and maintainable.

Useful docs in core:

- `README.md`
- `docs/architecture.md`
- `docs/how-it-works.md`
- `docs/roadmap.md`
- `docs/mobile-deep-linking.md`
- `docs/idp-setup-keycloak.md`
- `docs/idp-setup-auth0.md`

## Current Backlog Priorities

As of the July 29, 2026 handoff:

1. Reconcile or close stale done issues for wrapper M9 and real-IdP validation.
2. Harden core coverage, especially filestore fallback/re-key/corruption paths
   and refresh/grace edge cases.
3. Add core OS matrix and `govulncheck`.
4. Add Entra ID and generic OIDC setup docs.
5. Validate mobile deep-link delivery on emulator/device.
6. Dogfood with the Ordnett Pluss rewrite after library stability work.
