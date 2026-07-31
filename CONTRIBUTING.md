# Contributing to go-pkceflow

Thank you for your interest in contributing to go-pkceflow. This document explains how to get involved.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch from `master`
4. Make your changes
5. Submit a pull request targeting `master`

## Branch Model

This project uses trunk-based development:

- `master` - main branch, always the latest working code
- `feature/*` - new functionality
- `fix/*` - bug fixes
- `chore/*` - maintenance (deps, CI, tooling)
- Releases are tagged on master (e.g., `v1.0.0`)

## Commit Messages

Format: `type(scope): description`

Types: `feat`, `fix`, `chore`, `docs`, `refactor`, `test`, `ci`

Examples:
```
feat(auth): implement PKCE S256 login flow
fix(filestore): handle corrupted token file gracefully
chore: bump go-oidc v3.18.0 to v3.19.0
```

## Development Requirements

- Go 1.25 or later
- No CGo required for the core library

## Running Tests

```bash
go test ./...
go test -race -coverprofile=coverage.out ./...
go test ./.github/scripts/coveragecheck
go run ./.github/scripts/coveragecheck -profile coverage.out
```

All tests must pass without a real OIDC provider. The `oidctest` package provides `FakeIDPServer` and test doubles for all interfaces.

The coverage policy applies to library packages, not `examples`, although
examples remain part of `go test ./...`. Initial statement floors are 88% for
the root package; 80% for `desktopflow`, `eventbus`, `filestore`, and
`mobileflow`; 70% for `oidctest` and future packages; and 80% for the weighted
library aggregate. The checker compares exact covered/total statement counts,
not rounded display percentages.

## Code Guidelines

- This library implements Authorization Code with PKCE for public clients (RFC 8252, RFC 7636) -- native applications that cannot securely store a client secret
- The only supported flow is system browser redirect with PKCE S256; no implicit, client credentials, or embedded webview flows
- This is a framework-agnostic OIDC library; no imports of Wails, Fyne, or other UI frameworks
- No application-specific logic; the library provides auth primitives, not opinions on how apps use them
- No CGo; the library must cross-compile from any platform without platform toolchains
- No global state; everything is constructed and injected
- Errors must wrap with `%w` and include actionable context
- Never log tokens, codes, or secrets
- PKCE S256 only (never plain)
- All user-facing strings must support i18n
- Interfaces are focused and single-purpose

## Security

If you discover a security vulnerability, please report it privately via GitHub's security advisory feature rather than opening a public issue.

## Pull Request Process

1. Ensure all tests pass (`go test ./...`)
2. Ensure code passes `go vet ./...`
3. Update documentation if your change affects the public API
4. Fill out the PR template completely
5. One logical change per PR

## Documentation Checklist

When public API or behavior changes:

1. Check the root README and package `doc.go` examples.
2. Check `docs/how-it-works.md` and `docs/architecture.md` for lifecycle or
   security claims.
3. Check provider guides when scopes, redirects, token authentication, refresh,
   or logout behavior changes.
4. Check the paired wails-pkceflow README, package docs, and example when the
   wrapper-facing contract changes.
5. Update the roadmap and clearly distinguish automated, expected, and manually
   validated provider/platform support.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
