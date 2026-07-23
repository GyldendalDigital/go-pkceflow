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

- Go 1.26 or later
- No CGo required for core library (CGo used only behind build tags for platform-specific stores)

## Running Tests

```bash
go test ./...
```

All tests must pass without a real OIDC provider. The `oidctest` package provides `FakeIDPServer` and test doubles for all interfaces.

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

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
