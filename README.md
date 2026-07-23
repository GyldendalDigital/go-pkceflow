# go-pkceflow

A framework-agnostic Go library for OIDC Authorization Code flow with PKCE (RFC 7636, RFC 8252). Designed for native applications -- desktop, mobile, and CLI -- with pluggable token storage, event emission, and platform-specific auth flow handlers.

## Status

**Early development.** The API is not stable and the library is not yet ready for use.

## Features (planned)

- OIDC discovery and PKCE S256 authorization code flow
- Desktop auth via localhost callback server and system browser
- Mobile auth via deep links (Universal Links / App Links)
- Pluggable token persistence (encrypted filestore default, interface for custom backends)
- Background token refresh with DHCP-style adaptive timing
- Offline grace period for intermittent connectivity
- Event-driven auth state notifications
- Test infrastructure (`oidctest` package) for testing without a real IdP

## Installation

```bash
go get github.com/GyldendalDigital/go-pkceflow
```

## Related

- [wails-pkceflow](https://github.com/GyldendalDigital/wails-pkceflow) -- Wails v3 service wrapper for this library

## License

[MIT](LICENSE)
