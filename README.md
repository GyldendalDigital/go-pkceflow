# go-pkceflow

A framework-agnostic Go library for OIDC Authorization Code flow with PKCE (RFC 7636, RFC 8252). Designed for native applications -- desktop, mobile, and CLI -- with pluggable token storage, event emission, and platform-specific auth flow handlers.

## Status

**Early development.** The API is not stable and the library is not yet ready for use.

## Features

- OIDC discovery and PKCE S256 authorization code flow
- Desktop auth via localhost callback server and system browser
- Shared localhost callback broker (concurrent logins/logout, no port conflicts)
- Mobile auth via deep links (Universal Links / App Links)
- RP-Initiated Logout with separate, correlated post-logout redirect URIs
- ID token claims decoding (`client.Claims()`)
- Encrypted token persistence (AES-256-GCM filestore, pluggable interface)
- Background token refresh with DHCP-style adaptive timing
- Offline grace period for intermittent connectivity
- Event-driven auth state notifications
- Custom HTTP client injection (`WithHTTPClient`) for proxies, custom CA/mTLS, and transport tuning
- Test infrastructure (`oidctest` package with FakeIDPServer) for testing without a real IdP
- No CGo -- cross-compiles from any platform

## Installation

```bash
go get github.com/GyldendalDigital/go-pkceflow
```

## Quick Start

```go
package main

import (
    "context"
    "fmt"

    "github.com/GyldendalDigital/go-pkceflow"
    "github.com/GyldendalDigital/go-pkceflow/desktopflow"
    "github.com/GyldendalDigital/go-pkceflow/filestore"
)

func main() {
    // Set up components
    handler := desktopflow.New(15051)
    store, _ := filestore.New("my-app", "/home/user/.config/my-app")

    // Create client
    client, _ := pkceflow.New(pkceflow.Config{
        IssuerURL: "https://your-idp.com/realms/your-realm",
        ClientID:  "your-client-id",
    }, handler, pkceflow.WithTokenPersistence(store))

    ctx := context.Background()

    // Initialize and login
    client.Init(ctx)
    client.Login(ctx) // opens system browser

    // Use the token
    token := client.AccessToken(ctx)
    fmt.Println("Authenticated! Token:", token[:8]+"...")
}
```

## Example CLI App

An interactive CLI demonstrating the full auth lifecycle is included:

```bash
go run ./examples/cli \
  --issuer=https://your-idp.com \
  --client-id=your-client-id \
  --port=15051
```

This opens a menu for login, logout, token inspection, and status display.
See [`examples/cli/main.go`](examples/cli/main.go) for the complete source.

To try a distinct, separately registered post-logout redirect URI, add
`--logout-path=/logout` (and register that URI with your IdP).

## Configuration Notes

go-pkceflow targets public native clients. Do not configure or pass a
`client_secret`; native apps cannot keep one secret. `Config.ExtraAuthParams`
and `Config.ExtraTokenParams` are only for provider-specific additions such as
`prompt`, `audience`, or `resource`. Protected OAuth/OIDC/PKCE parameters such
as `nonce`, `state`, `scope`, `redirect_uri`, `code_challenge`,
`code_verifier`, `client_id`, and `client_secret` are owned by the library and
rejected during validation.

## Documentation

New to OAuth/OIDC or setting up an IdP for the first time? Start here:

| Guide | What it covers |
|-------|----------------|
| [How it works](docs/how-it-works.md) | Plain-language explanation of PKCE, the flow, tokens, and what the library does and does not solve |
| [Keycloak setup](docs/idp-setup-keycloak.md) | Run Keycloak locally and configure a public client, field by field |
| [Auth0 setup](docs/idp-setup-auth0.md) | Configure a hosted Native application (plus an Entra ID note) |
| [Mobile deep linking](docs/mobile-deep-linking.md) | Universal Links / App Links / custom schemes and wiring `DeliverURL` |
| [Architecture](docs/architecture.md) | Internal design, interfaces, token lifecycle |

## Packages

| Package | Purpose |
|---------|---------|
| `pkceflow` | Core Client API (New, Init, Login, Logout, AccessToken, AuthStatus) |
| `desktopflow` | Localhost callback server + system browser opener |
| `mobileflow` | Channel-based handler for mobile deep link callbacks |
| `filestore` | AES-256-GCM encrypted token persistence |
| `eventbus` | DeferredEventBus (startup ordering) and NoopEventBus |
| `oidctest` | FakeIDPServer and test doubles (MemoryStore, RecordingEmitter, FakeFlowHandler) |

## Related

- [wails-pkceflow](https://github.com/GyldendalDigital/wails-pkceflow) -- Wails v3 service wrapper for this library

## License

[MIT](LICENSE)
