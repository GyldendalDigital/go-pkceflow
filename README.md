# go-pkceflow

A framework-agnostic Go library for OIDC Authorization Code flow with PKCE (RFC 7636, RFC 8252). Designed for native applications -- desktop, mobile, and CLI -- with pluggable token storage, event emission, and platform-specific auth flow handlers.

## Status

**Pre-1.0 beta.** The API may still change. A vanilla Keycloak run has covered
login, token exchange, refresh, and logout on Linux, plus login, exchange, and
refresh on Windows. macOS, mobile, and Windows logout still need manual
validation before a stable release.

## Features

- OIDC discovery and PKCE S256 authorization code flow
- Desktop auth via localhost callback server and system browser
- Shared localhost callback broker (concurrent logins/logout, no port conflicts)
- Mobile auth via deep links (Universal Links / App Links)
- RP-Initiated Logout with separate, correlated post-logout redirect URIs
- ID token claims decoding (`client.Claims()`)
- Encrypted token persistence (AES-256-GCM filestore, pluggable interface)
- Background token refresh with adaptive timing
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
    "log"

    "github.com/GyldendalDigital/go-pkceflow"
    "github.com/GyldendalDigital/go-pkceflow/desktopflow"
    "github.com/GyldendalDigital/go-pkceflow/filestore"
)

func main() {
    ctx := context.Background()

    handler := desktopflow.New(15051)
    store, err := filestore.NewDefault("com.example.myapp")
    if err != nil {
        log.Fatal(err)
    }

    client, err := pkceflow.New(pkceflow.Config{
        IssuerURL: "https://your-idp.com/realms/your-realm",
        ClientID:  "your-client-id",
    }, handler, pkceflow.WithTokenPersistence(store))
    if err != nil {
        log.Fatal(err)
    }

    client.RestoreSession()
    if err := client.Init(ctx); err != nil {
        if !client.AuthStatus().CanUseApp {
            log.Fatal(err)
        }
        log.Printf("OIDC discovery unavailable; using restored session: %v", err)
    }

    client.StartRefreshLoop(ctx)
    defer client.StopRefreshLoop()

    if !client.AuthStatus().CanUseApp {
        if err := client.Login(ctx); err != nil { // opens the system browser
            log.Fatal(err)
        }
    }

    token := client.AccessToken(ctx)
    status := client.AuthStatus()
    if status.GraceMode {
        fmt.Println("Restored offline session in grace mode; API token may be expired.")
        return
    }
    if !status.Valid || token == "" {
        log.Fatal("no valid access token")
    }
    fmt.Println("Authenticated; a valid access token is available to the Go backend.")
}
```

Register `http://127.0.0.1:15051/callback` as an allowed native-app redirect
URI at the provider. The provider guides below cover the other required
settings. Keep access and refresh tokens in the Go backend; do not display them
or send them to a webview.

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
`client_secret`; native apps cannot keep one secret. Token requests put
`client_id` in the form body and never probe HTTP Basic authentication.

The default scopes are `openid profile email offline_access`. A provider may
require additional setup before it issues a refresh token, or a different
scope/authorization parameter entirely. Override `Config.Scopes` deliberately
when that is the case.

`Config.ExtraAuthParams` and `Config.ExtraTokenParams` are only for
provider-specific additions such as `prompt`, `audience`, or `resource`.
Protected OAuth/OIDC/PKCE parameters such as `nonce`, `state`, `scope`,
`redirect_uri`, `code_challenge`, `code_verifier`, `client_id`, and
`client_secret` are owned by the library and rejected during validation.
`ExtraTokenParams` applies to the initial authorization-code exchange, not
later refresh requests.

Use `WithHTTPClient` when discovery, JWKS, and token requests need a proxy,
custom CA bundle, mutual TLS, or transport tuning.

## Documentation

New to OAuth/OIDC or setting up an IdP for the first time? Start here:

| Guide | What it covers |
|-------|----------------|
| [How it works](docs/how-it-works.md) | Plain-language explanation of PKCE, the flow, tokens, and what the library does and does not solve |
| [Keycloak setup](docs/idp-setup-keycloak.md) | Run Keycloak locally and configure a public client, field by field |
| [Auth0 setup](docs/idp-setup-auth0.md) | Configure a hosted Native application, API audience, and refresh tokens |
| [Microsoft Entra ID setup](docs/idp-setup-entra.md) | Configure a native app registration, tenant issuer, redirects, and delegated scopes |
| [Generic OIDC setup](docs/idp-setup-generic-oidc.md) | Check any provider for discovery, public-client PKCE, refresh, and logout compatibility |
| [Mobile deep linking](docs/mobile-deep-linking.md) | Universal Links / App Links / custom schemes and wiring `DeliverURL` |
| [Architecture](docs/architecture.md) | Internal design, interfaces, token lifecycle |
| [Roadmap](docs/roadmap.md) | Completed milestones, remaining hardening, and release path |

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
