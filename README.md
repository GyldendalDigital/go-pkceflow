# go-pkceflow

A framework-agnostic Go library for OIDC Authorization Code flow with PKCE (RFC 7636, RFC 8252). Designed for native applications -- desktop, mobile, and CLI -- with pluggable token storage, event emission, and platform-specific auth flow handlers.

## Status

**Early development.** The API is not stable and the library is not yet ready for use.

## Features

- OIDC discovery and PKCE S256 authorization code flow
- Desktop auth via localhost callback server and system browser
- Mobile auth via deep links (Universal Links / App Links)
- Encrypted token persistence (AES-256-GCM filestore, pluggable interface)
- Background token refresh with DHCP-style adaptive timing
- Offline grace period for intermittent connectivity
- Event-driven auth state notifications
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
