# go-pkceflow

A framework-agnostic Go library for OIDC Authorization Code flow with PKCE (RFC 7636, RFC 8252). Designed for native applications -- desktop, mobile, and CLI -- with pluggable token storage, event emission, and platform-specific auth flow handlers.

## Status

**Pre-1.0 beta.** The API may still change. A vanilla Keycloak run has covered
login, token exchange, refresh, and logout on both Linux and Windows. The
framework-agnostic mobile callback handler is tested, but each application or
framework adapter remains responsible for delivering the OS launch URL to it.
The macOS auth lifecycle still needs manual validation before a stable core
release. Mobile host validation is adapter-specific and does not gate core v1
or desktop dogfooding.

## Features

- OIDC discovery and PKCE S256 authorization code flow
- Desktop auth via localhost callback server and system browser
- Shared localhost callback broker (safe concurrency across independent clients)
- Deterministic per-client ordering for overlapping login and logout commands
- Framework-agnostic mobile callback handling for delivered Universal Links,
  App Links, and custom-scheme URLs
- RP-Initiated Logout with separate, correlated post-logout redirect URIs
- ID token claims decoding (`client.Claims()`)
- Encrypted token persistence (AES-256-GCM filestore, pluggable interface)
- Background token refresh with DHCP-style lifetime scheduling
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

    if _, err := client.RestoreSession(); err != nil {
        log.Fatal(err)
    }
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

### Injecting Tokens into HTTP Clients

Use `BearerTransport` to automatically attach the access token to every
outgoing request:

```go
httpClient := &http.Client{
    Transport: pkceflow.BearerTransport(client.TokenFn(ctx), nil),
}
resp, err := httpClient.Get("https://api.example.com/protected")
```

The transport calls `TokenFn` on each request, refreshing the token if needed.
If no valid token is available, the request is sent without an Authorization
header. The original request is never mutated.

Register `http://127.0.0.1:15051/callback` as an allowed native-app redirect
URI at the provider. The provider guides below cover the other required
settings. Keep access and refresh tokens in the Go backend; do not display them
or send them to a webview.

### Login and Logout Callbacks (Desktop)

On desktop, the library opens a localhost server and shows an HTML page in the
browser when the IdP redirects back. To show the correct page for each flow,
configure a separate logout callback path and register it as a
`post_logout_redirect_uri` with the IdP:

```go
handler := desktopflow.New(15051)
if err := handler.SetLogoutPath("/logout-callback"); err != nil {
    log.Fatal(err)
}
// Register with the IdP:
//   redirect_uri:              http://127.0.0.1:15051/callback
//   post_logout_redirect_uri:  http://127.0.0.1:15051/logout-callback
```

With this setup, login shows "Authentication Successful" and logout shows
"Logged Out." Both paths share the same loopback port — only the path differs.

If `SetLogoutPath` is not called, the library falls back to the login path for
both flows and always shows "Authentication Successful." This works but is
confusing to end users.

### Login and Logout Callbacks (Mobile)

On mobile, callbacks arrive via deep links (Universal Links on iOS, App Links on
Android). The OS intercepts the redirect and delivers it directly to the app —
no browser page is rendered, so there is no HTML to customize. Use `SetLogoutURI`
to register a distinct deep link for logout:

```go
handler := mobileflow.New("https://myapp.example.com/auth/callback", openURL)
if err := handler.SetLogoutURI("https://myapp.example.com/auth/logout-callback"); err != nil {
    log.Fatal(err)
}
// Register with the IdP:
//   redirect_uri:              https://myapp.example.com/auth/callback
//   post_logout_redirect_uri:  https://myapp.example.com/auth/logout-callback
```

The separate URI is recommended so the app can distinguish which flow completed
and update its UI accordingly (e.g. show a "welcome back" screen vs. return to
the sign-in screen). Unlike desktop, there is no `LogoutHTML` field because the
user never sees a browser tab — the app resumes immediately.

### Custom Callback Pages (Desktop Only)

Override the default HTML pages shown in the browser after a callback:

```go
handler.SuccessHTML = "<html><body>You're signed in — close this tab.</body></html>"
handler.LogoutHTML  = "<html><body>Signed out — see you next time.</body></html>"
handler.ErrorHTML   = "<html><body>Something went wrong. Try again.</body></html>"
```

For production apps, use `//go:embed` to compile HTML files into the binary:

```go
import _ "embed"

//go:embed assets/success.html
var successPage string

//go:embed assets/logout.html
var logoutPage string

func setupHandler() *desktopflow.Handler {
    handler := desktopflow.New(15051)
    _ = handler.SetLogoutPath("/logout-callback")
    handler.SuccessHTML = successPage
    handler.LogoutHTML = logoutPage
    return handler
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

The CLI configures a distinct post-logout redirect URI by default, so register
both of these with your IdP before trying logout:

```text
redirect_uri:              http://127.0.0.1:15051/callback
post_logout_redirect_uri:  http://127.0.0.1:15051/logout-callback
```

Pass `--logout-path` to choose a different path on the same host and port, or
`--logout-uri` to supply a full URI. The two flags are mutually exclusive.

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

## Token Persistence Recovery

`RestoreSession` returns whether it installed a non-zero persisted state and an
error when the persistence backend could not be accessed. Missing or malformed
stored content is a normal logged-out result (`false, nil`). A restore error
does not change existing in-memory state, and its safe public message unwraps to
the backend cause for deliberate `errors.Is` or `errors.As` inspection. Token
validity and grace eligibility remain the responsibility of `AuthStatus`.

A verified refresh remains successful for the running process even if
`TokenPersistence.Save` reports an error. Rolling memory back is unsafe when a
provider has rotated and invalidated the previous refresh token. The Client
keeps the new generation authoritative, emits its auth event once, and marks
that exact generation for persistence recovery.

The same rule applies when Login commits successfully but its first Save fails.
While `StartRefreshLoop` is active, Save is retried independently after 1, 2,
4, and later seconds, capped at one minute. `StopRefreshLoop` pauses those
retries without forgetting them. A newer Login, refresh, or Logout supersedes
stale retry work under the same commit ordering used for normal persistence.

Until a Save returns nil, a restart may load the previous state, the new state,
or no readable state, depending on where the backend failed. A previous rotated
refresh token may be rejected after restart. go-pkceflow first checks whether
the stored state holds a newer refresh token than the one that was refused; if
it does, the refusal is treated as a superseded generation and grace continues.
Otherwise the refusal is authoritative and the session ends. The library never
forces a browser login. Save-recovery errors are logged without backend error text so a
custom store cannot accidentally expose token material.

After Logout, `RestoreSession` cannot reload tokens into that same Client even
if persistent deletion failed. A fresh process has no such in-memory tombstone,
so applications should treat a logged deletion failure as uncertain restart
durability while preserving Logout's existing best-effort return contract.

## Grace Period Semantics

`Config.GracePeriod` keeps the app usable when token refresh fails. It is
deliberately asymmetric, because "we could not ask the provider" and "we asked
and were refused" are different situations:

| Refresh outcome | Grace | `oidcauth:session-expired` |
|---|---|---|
| Transport error, DNS, timeout, offline | continues | at grace end |
| Any response carrying no OAuth error code, including 5xx | continues | at grace end |
| `invalid_client`, `unauthorized_client` | continues | at grace end |
| `invalid_grant` | **ends immediately** | immediately |
| Session-integrity failure | **ends immediately** | immediately |

Only the `invalid_grant` row's event is delivered without a running refresh
loop, because it is enqueued with the state commit. Every other row is delivered
by the background supervisor, so it is deferred while that loop is stopped or
paused. `AuthStatus` is authoritative in all cases.

`invalid_grant` means the provider was reachable and refused the refresh token
itself: it is revoked or expired. Extending a session on that answer would let a
deliberately revoked account keep working for the whole grace window, so
go-pkceflow instead replaces the session with a refused one. That refused state
is persisted, so the refusal also survives a restart; it keeps the ID token, so
`Claims` still names the user for a re-authentication prompt, and drops every
credential, so nothing can be replayed.

`invalid_client` and `unauthorized_client` refuse the *client registration*
rather than the token. The user cannot resolve those, and a fresh `Login` would
fail at the authorization endpoint too, so grace continues to cover them. Note
the consequence: disabling a client registration at the provider is not a
session-revocation mechanism, since every installed app keeps working for up to
`GracePeriod`. Revoke refresh tokens or user sessions instead.

Two cases are deliberately treated as inconclusive rather than authoritative,
because a provider that rotates refresh tokens answers `invalid_grant` for a
merely superseded token: a refresh abandoned in flight (a cancelled request,
`Pause`, or mobile backgrounding), and a stored state holding a demonstrably
newer refresh token. Both keep grace.

## Concurrent Login and Logout

Lifecycle ordering is scoped to one `Client`. The latest admitted `Login` or
`Logout` supersedes an older browser operation, except that overlapping Logout
calls coalesce. A superseded login returns `ErrFlowCancelled` and cannot persist
tokens or emit `oidcauth:logged-in`, even if its handler or HTTP transport
returns a late result. Logout clears local state and attempts persistent deletion
before its best-effort provider logout round trip.

Browser handler calls on one Client are handed off serially so a cancelled
mobile deep-link waiter can unregister before its replacement begins. Separate
Client instances remain independent and may use the desktop callback broker
concurrently. UI adapters may still reject overlapping commands as a user
experience guard; the Wails wrapper returns `flow_in_progress` for that case.

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
| `pkceflow` | Core Client API (New, Init, Login, Logout, AccessToken, TokenFn, BearerTransport) |
| `desktopflow` | Localhost callback server + system browser opener |
| `mobileflow` | URI- and state-correlated handler for mobile deep link callbacks |
| `filestore` | AES-256-GCM encrypted token persistence |
| `eventbus` | DeferredEventBus (startup ordering) and NoopEventBus |
| `oidctest` | FakeIDPServer and test doubles (MemoryStore, RecordingEmitter, FakeFlowHandler) |

## Related

- [wails-pkceflow](https://github.com/GyldendalDigital/wails-pkceflow) -- Wails v3 service wrapper for this library

## License

[MIT](LICENSE)
