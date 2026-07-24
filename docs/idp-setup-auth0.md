# Auth0 setup (hosted IdP)

Auth0 is a hosted identity provider, so there is nothing to install. This guide
maps Auth0's terminology onto the same public-client-with-PKCE concepts covered
in the [Keycloak guide](idp-setup-keycloak.md). If you have not read the
[how-it-works](how-it-works.md) overview, start there.

## 1. Create a Native application

In Auth0, an "application" is what other IdPs call a client. The **application
type** you choose determines whether a client secret is expected and whether
PKCE is enabled.

- In the Auth0 dashboard go to "Applications" and click "Create Application".
- Choose the **Native** application type.

Native is the correct choice for desktop, mobile, and CLI apps. Auth0 configures
Native apps as public clients and enables PKCE for the Authorization Code flow
automatically, which is exactly what go-pkceflow needs. Do not pick "Regular Web
Application" (that is a confidential client with a secret) or "Single Page
Application".

## 2. Note your issuer and client id

On the application's "Settings" tab:

- **Domain**: something like `your-tenant.eu.auth0.com`. Your issuer URL is that
  domain with an `https://` prefix and a trailing slash:

  ```
  https://your-tenant.eu.auth0.com/
  ```

  Pass this as `Config.IssuerURL`. go-pkceflow performs OIDC discovery against
  it automatically.

- **Client ID**: pass this as `Config.ClientID`. Native apps have no client
  secret you need to use.

## 3. Configure the callback URLs

Auth0 splits the allow-lists into separate fields, mirroring how go-pkceflow
separates login and logout callbacks.

- **Allowed Callback URLs**: your login redirect URI. For the desktop handler
  with `desktopflow.New(15051)`:

  ```
  http://127.0.0.1:15051/callback
  ```

- **Allowed Logout URLs**: the post-logout redirect URI. This is a distinct
  list, which is why go-pkceflow lets you set a separate logout path with
  `handler.SetLogoutPath("/logout")`:

  ```
  http://127.0.0.1:15051/logout
  ```

  If you do not configure a separate logout path, register the same login
  callback URL here as well, because go-pkceflow reuses it.

Auth0 accepts a comma-separated list in each field. Register the exact URIs your
app uses; matching is strict.

## 4. Run go-pkceflow against it

```bash
go run ./examples/cli \
  --issuer=https://your-tenant.eu.auth0.com/ \
  --client-id=YOUR_CLIENT_ID \
  --port=15051 \
  --logout-path=/logout
```

Log in with any user that exists in your Auth0 tenant. Use "Show access token"
to inspect the ID token claims and "Logout" to exercise RP-Initiated Logout
against Auth0's end-session endpoint.

## Field-to-parameter cheat sheet

| Auth0 field | go-pkceflow | Notes |
|-------------|-------------|-------|
| Application type = Native | (implicit) | Public client with PKCE enabled |
| Domain (as `https://.../`) | `Config.IssuerURL` | Trailing slash matters |
| Client ID | `Config.ClientID` | No secret used |
| Allowed Callback URLs | `handler.RedirectURI()` | Login redirect, exact match |
| Allowed Logout URLs | `handler.PostLogoutRedirectURI()` | Separate list; register logout path |

## Why Native is low maintenance

Because the Native type turns on PKCE and public-client behavior by default,
there is little ongoing configuration: no secret to rotate, no grant types to
untangle. Once the callback URLs are registered you rarely touch the settings
again.

## A note on Microsoft Entra ID

Entra ID (formerly Azure AD) follows the same public-client-with-PKCE model. The
mapping is:

- Register an app under "App registrations".
- Add a **Mobile and desktop applications** platform (or use
  `http://localhost` / a custom scheme redirect). This marks the app as a public
  client.
- The redirect URI is your `handler.RedirectURI()`; the post-logout redirect URI
  goes under the same platform's logout settings.
- Your issuer is
  `https://login.microsoftonline.com/{tenant-id}/v2.0`, passed as
  `Config.IssuerURL`.

The concepts (public client, exact redirect URIs, PKCE S256, separate logout
URI) are identical to the Keycloak and Auth0 flows above.
