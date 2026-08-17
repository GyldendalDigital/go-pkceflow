# Auth0 setup (hosted IdP)

Auth0 is a hosted identity provider, so there is nothing to install. This guide
maps Auth0's terminology onto the same public-client-with-PKCE concepts covered
in the [Keycloak guide](idp-setup-keycloak.md). If you have not read the
[how-it-works](how-it-works.md) overview, start there.

This guide describes the expected configuration from Auth0's current
first-party documentation. Keycloak is currently the only provider on which
this project has completed its own live end-to-end validation.

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

Do not copy the application secret into the app. go-pkceflow sends only the
public `client_id` in the token request body.

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
  `handler.SetLogoutPath("/logout-callback")`:

  ```
  http://127.0.0.1:15051/logout-callback
  ```

  The example CLI uses that same path by default.

  If you do not configure a separate logout path, register the same login
  callback URL here as well, because go-pkceflow reuses it.

Auth0 accepts a comma-separated list in each field. Register the exact URIs your
app uses; matching is strict.

For browser logout, also open the tenant's advanced login/logout settings and
enable **RP-Initiated Logout End Session Endpoint Discovery**. Newer tenants
normally enable it by default. go-pkceflow only starts the browser logout when
`end_session_endpoint` appears in discovery; otherwise it still clears the
local session.

## 4. Configure API access when needed

An Auth0 API has an **Identifier**, often a URL such as
`https://api.example.com`. Basic OIDC login does not necessarily need it. When
the access token must target that API, send the identifier as Auth0's
authorization-request `audience` parameter:

```go
cfg := pkceflow.Config{
    IssuerURL: "https://your-tenant.eu.auth0.com/",
    ClientID:  "YOUR_CLIENT_ID",
    ExtraAuthParams: map[string]string{
        "audience": "https://api.example.com",
    },
}
```

Add API permissions to `Config.Scopes` as well. When you set `Scopes`, include
the OIDC scopes you still need because it replaces the defaults:

```go
Scopes: []string{
    "openid", "profile", "email", "offline_access", "read:messages",
},
```

## 5. Enable refresh tokens

go-pkceflow includes `offline_access` in its default scopes. For Auth0 to return
a refresh token for an API:

- enable **Allow Offline Access** in that API's settings;
- make sure the Native application has the **Refresh Token** grant type
  enabled; and
- keep `offline_access` in `Config.Scopes`.

Refresh Token Rotation is supported and recommended for native clients. When
Auth0 rotates a token, go-pkceflow installs the replacement in memory and
persists it. If storage reports a failure, the active refresh loop retries that
same generation without repeating the Auth0 grant. Configure rotation and
expiration to match your application's session policy; those are provider
policy decisions, not client-library defaults.

## 6. Run go-pkceflow against it

```bash
go run ./examples/cli \
  --issuer=https://your-tenant.eu.auth0.com/ \
  --client-id=YOUR_CLIENT_ID \
  --port=15051
```

The CLI already defaults to `--logout-path=/logout-callback`, matching the
Allowed Logout URL registered above.

Log in with any user that exists in your Auth0 tenant. Use "Show access token"
to inspect the verified ID token claims and "Logout" to exercise RP-Initiated
Logout against Auth0's end-session endpoint.

The CLI demonstrates basic OIDC login and does not have an `audience` flag. Use
the `ExtraAuthParams` configuration above in your application when calling a
custom API.

## Field-to-parameter cheat sheet

| Auth0 field | go-pkceflow | Notes |
|-------------|-------------|-------|
| Application type = Native | (implicit) | Public client with PKCE enabled |
| Domain (as `https://.../`) | `Config.IssuerURL` | Trailing slash matters |
| Client ID | `Config.ClientID` | No secret used |
| Allowed Callback URLs | `handler.RedirectURI()` | Login redirect, exact match |
| Allowed Logout URLs | `handler.PostLogoutRedirectURI()` | Separate list; register logout path |
| API Identifier | `ExtraAuthParams["audience"]` | Optional for login; required when targeting that API |
| API Allow Offline Access | Default `offline_access` scope | Required when a refresh token is expected for that API |
| Refresh Token Rotation | Revision-fenced persistence recovery | Rotated tokens replace the previous generation; failed local saves are retried |

## Why Native is low maintenance

Because the Native type turns on PKCE and public-client behavior by default,
there is no client secret to rotate. Once callback URLs, API access, and refresh
policy are set, the remaining maintenance is mostly tenant policy rather than
client credentials.

## Troubleshooting

- **`unauthorized` or an opaque access token for the wrong API**: check the
  Auth0 API Identifier and `ExtraAuthParams["audience"]`.
- **Login succeeds but no refresh token arrives**: check `offline_access`, the
  API's **Allow Offline Access** setting, and the application's Refresh Token
  grant.
- **`invalid_grant` after refresh**: inspect the Auth0 tenant logs for expiry,
  revocation, or refresh-token reuse detection. Do not retry with an older
  rotated token.
- **Logout does not return to the app**: add the exact post-logout URI to
  **Allowed Logout URLs** and confirm RP-Initiated Logout endpoint discovery is
  enabled for the tenant.

For Microsoft identity, use the separate
[Microsoft Entra ID guide](idp-setup-entra.md).

## References

- [Auth0: Authorization Code Flow with PKCE token exchange](https://auth0.com/docs/api/authentication/authorization-code-flow-with-pkce/get-token-pkce)
- [Auth0: Configure Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/configure-refresh-token-rotation)
- [Auth0: Application Settings](https://auth0.com/docs/get-started/applications/application-settings)
- [Auth0: Log users out with the OIDC endpoint](https://auth0.com/docs/authenticate/login/logout/log-users-out-of-auth0)
