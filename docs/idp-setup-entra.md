# Microsoft Entra ID setup

This guide configures a Microsoft Entra ID app registration as a public native
client for Authorization Code + PKCE.

It is based on Microsoft's current protocol and app-registration
documentation. The project has not yet recorded a live Entra end-to-end run, so
keep that distinction when reporting compatibility.

## 1. Create an app registration

In the Microsoft Entra admin center:

1. Open **Entra ID > App registrations > New registration**.
2. Give the application a stable name.
3. Choose the supported account type deliberately. A single-tenant
   registration is the simplest starting point.
4. Register the application.

Copy both values from the overview:

- **Application (client) ID** becomes `Config.ClientID`.
- **Directory (tenant) ID** is used in the issuer URL.

Do not create or embed a client secret. A desktop or mobile executable cannot
keep one confidential, and go-pkceflow intentionally has no secret option.

## 2. Use a tenant-specific v2 issuer

Build the issuer with the **Directory (tenant) ID**:

```text
https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0
```

Use the tenant GUID rather than `common` or `organizations`. Those multi-tenant
discovery documents advertise an issuer template containing `{tenantid}`.
go-pkceflow, through go-oidc, requires the discovered issuer to exactly match
`Config.IssuerURL` so that ID token issuer validation remains strict.

This does not prevent a multi-tenant app registration, but the current library
configuration is for one concrete issuer per client instance. Supporting
dynamic tenant issuers would require a separate, explicitly designed trust
model.

## 3. Add the native redirect URIs

For the default desktop handler:

```go
handler := desktopflow.New(15051)
```

the login redirect is:

```text
http://127.0.0.1:15051/callback
```

If using a separate logout path:

```go
if err := handler.SetLogoutPath("/logout"); err != nil {
    return err
}
```

also register:

```text
http://127.0.0.1:15051/logout
```

Under **Authentication**, add a **Mobile and desktop applications** platform
and configure the redirect URIs as public-client redirects. Under **Advanced
settings**, enable **Allow public client flows**.

Microsoft recommends `127.0.0.1` for loopback reliability, but the portal UI
may reject an HTTP URI using that IP literal. In that case edit the app
manifest. In the current Microsoft Graph manifest format, put both URIs under
`publicClient.redirectUris`:

```json
{
  "publicClient": {
    "redirectUris": [
      "http://127.0.0.1:15051/callback",
      "http://127.0.0.1:15051/logout"
    ]
  }
}
```

Older Azure AD Graph format manifests call this `replyUrlsWithType` and use the
`InstalledClient` type. Follow the format shown by your tenant's manifest
editor; do not add the loopback URI as a Web or SPA redirect.

Entra ignores the port when matching `localhost` redirect URIs, but the
desktopflow listener still uses the configured port. Keep the path exact and
avoid registering multiple native redirects that differ only by localhost
port.

For mobile, register the claimed HTTPS or custom-scheme URI used by
`mobileflow.New` under the appropriate native platform and complete the OS
deep-link association described in the
[mobile guide](mobile-deep-linking.md).

## 4. Configure scopes and API permissions

go-pkceflow's defaults map directly to Entra's OIDC scopes:

```text
openid profile email offline_access
```

On the v2 endpoint, `offline_access` must be explicitly requested for a refresh
token. It is included by default here. The `email` claim is not guaranteed;
applications must handle users that do not have an email claim.

To call Microsoft Graph or your own protected API, add delegated scopes to the
app registration under **API permissions**, then include those scope values in
`Config.Scopes`. Setting `Scopes` replaces the defaults:

```go
Scopes: []string{
    "openid",
    "profile",
    "email",
    "offline_access",
    "User.Read",
},
```

For a custom API, use its exposed delegated scope, for example:

```text
api://YOUR_API_CLIENT_ID/access_as_user
```

Entra v2 selects API audiences through scopes. Do not copy Auth0's `audience`
parameter into this configuration.

Optional authorization behavior such as forcing an account chooser can use
`ExtraAuthParams`:

```go
ExtraAuthParams: map[string]string{
    "prompt": "select_account",
},
```

## 5. Build the client

```go
handler := desktopflow.New(15051)
if err := handler.SetLogoutPath("/logout"); err != nil {
    return err
}

store, err := filestore.NewDefault("com.example.myapp")
if err != nil {
    return err
}

client, err := pkceflow.New(pkceflow.Config{
    IssuerURL: "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0",
    ClientID:  "YOUR_APPLICATION_CLIENT_ID",
}, handler, pkceflow.WithTokenPersistence(store))
if err != nil {
    return err
}
```

The token exchange sends `client_id` in the form body with the authorization
code and PKCE verifier. It sends no client secret.

## 6. Run the CLI smoke test

```bash
go run ./examples/cli \
  --issuer=https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0 \
  --client-id=YOUR_APPLICATION_CLIENT_ID \
  --port=15051 \
  --logout-path=/logout
```

Verify login, ID token claims, refresh, and logout. If the tenant requires admin
consent for a requested delegated permission, grant it according to your
organization's policy rather than weakening the client configuration.

## Logout behavior

go-pkceflow discovers Entra's `end_session_endpoint` and sends the browser
there with an ID token hint, state, and `post_logout_redirect_uri`. Entra
requires the post-logout URI to match a redirect URI registered for the
application, which is why the `/logout` URI above appears in the same
public-client list.

In-memory state is cleared and persistent deletion is attempted even if the
browser logout or return redirect fails. A persistence deletion failure is
logged rather than returned. An existing Microsoft browser or device session
may still make a later login silent; RP-Initiated Logout is not a guarantee
that every Microsoft session on the device is removed.

## Troubleshooting

- **Issuer mismatch during discovery**: use the Directory (tenant) ID v2 issuer,
  not `common`, `organizations`, an authorization endpoint, or an alias whose
  discovery document advertises another issuer.
- **`AADSTS50011` reply URL mismatch**: compare the path and redirect type.
  For HTTP `127.0.0.1`, check the manifest entry.
- **`invalid_client` or secret-related error**: verify the redirect is a native
  public-client redirect and **Allow public client flows** is enabled.
- **No refresh token**: keep `offline_access` in the v2 authorization request
  and check tenant consent/policy.
- **Expected email is missing**: this is allowed even with the `email` scope;
  use stable identifiers such as `sub` for identity.
- **API returns the wrong-audience error**: request that API's delegated scope;
  access tokens are opaque and should not be decoded by the client.
- **Logout does not return**: register the exact post-logout URI as another
  public-client redirect.

## References

- [Microsoft identity platform: Authorization Code flow with PKCE](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow)
- [Microsoft identity platform: OpenID Connect scopes](https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc)
- [Microsoft identity platform: add a redirect URI](https://learn.microsoft.com/en-us/entra/identity-platform/how-to-add-redirect-uri)
- [Microsoft identity platform: redirect URI restrictions](https://learn.microsoft.com/en-us/entra/identity-platform/reply-url)
- [Microsoft identity platform: OIDC sign-out](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc#send-a-sign-out-request)
