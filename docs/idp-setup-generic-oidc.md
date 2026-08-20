# Generic OIDC provider setup

Use this checklist when your provider does not have a dedicated go-pkceflow
guide. It describes the protocol contract the library needs, the settings to
map, and a small CLI smoke test.

Passing this checklist means the provider is a reasonable compatibility
candidate. It is not a claim that the project has tested that provider. Today,
the project-owned live validation is against Keycloak; other providers rely on
their documentation and the automated fake IdP suite until recorded otherwise.

## 1. Check OIDC discovery

Start with the provider's issuer URL, not an authorization or token endpoint.
For an issuer such as:

```text
https://login.example.com/tenant
```

go-pkceflow fetches:

```text
https://login.example.com/tenant/.well-known/openid-configuration
```

Inspect it during setup:

```bash
curl -fsS \
  https://login.example.com/tenant/.well-known/openid-configuration
```

The discovery document must provide:

| Metadata | Why it matters |
|----------|----------------|
| `issuer` | Must exactly match `Config.IssuerURL`, including path and trailing-slash behavior |
| `authorization_endpoint` | System browser destination for login |
| `token_endpoint` | Authorization-code exchange and token refresh |
| `jwks_uri` | Signing keys used to verify ID tokens |
| `id_token_signing_alg_values_supported` | Must include an algorithm supported by go-oidc |

`end_session_endpoint` is optional. Without it, `Logout` still clears in-memory
state, attempts deletion through `TokenPersistence`, and emits the logged-out
event, but cannot end the provider's browser session. Persistence deletion
failures are logged rather than returned.

`revocation_endpoint` is also optional. When discovery advertises one, `Logout`
posts the refresh token to it with `token_type_hint=refresh_token` and the public
`client_id`, before the browser round trip. The endpoint must be absolute and
HTTPS (plain HTTP is accepted only when the issuer itself is plain HTTP, for a
local development provider), and redirects are not followed, so a refresh token
is never replayed to another host. Revocation is best effort and never changes
Logout's result. Providers without RFC 7009 support, such as Microsoft Entra ID,
simply skip this step.

Use HTTPS for a deployed issuer. Plain HTTP is appropriate only for a local
development provider on a trusted machine.

## 2. Register a public native client

Choose the provider's **Native**, **Desktop**, **Mobile**, **Installed**, or
**Public client** application type. The labels vary, but the resulting client
must have these properties:

- Authorization Code flow is enabled.
- PKCE is required or accepted with the `S256` challenge method.
- The client is public and has no client secret.
- The token endpoint accepts an unauthenticated public-client exchange with
  `client_id` in the form body.
- Implicit flow and password grants are unnecessary.
- Login uses the system browser, not an embedded webview.

go-pkceflow deliberately sets token-endpoint authentication to form parameters
to avoid an HTTP Basic probe. A provider that requires a client secret,
`private_key_jwt`, or another confidential-client credential is not compatible
with this library's native-app model.

## 3. Register redirect URIs

The URI registered at the provider must match the flow handler.

For the default desktop handler:

```go
handler := desktopflow.New(15051)
```

register:

```text
http://127.0.0.1:15051/callback
```

The handler binds loopback only. Use an exact URI when the provider permits it;
do not register wildcard hosts. Providers sometimes apply RFC 8252 exceptions
to loopback ports, so consult their native-app redirect documentation.

For mobile, register the claimed HTTPS Universal Link/App Link or custom-scheme
URI passed to `mobileflow.New`. The application must own the OS-level deep-link
association and deliver callbacks to the handler.

RP-Initiated Logout may use a separate allow-list. If you configure a distinct
post-logout URI with `SetLogoutPath` or `SetLogoutURI`, register that URI in the
provider's logout settings too.

## 4. Configure scopes and refresh tokens

The default scopes are:

```text
openid profile email offline_access
```

- `openid` is required. The token response must contain an ID token.
- `profile` and `email` request common identity claims; providers may omit
  claims that do not exist or are not allowed by policy.
- `offline_access` requests a refresh token.

Providers commonly require an additional offline-access toggle, role, grant, or
consent policy before returning a refresh token. Some use another
authorization-request parameter instead. If the provider rejects
`offline_access`, replace `Config.Scopes` with its supported set and add the
provider-specific parameter through `ExtraAuthParams`.

When setting `Config.Scopes`, remember that it replaces the defaults rather
than extending them:

```go
Scopes: []string{
    "openid",
    "profile",
    "email",
    "offline_access",
    "api.read",
},
```

## 5. Check ID token behavior

Login must return a signed ID token whose:

- issuer exactly matches the discovered issuer;
- audience contains the configured client ID;
- signature validates with the discovery JWKS;
- expiry is valid;
- `nonce` claim matches the nonce from the authorization request; and
- `azp` claim, if present, equals the configured client ID. go-pkceflow requires
  `azp` when `aud` carries more than one value, as OIDC Core 3.1.3.7 specifies,
  and accepts its absence for a single-audience token.

During refresh, the provider may omit `id_token`; go-pkceflow then retains the
previously verified one. If the provider returns a new ID token, it is verified
and must have the same non-empty `sub` claim as the current session. A changed
or unverifiable identity fails closed and bypasses grace mode. A provider that
refuses the refresh token with `invalid_grant` likewise ends grace, while a
refused client registration does not.

Access tokens are opaque to go-pkceflow. Their audience, format, and API
authorization rules belong to the provider and resource server.

## 6. Add only provider-specific parameters

Common examples include:

```go
ExtraAuthParams: map[string]string{
    "audience": "https://api.example.com",
    "prompt":   "login",
},
```

Use `ExtraTokenParams` only when the provider explicitly requires a
non-standard field during the initial authorization-code exchange. Those
parameters are not added to refresh requests; a provider that requires a custom
field on refresh is not currently compatible. The library rejects attempts to
override OAuth/OIDC/PKCE fields it owns, including `state`, `nonce`, `scope`,
`redirect_uri`, `code_challenge`, `code_verifier`, `client_id`, and
`client_secret`.

## 7. Build the client

```go
handler := desktopflow.New(15051)

store, err := filestore.NewDefault("com.example.myapp")
if err != nil {
    return err
}

client, err := pkceflow.New(pkceflow.Config{
    IssuerURL: "https://login.example.com/tenant",
    ClientID:  "my-native-client",
}, handler, pkceflow.WithTokenPersistence(store))
if err != nil {
    return err
}
```

Use `WithHTTPClient` if discovery, JWKS, or token endpoints require a corporate
proxy, private CA, mutual TLS transport, or custom connection settings. The
same client is used for every outbound OIDC request.

## 8. Run the CLI smoke test

```bash
go run ./examples/cli \
  --issuer=https://login.example.com/tenant \
  --client-id=my-native-client \
  --port=15051
```

Verify:

1. Discovery succeeds without an issuer mismatch.
2. The provider accepts the exact redirect URI.
3. Login returns through the loopback callback.
4. Verified ID token claims are available.
5. A refresh token is present when offline access is expected.
6. Refresh succeeds after the access token lifetime advances.
7. Logout clears local state and, when supported, returns through the registered
   post-logout URI.

## Troubleshooting

- **Issuer mismatch during `Init`**: use the exact `issuer` advertised by
  discovery. Alias and multi-tenant discovery URLs can advertise a different
  issuer and are rejected intentionally.
- **`invalid_client` or client-secret prompt**: the registration is
  confidential, or the provider does not allow a public token exchange.
- **`invalid_grant` during code exchange**: confirm Authorization Code + PKCE
  S256, exact redirect matching, and that the provider did not consume the code
  in an earlier failed exchange.
- **No ID token**: confirm OIDC and the `openid` scope are enabled. An
  OAuth-only provider is insufficient.
- **Nonce validation failure**: the provider must preserve the authorization
  request's nonce in the ID token.
- **Login works but refresh does not**: check offline-access policy, requested
  scopes, refresh-token rotation, expiry, and revocation logs.
- **`azp claim does not authorize this client`**: the provider issued an ID token
  whose authorized party is a different client, or a multi-audience token with no
  `azp`. Grep the logs for the matching `WARN` line: `ID token azp claim names a
  different client` (carrying `configured_client_id` and `received_azp`
  attributes), `ID token has multiple audiences but no azp claim`, or `ID token
  azp claim is not a string`. The log is the reliable signal, because a consuming
  application's error mapping may flatten the returned error into a generic
  failure. Check whether the provider adds extra audiences to ID tokens.
- **Logout is local only**: check discovery for `end_session_endpoint` and
  register the post-logout redirect URI.

## References

- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [RFC 7636: Proof Key for Code Exchange](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 8252: OAuth 2.0 for Native Apps](https://www.rfc-editor.org/rfc/rfc8252)
