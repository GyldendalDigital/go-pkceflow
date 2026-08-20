# Keycloak setup (local development)

This guide gets you a working IdP on your own machine in a few minutes, then
walks through every field you need to configure a public client with PKCE for
go-pkceflow. It explains the *concepts* behind each setting so the same
knowledge transfers to any IdP. Screenshots are intentionally omitted because
the Keycloak admin console changes between versions; the field names are stable.

This is the provider configuration used for the project's manual Linux and
Windows validation, including repeated refresh against a vanilla Docker
Keycloak instance.

## 1. Run Keycloak

Keycloak ships a container image. This command starts a throwaway instance for
local development only (it uses in-memory config and an insecure admin
password, so never expose it to a network):

```bash
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.0 start-dev
```

Open http://localhost:8080 and sign in to the admin console with `admin` /
`admin`. Version `26.0` matches the runnable Wails example and the recorded
manual validation; pin the version you certify rather than silently following
`latest`.

## 2. Create a realm

A **realm** is an isolated space of users, clients, and settings. The default
`master` realm is for administering Keycloak itself, so create your own.

- Open the realm dropdown (top left) and choose "Create realm".
- Name it, for example, `demo`.

Your issuer URL is then:

```
http://localhost:8080/realms/demo
```

That is the value you pass as `IssuerURL` to go-pkceflow. The library appends
`/.well-known/openid-configuration` automatically during discovery.

## 3. Create a public client

A **client** represents your application. For a native app you want a **public
client** with PKCE, which means no client secret.

- Go to "Clients" and click "Create client".
- **Client type**: OpenID Connect.
- **Client ID**: a stable identifier for your app, for example `demo-native`.
  This is the value you pass as `ClientID`.
- Continue to the capability settings.

### Capability settings

- **Client authentication**: **Off**. This is the switch that makes the client
  *public*. "On" would make it confidential and require a secret, which a
  shipped native binary cannot protect.
- **Authorization**: Off (not needed for login).
- **Standard flow**: **On**. This is the Authorization Code flow that
  go-pkceflow uses.
- **Direct access grants**: Off. That is the password grant, which you should
  not use.
- **Implicit flow**: Off. Deprecated and unsupported by this library.

go-pkceflow sends `client_id` in the token request body and does not send a
client secret or try HTTP Basic authentication. Keep **Client authentication**
off; adding a secret would turn this into a different client model.

### Enforce PKCE

Public clients should require PKCE so the flow cannot fall back to something
weaker.

- Open the client's "Advanced" tab.
- Under "Advanced settings", set **Proof Key for Code Exchange Code Challenge
  Method** to **S256**.

go-pkceflow always sends an S256 challenge, so this makes Keycloak reject any
request that does not.

## 4. Register the redirect URIs

The IdP will only send the user back to an address you have pre-approved. This
is the single most common source of "invalid redirect_uri" errors.

In the client's "Settings" tab:

- **Valid redirect URIs**: add your login callback. For the desktop handler
  with `desktopflow.New(15051)` the default is:

  ```
  http://127.0.0.1:15051/callback
  ```

  If you use a custom port or path, register that exact value. Keycloak matches
  strictly (a trailing slash or a different port will fail).

- **Valid post logout redirect URIs**: add the address the user returns to after
  logout. IdPs treat this as a *separate* list from the login redirect URIs,
  which is exactly why go-pkceflow lets you configure a distinct logout path. If
  you call `handler.SetLogoutPath("/logout-callback")`, register:

  ```
  http://127.0.0.1:15051/logout-callback
  ```

  The example CLI in step 7 uses that same path by default, so register it now
  if you plan to test logout there. If you do not configure a separate logout
  path, go-pkceflow reuses the login redirect URI, so add that same value here
  too.

> Tip for local development only: some teams register
> `http://127.0.0.1:*/callback` to allow any port. Wildcards weaken the security
> guarantees of the loopback pattern, so prefer exact URIs and only relax this
> locally if you must.

## 5. Create a test user

- Go to "Users", click "Add user", give it a username, and create it.
- Open the "Credentials" tab, set a password, and turn **Temporary** off so you
  are not forced to change it on first login.

## 6. Allow offline access

go-pkceflow requests `openid profile email offline_access` by default. In
Keycloak, `offline_access` asks for an offline token that can refresh outside
the normal browser SSO session. Two mappings must permit it:

- Open the client's **Client scopes** tab and make sure `offline_access` is
  assigned as an **Optional** client scope.
- Open the test user's **Role mapping** tab and assign the realm role
  `offline_access`.

Recent Keycloak realm defaults often provide the optional client scope, but do
not assume the user role is present. If either mapping is missing, login can
succeed without an **offline** token. Keycloak may still return a normal refresh
token tied to the browser SSO session, which the background loop can use until
that online session policy ends.

Keycloak offline tokens are deliberately independent of the browser SSO session
and remain valid after RP-Initiated Logout on their own. go-pkceflow therefore
posts the refresh token to Keycloak's `revocation_endpoint` (RFC 7009) during
`Logout`, before the browser round trip, in addition to clearing in-memory state
and asking the persistence backend to delete its copy. Deletion and revocation
failures are both logged rather than returned.

Revocation is best effort, so keep Keycloak's offline-session expiry and
administrative revocation controls in place for the cases it cannot cover: a
logout performed offline, or one where the endpoint is unreachable. Because
local state is cleared first, a revocation that fails leaves the token valid at
Keycloak and no longer revocable by this client.

One consequence of revoking before the browser round trip: revocation may end
the Keycloak session that the following `id_token_hint` names. Keycloak's
handling of a hint whose session is already gone is version-dependent, and a
realm that refuses to honour `post_logout_redirect_uri` in that state shows up as
the logout flow waiting out `Config.LogoutTimeout`. Validate the pair against
your realm rather than assuming it. Note that
Keycloak's `revocation_endpoint_auth_methods_supported` does not list `none`;
a public client authenticates with `client_id` alone, which Keycloak accepts in
practice, but verify it against your realm.

If your application deliberately does not need offline sessions, override
`Config.Scopes` and omit `offline_access`. The resulting refresh-token lifetime
then follows the provider's normal online-session policy.

## 7. Run go-pkceflow against it

```bash
go run ./examples/cli \
  --issuer=http://localhost:8080/realms/demo \
  --client-id=demo-native \
  --port=15051
```

Choose "Login", authenticate as your test user in the browser, and you should
land back on the localhost callback with a valid session. The CLI prints the
configured redirect URIs and can show the verified ID token claims. Choose
"Logout" to exercise RP-Initiated Logout.

The CLI defaults to the distinct post-logout callback
`http://127.0.0.1:15051/logout-callback`, which is the value registered in
step 4. Keycloak rejects a post-logout redirect that is not on that list, so
either register it or point the CLI elsewhere with `--logout-path` or
`--logout-uri`.

The CLI uses the library defaults. To test a different scope set, provide a
comma-separated list:

```bash
go run ./examples/cli \
  --issuer=http://localhost:8080/realms/demo \
  --client-id=demo-native \
  --port=15051 \
  --scopes=openid,profile,email
```

## Field-to-parameter cheat sheet

| Keycloak field | go-pkceflow | Notes |
|----------------|-------------|-------|
| Realm URL | `Config.IssuerURL` | `http://localhost:8080/realms/demo` |
| Client ID | `Config.ClientID` | Public client id |
| Client authentication = Off | (implicit) | Makes it a public client, no secret |
| PKCE method = S256 | (always sent) | Library only does S256 |
| Valid redirect URIs | `handler.RedirectURI()` | Must match exactly |
| Valid post logout redirect URIs | `handler.PostLogoutRedirectURI()` | Separate list; register the logout path |
| Optional client scope = `offline_access` | Default `Config.Scopes` | Allows the requested offline scope |
| User realm role = `offline_access` | Provider policy | Allows Keycloak to issue an offline token |

## Troubleshooting

- **"Invalid redirect_uri"**: the URI in the request is not in the Valid
  redirect URIs list. Compare character for character, including port and path.
- **Logout returns an error page**: the post-logout URI is not registered in the
  *post logout* list, or you configured a separate logout path but did not
  register it. See step 4.
- **"Client secret required"**: client authentication is On. Turn it Off to make
  the client public.
- **Login works but no offline token arrives**: check both `offline_access`
  mappings in step 6 and confirm the authorization request includes that scope.
- **`invalid_grant` on code exchange**: confirm the client is public. A
  confidential-client or Basic-auth expectation is incompatible with this
  library.

Once this works locally, the same field names and concepts apply to a hosted
IdP such as [Auth0](idp-setup-auth0.md), or use the
[generic OIDC checklist](idp-setup-generic-oidc.md).

## References

- [Keycloak Server Administration Guide: OIDC clients and PKCE](https://www.keycloak.org/docs/latest/server_admin/)
- [Keycloak Server Administration Guide: offline access](https://www.keycloak.org/docs/latest/server_admin/#_offline-access)
