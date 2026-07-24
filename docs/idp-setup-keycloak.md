# Keycloak setup (local proof of concept)

This guide gets you a working IdP on your own machine in a few minutes, then
walks through every field you need to configure a public client with PKCE for
go-pkceflow. It explains the *concepts* behind each setting so the same
knowledge transfers to any IdP. Screenshots are intentionally omitted because
the Keycloak admin console changes between versions; the field names are stable.

## 1. Run Keycloak

Keycloak ships a container image. This command starts a throwaway instance for
local development only (it uses in-memory config and an insecure admin
password, so never expose it to a network):

```bash
docker run --rm -p 8080:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

Open http://localhost:8080 and sign in to the admin console with `admin` /
`admin`.

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
  you call `handler.SetLogoutPath("/logout")`, register:

  ```
  http://127.0.0.1:15051/logout
  ```

  If you do not configure a separate logout path, go-pkceflow reuses the login
  redirect URI, so add that same value here too.

> Tip for local development only: some teams register
> `http://127.0.0.1:*/callback` to allow any port. Wildcards weaken the security
> guarantees of the loopback pattern, so prefer exact URIs and only relax this
> locally if you must.

## 5. Create a test user

- Go to "Users", click "Add user", give it a username, and create it.
- Open the "Credentials" tab, set a password, and turn **Temporary** off so you
  are not forced to change it on first login.

## 6. Run go-pkceflow against it

```bash
go run ./examples/cli \
  --issuer=http://localhost:8080/realms/demo \
  --client-id=demo-native \
  --port=15051
```

Choose "Login", authenticate as your test user in the browser, and you should
land back on the localhost callback with a valid session. Try "Show access
token" to see the decoded ID token claims, and "Logout" to exercise
RP-Initiated Logout.

## Field-to-parameter cheat sheet

| Keycloak field | go-pkceflow | Notes |
|----------------|-------------|-------|
| Realm URL | `Config.IssuerURL` | `http://localhost:8080/realms/demo` |
| Client ID | `Config.ClientID` | Public client id |
| Client authentication = Off | (implicit) | Makes it a public client, no secret |
| PKCE method = S256 | (always sent) | Library only does S256 |
| Valid redirect URIs | `handler.RedirectURI()` | Must match exactly |
| Valid post logout redirect URIs | `handler.PostLogoutRedirectURI()` | Separate list; register the logout path |

## Troubleshooting

- **"Invalid redirect_uri"**: the URI in the request is not in the Valid
  redirect URIs list. Compare character for character, including port and path.
- **Logout returns an error page**: the post-logout URI is not registered in the
  *post logout* list, or you configured a separate logout path but did not
  register it. See step 4.
- **"Client secret required"**: client authentication is On. Turn it Off to make
  the client public.

Once this works locally, the same field names and concepts apply to a hosted
IdP such as [Auth0](idp-setup-auth0.md).
