// Package pkceflow provides OIDC Authorization Code flow with PKCE for native applications.
//
// This is a framework-agnostic Go library for desktop, mobile, and CLI apps that
// need to authenticate users via an OIDC provider (Keycloak, Entra ID, Auth0, etc.)
// without a client secret.
//
// # Quick Start
//
//	handler := desktopflow.New(15051)
//	store, _ := filestore.New("my-app", configDir)
//
//	client, _ := pkceflow.New(pkceflow.Config{
//	    IssuerURL: "https://your-idp.com",
//	    ClientID:  "your-client-id",
//	}, handler, pkceflow.WithTokenPersistence(store))
//
//	client.Init(ctx)
//	client.Login(ctx) // opens browser
//	token := client.AccessToken(ctx) // use in API calls
//
// # Packages
//
//   - pkceflow: Core Client API (this package)
//   - desktopflow: Localhost callback handler for desktop apps
//   - mobileflow: Channel-based handler for mobile deep links
//   - filestore: AES-256-GCM encrypted token persistence
//   - eventbus: DeferredEventBus and NoopEventBus utilities
//   - oidctest: FakeIDPServer and test doubles
package pkceflow
