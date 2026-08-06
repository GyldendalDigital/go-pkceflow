// Package pkceflow provides OIDC Authorization Code flow with PKCE for native applications.
//
// This is a framework-agnostic Go library for desktop, mobile, and CLI apps that
// need to authenticate users via an OIDC provider (Keycloak, Entra ID, Auth0, etc.)
// without a client secret.
//
// # Quick Start
//
//	handler := desktopflow.New(15051)
//	store, err := filestore.NewDefault("com.example.myapp")
//	if err != nil {
//	    return err
//	}
//
//	client, err := pkceflow.New(pkceflow.Config{
//	    IssuerURL: "https://your-idp.com",
//	    ClientID:  "your-client-id",
//	}, handler, pkceflow.WithTokenPersistence(store))
//	if err != nil {
//	    return err
//	}
//
//	if _, err := client.RestoreSession(); err != nil {
//	    return err
//	}
//	if err := client.Init(ctx); err != nil && !client.AuthStatus().CanUseApp {
//	    return err
//	}
//	client.StartRefreshLoop(ctx)
//	defer client.StopRefreshLoop()
//
//	if !client.AuthStatus().CanUseApp {
//	    if err := client.Login(ctx); err != nil {
//	        return err
//	    }
//	}
//	token := client.AccessToken(ctx)
//	if client.AuthStatus().Valid && token != "" {
//	    // Keep the token in the Go backend for API calls.
//	}
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
