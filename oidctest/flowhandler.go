package oidctest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// FakeFlowHandler implements pkceflow.AuthFlowHandler by automatically completing
// the authorization flow against a FakeIDPServer. It simulates what a browser would
// do: GET the auth URL, follow the redirect, and return the callback URL.
//
// Use this in tests to avoid manual browser interaction.
type FakeFlowHandler struct {
	// RedirectURIValue is returned by RedirectURI().
	RedirectURIValue string

	// Server is the FakeIDPServer to complete the flow against.
	Server *FakeIDPServer

	// httpClient is used to make requests. Uses http.DefaultClient-like behavior
	// but does NOT follow redirects (we capture the redirect Location).
	httpClient *http.Client
}

// NewFakeFlowHandler creates a FakeFlowHandler that completes auth flows against the given server.
// The redirectURI should match what the FakeIDPServer was configured with.
func NewFakeFlowHandler(server *FakeIDPServer, redirectURI string) *FakeFlowHandler {
	return &FakeFlowHandler{
		RedirectURIValue: redirectURI,
		Server:           server,
		httpClient: &http.Client{
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse // don't follow redirects
			},
		},
	}
}

// StartAuthFlow completes the authorization flow by requesting the auth URL
// and capturing the redirect callback URL (with code and state).
func (h *FakeFlowHandler) StartAuthFlow(_ context.Context, authURL string) (string, error) {
	resp, err := h.httpClient.Get(authURL)
	if err != nil {
		return "", fmt.Errorf("oidctest: FakeFlowHandler request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != http.StatusFound {
		return "", fmt.Errorf("oidctest: FakeFlowHandler expected 302 redirect, got %d", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	if location == "" {
		return "", fmt.Errorf("oidctest: FakeFlowHandler got 302 but no Location header")
	}

	// Validate the redirect goes to our expected redirect URI
	loc, err := url.Parse(location)
	if err != nil {
		return "", fmt.Errorf("oidctest: FakeFlowHandler invalid redirect location: %w", err)
	}

	expected, _ := url.Parse(h.RedirectURIValue)
	if loc.Scheme != expected.Scheme || loc.Host != expected.Host || loc.Path != expected.Path {
		return "", fmt.Errorf("oidctest: FakeFlowHandler redirect %q does not match expected redirect URI %q", location, h.RedirectURIValue)
	}

	return location, nil
}

// RedirectURI returns the configured redirect URI.
func (h *FakeFlowHandler) RedirectURI() string {
	return h.RedirectURIValue
}
