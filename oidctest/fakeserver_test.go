package oidctest

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
)

func TestFakeIDP_Discovery(t *testing.T) {
	idp := NewFakeIDP(t)

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, idp.IssuerURL())
	if err != nil {
		t.Fatalf("OIDC discovery failed: %v", err)
	}

	// Verify endpoint is the IdP
	endpoint := provider.Endpoint()
	if endpoint.AuthURL != idp.IssuerURL()+"/authorize" {
		t.Errorf("AuthURL = %q, want %q", endpoint.AuthURL, idp.IssuerURL()+"/authorize")
	}
	if endpoint.TokenURL != idp.IssuerURL()+"/token" {
		t.Errorf("TokenURL = %q, want %q", endpoint.TokenURL, idp.IssuerURL()+"/token")
	}
}

func TestFakeIDP_FullRoundTrip(t *testing.T) {
	idp := NewFakeIDP(t, WithClientID("my-app"))

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, idp.IssuerURL())
	if err != nil {
		t.Fatalf("discovery failed: %v", err)
	}

	// Step 1: Authorize (simulate browser redirect)
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)

	authURL := idp.IssuerURL() + "/authorize?" + url.Values{
		"client_id":             {"my-app"},
		"redirect_uri":         {"http://127.0.0.1:0/callback"},
		"response_type":        {"code"},
		"state":                {"test-state-123"},
		"code_challenge":       {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse // don't follow redirects
	}}

	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("authorize request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize status = %d, want 302", resp.StatusCode)
	}

	location := resp.Header.Get("Location")
	callbackURL, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse callback URL: %v", err)
	}

	code := callbackURL.Query().Get("code")
	state := callbackURL.Query().Get("state")
	if code == "" {
		t.Fatal("no code in callback")
	}
	if state != "test-state-123" {
		t.Errorf("state = %q, want %q", state, "test-state-123")
	}

	// Step 2: Exchange code for tokens
	tokenResp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:0/callback"},
		"client_id":     {"my-app"},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatalf("token request failed: %v", err)
	}
	defer tokenResp.Body.Close()

	if tokenResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(tokenResp.Body)
		t.Fatalf("token exchange failed: %s", body)
	}

	var tokens struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(tokenResp.Body).Decode(&tokens); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	if tokens.AccessToken == "" {
		t.Error("empty access_token")
	}
	if tokens.RefreshToken == "" {
		t.Error("empty refresh_token")
	}
	if tokens.IDToken == "" {
		t.Error("empty id_token")
	}

	// Step 3: Verify ID token with go-oidc
	verifierCfg := &oidc.Config{ClientID: "my-app"}
	idTokenVerifier := provider.Verifier(verifierCfg)
	idToken, err := idTokenVerifier.Verify(ctx, tokens.IDToken)
	if err != nil {
		t.Fatalf("ID token verification failed: %v", err)
	}
	if idToken.Subject != "test-user" {
		t.Errorf("subject = %q, want %q", idToken.Subject, "test-user")
	}

	// Step 4: Refresh token
	refreshResp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {"my-app"},
	})
	if err != nil {
		t.Fatalf("refresh request failed: %v", err)
	}
	defer refreshResp.Body.Close()

	if refreshResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(refreshResp.Body)
		t.Fatalf("refresh failed: %s", body)
	}

	var refreshed struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(refreshResp.Body).Decode(&refreshed); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}

	if refreshed.AccessToken == "" {
		t.Error("empty refreshed access_token")
	}
	if refreshed.RefreshToken == "" {
		t.Error("empty new refresh_token")
	}
	// Refresh token should be rotated
	if refreshed.RefreshToken == tokens.RefreshToken {
		t.Error("refresh token was not rotated")
	}
}

func TestFakeIDP_PKCERequired(t *testing.T) {
	idp := NewFakeIDP(t)

	// Authorize with PKCE challenge
	challenge := computeS256Challenge("correct-verifier")
	authResp := authorizeRequest(t, idp, url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":         {"http://127.0.0.1:0/callback"},
		"response_type":        {"code"},
		"state":                {"s"},
		"code_challenge":       {challenge},
		"code_challenge_method": {"S256"},
	})

	code := authResp.Query().Get("code")

	// Exchange with wrong verifier should fail
	resp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:0/callback"},
		"client_id":     {"test-client"},
		"code_verifier": {"wrong-verifier"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for wrong verifier, got %d", resp.StatusCode)
	}

	var errResp struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&errResp) //nolint:errcheck
	if errResp.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", errResp.Error)
	}
}

func TestFakeIDP_QueueError(t *testing.T) {
	idp := NewFakeIDP(t)
	idp.QueueError("invalid_grant")

	resp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"anything"},
		"client_id":     {"test-client"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}

	var errResp struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp.Body).Decode(&errResp) //nolint:errcheck
	if errResp.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", errResp.Error)
	}
}

func TestFakeIDP_ConfigurableTokenExpiry(t *testing.T) {
	idp := NewFakeIDP(t, WithAccessTTL(10*time.Second))

	authResp := authorizeRequest(t, idp, url.Values{
		"client_id":      {"test-client"},
		"redirect_uri":  {"http://127.0.0.1:0/callback"},
		"response_type": {"code"},
		"state":         {"s"},
	})
	code := authResp.Query().Get("code")

	resp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://127.0.0.1:0/callback"},
		"client_id":    {"test-client"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	var tokens struct {
		ExpiresIn int `json:"expires_in"`
	}
	json.NewDecoder(resp.Body).Decode(&tokens) //nolint:errcheck
	if tokens.ExpiresIn != 10 {
		t.Errorf("expires_in = %d, want 10", tokens.ExpiresIn)
	}
}

func TestFakeIDP_RefreshTokenRotationInvalidatesOld(t *testing.T) {
	idp := NewFakeIDP(t)

	// Get initial tokens
	authResp := authorizeRequest(t, idp, url.Values{
		"client_id":      {"test-client"},
		"redirect_uri":  {"http://127.0.0.1:0/callback"},
		"response_type": {"code"},
		"state":         {"s"},
	})
	code := authResp.Query().Get("code")

	resp, _ := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"http://127.0.0.1:0/callback"},
		"client_id":    {"test-client"},
	})
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tokens) //nolint:errcheck
	resp.Body.Close()

	// Use refresh token once (success)
	resp2, _ := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {"test-client"},
	})
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("first refresh failed: %d", resp2.StatusCode)
	}

	// Use same refresh token again (should fail -- rotated)
	resp3, _ := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {"test-client"},
	})
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusBadRequest {
		t.Fatalf("reuse of rotated token should fail, got %d", resp3.StatusCode)
	}
}

// authorizeRequest is a test helper that performs the authorize redirect and returns the callback URL.
func authorizeRequest(t *testing.T, idp *FakeIDPServer, params url.Values) *url.URL {
	t.Helper()

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(idp.IssuerURL() + "/authorize?" + params.Encode())
	if err != nil {
		t.Fatalf("authorize: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("authorize status %d: %s", resp.StatusCode, body)
	}

	location := resp.Header.Get("Location")
	u, err := url.Parse(location)
	if err != nil {
		t.Fatalf("parse redirect: %v", err)
	}

	if errCode := u.Query().Get("error"); errCode != "" {
		t.Fatalf("authorize returned error: %s: %s", errCode, u.Query().Get("error_description"))
	}

	return u
}
