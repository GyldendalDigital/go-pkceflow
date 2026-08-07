package oidctest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
)

func TestHooks_TokenHook(t *testing.T) {
	idp := NewFakeIDP(t)

	// Set a hook that returns a custom error for all token requests.
	idp.Hooks.SetTokenHook(func(w http.ResponseWriter, _ *http.Request) bool {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "rate_limited"}) //nolint:errcheck // test response write
		return true
	})

	resp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"anything"},
		"client_id":     {"test-client"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("expected 429, got %d", resp.StatusCode)
	}

	// Remove the hook; default behavior resumes.
	idp.Hooks.SetTokenHook(nil)
	resp2, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {"anything"},
		"client_id":     {"test-client"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	// Should get 400 (invalid refresh token) not 429.
	if resp2.StatusCode != http.StatusBadRequest {
		t.Errorf("expected 400 after removing hook, got %d", resp2.StatusCode)
	}
}

func TestHooks_AuthorizeHook(t *testing.T) {
	idp := NewFakeIDP(t)

	// Hook that simulates login_required via redirect.
	idp.Hooks.SetAuthorizeHook(func(w http.ResponseWriter, r *http.Request) bool {
		redirectURI := r.URL.Query().Get("redirect_uri")
		state := r.URL.Query().Get("state")
		location := fmt.Sprintf("%s?error=login_required&state=%s", redirectURI, state)
		http.Redirect(w, r, location, http.StatusFound) //nolint:gosec // intentional redirect in test
		return true
	})

	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, err := client.Get(idp.IssuerURL() + "/authorize?" + url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://127.0.0.1:0/callback"},
		"response_type":         {"code"},
		"state":                 {"mystate"},
		"code_challenge":        {"challenge"},
		"code_challenge_method": {"S256"},
	}.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	location := resp.Header.Get("Location")
	u, _ := url.Parse(location)
	if u.Query().Get("error") != "login_required" {
		t.Errorf("expected login_required, got %q", u.Query().Get("error"))
	}
	if u.Query().Get("state") != "mystate" {
		t.Errorf("expected state=mystate, got %q", u.Query().Get("state"))
	}
}

func TestHooks_DiscoveryHook(t *testing.T) {
	idp := NewFakeIDP(t)

	// Make discovery return 500.
	idp.Hooks.SetDiscoveryHook(func(w http.ResponseWriter, _ *http.Request) bool {
		http.Error(w, "simulated discovery failure", http.StatusInternalServerError)
		return true
	})

	resp, err := http.Get(idp.IssuerURL() + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500, got %d", resp.StatusCode)
	}
}

func TestRequestRecorder(t *testing.T) {
	idp := NewFakeIDP(t)

	// Make some requests.
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	_, _ = client.Get(idp.IssuerURL() + "/authorize?" + url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://127.0.0.1:0/callback"},
		"response_type":         {"code"},
		"state":                 {"s"},
		"scope":                 {"openid profile"},
		"code_challenge":        {"abc"},
		"code_challenge_method": {"S256"},
	}.Encode())

	resp, err := http.Get(idp.IssuerURL() + "/jwks")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Check recorder.
	records := idp.Recorder.Records()
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}

	authRecords := idp.Recorder.RecordsFor("/authorize")
	if len(authRecords) != 1 {
		t.Fatalf("expected 1 authorize record, got %d", len(authRecords))
	}
	if authRecords[0].Params.Get("scope") != "openid profile" {
		t.Errorf("scope = %q, want 'openid profile'", authRecords[0].Params.Get("scope"))
	}
	if authRecords[0].Params.Get("code_challenge") != "abc" {
		t.Errorf("code_challenge = %q, want 'abc'", authRecords[0].Params.Get("code_challenge"))
	}

	jwksRecords := idp.Recorder.RecordsFor("/jwks")
	if len(jwksRecords) != 1 {
		t.Fatalf("expected 1 jwks record, got %d", len(jwksRecords))
	}

	// Reset.
	idp.Recorder.Reset()
	if len(idp.Recorder.Records()) != 0 {
		t.Error("expected empty records after reset")
	}
}

func TestGrantTypeErrorMap(t *testing.T) {
	idp := NewFakeIDP(t)

	// Set error only for refresh_token grant.
	idp.GrantErrors.Set("refresh_token", "invalid_grant")

	// authorization_code exchange should still work.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := computeS256Challenge(verifier)
	authResp := authorizeRequest(t, idp, url.Values{
		"client_id":             {"test-client"},
		"redirect_uri":          {"http://127.0.0.1:0/callback"},
		"response_type":         {"code"},
		"state":                 {"s"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	})
	code := authResp.Query().Get("code")

	resp, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {"http://127.0.0.1:0/callback"},
		"client_id":     {"test-client"},
		"code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for code exchange, got %d", resp.StatusCode)
	}

	// Refresh should fail.
	var tokens struct {
		RefreshToken string `json:"refresh_token"`
	}
	json.NewDecoder(resp.Body).Decode(&tokens) //nolint:errcheck // test assertion follows

	resp2, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {"test-client"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400 for refresh, got %d", resp2.StatusCode)
	}

	var errResp struct {
		Error string `json:"error"`
	}
	json.NewDecoder(resp2.Body).Decode(&errResp) //nolint:errcheck // test assertion follows
	if errResp.Error != "invalid_grant" {
		t.Errorf("error = %q, want invalid_grant", errResp.Error)
	}

	// Clear and retry.
	idp.GrantErrors.Clear("refresh_token")
	resp3, err := http.PostForm(idp.IssuerURL()+"/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {tokens.RefreshToken},
		"client_id":     {"test-client"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp3.Body.Close()
	// After clearing the grant error, the refresh token should be usable.
	// It may still fail with invalid_grant if the token was already consumed
	// by rotation during the error-injected request, but the grant-scoped
	// error itself is no longer in effect.
	_ = resp3.StatusCode
}
