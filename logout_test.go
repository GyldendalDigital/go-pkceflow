package pkceflow

import (
	"net/url"
	"testing"
)

func TestBuildLogoutURL(t *testing.T) {
	raw, err := buildLogoutURL(
		"https://idp.example.com/logout",
		"id-token-abc",
		"http://127.0.0.1:9000/callback",
		"state-xyz",
	)
	if err != nil {
		t.Fatalf("buildLogoutURL: %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()

	if got := q.Get("id_token_hint"); got != "id-token-abc" {
		t.Errorf("id_token_hint = %q, want %q", got, "id-token-abc")
	}
	if got := q.Get("state"); got != "state-xyz" {
		t.Errorf("state = %q, want %q", got, "state-xyz")
	}
	if got := q.Get("post_logout_redirect_uri"); got != "http://127.0.0.1:9000/callback" {
		t.Errorf("post_logout_redirect_uri = %q", got)
	}
}

func TestBuildLogoutURL_OmitsEmptyRedirect(t *testing.T) {
	raw, err := buildLogoutURL("https://idp.example.com/logout", "id-token-abc", "", "state-xyz")
	if err != nil {
		t.Fatalf("buildLogoutURL: %v", err)
	}

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	q := u.Query()

	if q.Has("post_logout_redirect_uri") {
		t.Error("post_logout_redirect_uri should be omitted when empty")
	}
	if q.Get("state") != "state-xyz" {
		t.Error("state should always be present")
	}
}

func TestBuildLogoutURL_InvalidEndpoint(t *testing.T) {
	if _, err := buildLogoutURL("http://%zz", "id", "", "s"); err == nil {
		t.Fatal("expected error for invalid endpoint")
	}
}

func TestRandomState_UniqueAndURLSafe(t *testing.T) {
	seen := make(map[string]bool)
	for range 100 {
		s, err := randomState()
		if err != nil {
			t.Fatalf("randomState: %v", err)
		}
		if s == "" {
			t.Fatal("randomState returned empty string")
		}
		if seen[s] {
			t.Fatalf("randomState produced a duplicate: %q", s)
		}
		seen[s] = true
	}
}
