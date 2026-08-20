package pkceflow

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A malformed revocation_endpoint must not discard a perfectly good
// end_session_endpoint. encoding/json records a type mismatch and keeps going,
// returning the error only at the end, so decoding both from one struct made an
// unrelated field able to disable RP-Initiated Logout.
func TestInitDecodesEndpointsIndependently(t *testing.T) {
	var issuer string
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                issuer + "/authorize",
			"token_endpoint":                        issuer + "/token",
			"jwks_uri":                              issuer + "/jwks",
			"end_session_endpoint":                  issuer + "/logout",
			"revocation_endpoint":                   []string{issuer + "/revoke"}, // wrong type
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	issuer = server.URL

	client, err := New(
		Config{IssuerURL: server.URL, ClientID: "test-app"},
		&discoveryTestFlow{},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}

	client.mu.Lock()
	endSession := client.endSessionEndpoint
	revocation := client.revocationEndpoint
	client.mu.Unlock()

	if endSession != server.URL+"/logout" {
		t.Fatalf("end_session_endpoint = %q, want it decoded despite the malformed sibling", endSession)
	}
	if revocation != "" {
		t.Fatalf("revocation_endpoint = %q, want it discarded as malformed", revocation)
	}
}

type discoveryTestFlow struct{}

func (*discoveryTestFlow) RedirectURI() string { return "http://127.0.0.1:9999/callback" }
func (*discoveryTestFlow) StartAuthFlow(context.Context, string) (string, error) {
	return "", nil
}
