package pkceflow

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// newRevocationTestClient returns a client and a counter of requests reaching a
// stand-in revocation endpoint.
func newRevocationTestClient(t *testing.T) (*Client, *httptest.Server, *atomic.Int32) {
	t.Helper()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	client := &Client{
		config: Config{
			IssuerURL: server.URL,
			ClientID:  "test-app",
		},
		store:         &memoryStore{},
		emitter:       noopEmitter{},
		logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		clock:         systemRefreshClock{},
		lifecycleFlow: make(chan struct{}, 1),
	}
	return client, server, &hits
}

// A Logout superseded by a newer Login must not revoke. On providers whose
// refresh tokens are session-bound, revoking the old token can tear down the
// session the new Login just established.
func TestRevokeRefreshTokenSkipsSupersededLogout(t *testing.T) {
	client, server, hits := newRevocationTestClient(t)
	ctx := context.Background()

	superseded := client.beginLifecycleOperation(ctx, lifecycleLogout)
	if superseded == nil {
		t.Fatal("could not begin the logout operation")
	}
	// A newer operation takes ownership, exactly as a concurrent Login would.
	if client.beginLifecycleOperation(ctx, lifecycleLogin) == nil {
		t.Fatal("could not begin the superseding operation")
	}

	client.revokeRefreshToken(superseded, server.URL, "refresh-old")

	if got := hits.Load(); got != 0 {
		t.Fatalf("revocation requests = %d, want 0 for a superseded logout", got)
	}
}

// The current operation revokes even though its caller's context is done: the
// fence is about ownership, not liveness.
func TestRevokeRefreshTokenIgnoresCallerCancellation(t *testing.T) {
	client, server, hits := newRevocationTestClient(t)

	ctx, cancel := context.WithCancel(context.Background())
	operation := client.beginLifecycleOperation(ctx, lifecycleLogout)
	if operation == nil {
		t.Fatal("could not begin the logout operation")
	}
	cancel()

	client.revokeRefreshToken(operation, server.URL, "refresh-old")

	if got := hits.Load(); got != 1 {
		t.Fatalf("revocation requests = %d, want 1 despite a cancelled caller", got)
	}
}

func TestRevokeRefreshTokenRejectsUnsuitableEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		// httpsIssuer controls whether plaintext is tolerated at all.
		httpsIssuer bool
		wantRequest bool
	}{
		{
			name:        "plaintext endpoint with a plaintext issuer",
			endpoint:    "", // filled with the test server URL
			wantRequest: true,
		},
		{
			name:        "plaintext endpoint with an https issuer",
			endpoint:    "",
			httpsIssuer: true,
		},
		{
			name:     "relative endpoint",
			endpoint: "/revoke",
		},
		{
			name:     "endpoint with embedded credentials",
			endpoint: "https://user:pass@idp.example.com/revoke",
		},
		{
			name:     "endpoint with a fragment",
			endpoint: "https://idp.example.com/revoke#frag",
		},
		{
			name:     "unsupported scheme",
			endpoint: "ftp://idp.example.com/revoke",
		},
		{
			name:     "unparseable endpoint",
			endpoint: "https://idp.example.com/revoke\x7f\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, server, hits := newRevocationTestClient(t)
			endpoint := tt.endpoint
			if endpoint == "" {
				endpoint = server.URL
			}
			if tt.httpsIssuer {
				client.config.IssuerURL = "https://idp.example.com"
			}

			operation := client.beginLifecycleOperation(context.Background(), lifecycleLogout)
			if operation == nil {
				t.Fatal("could not begin the logout operation")
			}
			client.revokeRefreshToken(operation, endpoint, "refresh-old")

			want := int32(0)
			if tt.wantRequest {
				want = 1
			}
			if got := hits.Load(); got != want {
				t.Fatalf("revocation requests = %d, want %d", got, want)
			}
		})
	}
}

// Nothing to revoke is not a failure, and must not produce a request.
func TestRevokeRefreshTokenSkipsWhenNothingToRevoke(t *testing.T) {
	client, server, hits := newRevocationTestClient(t)
	operation := client.beginLifecycleOperation(context.Background(), lifecycleLogout)
	if operation == nil {
		t.Fatal("could not begin the logout operation")
	}

	client.revokeRefreshToken(operation, server.URL, "")
	client.revokeRefreshToken(operation, "", "refresh-old")

	if got := hits.Load(); got != 0 {
		t.Fatalf("revocation requests = %d, want 0", got)
	}
}
