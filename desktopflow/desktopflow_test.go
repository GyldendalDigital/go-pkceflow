package desktopflow

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	h := New(15051)
	if h.RedirectURI() != "http://127.0.0.1:15051/callback" {
		t.Errorf("RedirectURI() = %q, want http://127.0.0.1:15051/callback", h.RedirectURI())
	}
}

func TestNewWithURI_Valid(t *testing.T) {
	tests := []struct {
		uri  string
		want string
	}{
		{"http://127.0.0.1:8080/callback", "http://127.0.0.1:8080/callback"},
		{"http://localhost:9999/auth/cb", "http://localhost:9999/auth/cb"},
		{"http://[::1]:3000/callback", "http://[::1]:3000/callback"},
	}

	for _, tt := range tests {
		h, err := NewWithURI(tt.uri)
		if err != nil {
			t.Errorf("NewWithURI(%q): %v", tt.uri, err)
			continue
		}
		if h.RedirectURI() != tt.want {
			t.Errorf("RedirectURI() = %q, want %q", h.RedirectURI(), tt.want)
		}
	}
}

func TestNewWithURI_RejectsNonLoopback(t *testing.T) {
	tests := []string{
		"http://0.0.0.0:8080/callback",
		"http://192.168.1.1:8080/callback",
		"http://example.com:8080/callback",
		"http://10.0.0.1:8080/callback",
	}

	for _, uri := range tests {
		_, err := NewWithURI(uri)
		if err == nil {
			t.Errorf("NewWithURI(%q) should reject non-loopback host", uri)
		}
	}
}

func TestNewWithURI_RejectsMissingPort(t *testing.T) {
	_, err := NewWithURI("http://127.0.0.1/callback")
	if err == nil {
		t.Error("NewWithURI without port should fail")
	}
}

func TestStartAuthFlow_ReceivesCallback(t *testing.T) {
	h := New(19876)
	h.OpenBrowser = func(_ string) error {
		// Simulate browser: make a request to the callback URL with code+state
		go func() {
			time.Sleep(50 * time.Millisecond)
			callbackURL := "http://127.0.0.1:19876/callback?code=testcode&state=teststate"
			resp, err := http.Get(callbackURL) //nolint:gosec // test-only URL
			if err != nil {
				t.Logf("callback request failed: %v", err)
				return
			}
			resp.Body.Close()
		}()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	callbackURL, err := h.StartAuthFlow(ctx, "http://idp.example.com/authorize?foo=bar")
	if err != nil {
		t.Fatalf("StartAuthFlow: %v", err)
	}

	if callbackURL == "" {
		t.Fatal("StartAuthFlow returned empty callback URL")
	}

	// Should contain the query params from the "browser" callback
	if !contains(callbackURL, "code=testcode") {
		t.Errorf("callback URL missing code: %s", callbackURL)
	}
	if !contains(callbackURL, "state=teststate") {
		t.Errorf("callback URL missing state: %s", callbackURL)
	}
}

func TestStartAuthFlow_ContextCancellation(t *testing.T) {
	h := New(19877)
	h.OpenBrowser = func(_ string) error { return nil } // don't open anything

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := h.StartAuthFlow(ctx, "http://idp.example.com/authorize")
	if err == nil {
		t.Fatal("StartAuthFlow should fail on context cancellation")
	}
}

func TestStartAuthFlow_PortInUse(t *testing.T) {
	// Occupy the port
	ln, err := net.Listen("tcp", "127.0.0.1:19878")
	if err != nil {
		t.Skipf("could not bind port for test: %v", err)
	}
	defer ln.Close()

	h := New(19878)
	h.OpenBrowser = func(_ string) error { return nil }

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err = h.StartAuthFlow(ctx, "http://idp.example.com/authorize")
	if err == nil {
		t.Error("StartAuthFlow should fail when port is in use")
	}
}

func TestStartAuthFlow_BrowserOpenFails(t *testing.T) {
	h := New(19879)
	h.OpenBrowser = func(_ string) error {
		return fmt.Errorf("browser not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := h.StartAuthFlow(ctx, "http://idp.example.com/authorize")
	if err == nil {
		t.Error("StartAuthFlow should fail when browser open fails")
	}
}

func TestDefaultBrowserOpener_TypeCheck(t *testing.T) {
	// Compile-time verification that DefaultBrowserOpener matches the expected signature
	var opener = DefaultBrowserOpener
	_ = opener
}

func contains(s, substr string) bool {
	for i := range s {
		if i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
