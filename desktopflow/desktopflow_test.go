package desktopflow

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
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

	callbackURL, err := h.StartAuthFlow(ctx, "http://idp.example.com/authorize?foo=bar&state=teststate")
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

// fireCallback returns an OpenBrowser func that, after a short delay, issues a
// callback request to the given port using the state carried in the auth URL.
func fireCallback(t *testing.T, port int, extraQuery string) func(string) error {
	t.Helper()
	return func(authURL string) error {
		st := stateFromURL(authURL)
		go func() {
			time.Sleep(20 * time.Millisecond)
			cbURL := fmt.Sprintf("http://127.0.0.1:%d/callback?code=code-%s&state=%s%s", port, st, st, extraQuery)
			resp, err := http.Get(cbURL) //nolint:gosec // test-only URL
			if err != nil {
				t.Logf("callback request failed: %v", err)
				return
			}
			resp.Body.Close()
		}()
		return nil
	}
}

func TestBroker_ConcurrentFlows(t *testing.T) {
	port := 19881
	h := New(port)
	h.OpenBrowser = fireCallback(t, port, "")

	states := []string{"alpha", "beta", "gamma"}
	results := make(chan string, len(states))
	errs := make(chan error, len(states))

	for _, st := range states {
		go func(state string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cb, err := h.StartAuthFlow(ctx, "http://idp.example.com/authorize?state="+state)
			if err != nil {
				errs <- err
				return
			}
			results <- cb
		}(st)
	}

	got := make(map[string]bool)
	for range states {
		select {
		case err := <-errs:
			t.Fatalf("StartAuthFlow: %v", err)
		case cb := <-results:
			u, err := url.Parse(cb)
			if err != nil {
				t.Fatalf("parse callback: %v", err)
			}
			got[u.Query().Get("state")] = true
		}
	}

	for _, st := range states {
		if !got[st] {
			t.Errorf("flow for state %q did not resolve", st)
		}
	}
}

func TestBroker_UnknownStateDropped(t *testing.T) {
	port := 19882
	h := New(port)
	// The browser fires a callback with a DIFFERENT state than the flow expects,
	// then the correct one. Only the correct state should resolve the flow.
	h.OpenBrowser = func(authURL string) error {
		st := stateFromURL(authURL)
		go func() {
			time.Sleep(20 * time.Millisecond)
			// Wrong state first (should be dropped with a generic page).
			if resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=x&state=wrongstate", port)); err == nil { //nolint:gosec // test-only URL
				resp.Body.Close()
			}
			// Correct state resolves the waiter.
			if resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/callback?code=y&state=%s", port, st)); err == nil { //nolint:gosec // test-only URL
				resp.Body.Close()
			}
		}()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cb, err := h.StartAuthFlow(ctx, "http://idp.example.com/authorize?state=rightstate")
	if err != nil {
		t.Fatalf("StartAuthFlow: %v", err)
	}
	u, _ := url.Parse(cb)
	if u.Query().Get("state") != "rightstate" {
		t.Errorf("resolved with state %q, want rightstate", u.Query().Get("state"))
	}
	if u.Query().Get("code") != "y" {
		t.Errorf("resolved with code %q, want y", u.Query().Get("code"))
	}
}

func TestBroker_PortReleasedAfterGrace(t *testing.T) {
	old := shutdownGrace
	shutdownGrace = 20 * time.Millisecond
	defer func() { shutdownGrace = old }()

	port := 19883
	h := New(port)
	h.OpenBrowser = fireCallback(t, port, "")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := h.StartAuthFlow(ctx, "http://idp.example.com/authorize?state=abc"); err != nil {
		t.Fatalf("StartAuthFlow: %v", err)
	}

	// After the grace period the port must be free to bind again.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			ln.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("port not released after grace period")
}

func TestBroker_ReusableAfterCompletion(t *testing.T) {
	port := 19884
	h := New(port)
	h.OpenBrowser = fireCallback(t, port, "")

	for i := range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		cb, err := h.StartAuthFlow(ctx, fmt.Sprintf("http://idp.example.com/authorize?state=run%d", i))
		cancel()
		if err != nil {
			t.Fatalf("StartAuthFlow run %d: %v", i, err)
		}
		if cb == "" {
			t.Fatalf("run %d: empty callback", i)
		}
	}
}

func TestCallbackKey_PathDisambiguates(t *testing.T) {
	// Same state on different paths must produce distinct keys so a login and a
	// logout callback never resolve each other's waiter.
	if callbackKey("/callback", "s") == callbackKey("/logout", "s") {
		t.Error("callbackKey collides across paths for the same state")
	}
	if callbackKey("/callback", "a") == callbackKey("/callback", "b") {
		t.Error("callbackKey collides across states for the same path")
	}
}

func TestSetLogoutPath(t *testing.T) {
	port := 19885
	h := New(port)
	if err := h.SetLogoutPath("/logout"); err != nil {
		t.Fatalf("SetLogoutPath: %v", err)
	}
	want := fmt.Sprintf("http://127.0.0.1:%d/logout", port)
	if h.PostLogoutRedirectURI() != want {
		t.Errorf("PostLogoutRedirectURI = %q, want %q", h.PostLogoutRedirectURI(), want)
	}
	if h.logoutPath != "/logout" {
		t.Errorf("logoutPath = %q, want /logout", h.logoutPath)
	}
}

func TestSetLogoutPath_RejectsRelative(t *testing.T) {
	h := New(19886)
	if err := h.SetLogoutPath("logout"); err == nil {
		t.Error("expected error for path without leading slash")
	}
}

func TestSetLogoutURI(t *testing.T) {
	port := 19887
	h := New(port)
	uri := fmt.Sprintf("http://127.0.0.1:%d/post-logout", port)
	if err := h.SetLogoutURI(uri); err != nil {
		t.Fatalf("SetLogoutURI: %v", err)
	}
	if h.PostLogoutRedirectURI() != uri {
		t.Errorf("PostLogoutRedirectURI = %q, want %q", h.PostLogoutRedirectURI(), uri)
	}
	if h.logoutPath != "/post-logout" {
		t.Errorf("logoutPath = %q, want /post-logout", h.logoutPath)
	}
}

func TestSetLogoutURI_RejectsDifferentPort(t *testing.T) {
	h := New(19888)
	if err := h.SetLogoutURI("http://127.0.0.1:19999/callback"); err == nil {
		t.Error("expected error for mismatched port")
	}
}

func TestSetLogoutURI_RejectsNonLoopback(t *testing.T) {
	port := 19889
	h := New(port)
	if err := h.SetLogoutURI(fmt.Sprintf("http://example.com:%d/callback", port)); err == nil {
		t.Error("expected error for non-loopback host")
	}
}

func TestPostLogoutRedirectURI_DefaultsToLogin(t *testing.T) {
	port := 19890
	h := New(port)
	want := fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	if h.PostLogoutRedirectURI() != want {
		t.Errorf("PostLogoutRedirectURI = %q, want %q", h.PostLogoutRedirectURI(), want)
	}
}

func TestStartLogoutFlow_SeparatePath(t *testing.T) {
	port := 19891
	h := New(port)
	if err := h.SetLogoutPath("/logout"); err != nil {
		t.Fatalf("SetLogoutPath: %v", err)
	}
	h.OpenBrowser = func(logoutURL string) error {
		st := stateFromURL(logoutURL)
		go func() {
			time.Sleep(20 * time.Millisecond)
			cbURL := fmt.Sprintf("http://127.0.0.1:%d/logout?state=%s", port, st)
			if resp, err := http.Get(cbURL); err == nil { //nolint:gosec // test-only URL
				resp.Body.Close()
			}
		}()
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cb, err := h.StartLogoutFlow(ctx, "http://idp.example.com/logout?state=logoutstate")
	if err != nil {
		t.Fatalf("StartLogoutFlow: %v", err)
	}
	u, err := url.Parse(cb)
	if err != nil {
		t.Fatalf("parse callback: %v", err)
	}
	if u.Path != "/logout" {
		t.Errorf("callback path = %q, want /logout", u.Path)
	}
	if u.Query().Get("state") != "logoutstate" {
		t.Errorf("state = %q, want logoutstate", u.Query().Get("state"))
	}
}

func contains(s, substr string) bool {
	for i := range s {
		if i+len(substr) <= len(s) && s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func TestHandler_PageFor_LoginSuccess(t *testing.T) {
	h := New(19500)
	got := h.pageFor("/callback", false)
	if !contains(got, "Authentication Successful") {
		t.Errorf("login success page should contain 'Authentication Successful', got %q", got)
	}
}

func TestHandler_PageFor_LogoutWithSeparatePath(t *testing.T) {
	h := New(19500)
	if err := h.SetLogoutPath("/logout-callback"); err != nil {
		t.Fatal(err)
	}
	got := h.pageFor("/logout-callback", false)
	if !contains(got, "Logged Out") {
		t.Errorf("logout page should contain 'Logged Out', got %q", got)
	}
	// Login path should still show authentication success.
	loginPage := h.pageFor("/callback", false)
	if !contains(loginPage, "Authentication Successful") {
		t.Errorf("login path should still show 'Authentication Successful', got %q", loginPage)
	}
}

func TestHandler_PageFor_LogoutSamePathFallsBackToSuccess(t *testing.T) {
	h := New(19500)
	// When login and logout share the same path (no SetLogoutPath called),
	// the page should show the login success message.
	got := h.pageFor("/callback", false)
	if !contains(got, "Authentication Successful") {
		t.Errorf("same-path logout should show 'Authentication Successful', got %q", got)
	}
}

func TestHandler_PageFor_CustomLogoutHTML(t *testing.T) {
	h := New(19500)
	if err := h.SetLogoutPath("/logout-callback"); err != nil {
		t.Fatal(err)
	}
	h.LogoutHTML = "<html><body>Custom Logout</body></html>"
	got := h.pageFor("/logout-callback", false)
	if got != h.LogoutHTML {
		t.Errorf("expected custom LogoutHTML, got %q", got)
	}
}

func TestHandler_PageFor_Error(t *testing.T) {
	h := New(19500)
	if err := h.SetLogoutPath("/logout-callback"); err != nil {
		t.Fatal(err)
	}
	// Errors on either path should show the error page.
	for _, path := range []string{"/callback", "/logout-callback"} {
		got := h.pageFor(path, true)
		if !contains(got, "Authentication Error") {
			t.Errorf("error page on %s should contain 'Authentication Error', got %q", path, got)
		}
	}
}
