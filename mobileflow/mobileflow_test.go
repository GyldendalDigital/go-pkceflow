package mobileflow

import (
	"context"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })
	if h.RedirectURI() != "https://myapp.example.com/callback" {
		t.Errorf("RedirectURI() = %q", h.RedirectURI())
	}
}

func TestStartAuthFlow_HappyPath(t *testing.T) {
	var openedURL string
	h := New("https://myapp.example.com/callback", func(url string) error {
		openedURL = url
		return nil
	})

	go func() {
		time.Sleep(50 * time.Millisecond)
		h.DeliverURL("https://myapp.example.com/callback?code=abc&state=xyz")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := h.StartAuthFlow(ctx, "https://idp.example.com/authorize?foo=bar")
	if err != nil {
		t.Fatalf("StartAuthFlow: %v", err)
	}

	if openedURL != "https://idp.example.com/authorize?foo=bar" {
		t.Errorf("openURL called with %q", openedURL)
	}

	if result != "https://myapp.example.com/callback?code=abc&state=xyz" {
		t.Errorf("result = %q", result)
	}
}

func TestStartAuthFlow_ContextCancellation(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := h.StartAuthFlow(ctx, "https://idp.example.com/authorize")
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
}

func TestDeliverURL_NoFlowInProgress(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	// Should not panic or block
	h.DeliverURL("https://myapp.example.com/callback?code=abc")
}

func TestStartAuthFlow_ConcurrentSafety(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.DeliverURL("https://myapp.example.com/callback?code=abc")
		}()
	}

	// Start a flow that one of the deliveries should satisfy
	go func() {
		time.Sleep(10 * time.Millisecond)
		h.DeliverURL("https://myapp.example.com/callback?code=final")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	_, err := h.StartAuthFlow(ctx, "https://idp.example.com/authorize")
	if err != nil {
		t.Logf("StartAuthFlow: %v (acceptable in race test)", err)
	}
	wg.Wait()
}

func TestStartAuthFlow_DrainsStaleDelivery(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	// Deliver before flow starts (stale)
	h.DeliverURL("https://myapp.example.com/callback?code=stale")

	// Now start a flow -- it should drain the stale delivery and wait for a new one
	go func() {
		time.Sleep(50 * time.Millisecond)
		h.DeliverURL("https://myapp.example.com/callback?code=fresh")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := h.StartAuthFlow(ctx, "https://idp.example.com/authorize")
	if err != nil {
		t.Fatalf("StartAuthFlow: %v", err)
	}

	if result != "https://myapp.example.com/callback?code=fresh" {
		t.Errorf("got stale delivery: %s", result)
	}
}

func TestPostLogoutRedirectURI_DefaultsToLogin(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })
	if got := h.PostLogoutRedirectURI(); got != "https://myapp.example.com/callback" {
		t.Errorf("PostLogoutRedirectURI() = %q, want login redirect URI", got)
	}
}

func TestSetLogoutURI(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	if err := h.SetLogoutURI("https://myapp.example.com/logout-done"); err != nil {
		t.Fatalf("SetLogoutURI: %v", err)
	}
	if got := h.PostLogoutRedirectURI(); got != "https://myapp.example.com/logout-done" {
		t.Errorf("PostLogoutRedirectURI() = %q after override", got)
	}

	// Custom scheme URIs are valid for mobile too.
	if err := h.SetLogoutURI("myapp://logout"); err != nil {
		t.Fatalf("SetLogoutURI (custom scheme): %v", err)
	}
	if got := h.PostLogoutRedirectURI(); got != "myapp://logout" {
		t.Errorf("PostLogoutRedirectURI() = %q after custom scheme override", got)
	}
}

func TestSetLogoutURI_Empty(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })
	if err := h.SetLogoutURI(""); err == nil {
		t.Fatal("expected error for empty logout URI")
	}
}

func TestStartLogoutFlow_HappyPath(t *testing.T) {
	var openedURL string
	h := New("https://myapp.example.com/callback", func(url string) error {
		openedURL = url
		return nil
	})

	go func() {
		time.Sleep(50 * time.Millisecond)
		h.DeliverURL("https://myapp.example.com/callback?state=logout")
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	result, err := h.StartLogoutFlow(ctx, "https://idp.example.com/logout?post_logout_redirect_uri=x")
	if err != nil {
		t.Fatalf("StartLogoutFlow: %v", err)
	}
	if openedURL != "https://idp.example.com/logout?post_logout_redirect_uri=x" {
		t.Errorf("openURL called with %q", openedURL)
	}
	if result != "https://myapp.example.com/callback?state=logout" {
		t.Errorf("result = %q", result)
	}
}

func TestStartLogoutFlow_ContextCancellation(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := h.StartLogoutFlow(ctx, "https://idp.example.com/logout")
	if err == nil {
		t.Fatal("expected error on context cancellation")
	}
}
