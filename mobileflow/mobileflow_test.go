package mobileflow

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const testTimeout = 2 * time.Second

type flowResult struct {
	callback string
	err      error
}

func startAuth(ctx context.Context, h *Handler, authURL string) <-chan flowResult {
	result := make(chan flowResult, 1)
	go func() {
		callback, err := h.StartAuthFlow(ctx, authURL)
		result <- flowResult{callback: callback, err: err}
	}()
	return result
}

func startLogout(ctx context.Context, h *Handler, logoutURL string) <-chan flowResult {
	result := make(chan flowResult, 1)
	go func() {
		callback, err := h.StartLogoutFlow(ctx, logoutURL)
		result <- flowResult{callback: callback, err: err}
	}()
	return result
}

func authTarget(state, redirectURI string) string {
	query := url.Values{
		"client_id":    {"test"},
		"redirect_uri": {redirectURI},
		"state":        {state},
	}
	return "https://idp.example.com/authorize?" + query.Encode()
}

func logoutTarget(state, redirectURI string) string {
	query := url.Values{
		"post_logout_redirect_uri": {redirectURI},
		"state":                    {state},
	}
	return "https://idp.example.com/logout?" + query.Encode()
}

func waitForOpenedURL(t *testing.T, opened <-chan string) string {
	t.Helper()
	select {
	case target := <-opened:
		return target
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for URL opener")
		return ""
	}
}

func waitForResult(t *testing.T, result <-chan flowResult) flowResult {
	t.Helper()
	select {
	case got := <-result:
		return got
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for flow result")
		return flowResult{}
	}
}

func waitForSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(testTimeout):
		t.Fatal("timed out waiting for test signal")
	}
}

func TestNew(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })
	if h.RedirectURI() != "https://myapp.example.com/callback" {
		t.Errorf("RedirectURI() = %q", h.RedirectURI())
	}
	if h.PostLogoutRedirectURI() != h.RedirectURI() {
		t.Errorf("PostLogoutRedirectURI() = %q, want login redirect URI", h.PostLogoutRedirectURI())
	}
}

func TestStartAuthFlowHappyPath(t *testing.T) {
	opened := make(chan string, 1)
	h := New("https://myapp.example.com/callback", func(target string) error {
		opened <- target
		return nil
	})

	target := authTarget("xyz", h.RedirectURI())
	result := startAuth(context.Background(), h, target)
	if got := waitForOpenedURL(t, opened); got != target {
		t.Errorf("openURL called with %q", got)
	}

	callback := "https://myapp.example.com/callback?code=abc&state=xyz"
	h.DeliverURL(callback)
	got := waitForResult(t, result)
	if got.err != nil {
		t.Fatalf("StartAuthFlow: %v", got.err)
	}
	if got.callback != callback {
		t.Errorf("callback = %q, want %q", got.callback, callback)
	}
}

func TestStartAuthFlowRegistersBeforeOpeningURL(t *testing.T) {
	var h *Handler
	h = New("myapp://auth/callback", func(_ string) error {
		h.DeliverURL("myapp://auth/callback?code=abc&state=sync")
		return nil
	})

	callback, err := h.StartAuthFlow(
		context.Background(),
		authTarget("sync", h.RedirectURI()),
	)
	if err != nil {
		t.Fatalf("StartAuthFlow: %v", err)
	}
	if callback != "myapp://auth/callback?code=abc&state=sync" {
		t.Errorf("callback = %q", callback)
	}
}

func TestStartAuthFlowFiltersUnrelatedURLs(t *testing.T) {
	opened := make(chan string, 1)
	h := New("https://app.example.com:8443/callback?tenant=one", func(target string) error {
		opened <- target
		return nil
	})

	result := startAuth(context.Background(), h, authTarget("expected", h.RedirectURI()))
	waitForOpenedURL(t, opened)

	unrelated := []string{
		"not-an-absolute-url",
		"http://app.example.com:8443/callback?tenant=one&state=expected",
		"https://other.example.com:8443/callback?tenant=one&state=expected",
		"https://app.example.com.evil:8443/callback?tenant=one&state=expected",
		"https://user@app.example.com:8443/callback?tenant=one&state=expected",
		"https://app.example.com/callback?tenant=one&state=expected",
		"https://app.example.com:8443/other?tenant=one&state=expected",
		"https://app.example.com:8443/callback/extra?tenant=one&state=expected",
		"https://app.example.com:8443/call%62ack?tenant=one&state=expected",
		"https://app.example.com:8443/callback/?tenant=one&state=expected",
		"https://app.example.com:8443/other/../callback?tenant=one&state=expected",
		"https://app.example.com:8443/callback?tenant=two&state=expected",
		"https://app.example.com:8443/callback?tenant=one&tenant=evil&state=expected",
		"https://app.example.com:8443/callback?tenant=one&state=wrong",
		"https://app.example.com:8443/callback?tenant=one",
		"https://app.example.com:8443/callback?tenant=one&state=",
		"https://app.example.com:8443/callback?tenant=one&state=expected&state=expected",
		"https://app.example.com:8443/callback?tenant=one&state=expected;bad=value",
		"https://app.example.com:8443/callback?tenant=one&state=expected#fragment",
	}
	for _, callback := range unrelated {
		h.DeliverURL(callback)
	}

	want := "https://APP.example.com:8443/callback?tenant=one&code=abc&state=expected"
	h.DeliverURL(want)
	got := waitForResult(t, result)
	if got.err != nil {
		t.Fatalf("StartAuthFlow: %v", got.err)
	}
	if got.callback != want {
		t.Errorf("callback = %q, want matching callback %q", got.callback, want)
	}
}

func TestStartAuthFlowDistinguishesURISyntax(t *testing.T) {
	tests := []struct {
		name       string
		redirect   string
		unrelated  string
		correlated string
	}{
		{
			name:       "custom scheme authority marker",
			redirect:   "com.example.app:/callback",
			unrelated:  "com.example.app:///callback?code=wrong&state=expected",
			correlated: "com.example.app:/callback?code=right&state=expected",
		},
		{
			name:       "explicit empty port",
			redirect:   "https://app.example.com/callback",
			unrelated:  "https://app.example.com:/callback?code=wrong&state=expected",
			correlated: "https://app.example.com/callback?code=right&state=expected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opened := make(chan string, 1)
			h := New(tt.redirect, func(target string) error {
				opened <- target
				return nil
			})
			result := startAuth(
				context.Background(),
				h,
				authTarget("expected", h.RedirectURI()),
			)
			waitForOpenedURL(t, opened)
			h.DeliverURL(tt.unrelated)
			h.DeliverURL(tt.correlated)

			got := waitForResult(t, result)
			if got.err != nil || got.callback != tt.correlated {
				t.Fatalf(
					"flow = (%q, %v), want correlated callback %q",
					got.callback,
					got.err,
					tt.correlated,
				)
			}
		})
	}
}

func TestDeliverURLBeforeFlowIsDropped(t *testing.T) {
	opened := make(chan string, 1)
	h := New("https://myapp.example.com/callback", func(target string) error {
		opened <- target
		return nil
	})
	h.DeliverURL("https://myapp.example.com/callback?code=stale&state=fresh")

	result := startAuth(context.Background(), h, authTarget("fresh", h.RedirectURI()))
	waitForOpenedURL(t, opened)
	want := "https://myapp.example.com/callback?code=fresh&state=fresh"
	h.DeliverURL(want)

	got := waitForResult(t, result)
	if got.err != nil {
		t.Fatalf("StartAuthFlow: %v", got.err)
	}
	if got.callback != want {
		t.Errorf("callback = %q, want %q", got.callback, want)
	}
}

func TestStartAuthFlowContextCancellation(t *testing.T) {
	opened := make(chan string, 1)
	h := New("https://myapp.example.com/callback", func(target string) error {
		opened <- target
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := startAuth(ctx, h, authTarget("cancel", h.RedirectURI()))
	waitForOpenedURL(t, opened)
	cancel()

	got := waitForResult(t, result)
	if !errors.Is(got.err, context.Canceled) {
		t.Fatalf("StartAuthFlow error = %v, want context.Canceled", got.err)
	}
}

func TestCancelledFlowDoesNotBlockNextFlow(t *testing.T) {
	opened := make(chan string, 2)
	h := New("https://myapp.example.com/callback", func(target string) error {
		opened <- target
		return nil
	})

	firstCtx, cancelFirst := context.WithCancel(context.Background())
	first := startAuth(firstCtx, h, authTarget("first", h.RedirectURI()))
	waitForOpenedURL(t, opened)
	cancelFirst()
	if got := waitForResult(t, first); !errors.Is(got.err, context.Canceled) {
		t.Fatalf("first flow error = %v, want context.Canceled", got.err)
	}
	h.DeliverURL("https://myapp.example.com/callback?code=late&state=first")

	second := startAuth(context.Background(), h, authTarget("second", h.RedirectURI()))
	waitForOpenedURL(t, opened)
	want := "https://myapp.example.com/callback?code=abc&state=second"
	h.DeliverURL(want)
	got := waitForResult(t, second)
	if got.err != nil || got.callback != want {
		t.Fatalf("second flow = (%q, %v), want (%q, nil)", got.callback, got.err, want)
	}
}

func TestConcurrentFlowIsRejected(t *testing.T) {
	tests := []struct {
		name       string
		firstKind  string
		secondKind string
	}{
		{name: "auth then auth", firstKind: "auth", secondKind: "auth"},
		{name: "auth then logout", firstKind: "auth", secondKind: "logout"},
		{name: "logout then auth", firstKind: "logout", secondKind: "auth"},
		{name: "logout then logout", firstKind: "logout", secondKind: "logout"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opened := make(chan string, 2)
			h := New("https://myapp.example.com/callback", func(target string) error {
				opened <- target
				return nil
			})

			var first <-chan flowResult
			if tt.firstKind == "auth" {
				first = startAuth(context.Background(), h, authTarget("first", h.RedirectURI()))
			} else {
				first = startLogout(
					context.Background(),
					h,
					logoutTarget("first", h.PostLogoutRedirectURI()),
				)
			}
			waitForOpenedURL(t, opened)

			var err error
			if tt.secondKind == "auth" {
				_, err = h.StartAuthFlow(
					context.Background(),
					authTarget("second", h.RedirectURI()),
				)
			} else {
				_, err = h.StartLogoutFlow(
					context.Background(),
					logoutTarget("second", h.PostLogoutRedirectURI()),
				)
			}
			if !errors.Is(err, ErrFlowInProgress) {
				t.Fatalf("concurrent %s error = %v, want ErrFlowInProgress", tt.secondKind, err)
			}
			select {
			case target := <-opened:
				t.Fatalf("concurrent flow unexpectedly opened %q", target)
			default:
			}

			h.DeliverURL("https://myapp.example.com/callback?code=abc&state=first")
			if got := waitForResult(t, first); got.err != nil {
				t.Fatalf("first flow: %v", got.err)
			}
		})
	}
}

func TestFirstMatchingDeliveryWins(t *testing.T) {
	openerStarted := make(chan struct{})
	releaseOpener := make(chan struct{})
	h := New("https://myapp.example.com/callback", func(_ string) error {
		close(openerStarted)
		<-releaseOpener
		return nil
	})

	result := startAuth(context.Background(), h, authTarget("one-shot", h.RedirectURI()))
	waitForSignal(t, openerStarted)
	first := "https://myapp.example.com/callback?code=first&state=one-shot"
	h.DeliverURL(first)
	h.DeliverURL("https://myapp.example.com/callback?code=second&state=one-shot")
	close(releaseOpener)

	got := waitForResult(t, result)
	if got.err != nil {
		t.Fatalf("StartAuthFlow: %v", got.err)
	}
	if got.callback != first {
		t.Errorf("callback = %q, want first matching callback %q", got.callback, first)
	}
}

func TestAcceptedDeliveryWinsConcurrentCancellation(t *testing.T) {
	openerStarted := make(chan struct{})
	releaseOpener := make(chan struct{})
	h := New("https://myapp.example.com/callback", func(_ string) error {
		close(openerStarted)
		<-releaseOpener
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	result := startAuth(ctx, h, authTarget("race", h.RedirectURI()))
	waitForSignal(t, openerStarted)

	want := "https://myapp.example.com/callback?code=accepted&state=race"
	h.DeliverURL(want)
	cancel()
	close(releaseOpener)

	got := waitForResult(t, result)
	if got.err != nil || got.callback != want {
		t.Fatalf("flow = (%q, %v), want accepted callback (%q, nil)", got.callback, got.err, want)
	}
}

func TestDeliverURLIsConcurrentSafe(t *testing.T) {
	opened := make(chan string, 1)
	h := New("https://myapp.example.com/callback", func(target string) error {
		opened <- target
		return nil
	})
	result := startAuth(context.Background(), h, authTarget("concurrent", h.RedirectURI()))
	waitForOpenedURL(t, opened)

	const deliveries = 32
	var wg sync.WaitGroup
	for i := range deliveries {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.DeliverURL(fmt.Sprintf(
				"https://myapp.example.com/callback?code=%d&state=concurrent",
				i,
			))
		}()
	}
	wg.Wait()

	got := waitForResult(t, result)
	if got.err != nil {
		t.Fatalf("StartAuthFlow: %v", got.err)
	}
	if !strings.Contains(got.callback, "state=concurrent") {
		t.Errorf("callback = %q", got.callback)
	}
}

func TestStartAuthFlowInputErrors(t *testing.T) {
	openErr := errors.New("cannot open browser")
	tests := []struct {
		name     string
		redirect string
		opener   func(string) error
		authURL  string
		ctx      context.Context
		want     string
	}{
		{
			name:     "cancelled context",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { t.Fatal("opener called"); return nil },
			authURL:  authTarget("x", "https://app.example.com/callback"),
			ctx:      cancelledContext(),
			want:     context.Canceled.Error(),
		},
		{
			name:     "invalid auth URL",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return nil },
			authURL:  "://bad",
			ctx:      context.Background(),
			want:     "invalid auth URL",
		},
		{
			name:     "missing state",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return nil },
			authURL:  authTarget("", "https://app.example.com/callback"),
			ctx:      context.Background(),
			want:     "auth URL must contain exactly one non-empty state",
		},
		{
			name:     "duplicate state",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return nil },
			authURL: authTarget("x", "https://app.example.com/callback") +
				"&state=duplicate",
			ctx:  context.Background(),
			want: "auth URL must contain exactly one non-empty state",
		},
		{
			name:     "missing redirect URI",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return nil },
			authURL:  "https://idp.example.com/authorize?state=x",
			ctx:      context.Background(),
			want:     "exactly one non-empty redirect_uri",
		},
		{
			name:     "duplicate redirect URI",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return nil },
			authURL: authTarget("x", "https://app.example.com/callback") +
				"&redirect_uri=https%3A%2F%2Fevil.example%2Fcallback",
			ctx:  context.Background(),
			want: "exactly one non-empty redirect_uri",
		},
		{
			name:     "redirect URI mismatch",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return nil },
			authURL:  authTarget("x", "https://evil.example/callback"),
			ctx:      context.Background(),
			want:     "does not match the configured redirect URI",
		},
		{
			name:     "malformed query",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return nil },
			authURL: authTarget("x", "https://app.example.com/callback") +
				";bad=value",
			ctx:  context.Background(),
			want: "invalid auth URL query",
		},
		{
			name:     "invalid redirect URI",
			redirect: "relative/callback",
			opener:   func(string) error { return nil },
			authURL:  authTarget("x", "relative/callback"),
			ctx:      context.Background(),
			want:     "invalid auth redirect URI",
		},
		{
			name:     "nil opener",
			redirect: "https://app.example.com/callback",
			authURL:  authTarget("x", "https://app.example.com/callback"),
			ctx:      context.Background(),
			want:     "URL opener is nil",
		},
		{
			name:     "opener failure",
			redirect: "https://app.example.com/callback",
			opener:   func(string) error { return openErr },
			authURL:  authTarget("x", "https://app.example.com/callback"),
			ctx:      context.Background(),
			want:     "failed to open auth URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := New(tt.redirect, tt.opener)
			_, err := h.StartAuthFlow(tt.ctx, tt.authURL)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("StartAuthFlow error = %v, want containing %q", err, tt.want)
			}
		})
	}
}

func TestOpenerFailureDoesNotBlockNextFlow(t *testing.T) {
	openErr := errors.New("cannot open browser")
	opened := make(chan string, 1)
	var calls int
	h := New("https://myapp.example.com/callback", func(target string) error {
		calls++
		if calls == 1 {
			return openErr
		}
		opened <- target
		return nil
	})

	if _, err := h.StartAuthFlow(
		context.Background(),
		authTarget("first", h.RedirectURI()),
	); !errors.Is(err, openErr) {
		t.Fatalf("first StartAuthFlow error = %v, want opener error", err)
	}

	second := startAuth(context.Background(), h, authTarget("second", h.RedirectURI()))
	waitForOpenedURL(t, opened)
	want := "https://myapp.example.com/callback?code=abc&state=second"
	h.DeliverURL(want)
	got := waitForResult(t, second)
	if got.err != nil || got.callback != want {
		t.Fatalf("second flow = (%q, %v), want (%q, nil)", got.callback, got.err, want)
	}
}

func TestStartLogoutFlowHappyPath(t *testing.T) {
	opened := make(chan string, 1)
	h := New("https://myapp.example.com/callback", func(target string) error {
		opened <- target
		return nil
	})
	if err := h.SetLogoutURI("https://myapp.example.com/logout-done"); err != nil {
		t.Fatalf("SetLogoutURI: %v", err)
	}

	result := startLogout(context.Background(), h, logoutTarget("logout", h.PostLogoutRedirectURI()))
	waitForOpenedURL(t, opened)
	callback := "https://myapp.example.com/logout-done?state=logout"
	h.DeliverURL(callback)

	got := waitForResult(t, result)
	if got.err != nil {
		t.Fatalf("StartLogoutFlow: %v", got.err)
	}
	if got.callback != callback {
		t.Errorf("callback = %q, want %q", got.callback, callback)
	}
}

func TestStartLogoutFlowAllowsMissingStateOnlyForMatchingURI(t *testing.T) {
	opened := make(chan string, 1)
	h := New("myapp://auth/callback", func(target string) error {
		opened <- target
		return nil
	})
	if err := h.SetLogoutURI("myapp://auth/logout"); err != nil {
		t.Fatalf("SetLogoutURI: %v", err)
	}

	result := startLogout(context.Background(), h, logoutTarget("expected", h.PostLogoutRedirectURI()))
	waitForOpenedURL(t, opened)
	h.DeliverURL("myapp://unrelated/logout")
	h.DeliverURL("myapp://auth/callback")
	h.DeliverURL("myapp://auth/logout?state=wrong")
	h.DeliverURL("myapp://auth/logout?code=authorization-code")
	h.DeliverURL("myapp://auth/logout?error=access_denied")
	want := "myapp://auth/logout"
	h.DeliverURL(want)

	got := waitForResult(t, result)
	if got.err != nil {
		t.Fatalf("StartLogoutFlow: %v", got.err)
	}
	if got.callback != want {
		t.Errorf("callback = %q, want matching missing-state callback %q", got.callback, want)
	}
}

func TestSetLogoutURI(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	if err := h.SetLogoutURI("https://myapp.example.com/logout-done"); err != nil {
		t.Fatalf("SetLogoutURI: %v", err)
	}
	if got := h.PostLogoutRedirectURI(); got != "https://myapp.example.com/logout-done" {
		t.Errorf("PostLogoutRedirectURI() = %q", got)
	}

	if err := h.SetLogoutURI("myapp://logout"); err != nil {
		t.Fatalf("SetLogoutURI custom scheme: %v", err)
	}
	if got := h.PostLogoutRedirectURI(); got != "myapp://logout" {
		t.Errorf("PostLogoutRedirectURI() = %q", got)
	}
}

func TestSetLogoutURIRejectsInvalidValues(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })
	for _, uri := range []string{
		"",
		"relative/callback",
		"https:///missing-host",
		"https://user@example.com/callback",
		"https://example.com/callback#fragment",
		"myapp:",
		"myapp:opaque",
	} {
		t.Run(uri, func(t *testing.T) {
			if err := h.SetLogoutURI(uri); err == nil {
				t.Fatalf("SetLogoutURI(%q) succeeded, want error", uri)
			}
		})
	}
}

func TestLogoutURIConcurrentAccess(t *testing.T) {
	h := New("https://myapp.example.com/callback", func(_ string) error { return nil })

	const iterations = 64
	var wg sync.WaitGroup
	for i := range iterations {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_ = h.SetLogoutURI(fmt.Sprintf("myapp://auth/logout/%d", i))
		}()
		go func() {
			defer wg.Done()
			_ = h.PostLogoutRedirectURI()
		}()
	}
	wg.Wait()
}

func cancelledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
