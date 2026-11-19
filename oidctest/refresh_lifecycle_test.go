package oidctest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// testClock is a manually advanced clock for WithClock. It is safe to read
// from the fake IdP's handler goroutines while the test advances it.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func newTestClock() *testClock { return &testClock{now: time.Now()} }

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// refreshOutcome is what a client sees from one refresh_token grant.
type refreshOutcome struct {
	status          int
	contentType     string
	body            string
	errorCode       string
	description     string
	hasDescription  bool
	refreshToken    string
	hasRefreshToken bool
}

func postRefresh(ctx context.Context, idp *FakeIDPServer, refreshToken string) (*http.Response, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {"test-client"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, idp.IssuerURL()+"/token", strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return http.DefaultClient.Do(req)
}

// refresh presents refreshToken and returns the response the client received.
func refresh(t *testing.T, idp *FakeIDPServer, refreshToken string) *refreshOutcome {
	t.Helper()
	resp, err := postRefresh(context.Background(), idp, refreshToken)
	if err != nil {
		t.Fatalf("refresh request: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read refresh response: %v", err)
	}
	got := &refreshOutcome{status: resp.StatusCode, contentType: resp.Header.Get("Content-Type"), body: string(raw)}
	if got.contentType != "application/json" {
		return got
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	got.errorCode, _ = fields["error"].(string)
	got.description, got.hasDescription = fields["error_description"].(string)
	got.refreshToken, got.hasRefreshToken = fields["refresh_token"].(string)
	return got
}

// mustRefresh presents refreshToken, requires success, and returns the refresh
// token the client holds afterwards: the rotated one, or the same one when the
// response omits refresh_token.
func mustRefresh(t *testing.T, idp *FakeIDPServer, refreshToken string) string {
	t.Helper()
	got := refresh(t, idp, refreshToken)
	if got.status != http.StatusOK {
		t.Fatalf("refresh status = %d (%s: %s), want 200", got.status, got.errorCode, got.description)
	}
	if !got.hasRefreshToken {
		return refreshToken
	}
	return got.refreshToken
}

func wantRefusal(t *testing.T, got *refreshOutcome, code, description string) {
	t.Helper()
	if got.status != http.StatusBadRequest || got.errorCode != code || got.description != description {
		t.Fatalf("refresh = %d %q %q, want 400 %q %q", got.status, got.errorCode, got.description, code, description)
	}
}

func TestFakeIDP_WithRefreshTTL_Expires(t *testing.T) {
	clock := newTestClock()
	idp := NewFakeIDP(t, WithClock(clock.Now), WithRefreshTTL(time.Hour))
	atLifetime := issueRefreshToken(t, idp, "test-client")
	pastLifetime := issueRefreshToken(t, idp, "test-client")

	clock.Advance(time.Hour)
	mustRefresh(t, idp, atLifetime)

	clock.Advance(time.Second)
	wantRefusal(t, refresh(t, idp, pastLifetime), "invalid_grant", "refresh token expired")
	// The expired token is gone, not merely refused once.
	wantRefusal(t, refresh(t, idp, pastLifetime), "invalid_grant", "invalid or expired refresh token")
}

func TestFakeIDP_RefreshTTL_DefaultIs24Hours(t *testing.T) {
	clock := newTestClock()
	idp := NewFakeIDP(t, WithClock(clock.Now))
	atLifetime := issueRefreshToken(t, idp, "test-client")
	pastLifetime := issueRefreshToken(t, idp, "test-client")

	clock.Advance(24 * time.Hour)
	mustRefresh(t, idp, atLifetime)

	clock.Advance(time.Second)
	wantRefusal(t, refresh(t, idp, pastLifetime), "invalid_grant", "refresh token expired")
}

func TestFakeIDP_WithRefreshTTL_ZeroDisablesExpiry(t *testing.T) {
	clock := newTestClock()
	idp := NewFakeIDP(t, WithClock(clock.Now), WithRefreshTTL(0))
	token := issueRefreshToken(t, idp, "test-client")

	clock.Advance(10 * 365 * 24 * time.Hour)
	mustRefresh(t, idp, token)
}

// A rotated refresh token keeps the absolute end of the session it descends
// from, as on a provider with a fixed maximum session length.
func TestFakeIDP_RefreshTTL_RotationKeepsSessionEnd(t *testing.T) {
	clock := newTestClock()
	idp := NewFakeIDP(t, WithClock(clock.Now), WithAccessTTL(time.Hour), WithRefreshTTL(24*time.Hour))
	token := issueRefreshToken(t, idp, "test-client")

	// Refresh hourly, as a client with one-hour access tokens does. Every
	// refresh rotates the token.
	for range 23 {
		clock.Advance(time.Hour)
		next := mustRefresh(t, idp, token)
		if next == token {
			t.Fatal("refresh did not rotate the token")
		}
		token = next
	}

	// 24 h + 1 s after sign-in, but only 1 h + 1 s after the last rotation.
	clock.Advance(time.Hour + time.Second)
	wantRefusal(t, refresh(t, idp, token), "invalid_grant", "refresh token expired")
}

func TestFakeIDP_WithSlidingRefreshExpiry(t *testing.T) {
	for _, rotate := range []bool{true, false} {
		name := "rotating"
		if !rotate {
			name = "not rotating"
		}
		t.Run(name, func(t *testing.T) {
			clock := newTestClock()
			idp := NewFakeIDP(t, WithClock(clock.Now), WithRefreshTTL(24*time.Hour), WithSlidingRefreshExpiry())
			idp.SetRefreshRotation(rotate)
			token := issueRefreshToken(t, idp, "test-client")

			// Each refresh within the lifetime restarts it, so the session
			// outlives the lifetime measured from sign-in.
			clock.Advance(23 * time.Hour)
			token = mustRefresh(t, idp, token)
			clock.Advance(23 * time.Hour)
			token = mustRefresh(t, idp, token)

			// An idle period longer than the lifetime ends it.
			clock.Advance(24*time.Hour + time.Second)
			wantRefusal(t, refresh(t, idp, token), "invalid_grant", "refresh token expired")
		})
	}
}

func TestFakeIDP_WithoutRefreshRotation(t *testing.T) {
	clock := newTestClock()
	idp := NewFakeIDP(t, WithClock(clock.Now), WithoutRefreshRotation())
	token := issueRefreshToken(t, idp, "test-client")

	// The same token keeps working, and responses carry no refresh_token.
	for range 2 {
		got := refresh(t, idp, token)
		if got.status != http.StatusOK {
			t.Fatalf("refresh status = %d (%s), want 200", got.status, got.description)
		}
		if got.hasRefreshToken {
			t.Fatal("refresh response carries refresh_token, want it omitted")
		}
	}

	// Turning rotation on mid-session rotates on the next refresh.
	idp.SetRefreshRotation(true)
	rotated := mustRefresh(t, idp, token)
	if rotated == token {
		t.Fatal("refresh did not rotate after SetRefreshRotation(true)")
	}
	wantRefusal(t, refresh(t, idp, token), "invalid_grant", "invalid or expired refresh token")

	// Turning it off again keeps the rotated token, which still ends with the
	// session it descends from.
	idp.SetRefreshRotation(false)
	if got := mustRefresh(t, idp, rotated); got != rotated {
		t.Fatal("refresh rotated after SetRefreshRotation(false)")
	}
	clock.Advance(24*time.Hour + time.Second)
	wantRefusal(t, refresh(t, idp, rotated), "invalid_grant", "refresh token expired")
}

func TestFakeIDP_WithRefreshReuseDetection(t *testing.T) {
	t.Run("reuse revokes the token family", func(t *testing.T) {
		idp := NewFakeIDP(t, WithRefreshReuseDetection())
		first := issueRefreshToken(t, idp, "test-client")
		second := mustRefresh(t, idp, first)
		live := mustRefresh(t, idp, second)
		otherSession := issueRefreshToken(t, idp, "test-client")

		wantRefusal(t, refresh(t, idp, first), "invalid_grant", "refresh token reuse detected; token family revoked")
		wantRefusal(t, refresh(t, idp, live), "invalid_grant", "invalid or expired refresh token")
		// Another sign-in's tokens are a different family.
		mustRefresh(t, idp, otherSession)
	})

	t.Run("off by default", func(t *testing.T) {
		idp := NewFakeIDP(t)
		first := issueRefreshToken(t, idp, "test-client")
		live := mustRefresh(t, idp, first)

		wantRefusal(t, refresh(t, idp, first), "invalid_grant", "invalid or expired refresh token")
		mustRefresh(t, idp, live)
	})

	t.Run("off keeps no rotation history", func(t *testing.T) {
		idp := NewFakeIDP(t)
		token := issueRefreshToken(t, idp, "test-client")
		for range 3 {
			token = mustRefresh(t, idp, token)
		}

		idp.mu.Lock()
		spent := len(idp.spentRefresh)
		idp.mu.Unlock()
		if spent != 0 {
			t.Fatalf("spent refresh tokens retained = %d, want 0 without reuse detection", spent)
		}
	})
}

// waitClosed fails the test unless ch is closed within a generous deadline.
func waitClosed(t *testing.T, ch <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}

func TestFakeIDP_LoseNextRefreshResponse(t *testing.T) {
	t.Run("bad gateway", func(t *testing.T) {
		idp := NewFakeIDP(t)
		token := issueRefreshToken(t, idp, "test-client")
		processed := idp.LoseNextRefreshResponse(ResponseLossBadGateway)

		got := refresh(t, idp, token)
		if got.status != http.StatusBadGateway || got.contentType != "text/html" || !strings.Contains(got.body, "502 Bad Gateway") {
			t.Fatalf("response = %d %q %q, want a 502 HTML page", got.status, got.contentType, got.body)
		}
		waitClosed(t, processed, "the refresh to be processed")
		// The refresh was processed before the response was lost: the token
		// the client still holds has been rotated out.
		wantRefusal(t, refresh(t, idp, token), "invalid_grant", "invalid or expired refresh token")
	})

	t.Run("reset", func(t *testing.T) {
		idp := NewFakeIDP(t)
		token := issueRefreshToken(t, idp, "test-client")
		processed := idp.LoseNextRefreshResponse(ResponseLossReset)

		resp, err := postRefresh(context.Background(), idp, token)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("client received status %d, want the connection reset", resp.StatusCode)
		}
		if runtime.GOOS == "linux" && !errors.Is(err, syscall.ECONNRESET) {
			t.Fatalf("client error = %v, want a connection reset", err)
		}
		waitClosed(t, processed, "the refresh to be processed")
		wantRefusal(t, refresh(t, idp, token), "invalid_grant", "invalid or expired refresh token")
	})

	t.Run("hang until the client gives up", func(t *testing.T) {
		idp := NewFakeIDP(t)
		token := issueRefreshToken(t, idp, "test-client")
		processed := idp.LoseNextRefreshResponse(ResponseLossHang)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		errc := make(chan error, 1)
		go func() {
			resp, err := postRefresh(ctx, idp, token)
			if err == nil {
				resp.Body.Close()
			}
			errc <- err
		}()

		waitClosed(t, processed, "the refresh to be processed")
		wantRefusal(t, refresh(t, idp, token), "invalid_grant", "invalid or expired refresh token")
		select {
		case err := <-errc:
			t.Fatalf("client returned before giving up: %v", err)
		case <-time.After(100 * time.Millisecond):
		}

		cancel()
		if err := <-errc; !errors.Is(err, context.Canceled) {
			t.Fatalf("client error = %v, want context.Canceled", err)
		}
	})

	t.Run("hang ends when the test does", func(t *testing.T) {
		errc := make(chan error, 1)
		t.Run("fake IdP", func(t *testing.T) {
			idp := NewFakeIDP(t)
			token := issueRefreshToken(t, idp, "test-client")
			processed := idp.LoseNextRefreshResponse(ResponseLossHang)
			go func() {
				// No deadline: the client never gives up on its own.
				resp, err := postRefresh(context.Background(), idp, token)
				if err == nil {
					resp.Body.Close()
				}
				errc <- err
			}()
			waitClosed(t, processed, "the refresh to be processed")
		})
		// The subtest's cleanup closed the fake IdP while the client waited.
		select {
		case err := <-errc:
			if err == nil {
				t.Fatal("client received a response, want the connection closed without one")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("client still hanging after the fake IdP was closed")
		}
	})

	t.Run("each call loses one refresh, in order", func(t *testing.T) {
		idp := NewFakeIDP(t, WithoutRefreshRotation())
		token := issueRefreshToken(t, idp, "test-client")
		first := idp.LoseNextRefreshResponse(ResponseLossBadGateway)
		second := idp.LoseNextRefreshResponse(ResponseLossReset)

		// A grant-scoped error answers before refresh processing and does not
		// consume a loss.
		idp.GrantErrors.Set("refresh_token", "temporarily_unavailable")
		if got := refresh(t, idp, token); got.errorCode != "temporarily_unavailable" {
			t.Fatalf("refresh error = %q, want the grant-scoped error", got.errorCode)
		}
		idp.GrantErrors.Clear("refresh_token")
		if isClosed(first) {
			t.Fatal("a grant-scoped error consumed the loss")
		}

		if got := refresh(t, idp, token); got.status != http.StatusBadGateway {
			t.Fatalf("first refresh status = %d, want 502", got.status)
		}
		waitClosed(t, first, "the first refresh to be processed")
		if isClosed(second) {
			t.Fatal("the second loss fired on the first refresh")
		}

		resp, err := postRefresh(context.Background(), idp, token)
		if err == nil {
			resp.Body.Close()
			t.Fatalf("second refresh status = %d, want the connection reset", resp.StatusCode)
		}
		waitClosed(t, second, "the second refresh to be processed")

		mustRefresh(t, idp, token)
	})

	t.Run("a retry after a lost response trips reuse detection", func(t *testing.T) {
		idp := NewFakeIDP(t, WithRefreshReuseDetection())
		token := issueRefreshToken(t, idp, "test-client")
		processed := idp.LoseNextRefreshResponse(ResponseLossBadGateway)

		if got := refresh(t, idp, token); got.status != http.StatusBadGateway {
			t.Fatalf("refresh status = %d, want 502", got.status)
		}
		waitClosed(t, processed, "the refresh to be processed")
		// The client never saw the rotated token, so it retries with the one it
		// has, which the provider now treats as reuse.
		wantRefusal(t, refresh(t, idp, token), "invalid_grant", "refresh token reuse detected; token family revoked")
	})
}

func TestFakeIDP_LoseNextRefreshResponse_UnknownLossPanics(t *testing.T) {
	idp := NewFakeIDP(t)
	defer func() {
		if recover() == nil {
			t.Fatal("LoseNextRefreshResponse(0) did not panic")
		}
	}()
	idp.LoseNextRefreshResponse(0)
}
