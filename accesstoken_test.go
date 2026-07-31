package pkceflow

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestAccessTokenRechecksGraceAfterFailedRefresh(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	gracePeriod := 100 * time.Second
	graceEnd := authenticatedAt.Add(gracePeriod)

	tests := []struct {
		name          string
		startAt       time.Time
		finishAt      time.Time
		wantToken     bool
		wantGraceMode bool
	}{
		{
			name:          "finishes inside grace",
			startAt:       graceEnd.Add(-2 * time.Nanosecond),
			finishAt:      graceEnd.Add(-time.Nanosecond),
			wantToken:     true,
			wantGraceMode: true,
		},
		{
			name:     "finishes at grace end",
			startAt:  graceEnd.Add(-time.Nanosecond),
			finishAt: graceEnd,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newManualRefreshClock(tt.startAt)
			store := &memoryStore{}
			client, state, endpoint := newRefreshConcurrencyClient(t, store, nil)
			state.ExpiresAt = authenticatedAt.Add(10 * time.Second)
			state.LastAuthAt = authenticatedAt
			if err := store.Save(state); err != nil {
				t.Fatalf("save state: %v", err)
			}

			client.mu.Lock()
			client.state = state
			client.clock = clock
			client.config.GracePeriod = gracePeriod
			client.mu.Unlock()
			endpoint.status = http.StatusServiceUnavailable

			result := make(chan string, 1)
			go func() {
				result <- client.AccessToken(context.Background())
			}()
			waitForTestSignal(t, endpoint.entered, "AccessToken refresh did not reach token endpoint")
			clock.set(tt.finishAt)
			endpoint.unblock()

			got := waitForTestString(t, result, "AccessToken did not return after failed refresh")
			want := ""
			if tt.wantToken {
				want = state.AccessToken
			}
			if got != want {
				t.Fatalf("AccessToken = %q, want %q", got, want)
			}
			status := client.AuthStatus()
			if status.GraceMode != tt.wantGraceMode || status.CanUseApp != tt.wantGraceMode {
				t.Fatalf("AuthStatus = %+v, want grace and usability %v", status, tt.wantGraceMode)
			}
			client.mu.Lock()
			current := client.state
			client.mu.Unlock()
			if current != state {
				t.Fatalf("state changed after failed refresh: %+v", current)
			}
			if requests := endpoint.requests.Load(); requests != 1 {
				t.Fatalf("token endpoint requests = %d, want 1", requests)
			}
		})
	}
}

func TestAccessTokenWithoutRefreshTokenHonorsGraceBoundary(t *testing.T) {
	authenticatedAt := time.Date(2026, time.July, 31, 12, 0, 0, 0, time.UTC)
	gracePeriod := 100 * time.Second
	graceEnd := authenticatedAt.Add(gracePeriod)

	tests := []struct {
		name          string
		now           time.Time
		gracePeriod   time.Duration
		wantToken     bool
		wantGraceMode bool
	}{
		{
			name:          "inside grace",
			now:           graceEnd.Add(-time.Nanosecond),
			gracePeriod:   gracePeriod,
			wantToken:     true,
			wantGraceMode: true,
		},
		{name: "at grace end", now: graceEnd, gracePeriod: gracePeriod},
		{name: "after grace", now: graceEnd.Add(time.Nanosecond), gracePeriod: gracePeriod},
		{name: "grace disabled", now: graceEnd.Add(-time.Nanosecond)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			clock := newManualRefreshClock(tt.now)
			store := &memoryStore{}
			client, state, endpoint := newRefreshConcurrencyClient(t, store, nil)
			state.RefreshToken = ""
			state.ExpiresAt = authenticatedAt.Add(10 * time.Second)
			state.LastAuthAt = authenticatedAt
			if err := store.Save(state); err != nil {
				t.Fatalf("save state: %v", err)
			}

			client.mu.Lock()
			client.state = state
			client.clock = clock
			client.config.GracePeriod = tt.gracePeriod
			client.mu.Unlock()

			got := client.AccessToken(context.Background())
			want := ""
			if tt.wantToken {
				want = state.AccessToken
			}
			if got != want {
				t.Fatalf("AccessToken = %q, want %q", got, want)
			}
			status := client.AuthStatus()
			if status.GraceMode != tt.wantGraceMode || status.CanUseApp != tt.wantGraceMode {
				t.Fatalf("AuthStatus = %+v, want grace and usability %v", status, tt.wantGraceMode)
			}
			if requests := endpoint.requests.Load(); requests != 0 {
				t.Fatalf("token endpoint requests = %d, want 0", requests)
			}
		})
	}
}
