package oidctest

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

func TestMemoryStore_SaveLoadDelete(t *testing.T) {
	store := &MemoryStore{}

	// Load on empty returns zero state
	state, err := store.Load()
	if err != nil {
		t.Fatalf("Load on empty: %v", err)
	}
	if !state.IsZero() {
		t.Error("Load on empty should return zero state")
	}

	// Save and load
	saved := pkceflow.TokenState{
		AccessToken:  "access",
		RefreshToken: "refresh",
		IDToken:      "id",
		ExpiresAt:    time.Now().Add(time.Hour),
		LastAuthAt:   time.Now(),
	}
	if err := store.Save(saved); err != nil {
		t.Fatalf("Save: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load after save: %v", err)
	}
	if loaded.AccessToken != "access" || loaded.RefreshToken != "refresh" || loaded.IDToken != "id" {
		t.Errorf("Load returned wrong state: %+v", loaded)
	}

	// Delete
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	state, _ = store.Load()
	if !state.IsZero() {
		t.Error("Load after delete should return zero state")
	}
}

func TestMemoryStore_Concurrent(t *testing.T) {
	store := &MemoryStore{}
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_ = store.Save(pkceflow.TokenState{AccessToken: "token"})
			_, _ = store.Load()
		}(i)
	}
	wg.Wait()
}

func TestRecordingEmitter_CaptureEvents(t *testing.T) {
	emitter := &RecordingEmitter{}

	// No events initially
	if emitter.HasEvent("anything") {
		t.Error("HasEvent should be false initially")
	}
	if len(emitter.Events()) != 0 {
		t.Error("Events should be empty initially")
	}

	// Emit and check
	emitter.Emit("oidcauth:logged-in", nil)
	emitter.Emit("oidcauth:token-refreshed", map[string]string{"key": "val"})

	if !emitter.HasEvent("oidcauth:logged-in") {
		t.Error("HasEvent should find logged-in")
	}
	if !emitter.HasEvent("oidcauth:token-refreshed") {
		t.Error("HasEvent should find token-refreshed")
	}
	if emitter.HasEvent("oidcauth:logged-out") {
		t.Error("HasEvent should not find logged-out")
	}

	events := emitter.Events()
	if len(events) != 2 {
		t.Fatalf("Events count = %d, want 2", len(events))
	}
	if events[0].Name != "oidcauth:logged-in" {
		t.Errorf("events[0].Name = %q, want oidcauth:logged-in", events[0].Name)
	}

	// Reset
	emitter.Reset()
	if len(emitter.Events()) != 0 {
		t.Error("Events should be empty after Reset")
	}
}

func TestRecordingEmitter_Concurrent(t *testing.T) {
	emitter := &RecordingEmitter{}
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			emitter.Emit("event", n)
			_ = emitter.HasEvent("event")
			_ = emitter.Events()
		}(i)
	}
	wg.Wait()
}

func TestRecordingEmitter_WaitForEvent(t *testing.T) {
	emitter := &RecordingEmitter{}

	// Event already emitted: should return immediately.
	emitter.Emit("existing", nil)
	if !emitter.WaitForEvent("existing", 100*time.Millisecond) {
		t.Error("WaitForEvent should find already-emitted event")
	}

	// Event emitted asynchronously: should wait and find it.
	go func() {
		time.Sleep(20 * time.Millisecond)
		emitter.Emit("async-event", "data")
	}()
	if !emitter.WaitForEvent("async-event", 2*time.Second) {
		t.Error("WaitForEvent should find async event")
	}

	// Timeout when event is never emitted.
	if emitter.WaitForEvent("never", 50*time.Millisecond) {
		t.Error("WaitForEvent should timeout for missing event")
	}
}

func TestFailingStore(t *testing.T) {
	store := &FailingStore{}

	// Works normally when no errors are set.
	saved := pkceflow.TokenState{AccessToken: "token1"}
	if err := store.Save(saved); err != nil {
		t.Fatalf("Save without error: %v", err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load without error: %v", err)
	}
	if loaded.AccessToken != "token1" {
		t.Errorf("Load returned wrong token: %q", loaded.AccessToken)
	}

	// Inject errors.
	testErr := fmt.Errorf("simulated failure")
	store.SetSaveErr(testErr)
	if err := store.Save(pkceflow.TokenState{}); err != testErr {
		t.Errorf("Save error = %v, want simulated failure", err)
	}

	store.SetLoadErr(testErr)
	_, err = store.Load()
	if err != testErr {
		t.Errorf("Load error = %v, want simulated failure", err)
	}

	store.SetDeleteErr(testErr)
	if err := store.Delete(); err != testErr {
		t.Errorf("Delete error = %v, want simulated failure", err)
	}

	// Clear errors and verify normal operation resumes.
	store.SetSaveErr(nil)
	store.SetLoadErr(nil)
	store.SetDeleteErr(nil)
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete after clearing error: %v", err)
	}
	loaded, _ = store.Load()
	if !loaded.IsZero() {
		t.Error("Load after delete should return zero state")
	}
}

func TestFakeFlowHandler_CompletesFlow(t *testing.T) {
	redirectURI := "http://127.0.0.1:9999/callback"
	server := NewFakeIDP(t,
		WithClientID("test-app"),
		WithRedirectURI(redirectURI),
	)

	handler := NewFakeFlowHandler(server, redirectURI)

	// Verify RedirectURI
	if got := handler.RedirectURI(); got != redirectURI {
		t.Errorf("RedirectURI() = %q, want %q", got, redirectURI)
	}

	// Build an auth URL like the Client would
	authURL := server.IssuerURL() + "/authorize?client_id=test-app&redirect_uri=" + redirectURI +
		"&response_type=code&state=teststate123&code_challenge=abc&code_challenge_method=S256&scope=openid"

	// StartAuthFlow should complete and return the callback URL with code + state
	callbackURL, err := handler.StartAuthFlow(context.Background(), authURL)
	if err != nil {
		t.Fatalf("StartAuthFlow: %v", err)
	}

	if callbackURL == "" {
		t.Fatal("StartAuthFlow returned empty callback URL")
	}

	// Should contain code and state in the callback
	if !containsParam(callbackURL, "code") {
		t.Errorf("callback URL missing code param: %s", callbackURL)
	}
	if !containsParam(callbackURL, "state=teststate123") {
		t.Errorf("callback URL missing state param: %s", callbackURL)
	}
}

func containsParam(rawURL, param string) bool {
	for i := range rawURL {
		if i+len(param) <= len(rawURL) && rawURL[i:i+len(param)] == param {
			return true
		}
	}
	return false
}
