package pkceflow

import (
	"context"
	"testing"
)

// testFlowHandler is a minimal AuthFlowHandler for unit tests.
type testFlowHandler struct {
	redirectURI string
}

func (h *testFlowHandler) StartAuthFlow(_ context.Context, _ string) (string, error) {
	return "", nil
}

func (h *testFlowHandler) RedirectURI() string { return h.redirectURI }

// testEmitter captures events for test assertions.
type testEmitter struct {
	events []string
}

func (e *testEmitter) Emit(event string, _ any) {
	e.events = append(e.events, event)
}

func (e *testEmitter) hasEvent(name string) bool {
	for _, ev := range e.events {
		if ev == name {
			return true
		}
	}
	return false
}

func TestNew_ValidConfig(t *testing.T) {
	handler := &testFlowHandler{redirectURI: "http://127.0.0.1:9999/callback"}

	client, err := New(Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}, handler)

	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if client == nil {
		t.Fatal("New returned nil client")
	}
}

func TestNew_NilFlowHandler(t *testing.T) {
	_, err := New(Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}, nil)

	if err == nil {
		t.Fatal("expected error for nil flow handler")
	}
}

func TestNew_InvalidConfig(t *testing.T) {
	handler := &testFlowHandler{redirectURI: "http://127.0.0.1:9999/callback"}

	_, err := New(Config{}, handler)
	if err == nil {
		t.Fatal("expected error for empty config")
	}
}

func TestNew_WithOptions(t *testing.T) {
	handler := &testFlowHandler{redirectURI: "http://127.0.0.1:9999/callback"}
	store := &memoryStore{}
	emitter := &testEmitter{}

	client, err := New(Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}, handler,
		WithTokenPersistence(store),
		WithEventEmitter(emitter),
	)

	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Verify store option applied
	if err := client.store.Save(TokenState{AccessToken: "test"}); err != nil {
		t.Fatalf("store.Save: %v", err)
	}
	state, _ := store.Load()
	if state.AccessToken != "test" {
		t.Error("WithTokenPersistence option not applied")
	}

	// Verify emitter option applied
	client.emitter.Emit("test", nil)
	if !emitter.hasEvent("test") {
		t.Error("WithEventEmitter option not applied")
	}
}

func TestNew_Defaults(t *testing.T) {
	handler := &testFlowHandler{redirectURI: "http://127.0.0.1:9999/callback"}

	client, err := New(Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}, handler)

	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if client.store == nil {
		t.Error("default store is nil")
	}
	if client.emitter == nil {
		t.Error("default emitter is nil")
	}
	if client.logger == nil {
		t.Error("default logger is nil")
	}
}
