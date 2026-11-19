package pkceflow_test

import (
	"context"
	"strings"
	"testing"
)

func TestLoginStoresInstantsWithoutMonotonicReading(t *testing.T) {
	client, _, store, _ := newTestClient(t)
	if err := client.Init(context.Background()); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(context.Background()); err != nil {
		t.Fatalf("Login: %v", err)
	}

	state, err := store.Load()
	if err != nil {
		t.Fatalf("store.Load: %v", err)
	}
	if state.ExpiresAt.IsZero() {
		t.Fatal("precondition: logged-in state has no expiry")
	}
	// Time.String ends in "m=±<value>" exactly when a monotonic reading is
	// present. oauth2 derives Expiry from time.Now, so it has one unless the
	// library strips it.
	if strings.Contains(state.ExpiresAt.String(), " m=") {
		t.Errorf("ExpiresAt carries a monotonic reading: %s", state.ExpiresAt)
	}
	if strings.Contains(state.LastAuthAt.String(), " m=") {
		t.Errorf("LastAuthAt carries a monotonic reading: %s", state.LastAuthAt)
	}
}
