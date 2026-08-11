package pkceflow

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBearerTransport_InjectsToken(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer server.Close()

	client := &http.Client{
		Transport: BearerTransport(func() string { return "test-access-token" }, nil),
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != "Bearer test-access-token" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer test-access-token")
	}
}

func TestBearerTransport_OmitsHeaderWhenEmpty(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
	}))
	defer server.Close()

	client := &http.Client{
		Transport: BearerTransport(func() string { return "" }, nil),
	}

	resp, err := client.Get(server.URL)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if gotAuth != "" {
		t.Errorf("Authorization should be empty when token is empty, got %q", gotAuth)
	}
}

func TestBearerTransport_UsesCustomBase(t *testing.T) {
	baseCalled := false
	customBase := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		baseCalled = true
		return &http.Response{StatusCode: http.StatusOK, Body: http.NoBody}, nil
	})

	transport := BearerTransport(func() string { return "tok" }, customBase)

	req, _ := http.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if !baseCalled {
		t.Error("custom base transport was not called")
	}
}

func TestBearerTransport_DoesNotMutateOriginalRequest(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()

	transport := BearerTransport(func() string { return "tok" }, nil)

	req, _ := http.NewRequest(http.MethodGet, server.URL, http.NoBody)
	origAuth := req.Header.Get("Authorization")

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip failed: %v", err)
	}
	defer resp.Body.Close()

	if req.Header.Get("Authorization") != origAuth {
		t.Error("original request was mutated")
	}
}

// roundTripFunc adapts a function to http.RoundTripper for testing.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}
