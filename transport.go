package pkceflow

import "net/http"

// BearerTransport returns an http.RoundTripper that injects a Bearer token
// from tokenFn into every outgoing request's Authorization header. If tokenFn
// returns an empty string (no valid token available), the request is sent
// without an Authorization header.
//
// The base transport handles the actual HTTP round trip. If base is nil,
// http.DefaultTransport is used.
//
// Usage with Client.TokenFn:
//
//	httpClient := &http.Client{
//	    Transport: pkceflow.BearerTransport(client.TokenFn(ctx), nil),
//	}
//	resp, err := httpClient.Get("https://api.example.com/protected")
func BearerTransport(tokenFn func() string, base http.RoundTripper) http.RoundTripper {
	if tokenFn == nil {
		panic("pkceflow.BearerTransport: tokenFn must not be nil")
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &bearerTransport{tokenFn: tokenFn, base: base}
}

type bearerTransport struct {
	tokenFn func() string
	base    http.RoundTripper
}

func (t *bearerTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	token := t.tokenFn()
	if token != "" {
		req = req.Clone(req.Context())
		req.Header.Set("Authorization", "Bearer "+token)
	} else if req.Header.Get("Authorization") != "" {
		// Remove any pre-existing Authorization header when no token is available.
		req = req.Clone(req.Context())
		req.Header.Del("Authorization")
	}
	return t.base.RoundTrip(req)
}
