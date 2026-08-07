package oidctest

import (
	"net/http"
	"net/url"
	"sync"
)

// RequestRecord captures a request made to the fake IdP.
type RequestRecord struct {
	// Endpoint is the path (e.g. "/authorize", "/token", "/jwks").
	Endpoint string
	// Method is the HTTP method.
	Method string
	// Params contains the request parameters (query for GET, form for POST).
	Params url.Values
}

// RequestRecorder captures all requests to the fake IdP for later assertion.
// Safe for concurrent use.
type RequestRecorder struct {
	mu      sync.Mutex
	records []RequestRecord
}

// Records returns a deep copy of all captured requests.
func (r *RequestRecorder) Records() []RequestRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]RequestRecord, len(r.records))
	for i, rec := range r.records {
		result[i] = RequestRecord{
			Endpoint: rec.Endpoint,
			Method:   rec.Method,
			Params:   cloneValues(rec.Params),
		}
	}
	return result
}

// RecordsFor returns captured requests for the given endpoint path.
func (r *RequestRecorder) RecordsFor(endpoint string) []RequestRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	var result []RequestRecord
	for _, rec := range r.records {
		if rec.Endpoint == endpoint {
			result = append(result, RequestRecord{
				Endpoint: rec.Endpoint,
				Method:   rec.Method,
				Params:   cloneValues(rec.Params),
			})
		}
	}
	return result
}

// Reset clears all captured requests.
func (r *RequestRecorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = nil
}

func (r *RequestRecorder) record(endpoint, method string, params url.Values) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records = append(r.records, RequestRecord{
		Endpoint: endpoint,
		Method:   method,
		Params:   params,
	})
}

// EndpointHook is a function called before the default handler for an endpoint.
// If it writes a response (returns true), the default handler is skipped.
type EndpointHook func(w http.ResponseWriter, r *http.Request) (handled bool)

// Hooks holds per-endpoint hooks that run before default handling.
// If a hook writes a response, the default handler is skipped.
type Hooks struct {
	mu sync.Mutex
	// Authorize is called before the /authorize handler.
	authorize EndpointHook
	// Token is called before the /token handler.
	token EndpointHook
	// JWKS is called before the /jwks handler.
	jwks EndpointHook
	// EndSession is called before the /end_session handler.
	endSession EndpointHook
	// Discovery is called before the /.well-known/openid-configuration handler.
	discovery EndpointHook
	// Userinfo is called before the /userinfo handler.
	userinfo EndpointHook
}

// SetAuthorizeHook sets a hook that runs before the authorize handler.
// Pass nil to remove.
func (h *Hooks) SetAuthorizeHook(hook EndpointHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.authorize = hook
}

// SetTokenHook sets a hook that runs before the token handler.
// Pass nil to remove.
func (h *Hooks) SetTokenHook(hook EndpointHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.token = hook
}

// SetJWKSHook sets a hook that runs before the JWKS handler.
// Pass nil to remove.
func (h *Hooks) SetJWKSHook(hook EndpointHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.jwks = hook
}

// SetEndSessionHook sets a hook that runs before the end_session handler.
// Pass nil to remove.
func (h *Hooks) SetEndSessionHook(hook EndpointHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.endSession = hook
}

// SetDiscoveryHook sets a hook that runs before the discovery handler.
// Pass nil to remove.
func (h *Hooks) SetDiscoveryHook(hook EndpointHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.discovery = hook
}

// SetUserinfoHook sets a hook that runs before the userinfo handler.
// Pass nil to remove.
func (h *Hooks) SetUserinfoHook(hook EndpointHook) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.userinfo = hook
}

func (h *Hooks) runAuthorize(w http.ResponseWriter, r *http.Request) bool {
	h.mu.Lock()
	hook := h.authorize
	h.mu.Unlock()
	if hook != nil {
		return hook(w, r)
	}
	return false
}

func (h *Hooks) runToken(w http.ResponseWriter, r *http.Request) bool {
	h.mu.Lock()
	hook := h.token
	h.mu.Unlock()
	if hook != nil {
		return hook(w, r)
	}
	return false
}

func (h *Hooks) runJWKS(w http.ResponseWriter, r *http.Request) bool {
	h.mu.Lock()
	hook := h.jwks
	h.mu.Unlock()
	if hook != nil {
		return hook(w, r)
	}
	return false
}

func (h *Hooks) runEndSession(w http.ResponseWriter, r *http.Request) bool {
	h.mu.Lock()
	hook := h.endSession
	h.mu.Unlock()
	if hook != nil {
		return hook(w, r)
	}
	return false
}

func (h *Hooks) runDiscovery(w http.ResponseWriter, r *http.Request) bool {
	h.mu.Lock()
	hook := h.discovery
	h.mu.Unlock()
	if hook != nil {
		return hook(w, r)
	}
	return false
}

func (h *Hooks) runUserinfo(w http.ResponseWriter, r *http.Request) bool {
	h.mu.Lock()
	hook := h.userinfo
	h.mu.Unlock()
	if hook != nil {
		return hook(w, r)
	}
	return false
}

// GrantTypeErrorMap holds per-grant-type error injection. When a grant type
// has an entry, the token handler returns that error code instead of processing.
type GrantTypeErrorMap struct {
	mu     sync.Mutex
	errors map[string]string
}

// Set configures an error for a specific grant type (e.g., "authorization_code"
// or "refresh_token"). The error will be returned on every token request with
// that grant_type until cleared.
func (m *GrantTypeErrorMap) Set(grantType, errorCode string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.errors == nil {
		m.errors = make(map[string]string)
	}
	m.errors[grantType] = errorCode
}

// Clear removes the error for a specific grant type.
func (m *GrantTypeErrorMap) Clear(grantType string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.errors, grantType)
}

// ClearAll removes all per-grant-type errors.
func (m *GrantTypeErrorMap) ClearAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors = nil
}

func (m *GrantTypeErrorMap) check(grantType string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.errors == nil {
		return "", false
	}
	code, ok := m.errors[grantType]
	return code, ok
}

// cloneValues returns a deep copy of url.Values.
func cloneValues(v url.Values) url.Values {
	if v == nil {
		return nil
	}
	c := make(url.Values, len(v))
	for key, vals := range v {
		c[key] = append([]string(nil), vals...)
	}
	return c
}
