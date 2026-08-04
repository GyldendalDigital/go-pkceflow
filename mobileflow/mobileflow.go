// Package mobileflow provides an AuthFlowHandler for mobile applications.
// It opens the auth URL via an injected function and waits for the callback
// URL to be delivered via DeliverURL (called from a browser-session completion
// or the app's OS lifecycle callback).
//
// This is a pure Go, framework-agnostic implementation. The platform-specific
// wiring is owned by the application and framework host. An adapter such as
// wails-pkceflow may forward a URL after its host surfaces one.
//
// Usage:
//
//	handler := mobileflow.New("https://myapp.example.com/auth/callback", openURL)
//	client, _ := pkceflow.New(cfg, handler)
//
//	// In your deep link handler:
//	handler.DeliverURL(callbackURL)
package mobileflow

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

// ErrFlowInProgress is returned when a login or logout flow is started while
// another mobile browser flow is still waiting for its callback.
var ErrFlowInProgress = errors.New("mobileflow: another browser flow is already in progress")

// Handler implements pkceflow.AuthFlowHandler for mobile applications.
// It opens the auth URL via an injected function and waits for the callback
// to be delivered via DeliverURL.
type Handler struct {
	redirectURI string
	openURL     func(string) error

	mu                sync.Mutex
	logoutRedirectURI string
	active            *flowWaiter
}

type flowWaiter struct {
	redirectURI *url.URL
	state       string
	// Some providers omit state from their post-logout callback. This weaker
	// compatibility path is never enabled for authorization callbacks.
	allowMissingState bool
	delivery          chan string
	delivered         bool
}

// New creates a Handler with the given redirect URI and URL opener.
// The redirectURI should be the exact claimed HTTPS URI (preferred) or
// private-use custom-scheme URI registered with the IdP.
// The openURL function is called to open the auth URL (e.g., via system browser).
func New(redirectURI string, openURL func(string) error) *Handler {
	return &Handler{
		redirectURI: redirectURI,
		// Logout defaults to the login redirect URI; override with SetLogoutURI
		// when the IdP registers a distinct post_logout_redirect_uri.
		logoutRedirectURI: redirectURI,
		openURL:           openURL,
	}
}

// RedirectURI returns the configured redirect URI.
func (h *Handler) RedirectURI() string {
	return h.redirectURI
}

// StartAuthFlow validates that authURL contains exactly one state and a
// redirect_uri matching this handler, opens it, and blocks until DeliverURL
// receives the correlated callback or the context is cancelled. Only one login
// or logout browser flow may be active.
func (h *Handler) StartAuthFlow(ctx context.Context, authURL string) (string, error) {
	return h.runFlow(ctx, "auth", authURL, h.redirectURI, "redirect_uri", false)
}

// DeliverURL delivers a callback URL to the active login or logout flow.
// Malformed URLs, unrelated deep links, callbacks with the wrong state, and
// deliveries made while no flow is active are silently dropped.
// This should be called from the platform callback when the IdP redirects back.
func (h *Handler) DeliverURL(callbackURL string) {
	callback, err := parseCallbackURI(callbackURL)
	if err != nil {
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active == nil || h.active.delivered || !h.active.matches(callback) {
		return
	}

	select {
	case h.active.delivery <- callbackURL:
		h.active.delivered = true
	default:
		// The matching one-shot callback is already queued.
	}
}

// StartLogoutFlow validates that logoutURL contains exactly one state and a
// post_logout_redirect_uri matching this handler, opens it, and blocks until
// DeliverURL receives the correlated callback or the context is cancelled. A
// missing returned state is accepted for providers that omit it, but only after
// the callback URI itself matches. It implements pkceflow.LogoutFlowHandler.
func (h *Handler) StartLogoutFlow(ctx context.Context, logoutURL string) (string, error) {
	h.mu.Lock()
	redirectURI := h.logoutRedirectURI
	h.mu.Unlock()
	return h.runFlow(ctx, "logout", logoutURL, redirectURI, "post_logout_redirect_uri", true)
}

// PostLogoutRedirectURI returns the URI sent as post_logout_redirect_uri. It
// defaults to the login redirect URI unless SetLogoutURI was called. It
// implements pkceflow.LogoutFlowHandler.
func (h *Handler) PostLogoutRedirectURI() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.logoutRedirectURI
}

// SetLogoutURI configures a distinct post-logout redirect URI for RP-Initiated
// Logout. IdPs commonly register post_logout_redirect_uris separately from
// redirect_uris. The URI must be a non-empty, parseable claimed HTTPS URI or
// custom scheme URI registered with the IdP; unlike desktop there is no
// loopback constraint because mobile callbacks arrive via deep links. Opaque
// URI syntax, user information, and fragments are rejected.
func (h *Handler) SetLogoutURI(uri string) error {
	if _, err := parseCallbackURI(uri); err != nil {
		return fmt.Errorf("mobileflow: invalid logout URI: %w", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	h.logoutRedirectURI = uri
	return nil
}

func (h *Handler) runFlow(
	ctx context.Context,
	kind string,
	targetURL string,
	redirectURI string,
	redirectParam string,
	allowMissingState bool,
) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}

	target, err := url.Parse(targetURL)
	if err != nil ||
		!target.IsAbs() ||
		(!strings.EqualFold(target.Scheme, "http") && !strings.EqualFold(target.Scheme, "https")) ||
		target.Host == "" ||
		target.User != nil ||
		target.Fragment != "" {
		return "", fmt.Errorf("mobileflow: invalid %s URL", kind)
	}
	targetQuery, err := url.ParseQuery(target.RawQuery)
	if err != nil {
		return "", fmt.Errorf("mobileflow: invalid %s URL query", kind)
	}
	state, ok := singleState(targetQuery)
	if !ok {
		return "", fmt.Errorf("mobileflow: %s URL must contain exactly one non-empty state", kind)
	}

	callback, err := parseCallbackURI(redirectURI)
	if err != nil {
		return "", fmt.Errorf("mobileflow: invalid %s redirect URI", kind)
	}
	requestedRedirect, ok := singleNonEmptyValue(targetQuery, redirectParam)
	if !ok {
		return "", fmt.Errorf(
			"mobileflow: %s URL must contain exactly one non-empty %s",
			kind,
			redirectParam,
		)
	}
	requestedCallback, err := parseCallbackURI(requestedRedirect)
	if err != nil || !sameRedirectURI(callback, requestedCallback) {
		return "", fmt.Errorf(
			"mobileflow: %s URL %s does not match the configured redirect URI",
			kind,
			redirectParam,
		)
	}

	waiter := &flowWaiter{
		redirectURI:       callback,
		state:             state,
		allowMissingState: allowMissingState,
		delivery:          make(chan string, 1),
	}
	if !h.register(waiter) {
		return "", ErrFlowInProgress
	}
	defer h.unregister(waiter)

	if h.openURL == nil {
		return "", fmt.Errorf("mobileflow: URL opener is nil")
	}
	if err := h.openURL(targetURL); err != nil {
		return "", fmt.Errorf("mobileflow: failed to open %s URL: %w", kind, err)
	}

	select {
	case callbackURL := <-waiter.delivery:
		return callbackURL, nil
	case <-ctx.Done():
		// Linearize cancellation against delivery. If DeliverURL accepted the
		// callback before cancellation removed this waiter, return that callback.
		h.unregister(waiter)
		select {
		case callbackURL := <-waiter.delivery:
			return callbackURL, nil
		default:
			return "", ctx.Err()
		}
	}
}

func (h *Handler) register(waiter *flowWaiter) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active != nil {
		return false
	}
	h.active = waiter
	return true
}

func (h *Handler) unregister(waiter *flowWaiter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.active == waiter {
		h.active = nil
	}
}

func (w *flowWaiter) matches(callback *url.URL) bool {
	callbackQuery, err := url.ParseQuery(callback.RawQuery)
	if err != nil || !sameCallbackTarget(w.redirectURI, callback, callbackQuery) {
		return false
	}

	states, present := callbackQuery["state"]
	if !present {
		return w.allowMissingState && !hasAuthorizationResponse(callbackQuery)
	}
	if len(states) != 1 || states[0] == "" {
		return false
	}
	returnedState := states[0]
	return subtle.ConstantTimeCompare([]byte(w.state), []byte(returnedState)) == 1
}

func singleState(query url.Values) (string, bool) {
	return singleNonEmptyValue(query, "state")
}

func singleNonEmptyValue(query url.Values, key string) (string, bool) {
	values, ok := query[key]
	if !ok || len(values) != 1 || values[0] == "" {
		return "", false
	}
	return values[0], true
}

func parseCallbackURI(raw string) (*url.URL, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, errors.New("callback URI must not be empty")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("callback URI is malformed")
	}
	if parsed.Scheme == "" {
		return nil, errors.New("callback URI must be absolute and include a scheme")
	}
	if parsed.Opaque != "" {
		return nil, errors.New("callback URI must not use opaque URI syntax")
	}
	if parsed.User != nil {
		return nil, errors.New("callback URI must not include user information")
	}
	if parsed.Fragment != "" {
		return nil, errors.New("callback URI must not include a fragment")
	}
	if (strings.EqualFold(parsed.Scheme, "http") || strings.EqualFold(parsed.Scheme, "https")) && parsed.Host == "" {
		return nil, errors.New("http(s) callback URI must include a host")
	}
	if parsed.Host == "" && parsed.Path == "" && parsed.Opaque == "" {
		return nil, errors.New("callback URI must include a target")
	}
	if _, err := url.ParseQuery(parsed.RawQuery); err != nil {
		return nil, errors.New("callback URI query is malformed")
	}
	return parsed, nil
}

func sameRedirectURI(expected, actual *url.URL) bool {
	if !sameCallbackBase(expected, actual) {
		return false
	}
	expectedQuery, _ := url.ParseQuery(expected.RawQuery)
	actualQuery, _ := url.ParseQuery(actual.RawQuery)
	return equalQueryValues(actualQuery, expectedQuery)
}

func sameCallbackTarget(expected, actual *url.URL, actualQuery url.Values) bool {
	if !sameCallbackBase(expected, actual) {
		return false
	}
	expectedQuery, _ := url.ParseQuery(expected.RawQuery)
	return containsFixedQuery(actualQuery, expectedQuery)
}

func sameCallbackBase(expected, actual *url.URL) bool {
	if !strings.EqualFold(expected.Scheme, actual.Scheme) ||
		expected.OmitHost != actual.OmitHost ||
		expected.User != nil ||
		actual.User != nil ||
		expected.Fragment != "" ||
		actual.Fragment != "" ||
		!strings.EqualFold(expected.Hostname(), actual.Hostname()) ||
		expected.Port() != actual.Port() ||
		hasExplicitEmptyPort(expected) != hasExplicitEmptyPort(actual) ||
		expected.EscapedPath() != actual.EscapedPath() {
		return false
	}
	return true
}

func hasExplicitEmptyPort(uri *url.URL) bool {
	return uri.Host != "" && strings.HasSuffix(uri.Host, ":")
}

func hasAuthorizationResponse(query url.Values) bool {
	return len(query["code"]) != 0 || len(query["error"]) != 0
}

func equalQueryValues(actual, expected url.Values) bool {
	return len(actual) == len(expected) && containsFixedQuery(actual, expected)
}

func containsFixedQuery(actual, expected url.Values) bool {
	for key, expectedValues := range expected {
		actualValues, ok := actual[key]
		if !ok || len(actualValues) != len(expectedValues) {
			return false
		}
		remaining := make(map[string]int, len(actualValues))
		for _, value := range actualValues {
			remaining[value]++
		}
		for _, value := range expectedValues {
			if remaining[value] == 0 {
				return false
			}
			remaining[value]--
		}
	}
	return true
}
