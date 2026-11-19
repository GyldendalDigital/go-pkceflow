package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// FakeIDPServer is a fake OIDC provider for testing.
// It implements discovery, authorization, token exchange, JWKS, and end_session endpoints.
// Safe for concurrent use and parallel tests.
//
// By default, the server enforces strict native-client protocol rules:
//   - PKCE S256 is mandatory (code_challenge + code_challenge_method required)
//   - redirect_uri must match a pre-registered value
//   - response_type must be "code"
//   - Authorization codes expire (default 30 seconds)
//   - client_id on token exchange must match the code's originating client
//
// Use WithLenientMode() to disable all strict checks (legacy behavior).
//
// Refresh tokens rotate by default: each successful refresh issues a new
// refresh token and invalidates the presented one. They expire WithRefreshTTL
// after the sign-in that started the session, and a rotated token keeps that
// session's end. WithoutRefreshRotation, WithSlidingRefreshExpiry,
// WithRefreshReuseDetection, and LoseNextRefreshResponse model other provider
// behaviours.
type FakeIDPServer struct {
	// Server is the underlying httptest.Server. Use IssuerURL() instead of accessing directly.
	Server *httptest.Server

	// Hooks provides per-endpoint hooks that run before the default handler.
	// If a hook writes a response, the default handler is skipped.
	Hooks Hooks

	// Recorder captures all requests made to the server for assertion.
	Recorder RequestRecorder

	// GrantErrors holds per-grant-type error injection for the token endpoint.
	GrantErrors GrantTypeErrorMap

	mu              sync.Mutex
	key             *rsa.PrivateKey
	signer          jose.Signer
	keyID           string     // current signing key ID
	extraKeys       []keyEntry // additional keys exposed in JWKS
	clientID        string
	redirectURIs    []string
	scopes          []string // allowed scopes; empty means accept any
	accessTTL       time.Duration
	refreshTTL      time.Duration // refresh token lifetime; <= 0 disables expiry
	idTokenTTL      time.Duration
	codeTTL         time.Duration           // authorization code lifetime
	codes           map[string]*pendingCode // authorization code -> pending exchange
	refreshTokens   map[string]*tokenState  // live refresh token -> associated state
	errorQueue      []string                // queued errors to return on next token request
	stickyError     string                  // when set, every token request returns this error
	rejectBasicAuth bool                    // when true, model a public client: reject HTTP Basic client auth and invalidate the code
	forceNonce      *string                 // when set, overrides the ID token nonce claim
	omitRefreshID   bool                    // when true, refresh responses omit id_token
	refreshSubject  *string                 // when set, overrides refresh ID token subject
	refreshRawID    *string                 // when set, refresh responses use this raw id_token
	lenient         bool                    // when true, disables strict protocol checks
	omitRevocation  bool                    // when true, discovery omits revocation_endpoint
	jwksError       *int                    // when set, JWKS endpoint returns this HTTP status code
	forceIssuer     *string                 // when set, overrides the issuer in ID tokens
	forceAudience   *string                 // when set, overrides the audience in ID tokens
	forceAudiences  *[]string               // when set, overrides aud with a multi-valued list
	forceAzpJSON    *string                 // when set, injects this raw JSON as the azp claim
	forceExpiry     *time.Time              // when set, overrides the expiry in ID tokens
	forceNotBefore  *time.Time              // when set, overrides nbf in ID tokens
	nowFunc         func() time.Time

	// Refresh-token lifecycle.
	spentRefresh   map[string]*refreshFamily // rotated-out refresh token -> its family
	slidingRefresh bool                      // when true, refreshTTL runs from the last refresh instead of sign-in
	reuseRefresh   bool                      // when true, refresh does not rotate: the token stays valid and refresh_token is omitted
	reuseDetection bool                      // when true, presenting a rotated-out token revokes its family
	refreshLosses  []refreshLoss             // armed response losses for upcoming refresh grants (FIFO)
	done           chan struct{}             // closed at test cleanup; releases hanging handlers
}

// keyEntry is an additional RSA key exposed via the JWKS endpoint.
type keyEntry struct {
	key   *rsa.PrivateKey
	keyID string
}

type pendingCode struct {
	clientID     string
	redirectURI  string
	nonce        string
	codeVerifier string // expected PKCE verifier (S256)
	subject      string
	createdAt    time.Time
}

type tokenState struct {
	subject  string
	clientID string
	family   *refreshFamily
}

// refreshFamily links the refresh tokens that descend, by rotation, from one
// sign-in. It carries the session clock, so a rotated token keeps the session's
// end, and the family's single live token, so reuse detection can revoke it.
type refreshFamily struct {
	signedInAt    time.Time // authorization-code exchange that started the session
	lastRefreshAt time.Time // most recent successful refresh, or signedInAt
	live          string    // currently valid refresh token; "" once revoked
}

// refreshLoss is one armed LoseNextRefreshResponse call.
type refreshLoss struct {
	mode      ResponseLoss
	processed chan struct{}
}

// ResponseLoss selects how LoseNextRefreshResponse loses a refresh response
// after the fake IdP has processed the refresh.
type ResponseLoss int

const (
	// ResponseLossHang sends nothing and holds the connection open until the
	// client gives up (its context is cancelled, its timeout fires, or it
	// closes the connection) or the test ends. The connection is then closed
	// without a response.
	ResponseLossHang ResponseLoss = iota + 1
	// ResponseLossReset closes the connection without a response, with a TCP
	// reset (SO_LINGER 0), as a crashed or restarted proxy would.
	ResponseLossReset
	// ResponseLossBadGateway answers 502 Bad Gateway with an HTML body, as a
	// reverse proxy does when its upstream response is lost.
	ResponseLossBadGateway
)

// Option configures a FakeIDPServer.
type Option func(*FakeIDPServer)

// WithClientID sets the expected client ID. Default: "test-client".
func WithClientID(id string) Option {
	return func(s *FakeIDPServer) { s.clientID = id }
}

// WithRedirectURI adds an allowed redirect URI. Default: "http://127.0.0.1:0/callback".
func WithRedirectURI(uri string) Option {
	return func(s *FakeIDPServer) { s.redirectURIs = append(s.redirectURIs, uri) }
}

// WithAccessTTL sets the access token lifetime. Default: 5 minutes.
func WithAccessTTL(d time.Duration) Option {
	return func(s *FakeIDPServer) { s.accessTTL = d }
}

// WithRefreshTTL sets the refresh token lifetime. Default: 24 hours.
//
// The lifetime is measured from the sign-in (the authorization-code exchange)
// that started the session, and rotation does not restart it: a rotated
// refresh token keeps the session's absolute end, as providers with a fixed
// maximum session length do. Once more than d has elapsed, the refresh grant
// fails with invalid_grant. Use WithSlidingRefreshExpiry to measure it from the
// most recent refresh instead. A zero or negative d disables expiry.
//
// Time comes from WithClock, so tests can step past the lifetime. The lifetime
// is enforced in lenient mode too.
func WithRefreshTTL(d time.Duration) Option {
	return func(s *FakeIDPServer) { s.refreshTTL = d }
}

// WithSlidingRefreshExpiry measures the WithRefreshTTL lifetime from the most
// recent successful refresh instead of from sign-in, modelling an idle timeout:
// a session that refreshes at least once per lifetime never expires.
func WithSlidingRefreshExpiry() Option {
	return func(s *FakeIDPServer) { s.slidingRefresh = true }
}

// WithoutRefreshRotation models a provider that does not rotate refresh
// tokens. A successful refresh leaves the presented refresh token valid and
// omits refresh_token from the response, so a client keeps the token it has
// (RFC 6749 section 6). SetRefreshRotation switches rotation at run time.
func WithoutRefreshRotation() Option {
	return func(s *FakeIDPServer) { s.reuseRefresh = true }
}

// WithRefreshReuseDetection models a provider that detects refresh-token
// reuse, as Auth0, Okta, and Keycloak (with "Revoke Refresh Token" on) do.
// Presenting a refresh token that was already rotated out revokes the live
// refresh token descended from the same sign-in, and both requests fail with
// invalid_grant. Without this option a rotated-out token is refused but the
// live token keeps working. It has no effect while rotation is off, because no
// token is then rotated out.
func WithRefreshReuseDetection() Option {
	return func(s *FakeIDPServer) { s.reuseDetection = true }
}

// WithIDTokenTTL sets the ID token lifetime. Default: 5 minutes.
func WithIDTokenTTL(d time.Duration) Option {
	return func(s *FakeIDPServer) { s.idTokenTTL = d }
}

// WithClock sets the time function. Default: time.Now. Use for testing token expiry.
func WithClock(now func() time.Time) Option {
	return func(s *FakeIDPServer) { s.nowFunc = now }
}

// WithForcedIDTokenNonce overrides the nonce claim written into issued ID tokens,
// regardless of the nonce sent on the authorization request. Use it in
// tests to exercise nonce-mismatch handling. Pass an empty string to omit the
// nonce claim entirely.
func WithForcedIDTokenNonce(nonce string) Option {
	return func(s *FakeIDPServer) { s.forceNonce = &nonce }
}

// WithOmitRefreshIDToken makes refresh responses omit id_token. Some providers
// only return a fresh access token and refresh token during refresh; clients
// should preserve the already-verified ID token in that case.
func WithOmitRefreshIDToken() Option {
	return func(s *FakeIDPServer) { s.omitRefreshID = true }
}

// WithRefreshIDTokenSubject overrides the subject claim used in ID tokens
// returned by refresh responses. Use it to exercise clients that must reject a
// refresh response for a different user while accepting the same issuer/audience.
func WithRefreshIDTokenSubject(subject string) Option {
	return func(s *FakeIDPServer) { s.refreshSubject = &subject }
}

// WithRawRefreshIDToken makes refresh responses return raw as id_token. Use it
// to test clients rejecting malformed or incorrectly signed refreshed ID tokens.
func WithRawRefreshIDToken(raw string) Option {
	return func(s *FakeIDPServer) { s.refreshRawID = &raw }
}

// WithRejectBasicAuth models a public OAuth client (like a Keycloak public
// client): the token endpoint rejects HTTP Basic client authentication with
// invalid_client AND invalidates the single-use authorization code. This
// reproduces the failure mode where a client that probes Basic-first cannot
// silently recover by retrying with the client_id in the body, because the code
// is already consumed. A correct public client must send client_id in the body
// (oauth2.AuthStyleInParams) and never attempt Basic auth.
func WithRejectBasicAuth() Option {
	return func(s *FakeIDPServer) { s.rejectBasicAuth = true }
}

// WithAllowedScopes sets the scopes the server will accept. Unknown scopes in
// the authorization request cause an invalid_scope error redirect. An empty
// list (the default) accepts any scope.
func WithAllowedScopes(scopes ...string) Option {
	return func(s *FakeIDPServer) { s.scopes = append([]string(nil), scopes...) }
}

// WithCodeTTL sets the authorization code lifetime. Default: 30 seconds.
// Real IdPs typically use 30-60 seconds.
func WithCodeTTL(d time.Duration) Option {
	return func(s *FakeIDPServer) { s.codeTTL = d }
}

// WithOmitRevocationEndpoint makes discovery omit revocation_endpoint, modeling
// a provider that does not implement RFC 7009 (for example Microsoft Entra ID).
func WithOmitRevocationEndpoint() Option {
	return func(s *FakeIDPServer) { s.omitRevocation = true }
}

// WithLenientMode disables strict protocol enforcement. In lenient mode, the
// server does not require PKCE, does not validate redirect URIs against the
// registered list, and does not enforce code expiry. Use this only for legacy
// tests that were written before strict mode was the default.
func WithLenientMode() Option {
	return func(s *FakeIDPServer) { s.lenient = true }
}

// NewFakeIDP creates and starts a fake OIDC provider.
// The server is automatically closed when the test ends via t.Cleanup.
func NewFakeIDP(t *testing.T, opts ...Option) *FakeIDPServer {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: generate RSA key: %v", err)
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: key}
	signer, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test-key-1"))
	if err != nil {
		t.Fatalf("oidctest: create signer: %v", err)
	}

	s := &FakeIDPServer{
		key:           key,
		signer:        signer,
		keyID:         "test-key-1",
		clientID:      "test-client",
		redirectURIs:  []string{"http://127.0.0.1:0/callback"},
		accessTTL:     5 * time.Minute,
		refreshTTL:    24 * time.Hour,
		idTokenTTL:    5 * time.Minute,
		codeTTL:       30 * time.Second,
		codes:         make(map[string]*pendingCode),
		refreshTokens: make(map[string]*tokenState),
		spentRefresh:  make(map[string]*refreshFamily),
		done:          make(chan struct{}),
		nowFunc:       time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.wrapHandler("/.well-known/openid-configuration", s.Hooks.runDiscovery, s.handleDiscovery))
	mux.HandleFunc("GET /authorize", s.wrapHandler("/authorize", s.Hooks.runAuthorize, s.handleAuthorize))
	mux.HandleFunc("POST /token", s.wrapHandler("/token", s.Hooks.runToken, s.handleToken))
	mux.HandleFunc("GET /jwks", s.wrapHandler("/jwks", s.Hooks.runJWKS, s.handleJWKS))
	mux.HandleFunc("GET /end_session", s.wrapHandler("/end_session", s.Hooks.runEndSession, s.handleEndSession))
	mux.HandleFunc("GET /userinfo", s.wrapHandler("/userinfo", s.Hooks.runUserinfo, s.handleUserinfo))
	mux.HandleFunc("POST /revoke", s.wrapHandler("/revoke", s.Hooks.runRevocation, s.handleRevoke))

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)
	// Cleanups run last-in first-out, so this releases any handler still
	// hanging under ResponseLossHang before Server.Close waits for handlers.
	t.Cleanup(func() { close(s.done) })

	return s
}

// IssuerURL returns the base URL of the fake IdP (used for OIDC discovery).
func (s *FakeIDPServer) IssuerURL() string {
	return s.Server.URL
}

// wrapHandler returns an http.HandlerFunc that records the request, runs the
// hook (if set), and then calls the default handler.
func (s *FakeIDPServer) wrapHandler(endpoint string, hookFn func(http.ResponseWriter, *http.Request) bool, defaultHandler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Record the request.
		params := r.URL.Query()
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			params = r.PostForm
		}
		s.Recorder.record(endpoint, r.Method, params)

		// Run hook; if it handled the response, skip the default handler.
		if hookFn(w, r) {
			return
		}

		defaultHandler(w, r)
	}
}

// QueueError queues an OAuth error code to be returned on the next token request.
// Multiple calls queue multiple errors (FIFO).
func (s *FakeIDPServer) QueueError(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errorQueue = append(s.errorQueue, code)
}

// SetTokenError makes every token request fail with the given OAuth error code
// until ClearTokenError is called. Use it to model a persistent condition such
// as a revoked refresh token, which a one-shot QueueError cannot represent
// because the oauth2 client may retry the token request (for example while
// probing the client authentication style). Passing an empty string clears it.
func (s *FakeIDPServer) SetTokenError(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stickyError = code
}

// ClearTokenError removes any persistent token error set via SetTokenError.
func (s *FakeIDPServer) ClearTokenError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stickyError = ""
}

// SetRefreshRotation turns refresh-token rotation on or off for subsequent
// refresh grants, so a test can model a provider whose configuration changes
// mid-session. Rotation is on by default; off behaves as WithoutRefreshRotation.
func (s *FakeIDPServer) SetRefreshRotation(enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reuseRefresh = !enabled
}

// LoseNextRefreshResponse makes the next refresh_token grant be processed in
// full and then lose its response the way loss describes. Processing is
// everything a delivered refresh does: a valid refresh token is rotated (or,
// with rotation off, its session clock advanced), and an expired or reused one
// is refused, revoking its family under WithRefreshReuseDetection. The client
// never sees the outcome. Only grants that reach refresh processing consume a
// loss; requests answered by QueueError, SetTokenError, GrantErrors, or a
// token hook do not.
//
// The returned channel is closed once processing has finished and before the
// response is lost, so a test can wait for the rotation to have happened.
// Each call arms one loss; several calls apply to successive refresh grants in
// order. It panics on an unknown ResponseLoss.
func (s *FakeIDPServer) LoseNextRefreshResponse(loss ResponseLoss) <-chan struct{} {
	switch loss {
	case ResponseLossHang, ResponseLossReset, ResponseLossBadGateway:
	default:
		panic(fmt.Sprintf("oidctest: unknown ResponseLoss %d", loss))
	}
	processed := make(chan struct{})
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshLosses = append(s.refreshLosses, refreshLoss{mode: loss, processed: processed})
	return processed
}

// SetAccessTTL changes the access token lifetime for subsequent token responses.
func (s *FakeIDPServer) SetAccessTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTTL = d
}

// RotateKey generates a new signing key with the given kid and makes it the
// active signer. The old key remains in the JWKS response so existing tokens
// can still be verified. This simulates IdP key rotation.
func (s *FakeIDPServer) RotateKey(t *testing.T, newKeyID string) {
	t.Helper()

	if newKeyID == "" {
		t.Fatal("oidctest: RotateKey requires a non-empty kid")
	}

	newKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("oidctest: generate rotated key: %v", err)
	}

	signingKey := jose.SigningKey{Algorithm: jose.RS256, Key: newKey}
	newSigner, err := jose.NewSigner(signingKey, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", newKeyID))
	if err != nil {
		t.Fatalf("oidctest: create rotated signer: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Reject duplicate kid.
	if s.keyID == newKeyID {
		t.Fatalf("oidctest: RotateKey kid %q is already the active key", newKeyID)
	}
	for _, ek := range s.extraKeys {
		if ek.keyID == newKeyID {
			t.Fatalf("oidctest: RotateKey kid %q already exists in JWKS", newKeyID)
		}
	}

	// Move the current key to extraKeys so it stays in JWKS.
	s.extraKeys = append(s.extraKeys, keyEntry{key: s.key, keyID: s.keyID})
	s.key = newKey
	s.signer = newSigner
	s.keyID = newKeyID
}

// SetJWKSError makes the JWKS endpoint return the given HTTP status code on
// every request until ClearJWKSError is called. Use this to simulate JWKS
// endpoint unavailability.
func (s *FakeIDPServer) SetJWKSError(statusCode int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwksError = &statusCode
}

// ClearJWKSError removes any forced JWKS endpoint error.
func (s *FakeIDPServer) ClearJWKSError() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jwksError = nil
}

// SetForceIssuer overrides the issuer claim in subsequently issued ID tokens.
// Pass empty string to revert to the default (server URL).
func (s *FakeIDPServer) SetForceIssuer(issuer string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if issuer == "" {
		s.forceIssuer = nil
	} else {
		s.forceIssuer = &issuer
	}
}

// SetForceAudience overrides the audience claim in subsequently issued ID tokens
// with a single value. Pass empty string to revert to the default (client ID).
//
// SetForceAudiences overrides this while it is set.
func (s *FakeIDPServer) SetForceAudience(aud string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if aud == "" {
		s.forceAudience = nil
	} else {
		s.forceAudience = &aud
	}
}

// SetForceAudiences overrides the ID token "aud" claim with a multi-valued list,
// the shape that makes an "azp" claim mandatory under OIDC Core 3.1.3.7. Pass no
// arguments to clear.
//
// It takes precedence over SetForceAudience while set.
func (s *FakeIDPServer) SetForceAudiences(auds ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(auds) == 0 {
		s.forceAudiences = nil
		return
	}
	list := append([]string(nil), auds...)
	s.forceAudiences = &list
}

// SetForceAzp adds an "azp" (authorized party) claim to issued ID tokens. Pass
// an empty string to clear.
func (s *FakeIDPServer) SetForceAzp(azp string) {
	if azp == "" {
		s.SetForceAzpRawJSON("")
		return
	}
	encoded, err := json.Marshal(azp)
	if err != nil { // unreachable for a string
		panic("oidctest: marshal azp: " + err.Error())
	}
	s.SetForceAzpRawJSON(string(encoded))
}

// SetForceAzpRawJSON injects raw JSON as the "azp" claim, so a test can present
// a well-formed token whose azp is not a string. Pass an empty string to clear.
func (s *FakeIDPServer) SetForceAzpRawJSON(raw string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if raw == "" {
		s.forceAzpJSON = nil
		return
	}
	s.forceAzpJSON = &raw
}

// SetForceExpiry overrides the exp claim in subsequently issued ID tokens.
// Pass zero time to revert to the default (now + idTokenTTL).
func (s *FakeIDPServer) SetForceExpiry(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.IsZero() {
		s.forceExpiry = nil
	} else {
		s.forceExpiry = &t
	}
}

// SetForceNotBefore overrides the nbf claim in subsequently issued ID tokens.
// Pass zero time to revert to the default (now - 1 minute).
func (s *FakeIDPServer) SetForceNotBefore(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.IsZero() {
		s.forceNotBefore = nil
	} else {
		s.forceNotBefore = &t
	}
}

func (s *FakeIDPServer) now() time.Time {
	return s.nowFunc()
}

// handleDiscovery serves /.well-known/openid-configuration
func (s *FakeIDPServer) handleDiscovery(w http.ResponseWriter, _ *http.Request) {
	issuer := s.Server.URL
	doc := map[string]any{
		"issuer":                                issuer,
		"authorization_endpoint":                issuer + "/authorize",
		"token_endpoint":                        issuer + "/token",
		"jwks_uri":                              issuer + "/jwks",
		"userinfo_endpoint":                     issuer + "/userinfo",
		"end_session_endpoint":                  issuer + "/end_session",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post"},
		"code_challenge_methods_supported":      []string{"S256"},
	}
	s.mu.Lock()
	omitRevocation := s.omitRevocation
	s.mu.Unlock()
	if !omitRevocation {
		doc["revocation_endpoint"] = issuer + "/revoke"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc) //nolint:errcheck // response write failure surfaces as client-side error in test
}

// handleRevoke implements RFC 7009 token revocation. It really deletes the
// refresh token, so a test can assert the credential stopped working rather than
// merely that a request was recorded.
//
// Per RFC 7009 section 2.2 an unknown or already-revoked token still returns 200,
// so a 200 alone never proves anything was revoked.
func (s *FakeIDPServer) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "malformed form body")
		return
	}
	if r.Form.Get("token") == "" {
		tokenError(w, "invalid_request", "token parameter is required")
		return
	}

	s.mu.Lock()
	delete(s.refreshTokens, r.Form.Get("token"))
	s.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// handleAuthorize simulates the authorization endpoint.
// It redirects to the redirect_uri with code and state parameters.
// In strict mode (default), it enforces native-client protocol requirements.
func (s *FakeIDPServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	scope := r.URL.Query().Get("scope")
	nonce := r.URL.Query().Get("nonce")

	// Validate client_id (always enforced).
	if clientID != s.clientID {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}

	// Validate redirect_uri is registered (pre-redirect check: errors here
	// must NOT redirect, since the redirect target is untrusted).
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	if !s.lenient && !s.isRegisteredRedirectURI(redirectURI) {
		http.Error(w, "unregistered redirect_uri", http.StatusBadRequest)
		return
	}

	// From this point, redirect_uri is trusted — errors redirect with error params.

	// Validate response_type (strict mode).
	if !s.lenient && responseType != "code" {
		redirectWithError(w, r, redirectURI, state, "unsupported_response_type", "only code is supported")
		return
	}

	// Validate PKCE (strict mode: mandatory for native public clients per RFC 7636).
	if !s.lenient {
		if codeChallenge == "" {
			redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge is required")
			return
		}
		if codeChallengeMethod != "S256" {
			redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge_method must be S256")
			return
		}
	} else if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "only S256 supported")
		return
	}

	// Validate scopes (if allowed scopes are configured).
	s.mu.Lock()
	allowedScopes := s.scopes
	s.mu.Unlock()
	if len(allowedScopes) > 0 && scope != "" {
		if unknownScope := s.findUnknownScope(scope, allowedScopes); unknownScope != "" {
			redirectWithError(w, r, redirectURI, state, "invalid_scope", "unknown scope: "+unknownScope)
			return
		}
	}

	// Generate authorization code
	code := generateRandomString(32)

	s.mu.Lock()
	if s.forceNonce != nil {
		nonce = *s.forceNonce
	}
	s.codes[code] = &pendingCode{
		clientID:     clientID,
		redirectURI:  redirectURI,
		nonce:        nonce,
		codeVerifier: codeChallenge, // store the challenge; verify against verifier in token exchange
		subject:      "test-user",
		createdAt:    s.now(),
	}
	s.mu.Unlock()

	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound) //nolint:gosec // G710: intentional redirect in test OIDC server
}

// handleToken handles token exchange (authorization_code) and refresh (refresh_token).
func (s *FakeIDPServer) handleToken(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		tokenError(w, "invalid_request", "failed to parse form")
		return
	}

	// Check for queued errors
	s.mu.Lock()
	if s.stickyError != "" {
		code := s.stickyError
		s.mu.Unlock()
		tokenError(w, code, "simulated persistent error")
		return
	}
	if len(s.errorQueue) > 0 {
		errCode := s.errorQueue[0]
		s.errorQueue = s.errorQueue[1:]
		s.mu.Unlock()
		tokenError(w, errCode, "simulated error")
		return
	}
	s.mu.Unlock()

	// Model a public client: HTTP Basic client authentication is rejected, and
	// the single-use authorization code is invalidated (as Keycloak does), so a
	// client that probes Basic-first cannot recover by retrying.
	if s.rejectBasicAuth {
		if _, _, ok := r.BasicAuth(); ok {
			if code := r.FormValue("code"); code != "" {
				s.mu.Lock()
				delete(s.codes, code)
				s.mu.Unlock()
			}
			tokenError(w, "invalid_client", "client authentication not allowed for public client")
			return
		}
	}

	grantType := r.FormValue("grant_type")

	// Check per-grant-type errors.
	if grantErr, ok := s.GrantErrors.check(grantType); ok {
		tokenError(w, grantErr.code, grantErr.description)
		return
	}

	switch grantType {
	case "authorization_code":
		s.handleAuthCodeExchange(w, r)
	case "refresh_token":
		loss, armed := s.takeRefreshLoss()
		if !armed {
			s.handleRefreshExchange(w, r)
			return
		}
		// Process the refresh in full and discard its response; only then
		// lose the response the client sees.
		s.handleRefreshExchange(httptest.NewRecorder(), r)
		close(loss.processed)
		s.loseResponse(w, r, loss.mode)
	default:
		tokenError(w, "unsupported_grant_type", "unsupported grant_type: "+grantType)
	}
}
func (s *FakeIDPServer) handleAuthCodeExchange(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")
	clientID := r.FormValue("client_id")
	redirectURI := r.FormValue("redirect_uri")

	s.mu.Lock()
	pending, ok := s.codes[code]
	if ok {
		delete(s.codes, code) // one-time use
	}
	codeTTL := s.codeTTL
	lenient := s.lenient
	s.mu.Unlock()

	if !ok {
		tokenError(w, "invalid_grant", "invalid or expired authorization code")
		return
	}

	// Enforce code expiry (strict mode).
	if !lenient && codeTTL > 0 {
		if s.now().Sub(pending.createdAt) > codeTTL {
			tokenError(w, "invalid_grant", "authorization code expired")
			return
		}
	}

	// Verify client_id matches the one that initiated the authorization (strict mode).
	if !lenient && clientID != pending.clientID {
		tokenError(w, "invalid_grant", "client_id mismatch")
		return
	}

	// Verify redirect_uri matches the one used in the authorization request (strict mode).
	if !lenient && redirectURI != pending.redirectURI {
		tokenError(w, "invalid_grant", "redirect_uri mismatch")
		return
	}

	// Verify PKCE S256
	if pending.codeVerifier != "" {
		if codeVerifier == "" {
			tokenError(w, "invalid_grant", "code_verifier required")
			return
		}
		expected := computeS256Challenge(codeVerifier)
		if expected != pending.codeVerifier {
			tokenError(w, "invalid_grant", "code_verifier mismatch")
			return
		}
	}

	s.mu.Lock()
	accessTTL := s.accessTTL
	idTokenTTL := s.idTokenTTL
	s.mu.Unlock()

	now := s.now()
	accessToken := generateRandomString(32)
	refreshToken := generateRandomString(32)
	idToken, err := s.signIDToken(pending.subject, pending.clientID, pending.nonce, now, idTokenTTL)
	if err != nil {
		tokenError(w, "server_error", "failed to sign ID token")
		return
	}

	// Store the refresh token as the first of a new family.
	s.mu.Lock()
	s.refreshTokens[refreshToken] = &tokenState{
		subject:  pending.subject,
		clientID: pending.clientID,
		family:   &refreshFamily{signedInAt: now, lastRefreshAt: now, live: refreshToken},
	}
	s.mu.Unlock()

	resp := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"refresh_token": refreshToken,
		"id_token":      idToken,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck // response write failure surfaces as client-side error in test
}

func (s *FakeIDPServer) handleRefreshExchange(w http.ResponseWriter, r *http.Request) {
	now := s.now()

	s.mu.Lock()
	state, newRefreshToken, refusal := s.redeemRefreshToken(r.FormValue("refresh_token"), now)
	accessTTL := s.accessTTL
	idTokenTTL := s.idTokenTTL
	omitIDToken := s.omitRefreshID
	rawIDToken := s.refreshRawID
	subject := stateSubject(state)
	if s.refreshSubject != nil {
		subject = *s.refreshSubject
	}
	s.mu.Unlock()

	if refusal != "" {
		tokenError(w, "invalid_grant", refusal)
		return
	}

	accessToken := generateRandomString(32)
	var idToken string
	if !omitIDToken {
		if rawIDToken != nil {
			idToken = *rawIDToken
		} else {
			var err error
			idToken, err = s.signIDToken(subject, state.clientID, "", now, idTokenTTL)
			if err != nil {
				tokenError(w, "server_error", "failed to sign ID token")
				return
			}
		}
	}

	resp := map[string]any{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   int(accessTTL.Seconds()),
	}
	if newRefreshToken != "" {
		resp["refresh_token"] = newRefreshToken
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck // response write failure surfaces as client-side error in test
}

// redeemRefreshToken validates a presented refresh token and, when it is
// accepted, advances its session clock and rotates it unless rotation is off.
// It returns the token's state, the new refresh token to send ("" when the
// token was not rotated), and a non-empty error_description when the grant
// must fail with invalid_grant. Validation and rotation happen in one critical
// section, so two concurrent presentations of one token cannot both succeed.
// The caller must hold s.mu.
func (s *FakeIDPServer) redeemRefreshToken(presented string, now time.Time) (state *tokenState, rotated, refusal string) {
	state, ok := s.refreshTokens[presented]
	if !ok {
		if family, spent := s.spentRefresh[presented]; spent && s.reuseDetection {
			delete(s.refreshTokens, family.live)
			family.live = ""
			return nil, "", "refresh token reuse detected; token family revoked"
		}
		return nil, "", "invalid or expired refresh token"
	}
	if s.refreshExpired(state.family, now) {
		delete(s.refreshTokens, presented)
		return nil, "", "refresh token expired"
	}

	state.family.lastRefreshAt = now
	if s.reuseRefresh {
		return state, "", ""
	}

	rotated = generateRandomString(32)
	delete(s.refreshTokens, presented)
	s.spentRefresh[presented] = state.family
	s.refreshTokens[rotated] = &tokenState{
		subject:  state.subject,
		clientID: state.clientID,
		family:   state.family,
	}
	state.family.live = rotated
	return state, rotated, ""
}

// refreshExpired reports whether family's session has outlived refreshTTL,
// measured from sign-in by default or from the most recent refresh under
// WithSlidingRefreshExpiry. The caller must hold s.mu.
func (s *FakeIDPServer) refreshExpired(family *refreshFamily, now time.Time) bool {
	if s.refreshTTL <= 0 {
		return false
	}
	start := family.signedInAt
	if s.slidingRefresh {
		start = family.lastRefreshAt
	}
	return now.Sub(start) > s.refreshTTL
}

// takeRefreshLoss pops the oldest loss armed by LoseNextRefreshResponse.
func (s *FakeIDPServer) takeRefreshLoss() (refreshLoss, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.refreshLosses) == 0 {
		return refreshLoss{}, false
	}
	loss := s.refreshLosses[0]
	s.refreshLosses = s.refreshLosses[1:]
	return loss, true
}

// badGatewayPage is the body ResponseLossBadGateway sends: a reverse proxy's
// HTML error page, not an OAuth error response.
const badGatewayPage = `<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>gateway</center>
</body>
</html>
`

// loseResponse makes sure the client never receives a processed refresh
// response, in the way mode describes.
func (s *FakeIDPServer) loseResponse(w http.ResponseWriter, r *http.Request, mode ResponseLoss) {
	switch mode {
	case ResponseLossHang:
		select {
		case <-r.Context().Done(): // the client gave up and closed the connection
		case <-s.done: // the test is ending
		}
		// Abort without writing, so the connection closes with no response
		// even if the client is still waiting.
		panic(http.ErrAbortHandler)
	case ResponseLossReset:
		conn, _, err := http.NewResponseController(w).Hijack()
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0) // close with RST instead of FIN
		}
		_ = conn.Close()
	default: // ResponseLossBadGateway
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, badGatewayPage) //nolint:errcheck // response write failure surfaces as client-side error in test
	}
}

func stateSubject(state *tokenState) string {
	if state == nil {
		return ""
	}
	return state.subject
}

// handleJWKS serves the JSON Web Key Set.
func (s *FakeIDPServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	s.mu.Lock()
	jwksErr := s.jwksError
	s.mu.Unlock()

	if jwksErr != nil {
		http.Error(w, "simulated JWKS failure", *jwksErr)
		return
	}

	s.mu.Lock()
	keys := []jose.JSONWebKey{
		{
			Key:       &s.key.PublicKey,
			KeyID:     s.keyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		},
	}
	for _, ek := range s.extraKeys {
		keys = append(keys, jose.JSONWebKey{
			Key:       &ek.key.PublicKey,
			KeyID:     ek.keyID,
			Algorithm: string(jose.RS256),
			Use:       "sig",
		})
	}
	s.mu.Unlock()

	jwks := jose.JSONWebKeySet{Keys: keys}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks) //nolint:errcheck // response write failure surfaces as client-side error in test
}

// handleEndSession simulates RP-Initiated Logout.
// Redirects to post_logout_redirect_uri if provided, echoing back the state
// parameter as required by OIDC RP-Initiated Logout 1.0.
func (s *FakeIDPServer) handleEndSession(w http.ResponseWriter, r *http.Request) {
	postLogoutURI := r.URL.Query().Get("post_logout_redirect_uri")
	if postLogoutURI != "" {
		if state := r.URL.Query().Get("state"); state != "" {
			if u, err := url.Parse(postLogoutURI); err == nil {
				q := u.Query()
				q.Set("state", state)
				u.RawQuery = q.Encode()
				postLogoutURI = u.String()
			}
		}
		http.Redirect(w, r, postLogoutURI, http.StatusFound) //nolint:gosec // G710: intentional redirect in test OIDC server
		return
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, "Logged out") //nolint:errcheck // response write failure surfaces as client-side error in test
}

// handleUserinfo returns basic user info claims.
func (s *FakeIDPServer) handleUserinfo(w http.ResponseWriter, _ *http.Request) {
	claims := map[string]any{
		"sub":   "test-user",
		"name":  "Test User",
		"email": "test@example.com",
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(claims) //nolint:errcheck // response write failure surfaces as client-side error in test
}

// signIDToken creates a signed JWT ID token.
func (s *FakeIDPServer) signIDToken(subject, audience, nonce string, now time.Time, ttl time.Duration) (string, error) {
	s.mu.Lock()
	issuer := s.Server.URL
	if s.forceIssuer != nil {
		issuer = *s.forceIssuer
	}
	if s.forceAudience != nil {
		audience = *s.forceAudience
	}
	audiences := jwt.Audience{audience}
	if s.forceAudiences != nil {
		audiences = jwt.Audience(append([]string(nil), *s.forceAudiences...))
	}
	var azpJSON *string
	if s.forceAzpJSON != nil {
		raw := *s.forceAzpJSON
		azpJSON = &raw
	}
	expiry := now.Add(ttl)
	if s.forceExpiry != nil {
		expiry = *s.forceExpiry
	}
	notBefore := now.Add(-1 * time.Minute)
	if s.forceNotBefore != nil {
		notBefore = *s.forceNotBefore
	}
	signer := s.signer // capture under lock to avoid race with RotateKey
	s.mu.Unlock()

	claims := jwt.Claims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audiences,
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(expiry),
		NotBefore: jwt.NewNumericDate(notBefore),
	}

	type extraClaims struct {
		Nonce string           `json:"nonce,omitempty"`
		Email string           `json:"email,omitempty"`
		Name  string           `json:"name,omitempty"`
		Azp   *json.RawMessage `json:"azp,omitempty"`
	}
	extra := extraClaims{
		Nonce: nonce,
		Email: "test@example.com",
		Name:  "Test User",
	}
	if azpJSON != nil {
		raw := json.RawMessage(*azpJSON)
		extra.Azp = &raw
	}

	token, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		return "", fmt.Errorf("sign ID token: %w", err)
	}
	return token, nil
}

// computeS256Challenge computes the S256 code challenge from a verifier.
func computeS256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func generateRandomString(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("oidctest: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// tokenError writes an OAuth error response. An empty description omits the
// optional error_description member.
func tokenError(w http.ResponseWriter, code, description string) {
	body := map[string]string{"error": code}
	if description != "" {
		body["error_description"] = description
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(body) //nolint:errcheck // response write failure surfaces as client-side error in test
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}
	q := redirectURL.Query()
	q.Set("error", code)
	q.Set("error_description", description)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()
	http.Redirect(w, r, redirectURL.String(), http.StatusFound) //nolint:gosec // G710: intentional redirect in test OIDC server
}

// isRegisteredRedirectURI checks whether the given URI matches a registered one.
// A registered URI of "http://127.0.0.1:0/callback" matches any port on 127.0.0.1
// with the path /callback (wildcard port convention for test servers).
func (s *FakeIDPServer) isRegisteredRedirectURI(uri string) bool {
	parsed, err := url.Parse(uri)
	if err != nil {
		return false
	}
	for _, registered := range s.redirectURIs {
		reg, err := url.Parse(registered)
		if err != nil {
			continue
		}
		// Wildcard port: port "0" matches any port.
		if reg.Scheme == parsed.Scheme && reg.Path == parsed.Path {
			regHost := reg.Hostname()
			parsedHost := parsed.Hostname()
			if regHost == parsedHost {
				if reg.Port() == "0" || reg.Port() == parsed.Port() {
					return true
				}
			}
		}
	}
	return false
}

// findUnknownScope returns the first scope in the space-separated scope string
// that is not in the allowed list. Returns empty string if all are valid.
func (s *FakeIDPServer) findUnknownScope(scopeStr string, allowed []string) string {
	allowedSet := make(map[string]struct{}, len(allowed))
	for _, sc := range allowed {
		allowedSet[sc] = struct{}{}
	}
	for _, sc := range strings.Fields(scopeStr) {
		if _, ok := allowedSet[sc]; !ok {
			return sc
		}
	}
	return ""
}
