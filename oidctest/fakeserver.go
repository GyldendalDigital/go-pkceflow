package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// FakeIDPServer is a fake OIDC provider for testing.
// It implements discovery, authorization, token exchange, JWKS, and end_session endpoints.
// Safe for concurrent use and parallel tests.
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
	clientID        string
	redirectURIs    []string
	accessTTL       time.Duration
	refreshTTL      time.Duration
	idTokenTTL      time.Duration
	codes           map[string]*pendingCode // authorization code -> pending exchange
	refreshTokens   map[string]*tokenState  // refresh token -> associated state
	errorQueue      []string                // queued errors to return on next token request
	stickyError     string                  // when set, every token request returns this error
	rejectBasicAuth bool                    // when true, model a public client: reject HTTP Basic client auth and invalidate the code
	forceNonce      *string                 // when set, overrides the ID token nonce claim
	omitRefreshID   bool                    // when true, refresh responses omit id_token
	refreshSubject  *string                 // when set, overrides refresh ID token subject
	refreshRawID    *string                 // when set, refresh responses use this raw id_token
	nowFunc         func() time.Time
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
	subject   string
	clientID  string
	createdAt time.Time
}

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
func WithRefreshTTL(d time.Duration) Option {
	return func(s *FakeIDPServer) { s.refreshTTL = d }
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
		clientID:      "test-client",
		redirectURIs:  []string{"http://127.0.0.1:0/callback"},
		accessTTL:     5 * time.Minute,
		refreshTTL:    24 * time.Hour,
		idTokenTTL:    5 * time.Minute,
		codes:         make(map[string]*pendingCode),
		refreshTokens: make(map[string]*tokenState),
		nowFunc:       time.Now,
	}

	for _, opt := range opts {
		opt(s)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", s.wrapHandler("/discovery", s.Hooks.runDiscovery, s.handleDiscovery))
	mux.HandleFunc("GET /authorize", s.wrapHandler("/authorize", s.Hooks.runAuthorize, s.handleAuthorize))
	mux.HandleFunc("POST /token", s.wrapHandler("/token", s.Hooks.runToken, s.handleToken))
	mux.HandleFunc("GET /jwks", s.wrapHandler("/jwks", s.Hooks.runJWKS, s.handleJWKS))
	mux.HandleFunc("GET /end_session", s.wrapHandler("/end_session", s.Hooks.runEndSession, s.handleEndSession))
	mux.HandleFunc("GET /userinfo", s.wrapHandler("/userinfo", s.Hooks.runUserinfo, s.handleUserinfo))

	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Server.Close)

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

// SetAccessTTL changes the access token lifetime for subsequent token responses.
func (s *FakeIDPServer) SetAccessTTL(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.accessTTL = d
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(doc) //nolint:errcheck // response write failure surfaces as client-side error in test
}

// handleAuthorize simulates the authorization endpoint.
// It redirects to the redirect_uri with code and state parameters.
func (s *FakeIDPServer) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	state := r.URL.Query().Get("state")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	nonce := r.URL.Query().Get("nonce")

	if clientID != s.clientID {
		http.Error(w, "invalid client_id", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod != "" && codeChallengeMethod != "S256" {
		redirectWithError(w, r, redirectURI, state, "invalid_request", "only S256 supported")
		return
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

	// Redirect with code + state
	sep := "?"
	if redirectURI == "" {
		http.Error(w, "missing redirect_uri", http.StatusBadRequest)
		return
	}
	location := fmt.Sprintf("%s%scode=%s&state=%s", redirectURI, sep, code, state)
	http.Redirect(w, r, location, http.StatusFound) //nolint:gosec // G710: intentional redirect in test OIDC server
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
	if errCode, ok := s.GrantErrors.check(grantType); ok {
		tokenError(w, errCode, "simulated grant-scoped error")
		return
	}

	switch grantType {
	case "authorization_code":
		s.handleAuthCodeExchange(w, r)
	case "refresh_token":
		s.handleRefreshExchange(w, r)
	default:
		tokenError(w, "unsupported_grant_type", "unsupported grant_type: "+grantType)
	}
}
func (s *FakeIDPServer) handleAuthCodeExchange(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	codeVerifier := r.FormValue("code_verifier")

	s.mu.Lock()
	pending, ok := s.codes[code]
	if ok {
		delete(s.codes, code) // one-time use
	}
	s.mu.Unlock()

	if !ok {
		tokenError(w, "invalid_grant", "invalid or expired authorization code")
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

	// Store refresh token
	s.mu.Lock()
	s.refreshTokens[refreshToken] = &tokenState{
		subject:   pending.subject,
		clientID:  pending.clientID,
		createdAt: now,
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
	oldRefresh := r.FormValue("refresh_token")

	s.mu.Lock()
	state, ok := s.refreshTokens[oldRefresh]
	if ok {
		delete(s.refreshTokens, oldRefresh) // rotation: old token invalidated
	}
	accessTTL := s.accessTTL
	idTokenTTL := s.idTokenTTL
	omitIDToken := s.omitRefreshID
	rawIDToken := s.refreshRawID
	subject := stateSubject(state)
	if s.refreshSubject != nil {
		subject = *s.refreshSubject
	}
	s.mu.Unlock()

	if !ok {
		tokenError(w, "invalid_grant", "invalid or expired refresh token")
		return
	}

	now := s.now()
	accessToken := generateRandomString(32)
	newRefreshToken := generateRandomString(32)
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

	// Store new refresh token
	s.mu.Lock()
	s.refreshTokens[newRefreshToken] = &tokenState{
		subject:   state.subject,
		clientID:  state.clientID,
		createdAt: now,
	}
	s.mu.Unlock()

	resp := map[string]any{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"refresh_token": newRefreshToken,
	}
	if idToken != "" {
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck // response write failure surfaces as client-side error in test
}

func stateSubject(state *tokenState) string {
	if state == nil {
		return ""
	}
	return state.subject
}

// handleJWKS serves the JSON Web Key Set.
func (s *FakeIDPServer) handleJWKS(w http.ResponseWriter, _ *http.Request) {
	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &s.key.PublicKey,
				KeyID:     "test-key-1",
				Algorithm: string(jose.RS256),
				Use:       "sig",
			},
		},
	}
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
	claims := jwt.Claims{
		Issuer:    s.Server.URL,
		Subject:   subject,
		Audience:  jwt.Audience{audience},
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(ttl)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Minute)), // 1min clock skew tolerance
	}

	type extraClaims struct {
		Nonce string `json:"nonce,omitempty"`
		Email string `json:"email,omitempty"`
		Name  string `json:"name,omitempty"`
	}
	extra := extraClaims{
		Nonce: nonce,
		Email: "test@example.com",
		Name:  "Test User",
	}

	token, err := jwt.Signed(s.signer).Claims(claims).Claims(extra).Serialize()
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

func tokenError(w http.ResponseWriter, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck // response write failure surfaces as client-side error in test
		"error":             code,
		"error_description": description,
	})
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	location := fmt.Sprintf("%s?error=%s&error_description=%s&state=%s", redirectURI, code, description, state)
	http.Redirect(w, r, location, http.StatusFound) //nolint:gosec // G710: intentional redirect in test OIDC server
}
