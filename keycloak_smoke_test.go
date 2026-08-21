package pkceflow_test

// Live-provider smoke check for RFC 7009 revocation on logout.
//
// Skipped unless PKCEFLOW_SMOKE_ISSUER is set, so it never runs in CI. It exists
// because two questions cannot be answered by the fake IdP:
//
//  1. Does the revocation endpoint accept a public client authenticating with
//     client_id alone? Keycloak advertises revocation_endpoint but omits "none"
//     from revocation_endpoint_auth_methods_supported, so the metadata says no
//     while the implementation says yes.
//  2. Does end_session still honour post_logout_redirect_uri after revocation
//     has already destroyed the session that id_token_hint names? Logout runs
//     revocation first, and provider behaviour here is version-dependent.
//
// Run it against the dockerized demo realm in the wails-pkceflow repository
// (examples/wails-desktop/keycloak):
//
//	docker compose up -d
//	PKCEFLOW_SMOKE_ISSUER=http://localhost:8080/realms/demo \
//	PKCEFLOW_SMOKE_CLIENT_ID=demo-native \
//	PKCEFLOW_SMOKE_USERNAME=demo \
//	PKCEFLOW_SMOKE_PASSWORD=demo \
//	go test -run TestKeycloakRevokesRefreshTokenOnLogout -v .
//
// Any realm configured as docs/idp-setup-keycloak.md describes will do; the
// redirect URIs default to the demo realm's port and can be overridden with
// PKCEFLOW_SMOKE_REDIRECT_URI and PKCEFLOW_SMOKE_POST_LOGOUT_URI.

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	pkceflow "github.com/GyldendalDigital/go-pkceflow"
)

type smokeConfig struct {
	issuer        string
	clientID      string
	username      string
	password      string
	redirectURI   string
	postLogoutURI string
}

func smokeEnv(t *testing.T) *smokeConfig {
	t.Helper()
	issuer := os.Getenv("PKCEFLOW_SMOKE_ISSUER")
	if issuer == "" {
		t.Skip("set PKCEFLOW_SMOKE_ISSUER to run the live provider smoke check")
	}
	cfg := &smokeConfig{
		issuer:        issuer,
		clientID:      envOr("PKCEFLOW_SMOKE_CLIENT_ID", "demo-native"),
		username:      envOr("PKCEFLOW_SMOKE_USERNAME", "demo"),
		password:      envOr("PKCEFLOW_SMOKE_PASSWORD", "demo"),
		redirectURI:   envOr("PKCEFLOW_SMOKE_REDIRECT_URI", "http://127.0.0.1:34115/callback"),
		postLogoutURI: envOr("PKCEFLOW_SMOKE_POST_LOGOUT_URI", "http://127.0.0.1:34115/logout-callback"),
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// smokeBrowser stands in for the system browser and the loopback listener: it
// submits the provider's login form and captures the callback redirects instead
// of following them to a port nothing is listening on.
//
// The form scraping is deliberately minimal and Keycloak-shaped. It is a test
// fixture, not a general-purpose user agent.
type smokeBrowser struct {
	cfg    smokeConfig
	client *http.Client

	// Logout swallows RP-initiated logout failures by design, so the outcome of
	// the end_session leg is only observable from in here.
	logoutCallback string
	logoutErr      error
}

func newSmokeBrowser(t *testing.T, cfg *smokeConfig) *smokeBrowser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	callback, err := url.Parse(cfg.redirectURI)
	if err != nil {
		t.Fatalf("parse redirect URI: %v", err)
	}
	return &smokeBrowser{
		cfg: *cfg,
		client: &http.Client{
			Jar:     jar,
			Timeout: 30 * time.Second,
			CheckRedirect: func(req *http.Request, _ []*http.Request) error {
				if req.URL.Host == callback.Host {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}
}

func (b *smokeBrowser) RedirectURI() string           { return b.cfg.redirectURI }
func (b *smokeBrowser) PostLogoutRedirectURI() string { return b.cfg.postLogoutURI }

func (b *smokeBrowser) StartAuthFlow(_ context.Context, authURL string) (string, error) {
	page, err := b.client.Get(authURL)
	if err != nil {
		return "", err
	}
	defer page.Body.Close()
	body, err := io.ReadAll(page.Body)
	if err != nil {
		return "", err
	}
	action, err := loginFormAction(string(body))
	if err != nil {
		return "", err
	}

	submitted, err := b.client.PostForm(action, url.Values{
		"username": {b.cfg.username},
		"password": {b.cfg.password},
	})
	if err != nil {
		return "", err
	}
	defer submitted.Body.Close()
	location := submitted.Header.Get("Location")
	if location == "" {
		return "", errSmokef("login did not redirect to the callback (status %d)", submitted.StatusCode)
	}
	return location, nil
}

func (b *smokeBrowser) StartLogoutFlow(_ context.Context, logoutURL string) (string, error) {
	resp, err := b.client.Get(logoutURL)
	if err != nil {
		b.logoutErr = err
		return "", err
	}
	defer resp.Body.Close()
	if location := resp.Header.Get("Location"); location != "" {
		b.logoutCallback = location
		return location, nil
	}
	body, _ := io.ReadAll(resp.Body)
	b.logoutErr = errSmokef(
		"end_session did not redirect: status %d, body starts %.160q",
		resp.StatusCode, strings.TrimSpace(string(body)),
	)
	return "", b.logoutErr
}

func loginFormAction(page string) (string, error) {
	const marker = `action="`
	start := strings.Index(page, marker)
	if start < 0 {
		return "", errSmokef("no form action in the login page")
	}
	rest := page[start+len(marker):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return "", errSmokef("unterminated form action in the login page")
	}
	return strings.NewReplacer("&amp;", "&").Replace(rest[:end]), nil
}

type smokeStore struct{ state pkceflow.TokenState }

func (s *smokeStore) Save(state pkceflow.TokenState) error { //nolint:gocritic // hugeParam: matches TokenPersistence
	s.state = state
	return nil
}
func (s *smokeStore) Load() (pkceflow.TokenState, error) { return s.state, nil }
func (s *smokeStore) Delete() error                      { s.state = pkceflow.TokenState{}; return nil }

// TestKeycloakRevokesRefreshTokenOnLogout asserts the credential actually dies.
// A recorded POST would prove nothing: RFC 7009 section 2.2 requires a 200 even
// for a token the provider does not recognize.
func TestKeycloakRevokesRefreshTokenOnLogout(t *testing.T) {
	cfg := smokeEnv(t)
	ctx := context.Background()

	flow := newSmokeBrowser(t, cfg)
	store := &smokeStore{}
	client, err := pkceflow.New(pkceflow.Config{
		IssuerURL: cfg.issuer,
		ClientID:  cfg.clientID,
		Scopes:    []string{"openid", "profile", "email", "offline_access"},
	}, flow,
		pkceflow.WithTokenPersistence(store),
		pkceflow.WithHTTPClient(&http.Client{Timeout: 30 * time.Second}),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := client.Init(ctx); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if store.state.RefreshToken == "" {
		t.Fatal("login produced no refresh token; check that offline_access is granted")
	}

	// Control: the token works before logout. Keycloak rotates on redemption, so
	// re-read the state the client committed afterwards.
	if status, body := redeemSmokeToken(t, cfg, store.state.RefreshToken); status != http.StatusOK {
		t.Fatalf("refresh token was not redeemable before logout: status %d, %s", status, body)
	}
	live := store.state.RefreshToken
	if live == "" {
		t.Fatal("no refresh token held after the control redemption")
	}

	if err := client.Logout(ctx); err != nil {
		t.Fatalf("Logout: %v", err)
	}

	// Gate 1: the endpoint accepted a public client authenticating with
	// client_id alone, despite revocation_endpoint_auth_methods_supported
	// omitting "none".
	status, body := redeemSmokeToken(t, cfg, live)
	if status == http.StatusOK {
		t.Fatal("refresh token is still redeemable after logout: revocation did not take effect")
	}
	t.Logf("gate 1 ok: token rejected after logout (status %d, %s)", status, body)

	// Gate 2: revocation destroyed the session that id_token_hint names, so
	// confirm end_session still honoured post_logout_redirect_uri.
	if flow.logoutErr != nil {
		t.Fatalf("end_session did not honour post_logout_redirect_uri after revocation: %v", flow.logoutErr)
	}
	if !strings.HasPrefix(flow.logoutCallback, cfg.postLogoutURI) {
		t.Fatalf("end_session redirected to %q, want a %q callback", flow.logoutCallback, cfg.postLogoutURI)
	}
	parsed, err := url.Parse(flow.logoutCallback)
	if err != nil {
		t.Fatalf("unparseable logout callback %q: %v", flow.logoutCallback, err)
	}
	if parsed.Query().Get("state") == "" {
		t.Fatalf("logout callback carried no state parameter: %q", flow.logoutCallback)
	}
	t.Log("gate 2 ok: end_session honoured post_logout_redirect_uri, with state")
}

func redeemSmokeToken(t *testing.T, cfg *smokeConfig, refreshToken string) (status int, body string) {
	t.Helper()
	resp, err := http.PostForm(cfg.issuer+"/protocol/openid-connect/token", url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {cfg.clientID},
	})
	if err != nil {
		t.Fatalf("redeem refresh token: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(raw))
}

func errSmokef(format string, args ...any) error { return fmt.Errorf(format, args...) }
