package pkceflow

import (
	"errors"
	"fmt"

	"golang.org/x/oauth2"
)

// Sentinel errors returned by Client methods.
var (
	// ErrNotInitialized is returned when a method requiring OIDC discovery
	// (e.g., Login) is called before Init() succeeds.
	ErrNotInitialized = errors.New("pkceflow: client not initialized (call Init first)")

	// ErrStateMismatch is returned when the state parameter in the callback
	// does not match the state sent in the authorization request.
	// This indicates a potential CSRF attack or a stale callback.
	ErrStateMismatch = errors.New("pkceflow: state parameter mismatch")

	// ErrNonceMismatch is returned when the nonce claim in the returned ID
	// token does not match the nonce sent in the authorization request.
	// This indicates a potential token replay or injection attack.
	ErrNonceMismatch = errors.New("pkceflow: nonce mismatch")

	// ErrFlowCancelled is returned when Login is cancelled by its context,
	// times out, is cancelled by user action, or is superseded by a newer Login
	// or Logout on the same Client.
	ErrFlowCancelled = errors.New("pkceflow: auth flow cancelled")

	// ErrNotAuthenticated is returned by methods that require an authenticated
	// session (e.g., Claims) when no ID token is available.
	ErrNotAuthenticated = errors.New("pkceflow: not authenticated (no ID token available)")

	errSessionIntegrity          = errors.New("pkceflow: session integrity check failed")
	errRefreshPermanentlyBlocked = errors.New("pkceflow: token generation is permanently blocked")
)

// restoreSessionError keeps arbitrary persistence error text out of logs while
// preserving the original cause for deliberate errors.Is/errors.As inspection.
type restoreSessionError struct {
	cause error
}

func (e *restoreSessionError) Error() string {
	return "pkceflow: failed to restore persisted session"
}

func (e *restoreSessionError) Unwrap() error {
	return e.cause
}

// AuthError represents an OAuth2/OIDC error returned by the identity provider.
// The Code field contains the OAuth2 error code (e.g., "invalid_grant").
type AuthError struct {
	Code    string
	Message string
}

func (e *AuthError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("pkceflow: auth error: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("pkceflow: auth error: %s", e.Code)
}

// permanentErrorCodes are OAuth2 error codes that indicate the refresh token
// is permanently invalid and retrying will not help.
var permanentErrorCodes = map[string]bool{
	"invalid_grant":       true,
	"invalid_client":      true,
	"unauthorized_client": true,
}

// IsPermanentError reports whether err represents a permanent OAuth2 or
// session-integrity error that cannot be resolved by retrying. When true, the
// refresh token is invalid (revoked, expired, or the client is no longer
// authorized), or the refreshed session no longer matches the trusted session.
func IsPermanentError(err error) bool {
	if errors.Is(err, errSessionIntegrity) ||
		errors.Is(err, errRefreshPermanentlyBlocked) {
		return true
	}
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return permanentErrorCodes[authErr.Code]
	}
	return false
}

func newSessionIntegrityError(message string, cause error) error {
	if cause != nil {
		return fmt.Errorf("%w: %s: %w", errSessionIntegrity, message, cause)
	}
	return fmt.Errorf("%w: %s", errSessionIntegrity, message)
}

func isSessionIntegrityError(err error) bool {
	return errors.Is(err, errSessionIntegrity)
}

// asAuthError converts an OAuth2 token-endpoint error into an *AuthError,
// preserving the OAuth2 error code (RFC 6749 section 5.2) so IsPermanentError
// and consumer inspection work uniformly across the login and refresh paths.
//
// golang.org/x/oauth2 returns *oauth2.RetrieveError for token-endpoint failures;
// its Error() can include the raw response body, so converting here also stops
// that body from propagating into logs and consumer errors. Non-standard
// responses without an OAuth2 error code are still converted so raw response
// bodies never escape through the public API or debug logs.
func asAuthError(err error) error {
	var re *oauth2.RetrieveError
	if !errors.As(err, &re) {
		return err
	}

	code := re.ErrorCode
	if code == "" {
		code = "token_endpoint_error"
	}

	message := re.ErrorDescription
	if message == "" && re.Response != nil {
		message = "token endpoint returned " + re.Response.Status
	}

	return &AuthError{Code: code, Message: message}
}
