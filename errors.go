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

	// ErrFlowCancelled is returned when the auth flow is cancelled,
	// either by context cancellation or user action.
	ErrFlowCancelled = errors.New("pkceflow: auth flow cancelled")

	// ErrNotAuthenticated is returned by methods that require an authenticated
	// session (e.g., Claims) when no ID token is available.
	ErrNotAuthenticated = errors.New("pkceflow: not authenticated (no ID token available)")
)

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

// IsPermanentError reports whether err represents a permanent OAuth2 error
// that cannot be resolved by retrying. When true, the refresh token is
// invalid (revoked, expired, or the client is no longer authorized) and
// the user must re-authenticate via Login().
func IsPermanentError(err error) bool {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return permanentErrorCodes[authErr.Code]
	}
	return false
}

// asAuthError converts an OAuth2 token-endpoint error into an *AuthError,
// preserving the OAuth2 error code (RFC 6749 section 5.2) so IsPermanentError
// and consumer inspection work uniformly across the login and refresh paths.
//
// golang.org/x/oauth2 returns *oauth2.RetrieveError for token-endpoint failures;
// its Error() can include the raw response body, so converting here also stops
// that body from propagating into logs and consumer errors. Errors without an
// OAuth2 error code (network failures, non-standard responses) are returned
// unchanged so their original context is preserved.
func asAuthError(err error) error {
	var re *oauth2.RetrieveError
	if errors.As(err, &re) && re.ErrorCode != "" {
		return &AuthError{Code: re.ErrorCode, Message: re.ErrorDescription}
	}
	return err
}
