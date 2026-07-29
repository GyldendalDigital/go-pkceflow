package pkceflow

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

func TestAuthError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  AuthError
		want string
	}{
		{
			name: "code and message",
			err:  AuthError{Code: "invalid_grant", Message: "token revoked"},
			want: "pkceflow: auth error: invalid_grant: token revoked",
		},
		{
			name: "code only",
			err:  AuthError{Code: "invalid_client"},
			want: "pkceflow: auth error: invalid_client",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAuthError_ErrorsAs(t *testing.T) {
	original := &AuthError{Code: "invalid_grant", Message: "token expired"}
	wrapped := fmt.Errorf("refresh failed: %w", original)

	var target *AuthError
	if !errors.As(wrapped, &target) {
		t.Fatal("errors.As failed to unwrap AuthError")
	}
	if target.Code != "invalid_grant" {
		t.Errorf("Code = %q, want %q", target.Code, "invalid_grant")
	}
}

func TestSentinelErrors_ErrorsIs(t *testing.T) {
	wrapped := fmt.Errorf("operation failed: %w", ErrStateMismatch)
	if !errors.Is(wrapped, ErrStateMismatch) {
		t.Error("errors.Is failed for wrapped ErrStateMismatch")
	}
}

func TestIsPermanentError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "invalid_grant is permanent",
			err:  &AuthError{Code: "invalid_grant"},
			want: true,
		},
		{
			name: "invalid_client is permanent",
			err:  &AuthError{Code: "invalid_client"},
			want: true,
		},
		{
			name: "unauthorized_client is permanent",
			err:  &AuthError{Code: "unauthorized_client"},
			want: true,
		},
		{
			name: "server_error is not permanent",
			err:  &AuthError{Code: "server_error"},
			want: false,
		},
		{
			name: "wrapped permanent error detected",
			err:  fmt.Errorf("refresh: %w", &AuthError{Code: "invalid_grant"}),
			want: true,
		},
		{
			name: "session integrity error is permanent",
			err:  newSessionIntegrityError("refreshed ID token subject changed", nil),
			want: true,
		},
		{
			name: "non-AuthError is not permanent",
			err:  errors.New("network timeout"),
			want: false,
		},
		{
			name: "nil is not permanent",
			err:  nil,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsPermanentError(tt.err); got != tt.want {
				t.Errorf("IsPermanentError() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAsAuthError(t *testing.T) {
	t.Run("oauth2 RetrieveError converts to AuthError", func(t *testing.T) {
		re := &oauth2.RetrieveError{
			ErrorCode:        "invalid_grant",
			ErrorDescription: "token revoked",
		}
		wrapped := fmt.Errorf("pkceflow: token refresh failed: %w", asAuthError(re))

		var authErr *AuthError
		if !errors.As(wrapped, &authErr) {
			t.Fatalf("expected *AuthError in chain, got %v", wrapped)
		}
		if authErr.Code != "invalid_grant" {
			t.Errorf("Code = %q, want invalid_grant", authErr.Code)
		}
		if authErr.Message != "token revoked" {
			t.Errorf("Message = %q, want token revoked", authErr.Message)
		}
		if !IsPermanentError(wrapped) {
			t.Error("IsPermanentError should be true for a converted invalid_grant")
		}
	})

	t.Run("RetrieveError without code is sanitized", func(t *testing.T) {
		re := &oauth2.RetrieveError{
			Response: &http.Response{
				Status:     "500 Internal Server Error",
				StatusCode: http.StatusInternalServerError,
			},
			Body: []byte(`{"access_token":"secret-token","refresh_token":"secret-refresh"}`),
		}
		got := asAuthError(re)
		var authErr *AuthError
		if !errors.As(got, &authErr) {
			t.Fatalf("expected *AuthError, got %T %[1]v", got)
		}
		if authErr.Code != "token_endpoint_error" {
			t.Errorf("Code = %q, want token_endpoint_error", authErr.Code)
		}
		if !strings.Contains(authErr.Message, "500 Internal Server Error") {
			t.Errorf("Message = %q, want status context", authErr.Message)
		}
		for _, secret := range []string{"secret-token", "secret-refresh", "access_token", "refresh_token"} {
			if strings.Contains(got.Error(), secret) {
				t.Fatalf("sanitized error leaked %q in %q", secret, got.Error())
			}
		}
	})

	t.Run("non-oauth2 error is returned unchanged", func(t *testing.T) {
		orig := errors.New("network timeout")
		if got := asAuthError(orig); got != orig {
			t.Errorf("expected original error, got %v", got)
		}
	})
}
