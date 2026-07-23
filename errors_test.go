package pkceflow

import (
	"errors"
	"fmt"
	"testing"
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
