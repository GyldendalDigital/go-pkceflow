package pkceflow

import (
	"testing"
	"time"
)

func TestTokenState_IsZero(t *testing.T) {
	tests := []struct {
		name  string
		state TokenState
		want  bool
	}{
		{
			name:  "zero value is zero",
			state: TokenState{},
			want:  true,
		},
		{
			name:  "only timestamps is still zero",
			state: TokenState{ExpiresAt: time.Now(), LastAuthAt: time.Now()},
			want:  true,
		},
		{
			name:  "access token makes it non-zero",
			state: TokenState{AccessToken: "token"},
			want:  false,
		},
		{
			name:  "refresh token makes it non-zero",
			state: TokenState{RefreshToken: "refresh"},
			want:  false,
		},
		{
			name:  "id token makes it non-zero",
			state: TokenState{IDToken: "id"},
			want:  false,
		},
		{
			name: "fully populated is non-zero",
			state: TokenState{
				AccessToken:  "access",
				RefreshToken: "refresh",
				IDToken:      "id",
				ExpiresAt:    time.Now().Add(time.Hour),
				LastAuthAt:   time.Now(),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.state.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}
