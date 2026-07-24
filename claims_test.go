package pkceflow

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// makeIDToken builds an unsigned JWT-shaped token (header.payload.signature)
// whose payload is the given claim map. The signature segment is a placeholder
// because DecodeIDToken does not verify signatures.
func makeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".signature-not-verified"
}

func TestDecodeIDToken_StandardClaims(t *testing.T) {
	now := time.Now().Unix()
	token := makeIDToken(t, map[string]any{
		"sub":                "user-123",
		"name":               "Ada Lovelace",
		"given_name":         "Ada",
		"family_name":        "Lovelace",
		"preferred_username": "ada",
		"email":              "ada@example.com",
		"email_verified":     true,
		"iss":                "https://idp.example.com",
		"aud":                "my-app",
		"exp":                float64(now + 3600),
		"iat":                float64(now),
		"auth_time":          float64(now - 5),
	})

	claims, err := DecodeIDToken(token)
	if err != nil {
		t.Fatalf("DecodeIDToken: %v", err)
	}

	if claims.Subject != "user-123" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Name != "Ada Lovelace" {
		t.Errorf("Name = %q", claims.Name)
	}
	if claims.GivenName != "Ada" || claims.FamilyName != "Lovelace" {
		t.Errorf("given/family = %q/%q", claims.GivenName, claims.FamilyName)
	}
	if claims.PreferredUsername != "ada" {
		t.Errorf("PreferredUsername = %q", claims.PreferredUsername)
	}
	if claims.Email != "ada@example.com" || !claims.EmailVerified {
		t.Errorf("email = %q verified = %v", claims.Email, claims.EmailVerified)
	}
	if claims.Issuer != "https://idp.example.com" {
		t.Errorf("Issuer = %q", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "my-app" {
		t.Errorf("Audience = %v", claims.Audience)
	}
	if claims.ExpiresAt.Unix() != now+3600 {
		t.Errorf("ExpiresAt = %v", claims.ExpiresAt)
	}
	if claims.IssuedAt.Unix() != now {
		t.Errorf("IssuedAt = %v", claims.IssuedAt)
	}
	if claims.AuthTime.Unix() != now-5 {
		t.Errorf("AuthTime = %v", claims.AuthTime)
	}
}

func TestDecodeIDToken_AudienceArray(t *testing.T) {
	token := makeIDToken(t, map[string]any{
		"sub": "u",
		"aud": []any{"app-a", "app-b"},
	})
	claims, err := DecodeIDToken(token)
	if err != nil {
		t.Fatalf("DecodeIDToken: %v", err)
	}
	if len(claims.Audience) != 2 || claims.Audience[0] != "app-a" || claims.Audience[1] != "app-b" {
		t.Errorf("Audience = %v", claims.Audience)
	}
}

func TestDecodeIDToken_ProviderSpecificViaGet(t *testing.T) {
	token := makeIDToken(t, map[string]any{
		"sub":    "u",
		"groups": []any{"admins", "users"},
	})
	claims, err := DecodeIDToken(token)
	if err != nil {
		t.Fatalf("DecodeIDToken: %v", err)
	}
	v, ok := claims.Get("groups")
	if !ok {
		t.Fatal("groups claim not present")
	}
	groups, ok := v.([]any)
	if !ok || len(groups) != 2 {
		t.Errorf("groups = %v", v)
	}
	if _, ok := claims.Get("nonexistent"); ok {
		t.Error("Get returned ok for missing claim")
	}
}

func TestDecodeIDToken_MalformedSegments(t *testing.T) {
	if _, err := DecodeIDToken("not-a-jwt"); err == nil {
		t.Error("expected error for token without 3 segments")
	}
}

func TestDecodeIDToken_InvalidBase64(t *testing.T) {
	if _, err := DecodeIDToken("aaa.!!!invalid!!!.bbb"); err == nil {
		t.Error("expected error for invalid base64 payload")
	}
}

func TestDecodeIDToken_InvalidJSON(t *testing.T) {
	payload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	if _, err := DecodeIDToken("aaa." + payload + ".bbb"); err == nil {
		t.Error("expected error for non-JSON payload")
	}
}

func TestClient_Claims(t *testing.T) {
	handler := &testFlowHandler{redirectURI: "http://127.0.0.1:9999/callback"}
	client, err := New(Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}, handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	token := makeIDToken(t, map[string]any{
		"sub":   "user-42",
		"email": "user@example.com",
	})
	client.state = TokenState{IDToken: token}

	claims, err := client.Claims()
	if err != nil {
		t.Fatalf("Claims: %v", err)
	}
	if claims.Subject != "user-42" {
		t.Errorf("Subject = %q", claims.Subject)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q", claims.Email)
	}
}

func TestClient_Claims_NotAuthenticated(t *testing.T) {
	handler := &testFlowHandler{redirectURI: "http://127.0.0.1:9999/callback"}
	client, err := New(Config{
		IssuerURL: "https://idp.example.com",
		ClientID:  "my-app",
	}, handler)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := client.Claims(); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("Claims error = %v, want ErrNotAuthenticated", err)
	}
}
