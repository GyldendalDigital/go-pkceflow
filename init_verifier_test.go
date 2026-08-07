package pkceflow

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

type initTestJSONWebKey struct {
	KeyType   string `json:"kty"`
	KeyID     string `json:"kid"`
	Use       string `json:"use"`
	Algorithm string `json:"alg"`
	Modulus   string `json:"n"`
	Exponent  string `json:"e"`
}

func TestInitCommittedVerifierUsesLatestJWKSAndSigningPolicy(t *testing.T) {
	client, transport := newInitTestClient(t, nil, nil)
	if err := runScriptedInit(
		t,
		client,
		transport,
		initDiscoveryBodyWithAlgorithms(t, initTestIssuer, "old", true, []string{"PS256"}),
	); err != nil {
		t.Fatalf("old Init: %v", err)
	}
	if err := runScriptedInit(
		t,
		client,
		transport,
		initDiscoveryBodyWithAlgorithms(t, initTestIssuer, "new", true, []string{"RS256"}),
	); err != nil {
		t.Fatalf("new Init: %v", err)
	}
	committed := captureInitSnapshot(client)

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	rawIDToken := signInitTestIDToken(t, privateKey, "new-key", "RS256")
	type verificationResult struct {
		subject string
		err     error
	}
	result := make(chan verificationResult, 1)
	verifyCtx, cancelVerify := context.WithCancel(context.Background())
	defer cancelVerify()
	go func() {
		idToken, verifyErr := committed.verifier.Verify(verifyCtx, rawIDToken)
		var subject string
		if idToken != nil {
			subject = idToken.Subject
		}
		result <- verificationResult{subject: subject, err: verifyErr}
	}()

	jwksCall := nextInitCall(t, transport)
	if got, want := jwksCall.request.URL.String(), initTestIssuer+"/jwks/new"; got != want {
		jwksCall.fail(context.Canceled)
		t.Fatalf("JWKS request URL = %q, want %q", got, want)
	}
	jwksCall.respond(initTestJWKS(t, &privateKey.PublicKey, "new-key"))

	select {
	case verified := <-result:
		if verified.err != nil {
			t.Fatalf("verify ID token: %v", verified.err)
		}
		if verified.subject != "test-user" {
			t.Fatalf("verified subject = %q, want %q", verified.subject, "test-user")
		}
	case <-time.After(2 * time.Second):
		cancelVerify()
		t.Fatal("ID token verification did not return")
	}

	pssIDToken := signInitTestIDToken(t, privateKey, "new-key", "PS256")
	if _, err := committed.verifier.Verify(context.Background(), pssIDToken); err == nil {
		t.Fatal("latest verifier accepted PS256 outside the advertised RS256 policy")
	}
	assertNoInitCall(t, transport)
}

func signInitTestIDToken(
	t *testing.T,
	privateKey *rsa.PrivateKey,
	keyID string,
	algorithm string,
) string {
	t.Helper()
	header := marshalInitTestJSON(t, struct {
		Algorithm string `json:"alg"`
		KeyID     string `json:"kid"`
		Type      string `json:"typ"`
	}{Algorithm: algorithm, KeyID: keyID, Type: "JWT"})
	claims := marshalInitTestJSON(t, struct {
		Issuer    string `json:"iss"`
		Subject   string `json:"sub"`
		Audience  string `json:"aud"`
		ExpiresAt int64  `json:"exp"`
		IssuedAt  int64  `json:"iat"`
	}{
		Issuer:    initTestIssuer,
		Subject:   "test-user",
		Audience:  "test-client",
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
		IssuedAt:  time.Now().Add(-time.Minute).Unix(),
	})
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedClaims := base64.RawURLEncoding.EncodeToString(claims)
	signingInput := encodedHeader + "." + encodedClaims
	digest := sha256.Sum256([]byte(signingInput))
	var signature []byte
	var err error
	switch algorithm {
	case "RS256":
		signature, err = rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	case "PS256":
		signature, err = rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:], nil)
	default:
		t.Fatalf("unsupported test signing algorithm %q", algorithm)
	}
	if err != nil {
		t.Fatalf("sign ID token: %v", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func initTestJWKS(t *testing.T, publicKey *rsa.PublicKey, keyID string) []byte {
	t.Helper()
	return marshalInitTestJSON(t, struct {
		Keys []initTestJSONWebKey `json:"keys"`
	}{Keys: []initTestJSONWebKey{{
		KeyType:   "RSA",
		KeyID:     keyID,
		Use:       "sig",
		Algorithm: "RS256",
		Modulus:   base64.RawURLEncoding.EncodeToString(publicKey.N.Bytes()),
		Exponent:  base64.RawURLEncoding.EncodeToString(big.NewInt(int64(publicKey.E)).Bytes()),
	}}})
}

func marshalInitTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal test JSON: %v", err)
	}
	return encoded
}
