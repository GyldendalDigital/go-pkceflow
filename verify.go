package pkceflow

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// errAzpMismatch reports an ID token whose authorized-party claim does not name
// this client. Deliberately unexported: IsPermanentError already answers the
// actionable question on the refresh path, and the pre-1.0 API should not grow a
// sentinel that the RC boundary would then freeze.
var errAzpMismatch = errors.New("pkceflow: ID token azp claim does not authorize this client")

// verifyIDToken verifies raw and then enforces the authorized-party rules of
// OIDC Core 3.1.3.7 steps 4 and 5, which go-oidc does not implement: its
// verifier only checks that the client ID appears in aud, and says so explicitly
// in its own documentation.
//
// The verifier is a parameter rather than a read of c.verifier because both call
// sites capture it when their operation starts, so a concurrent Init cannot swap
// the verifier midway through a login or refresh.
//
// Rules: azp absent is accepted for a single-audience token and rejected for a
// multi-audience one, where the spec requires it; azp present must be a string
// equal to the configured client ID.
func (c *Client) verifyIDToken(
	ctx context.Context,
	verifier *oidc.IDTokenVerifier,
	raw string,
) (*oidc.IDToken, error) {
	idToken, err := verifier.Verify(ctx, raw)
	if err != nil {
		return nil, err
	}

	// Read the claim set go-oidc already verified rather than decoding the raw
	// token a second time. A map, not a typed struct: a struct field cannot
	// distinguish an absent azp from one that is present but not a string,
	// because encoding/json fails the whole payload on a type mismatch.
	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("pkceflow: reading ID token claims: %w", err)
	}

	if err := c.checkAuthorizedParty(claims, idToken.Audience); err != nil {
		return nil, err
	}
	return idToken, nil
}

// checkAuthorizedParty applies the authorized-party rules to an already-verified
// claim set. Split out from verifyIDToken so the rules can be exercised without
// a signed token.
func (c *Client) checkAuthorizedParty(claims map[string]any, audience []string) error {
	value, present := claims["azp"]
	if !present {
		if len(audience) > 1 {
			c.logger.Warn(
				"ID token has multiple audiences but no azp claim",
				"audiences", len(audience),
			)
			return fmt.Errorf("%w: multiple audiences require azp", errAzpMismatch)
		}
		return nil
	}

	azp, ok := value.(string)
	if !ok {
		c.logger.Warn("ID token azp claim is not a string")
		return fmt.Errorf("%w: azp is not a string", errAzpMismatch)
	}
	if azp != c.config.ClientID {
		// Neither value is a secret; the client ID already appears in
		// Config.RedactedString. Logging both is what makes a provider
		// misconfiguration diagnosable in the field, where the error itself may
		// be flattened into a generic failure by the consuming application.
		c.logger.Warn(
			"ID token azp claim names a different client",
			"configured_client_id", c.config.ClientID,
			"received_azp", azp,
		)
		return fmt.Errorf("%w: azp names another client", errAzpMismatch)
	}
	return nil
}
