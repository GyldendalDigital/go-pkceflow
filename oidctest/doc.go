// Package oidctest provides test infrastructure for OIDC client testing.
//
// FakeIDPServer is a controllable OIDC test double built on httptest.Server. It
// supports PKCE-shaped public-client flows, token refresh with rotation, error
// simulation, and configurable token lifetimes.
//
// Refresh tokens follow a provider-like lifecycle. By default they rotate on
// every refresh and expire WithRefreshTTL after sign-in, and a rotated token
// keeps that absolute session end. WithSlidingRefreshExpiry turns the lifetime
// into an idle timeout. WithoutRefreshRotation (or SetRefreshRotation) models a
// provider that keeps one refresh token, and WithRefreshReuseDetection one that
// revokes the whole token family when a rotated-out token is presented again.
// GrantErrors.SetWithDescription refuses one grant type with a chosen error and
// error_description. LoseNextRefreshResponse processes a refresh in full, so the
// token really rotates, and then loses the response by hanging, resetting the
// connection, or answering 502, so the client never learns its new refresh
// token. Use WithClock to step through lifetimes.
//
// It is designed to be reusable by Go projects testing OIDC flows and has zero
// go-pkceflow imports. It is not an OIDC conformance suite; tests that depend on
// strict provider rejection should enable or add the corresponding assertion.
//
// Test doubles (MemoryStore, RecordingEmitter, FakeFlowHandler) implement
// go-pkceflow interfaces for use in unit and integration tests.
package oidctest
