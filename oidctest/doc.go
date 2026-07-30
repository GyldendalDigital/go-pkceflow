// Package oidctest provides test infrastructure for OIDC client testing.
//
// FakeIDPServer is a controllable OIDC test double built on httptest.Server. It
// supports PKCE-shaped public-client flows, token refresh with rotation, error
// simulation, and configurable token lifetimes.
//
// It is designed to be reusable by Go projects testing OIDC flows and has zero
// go-pkceflow imports. It is not an OIDC conformance suite; tests that depend on
// strict provider rejection should enable or add the corresponding assertion.
//
// Test doubles (MemoryStore, RecordingEmitter, FakeFlowHandler) implement
// go-pkceflow interfaces for use in unit and integration tests.
package oidctest
