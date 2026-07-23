// Package oidctest provides test infrastructure for OIDC client testing.
//
// FakeIDPServer is a standards-compliant fake OIDC provider built on httptest.Server.
// It supports public clients (PKCE, no client secret), confidential clients,
// token refresh with rotation, error simulation, and configurable token lifetimes.
//
// Designed to be reusable by any Go project testing OIDC flows, not just go-pkceflow.
// The server speaks standard OIDC protocol and has zero go-pkceflow imports.
//
// Test doubles (MemoryStore, RecordingEmitter, FakeFlowHandler) implement
// go-pkceflow interfaces for use in unit and integration tests.
package oidctest
