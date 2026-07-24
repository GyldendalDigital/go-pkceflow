// Package filestore provides AES-256-GCM encrypted file-based token persistence.
//
// This is the default TokenPersistence implementation for go-pkceflow.
// It encrypts tokens at rest using a key derived from the app ID and machine ID,
// with a fallback to a persisted random key when machine ID is unavailable.
//
// Usage:
//
//	store, err := filestore.New("my-app", "/home/user/.config/my-app")
//	client, _ := pkceflow.New(cfg, handler, pkceflow.WithTokenPersistence(store))
//
// # Security
//
// Files are created with 0600 permissions, directories with 0700.
// The encryption key is derived from SHA-256(appID + ":" + machineID).
// If the machine ID changes or the key file is lost, existing tokens become
// unreadable and the user must log in again (zero TokenState returned, not error).
//
// AES-256-GCM at rest, together with per-user file permissions on desktop and
// the application sandbox on mobile, is sufficient for storing typical OIDC
// tokens. This default deliberately favours a dependency-free, CGo-free,
// cross-platform implementation over an OS credential manager.
//
// Consumers with stricter requirements (regulatory constraints, hardware-backed
// key storage, an OS keyring or Keychain, or a secure enclave) can implement the
// pkceflow.TokenPersistence interface themselves and inject it with
// pkceflow.WithTokenPersistence. No other code changes are needed.
package filestore
