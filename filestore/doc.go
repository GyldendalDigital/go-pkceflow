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
package filestore
