// Package filestore provides AES-256-GCM encrypted file-based token persistence.
//
// This is the included file-based TokenPersistence implementation for
// go-pkceflow. Clients use in-memory persistence unless a store is injected.
// Store encrypts tokens at rest using a key derived from the app ID and machine
// ID, with a fallback to a persisted random key when machine ID is unavailable.
//
// Usage:
//
//	// Desktop: resolve the per-user config dir automatically.
//	store, err := filestore.NewDefault("com.example.my-app")
//
//	// Or pass an explicit directory (required on mobile: use the app sandbox).
//	store, err := filestore.New("com.example.my-app", sandboxDir)
//
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
// tokens. This implementation deliberately favours a dependency-free, CGo-free,
// cross-platform implementation over an OS credential manager.
//
// The encryption primarily protects tokens against disk or backup exposure and
// access by other user accounts. It is not a strong defence against an attacker
// already running as the same OS user: the Linux machine ID is world-readable
// and the fallback key file sits beside the token file under the same 0600
// permissions, so a same-user attacker can derive or read the key. Threat
// models that include same-user compromise should use a hardware-backed or OS
// keyring implementation (see below).
//
// Consumers with stricter requirements (regulatory constraints, hardware-backed
// key storage, an OS keyring or Keychain, or a secure enclave) can implement the
// pkceflow.TokenPersistence interface themselves and inject it with
// pkceflow.WithTokenPersistence. No other code changes are needed.
package filestore
