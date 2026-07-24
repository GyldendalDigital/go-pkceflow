// Command cli is an interactive example application demonstrating go-pkceflow.
// It provides a simple text menu for login, logout, token inspection, and
// status checking against any OIDC provider.
//
// Usage:
//
//	go run ./examples/cli --issuer=https://your-idp.com --client-id=your-client-id
//
// See the go-pkceflow README for full documentation.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/GyldendalDigital/go-pkceflow"
	"github.com/GyldendalDigital/go-pkceflow/desktopflow"
	"github.com/GyldendalDigital/go-pkceflow/filestore"
)

func main() {
	issuer := flag.String("issuer", "", "OIDC issuer URL (required)")
	clientID := flag.String("client-id", "", "OAuth2 client ID (required)")
	port := flag.Int("port", 15051, "Localhost callback port (must be registered with IdP)")
	callbackPath := flag.String("callback-path", "/callback", "Callback path on the localhost server")
	redirectURI := flag.String("redirect-uri", "", "Full redirect URI (overrides --port and --callback-path)")
	scopes := flag.String("scopes", "", "Comma-separated scopes (default: openid,profile,email,offline_access)")
	graceDays := flag.Int("grace-days", 0, "Offline grace period in days (0 = disabled)")
	dataDir := flag.String("data-dir", "", "Token storage directory (default: ~/.config/pkceflow-example)")

	flag.Parse()

	if *issuer == "" || *clientID == "" {
		fmt.Fprintln(os.Stderr, "Error: --issuer and --client-id are required")
		fmt.Fprintln(os.Stderr)
		flag.Usage()
		os.Exit(1)
	}

	if *redirectURI != "" && (*callbackPath != "/callback" || isFlagSet("port")) {
		fmt.Fprintln(os.Stderr, "Error: --redirect-uri cannot be combined with --port or --callback-path")
		os.Exit(1)
	}

	// Set up token storage directory
	dir := *dataDir
	if dir == "" {
		home, _ := os.UserHomeDir()
		dir = home + "/.config/pkceflow-example"
	}

	// Create components
	store, err := filestore.New("pkceflow-example", dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating token store: %v\n", err)
		os.Exit(1)
	}

	// Create flow handler
	var handler *desktopflow.Handler
	if *redirectURI != "" {
		handler, err = desktopflow.NewWithURI(*redirectURI)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid redirect URI: %v\n", err)
			os.Exit(1)
		}
	} else {
		uri := fmt.Sprintf("http://127.0.0.1:%d%s", *port, *callbackPath)
		handler, err = desktopflow.NewWithURI(uri)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid callback configuration: %v\n", err)
			os.Exit(1)
		}
	}

	// Build config
	cfg := pkceflow.Config{
		IssuerURL: *issuer,
		ClientID:  *clientID,
	}
	if *scopes != "" {
		cfg.Scopes = strings.Split(*scopes, ",")
	}
	if *graceDays > 0 {
		cfg.GracePeriod = time.Duration(*graceDays) * 24 * time.Hour
	}

	// Create client
	client, err := pkceflow.New(cfg, handler, pkceflow.WithTokenPersistence(store))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating client: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()

	// Restore previous session
	if client.RestoreSession() {
		fmt.Println("Restored previous session.")
	}

	// Initialize OIDC discovery
	fmt.Printf("Redirect URI: %s (register this with your IdP)\n", handler.RedirectURI())
	fmt.Printf("Discovering OIDC configuration from %s...\n", *issuer)
	if err := client.Init(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: OIDC discovery failed: %v\n", err)
		fmt.Println("Continuing in offline mode (cached tokens may still work).")
	} else {
		fmt.Println("OIDC discovery successful.")
	}

	// Start refresh loop
	client.StartRefreshLoop(ctx)
	defer client.StopRefreshLoop()

	fmt.Println()
	printStatus(client, store)
	fmt.Println()

	// Interactive loop
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Println("  [l] Login")
		fmt.Println("  [s] Show status")
		fmt.Println("  [t] Show access token")
		fmt.Println("  [r] Refresh token (manual)")
		fmt.Println("  [o] Logout")
		fmt.Println("  [q] Quit")
		fmt.Print("\n> ")

		if !scanner.Scan() {
			break
		}

		input := strings.TrimSpace(scanner.Text())
		fmt.Println()

		switch strings.ToLower(input) {
		case "l":
			fmt.Println("Opening browser for login...")
			if err := client.Login(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
			} else {
				fmt.Println("Login successful!")
			}

		case "s":
			printStatus(client, store)

		case "t":
			printTokenInfo(client, store, ctx)

		case "r":
			fmt.Println("Attempting manual token refresh...")
			// AccessToken triggers refresh if needed
			token := client.AccessToken(ctx)
			if token != "" {
				fmt.Println("Token refreshed successfully.")
			} else {
				fmt.Println("Refresh failed or no session.")
			}

		case "o":
			fmt.Println("Logging out...")
			if err := client.Logout(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "Logout error: %v\n", err)
			} else {
				fmt.Println("Logged out.")
			}

		case "q":
			fmt.Println("Bye!")
			return

		default:
			fmt.Println("Unknown command.")
		}
		fmt.Println()
	}

	if err := scanner.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "Input error: %v\n", err)
	}
}

func printStatus(client *pkceflow.Client, store pkceflow.TokenPersistence) {
	status := client.AuthStatus()

	fmt.Println("--- Auth Status ---")
	switch {
	case status.Valid:
		fmt.Println("  State:  Authenticated")
	case status.GraceMode:
		fmt.Printf("  State:  Grace mode (%d days remaining)\n", status.GraceDaysLeft)
	default:
		fmt.Println("  State:  Not authenticated")
	}
	fmt.Printf("  CanUseApp: %v\n", status.CanUseApp)

	// Show token timestamps if we have a session
	state, _ := store.Load()
	if !state.IsZero() {
		fmt.Printf("  Expires:    %s\n", state.ExpiresAt.Format("15:04:05"))
		fmt.Printf("  Last auth:  %s\n", state.LastAuthAt.Format("2006-01-02 15:04:05"))
		remaining := time.Until(state.ExpiresAt)
		if remaining > 0 {
			fmt.Printf("  TTL:        %s\n", remaining.Truncate(time.Second))
		} else {
			fmt.Printf("  TTL:        expired %s ago\n", (-remaining).Truncate(time.Second))
		}
	}
	fmt.Println("-------------------")
}

func printTokenInfo(client *pkceflow.Client, store pkceflow.TokenPersistence, ctx context.Context) {
	token := client.AccessToken(ctx)
	if token == "" {
		fmt.Println("No valid access token available.")
		return
	}

	// Show access token summary
	if len(token) > 20 {
		fmt.Printf("Access token: %s...%s (%d chars)\n", token[:8], token[len(token)-8:], len(token))
	} else {
		fmt.Printf("Access token: %s (%d chars)\n", token, len(token))
	}

	// Decode ID token claims (already verified at login, just reading payload)
	state, _ := store.Load()
	if state.IDToken != "" {
		claims := decodeJWTPayload(state.IDToken)
		if claims != nil {
			fmt.Println("\n--- ID Token Claims ---")
			for k, v := range claims {
				// Skip raw token values and internal claims
				switch k {
				case "at_hash", "c_hash", "nonce", "sid":
					continue
				}
				fmt.Printf("  %s: %v\n", k, v)
			}
			fmt.Println("-----------------------")
		}
	}
}

// decodeJWTPayload decodes the payload segment of a JWT without verification.
// Returns nil if the token is not a valid JWT format.
func decodeJWTPayload(token string) map[string]any {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return nil
	}

	// Base64url decode the payload (middle segment)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}

	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}

	// Convert numeric timestamps to readable format
	for _, key := range []string{"exp", "iat", "auth_time"} {
		if v, ok := claims[key].(float64); ok {
			t := time.Unix(int64(v), 0)
			claims[key] = t.Format("2006-01-02 15:04:05")
		}
	}

	return claims
}

// isFlagSet reports whether a flag was explicitly set on the command line.
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
