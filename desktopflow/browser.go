package desktopflow

import (
	"fmt"
	"os/exec"
	"runtime"
)

// DefaultBrowserOpener opens a URL in the user's default browser.
// Uses platform-specific commands: xdg-open (Linux), open (macOS),
// rundll32 url.dll,FileProtocolHandler (Windows).
func DefaultBrowserOpener(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url) //nolint:gosec,noctx // G204: caller-provided URL; fire-and-forget process doesn't need context
	case "darwin":
		cmd = exec.Command("open", url) //nolint:gosec,noctx // G204: caller-provided URL; fire-and-forget process doesn't need context
	case "windows":
		// rundll32 hands the URL directly to the shell URL handler, avoiding
		// cmd.exe, which would otherwise interpret the "&" separators in an
		// OAuth authorization URL as command separators.
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url) //nolint:gosec,noctx // G204: caller-provided URL; fire-and-forget process doesn't need context
	default:
		return fmt.Errorf("desktopflow: unsupported platform %q for browser opening", runtime.GOOS)
	}

	return cmd.Start()
}
