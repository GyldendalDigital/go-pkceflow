package desktopflow

import (
	"fmt"
	"os/exec"
	"runtime"
)

// DefaultBrowserOpener opens a URL in the user's default browser.
// Uses platform-specific commands: xdg-open (Linux), open (macOS), cmd /c start (Windows).
func DefaultBrowserOpener(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("xdg-open", url) //nolint:gosec,noctx // G204: caller-provided URL; fire-and-forget process doesn't need context
	case "darwin":
		cmd = exec.Command("open", url) //nolint:gosec,noctx // G204: caller-provided URL; fire-and-forget process doesn't need context
	case "windows":
		cmd = exec.Command("cmd", "/c", "start", "", url) //nolint:gosec,noctx // G204: caller-provided URL; fire-and-forget process doesn't need context
	default:
		return fmt.Errorf("desktopflow: unsupported platform %q for browser opening", runtime.GOOS)
	}

	return cmd.Start()
}
