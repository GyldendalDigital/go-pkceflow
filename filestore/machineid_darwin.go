//go:build darwin

package filestore

import (
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

var uuidRegexp = regexp.MustCompile(`"IOPlatformUUID"\s*=\s*"([^"]+)"`)

// machineID executes ioreg and parses IOPlatformUUID on macOS.
func machineID() (string, error) {
	out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", fmt.Errorf("exec ioreg: %w", err)
	}

	matches := uuidRegexp.FindSubmatch(out)
	if len(matches) < 2 {
		return "", fmt.Errorf("IOPlatformUUID not found in ioreg output")
	}

	return strings.TrimSpace(string(matches[1])), nil
}
