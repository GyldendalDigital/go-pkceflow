//go:build linux

package filestore

import (
	"os"
	"strings"
)

// machineID reads /etc/machine-id on Linux.
func machineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}
