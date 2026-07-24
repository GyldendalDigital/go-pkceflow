//go:build windows

package filestore

import (
	"fmt"
	"syscall"
	"unsafe"
)

// machineID reads MachineGuid from the Windows registry.
func machineID() (string, error) {
	const subKey = `SOFTWARE\Microsoft\Cryptography`
	const valueName = `MachineGuid`

	var hKey syscall.Handle
	keyPath, err := syscall.UTF16PtrFromString(subKey)
	if err != nil {
		return "", fmt.Errorf("utf16 key path: %w", err)
	}

	err = syscall.RegOpenKeyEx(
		syscall.HKEY_LOCAL_MACHINE,
		keyPath,
		0,
		syscall.KEY_READ|syscall.KEY_WOW64_64KEY,
		&hKey,
	)
	if err != nil {
		return "", fmt.Errorf("open registry key: %w", err)
	}
	defer syscall.RegCloseKey(hKey) //nolint:errcheck

	var bufLen uint32 = 128
	buf := make([]uint16, bufLen)

	valName, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return "", fmt.Errorf("utf16 value name: %w", err)
	}

	err = syscall.RegQueryValueEx(
		hKey,
		valName,
		nil,
		nil,
		(*byte)(unsafe.Pointer(&buf[0])),
		&bufLen,
	)
	if err != nil {
		return "", fmt.Errorf("query registry value: %w", err)
	}

	return syscall.UTF16ToString(buf), nil
}
