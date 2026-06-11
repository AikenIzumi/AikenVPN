//go:build windows

package vpn

import (
	"os"

	"golang.org/x/sys/windows/registry"

	"github.com/jamalfa/jamvpn/internal/logger"
)

const autoStartKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const autoStartValue = "JamVPN"

// SetAutoStart enables or disables the Windows autostart registry entry.
func SetAutoStart(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, autoStartKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if enable {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := k.SetStringValue(autoStartValue, `"`+exe+`"`); err != nil {
			return err
		}
		logger.Info("autostart: enabled (%s)", exe)
	} else {
		_ = k.DeleteValue(autoStartValue) // ignore "not found" error
		logger.Info("autostart: disabled")
	}
	return nil
}

// GetAutoStart reports whether the autostart registry entry exists.
func GetAutoStart() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, autoStartKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(autoStartValue)
	return err == nil
}
