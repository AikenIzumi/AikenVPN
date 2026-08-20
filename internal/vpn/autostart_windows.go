//go:build windows

package vpn

import (
	"os"

	"golang.org/x/sys/windows/registry"

	"github.com/jamalfa/jamvpn/internal/logger"
)

const autoStartKey = `Software\Microsoft\Windows\CurrentVersion\Run`
const autoStartValue = "AikenVPN"
const autoStartValueOld = "JamVPN" // pre-rename entry, cleaned up on every Set

// SetAutoStart enables or disables the Windows autostart registry entry.
// The command carries --autostart so the app can tell a login launch from a
// manual one (manual launches always show the window).
func SetAutoStart(enable bool) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, autoStartKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	_ = k.DeleteValue(autoStartValueOld) // drop the pre-rename entry if present

	if enable {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		if err := k.SetStringValue(autoStartValue, `"`+exe+`" --autostart`); err != nil {
			return err
		}
		logger.Info("autostart: enabled (%s)", exe)
	} else {
		_ = k.DeleteValue(autoStartValue) // ignore "not found" error
		logger.Info("autostart: disabled")
	}
	return nil
}

// GetAutoStart reports whether the autostart registry entry exists
// (either the current name or the pre-rename one).
func GetAutoStart() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, autoStartKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if _, _, err = k.GetStringValue(autoStartValue); err == nil {
		return true
	}
	_, _, err = k.GetStringValue(autoStartValueOld)
	return err == nil
}
