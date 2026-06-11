//go:build !windows

package vpn

import "github.com/jamalfa/jamvpn/internal/config"

func ApplySplitTunnel(p config.Profile, s config.AppSettings) {}
func RemoveSplitTunnel(p config.Profile)                      {}
func GetRunningProcesses() []string                           { return nil }
