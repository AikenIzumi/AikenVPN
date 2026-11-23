//go:build !windows

package vpn

import (
	"context"

	"github.com/jamalfa/jamvpn/internal/config"
)

func ApplySplitTunnel(ctx context.Context, p config.Profile, s config.AppSettings) {}
func RemoveSplitTunnel(p config.Profile)                                           {}
func GetRunningProcesses() []string                                                { return nil }
