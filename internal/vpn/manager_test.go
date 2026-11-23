package vpn

import (
	"testing"

	"github.com/jamalfa/jamvpn/internal/config"
)

func TestStartupConnectYieldsToExplicitCommand(t *testing.T) {
	startupProfile := config.Profile{ID: "startup", TunnelType: "unsupported-for-test"}
	manualProfile := config.Profile{ID: "manual", TunnelType: "unsupported-for-test"}

	t.Run("connect", func(t *testing.T) {
		manager := NewManager()
		if err := manager.Connect(manualProfile); err != nil {
			t.Fatal(err)
		}
		if manager.ConnectOnStartup(startupProfile) {
			t.Fatal("startup connection replaced a manual connection attempt")
		}
		if status := manager.Status(); status.ProfileID != manualProfile.ID {
			t.Fatalf("unexpected active profile: %q", status.ProfileID)
		}
	})

	t.Run("disconnect while idle", func(t *testing.T) {
		manager := NewManager()
		if err := manager.Disconnect(); err != nil {
			t.Fatal(err)
		}
		if manager.ConnectOnStartup(startupProfile) {
			t.Fatal("startup connected after an explicit disconnect")
		}
	})
}
