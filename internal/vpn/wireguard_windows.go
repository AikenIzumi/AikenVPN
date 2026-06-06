//go:build windows

package vpn

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/parser"
)

// connectWireGuard writes the WireGuard config to a temp file and
// installs the tunnel via wireguard.exe.
func connectWireGuard(p config.Profile) error {
	if p.WireGuard == nil {
		return fmt.Errorf("WireGuard config is empty")
	}

	// Generate .conf file content
	conf, err := parser.ToWireGuardConf(p)
	if err != nil {
		return fmt.Errorf("build WireGuard config: %w", err)
	}

	// Write to %TEMP%\jamvpn-<name>.conf
	tmpDir := os.TempDir()
	safeName := sanitizeTunnelName(p.Name)
	confPath := filepath.Join(tmpDir, "jamvpn-"+safeName+".conf")

	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return fmt.Errorf("write WireGuard conf: %w", err)
	}

	// Try wireguard.exe (must be in PATH or Program Files)
	wireguardExe, err := findWireGuardExe()
	if err != nil {
		// Fallback: use netsh (limited WireGuard support)
		return connectWireGuardNetsh(p)
	}

	// Uninstall any existing tunnel with the same name first
	_ = wgCmd(wireguardExe, "/uninstalltunnel", safeName).Run()

	// Install tunnel (this also connects it)
	out, err := wgCmd(wireguardExe, "/installtunnel", confPath).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wireguard install tunnel: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// disconnectWireGuard uninstalls the WireGuard tunnel
func disconnectWireGuard(p config.Profile) error {
	wireguardExe, err := findWireGuardExe()
	if err != nil {
		return nil // already gone
	}
	safeName := sanitizeTunnelName(p.Name)
	out, err := wgCmd(wireguardExe, "/uninstalltunnel", safeName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("wireguard uninstall: %w\n%s", err, strings.TrimSpace(string(out)))
	}

	// Clean up temp conf
	tmpDir := os.TempDir()
	confPath := filepath.Join(tmpDir, "jamvpn-"+safeName+".conf")
	_ = os.Remove(confPath)

	return nil
}

// connectWireGuardNetsh is a fallback using netsh for systems without wireguard.exe
func connectWireGuardNetsh(p config.Profile) error {
	return fmt.Errorf("WireGuard not installed. Download from https://www.wireguard.com/install/")
}

func findWireGuardExe() (string, error) {
	// Check PATH first
	if path, err := exec.LookPath("wireguard.exe"); err == nil {
		return path, nil
	}
	// Common install locations
	candidates := []string{
		`C:\Program Files\WireGuard\wireguard.exe`,
		`C:\Program Files (x86)\WireGuard\wireguard.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("wireguard.exe not found")
}

func sanitizeTunnelName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	s := sb.String()
	if s == "" {
		return "jamvpn"
	}
	return s
}

func wgCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd
}

// Ensure config package is used (avoid import cycle by having type reference here)
var _ config.Profile
