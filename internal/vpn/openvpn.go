package vpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jamalfa/jamvpn/internal/config"
)

var openvpnCmd *exec.Cmd
var openvpnCancel context.CancelFunc

// connectOpenVPN writes .ovpn config + credentials to temp files and starts openvpn.exe.
// The openvpn binary is extracted from the embedded assets on first use.
func connectOpenVPN(p config.Profile, m *Manager) error {
	if p.OpenVPN == nil || p.OpenVPN.ConfigContent == "" {
		return fmt.Errorf("OpenVPN config is empty")
	}

	// Use embedded openvpn.exe (extracted from assets/openvpn/ at runtime).
	ovpnExe, err := ensureOpenVPN()
	if err != nil {
		// Fall back to system-installed openvpn if assets not embedded yet.
		ovpnExe, err = findOpenVPNExe()
		if err != nil {
			return err
		}
	}

	tmpDir := os.TempDir()
	safeName := sanitizeName(p.Name)

	ovpnPath := filepath.Join(tmpDir, "jamvpn-"+safeName+".ovpn")
	if err := os.WriteFile(ovpnPath, []byte(p.OpenVPN.ConfigContent), 0600); err != nil {
		return fmt.Errorf("write ovpn config: %w", err)
	}

	args := []string{"--config", ovpnPath, "--verb", "3"}

	if p.OpenVPN.Username != "" || p.Username != "" {
		username := p.OpenVPN.Username
		password := p.OpenVPN.Password
		if username == "" {
			username = p.Username
			password = p.Password
		}
		credPath := filepath.Join(tmpDir, "jamvpn-"+safeName+".creds")
		if err := os.WriteFile(credPath, []byte(username+"\n"+password+"\n"), 0600); err != nil {
			return fmt.Errorf("write credentials: %w", err)
		}
		args = append(args, "--auth-user-pass", credPath)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, ovpnExe, args...)
	hideWindow(cmd)

	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start openvpn: %w", err)
	}
	openvpnCmd = cmd
	openvpnCancel = cancel

	m.SetCancelFn(func() {
		cancel()
		_ = disconnectOpenVPN()
	})
	return nil
}

func disconnectOpenVPN() error {
	if openvpnCancel != nil {
		openvpnCancel()
		openvpnCancel = nil
	}
	if openvpnCmd != nil && openvpnCmd.Process != nil {
		_ = openvpnCmd.Process.Kill()
		openvpnCmd = nil
	}
	return nil
}

// findOpenVPNExe searches for a system-installed openvpn.exe (fallback).
func findOpenVPNExe() (string, error) {
	if path, err := exec.LookPath("openvpn.exe"); err == nil {
		return path, nil
	}
	candidates := []string{
		`C:\Program Files\OpenVPN\bin\openvpn.exe`,
		`C:\Program Files (x86)\OpenVPN\bin\openvpn.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("openvpn.exe не найден. Скачайте OpenVPN с https://openvpn.net/")
}

var _ = config.TunnelOpenVPN
