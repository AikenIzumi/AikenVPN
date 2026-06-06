package vpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jamalfa/jamvpn/internal/config"
)

var openvpnCmd *exec.Cmd
var openvpnCancel context.CancelFunc

// connectOpenVPN writes .ovpn config + credentials to temp files and starts openvpn.exe
func connectOpenVPN(p config.Profile, m *Manager) error {
	if p.OpenVPN == nil || p.OpenVPN.ConfigContent == "" {
		return fmt.Errorf("OpenVPN config is empty")
	}

	ovpnExe, err := findOpenVPNExe()
	if err != nil {
		return err
	}

	tmpDir := os.TempDir()
	safeName := sanitizeName(p.Name)

	// Write .ovpn file
	ovpnPath := filepath.Join(tmpDir, "jamvpn-"+safeName+".ovpn")
	if err := os.WriteFile(ovpnPath, []byte(p.OpenVPN.ConfigContent), 0600); err != nil {
		return fmt.Errorf("write ovpn config: %w", err)
	}

	args := []string{"--config", ovpnPath, "--verb", "3"}

	// Write credentials file if username is set
	if p.OpenVPN.Username != "" || p.Username != "" {
		username := p.OpenVPN.Username
		password := p.OpenVPN.Password
		if username == "" {
			username = p.Username
			password = p.Password
		}
		credPath := filepath.Join(tmpDir, "jamvpn-"+safeName+".creds")
		creds := username + "\n" + password + "\n"
		if err := os.WriteFile(credPath, []byte(creds), 0600); err != nil {
			return fmt.Errorf("write credentials: %w", err)
		}
		args = append(args, "--auth-user-pass", credPath)
	}

	ctx, cancel := context.WithCancel(context.Background())

	cmd := exec.CommandContext(ctx, ovpnExe, args...)
	hideWindow(cmd) // suppress console window on Windows
	if err := cmd.Start(); err != nil {
		cancel()
		return fmt.Errorf("start openvpn: %w", err)
	}
	openvpnCmd = cmd
	openvpnCancel = cancel

	// Store cancel function so Manager can stop it
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

func findOpenVPNExe() (string, error) {
	if path, err := exec.LookPath("openvpn.exe"); err == nil {
		return path, nil
	}
	candidates := []string{
		`C:\Program Files\OpenVPN\bin\openvpn.exe`,
		`C:\Program Files (x86)\OpenVPN\bin\openvpn.exe`,
		`C:\Program Files\OpenVPN Connect\openssl.exe`,
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c, nil
		}
	}
	return "", fmt.Errorf("openvpn.exe not found. Install OpenVPN from https://openvpn.net/")
}

func sanitizeName(name string) string {
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
		return "ovpn"
	}
	return s
}

// Ensure config package is referenced
var _ = config.TunnelOpenVPN
