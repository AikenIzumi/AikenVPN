package vpn

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
)

// connectOpenVPN writes .ovpn config + credentials to temp files and starts openvpn.exe.
// The openvpn binary is extracted from the embedded assets on first use.
func connectOpenVPN(ctx context.Context, p config.Profile, stopped chan<- struct{}) (<-chan error, error) {
	started := false
	defer func() {
		if !started {
			close(stopped)
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p.OpenVPN == nil || p.OpenVPN.ConfigContent == "" {
		return nil, fmt.Errorf("OpenVPN config is empty")
	}

	// Use embedded openvpn.exe (extracted from assets/openvpn/ at runtime).
	ovpnExe, err := ensureOpenVPN()
	if err != nil {
		// Fall back to system-installed openvpn if assets not embedded yet.
		ovpnExe, err = findOpenVPNExe()
		if err != nil {
			return nil, err
		}
	}

	tmpDir, err := os.MkdirTemp("", "aikenvpn-openvpn-")
	if err != nil {
		return nil, fmt.Errorf("create OpenVPN temporary directory: %w", err)
	}
	cleanup := func() {
		if err := os.RemoveAll(tmpDir); err != nil {
			logger.Error("remove OpenVPN temporary files: %v", err)
		}
	}
	defer func() {
		if !started {
			cleanup()
		}
	}()

	ovpnPath := filepath.Join(tmpDir, "profile.ovpn")
	if err := os.WriteFile(ovpnPath, []byte(p.OpenVPN.ConfigContent), 0600); err != nil {
		return nil, fmt.Errorf("write ovpn config: %w", err)
	}

	args := []string{"--config", ovpnPath, "--verb", "3"}

	if p.OpenVPN.Username != "" || p.Username != "" {
		username := p.OpenVPN.Username
		password := p.OpenVPN.Password
		if username == "" {
			username = p.Username
			password = p.Password
		}
		credPath := filepath.Join(tmpDir, "credentials")
		if err := os.WriteFile(credPath, []byte(username+"\n"+password+"\n"), 0600); err != nil {
			return nil, fmt.Errorf("write credentials: %w", err)
		}
		args = append(args, "--auth-user-pass", credPath)
	}

	cmd := exec.CommandContext(ctx, ovpnExe, args...)
	hideWindow(cmd)

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start openvpn: %w", err)
	}
	started = true
	done := make(chan error, 1)
	go func() {
		err := cmd.Wait()
		cleanup()
		close(stopped)
		done <- err
	}()
	return done, nil
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
