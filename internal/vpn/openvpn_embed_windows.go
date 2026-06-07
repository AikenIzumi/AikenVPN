//go:build with_openvpn

package vpn

// Build with: -tags with_openvpn
// Place the following files in assets/openvpn/ before building:
//   openvpn.exe, libssl-3-x64.dll, libcrypto-3-x64.dll, liblzo2-2.dll

import (
	"embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

//go:embed assets/openvpn/*
var ovpnAssets embed.FS

var (
	ovpnOnce   sync.Once
	ovpnErr    error
	ovpnExtDir string
)

// ensureOpenVPN extracts bundled OpenVPN binaries to a temp directory and
// returns the path to openvpn.exe. Called automatically by connectOpenVPN.
func ensureOpenVPN() (string, error) {
	ovpnOnce.Do(func() {
		dir := filepath.Join(os.TempDir(), "jamvpn-ovpn")
		if err := os.MkdirAll(dir, 0700); err != nil {
			ovpnErr = fmt.Errorf("create openvpn dir: %w", err)
			return
		}

		entries, err := ovpnAssets.ReadDir("assets/openvpn")
		if err != nil {
			ovpnErr = fmt.Errorf("read embedded openvpn assets: %w", err)
			return
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			data, err := ovpnAssets.ReadFile("assets/openvpn/" + entry.Name())
			if err != nil {
				ovpnErr = fmt.Errorf("read %s: %w", entry.Name(), err)
				return
			}
			dst := filepath.Join(dir, entry.Name())
			// Skip if already extracted with same size
			if info, err := os.Stat(dst); err == nil && info.Size() == int64(len(data)) {
				continue
			}
			if err := os.WriteFile(dst, data, 0700); err != nil {
				ovpnErr = fmt.Errorf("write %s: %w", entry.Name(), err)
				return
			}
		}
		ovpnExtDir = dir
	})

	if ovpnErr != nil {
		return "", ovpnErr
	}
	return filepath.Join(ovpnExtDir, "openvpn.exe"), nil
}
