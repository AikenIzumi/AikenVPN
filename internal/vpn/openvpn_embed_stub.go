//go:build !with_openvpn

package vpn

import "fmt"

// ensureOpenVPN returns an error when OpenVPN was not bundled at build time.
// connectOpenVPN will fall back to searching for a system-installed openvpn.exe.
func ensureOpenVPN() (string, error) {
	return "", fmt.Errorf("openvpn not bundled")
}
