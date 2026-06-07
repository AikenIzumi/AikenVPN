// Package vpn — embedded WireGuard using wireguard-go + wintun.
// wintun.dll is bundled in assets/ and extracted to the exe directory at runtime.
// No external wireguard.exe required.
package vpn

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/jamalfa/jamvpn/internal/config"
)

const wgTUNName = "JamVPN"

var (
	wgDevice         *device.Device
	wgTUNDev         tun.Device
	wgMu             sync.Mutex
	wgLastAllowedIPs string // saved for route cleanup on disconnect
)

// connectWireGuard starts an embedded WireGuard tunnel.
func connectWireGuard(p config.Profile) error {
	wgMu.Lock()
	defer wgMu.Unlock()

	if p.WireGuard == nil {
		return fmt.Errorf("WireGuard config is empty")
	}
	wg := p.WireGuard

	// Extract wintun.dll next to the exe (LOAD_LIBRARY_SEARCH_APPLICATION_DIR).
	if err := ensureWintun(); err != nil {
		return fmt.Errorf("wintun: %w", err)
	}

	mtu := wg.MTU
	if mtu == 0 {
		mtu = device.DefaultMTU
	}

	tunDev, err := tun.CreateTUN(wgTUNName, mtu)
	if err != nil {
		return fmt.Errorf("create TUN adapter: %w", err)
	}

	realName, err := tunDev.Name()
	if err != nil {
		realName = wgTUNName
	}

	logger := device.NewLogger(device.LogLevelSilent, "")
	dev := device.NewDevice(tunDev, conn.NewDefaultBind(), logger)

	ipcConf, err := buildWGIPCConf(wg)
	if err != nil {
		_ = tunDev.Close()
		return fmt.Errorf("build WireGuard IPC config: %w", err)
	}

	if err := dev.IpcSet(ipcConf); err != nil {
		dev.Close()
		return fmt.Errorf("configure WireGuard: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("bring up WireGuard: %w", err)
	}

	if err := netshSetAddr(realName, wg.Address); err != nil {
		dev.Close()
		return fmt.Errorf("set interface address: %w", err)
	}
	if wg.DNS != "" {
		_ = netshSetDNS(realName, wg.DNS)
	}

	allowedIPs := wg.PeerAllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0"
	}
	wgLastAllowedIPs = allowedIPs
	_ = addWGRoutes(realName, wg.PeerEndpoint, allowedIPs)

	wgDevice = dev
	wgTUNDev = tunDev
	return nil
}

// disconnectWireGuard tears down the embedded WireGuard tunnel.
func disconnectWireGuard(_ config.Profile) error {
	wgMu.Lock()
	defer wgMu.Unlock()

	removeWGRoutes(wgLastAllowedIPs)
	wgLastAllowedIPs = ""

	if wgDevice != nil {
		wgDevice.Down()
		wgDevice.Close()
		wgDevice = nil
	}
	if wgTUNDev != nil {
		_ = wgTUNDev.Close()
		wgTUNDev = nil
	}
	return nil
}

// ── WireGuard IPC config ──────────────────────────

// buildWGIPCConf converts profile keys from base64 to the hex format
// required by wireguard-go's IPC protocol.
func buildWGIPCConf(wg *config.WireGuardConfig) (string, error) {
	privHex, err := wgKeyToHex(wg.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	pubHex, err := wgKeyToHex(wg.PeerPublicKey)
	if err != nil {
		return "", fmt.Errorf("public key: %w", err)
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "private_key=%s\n", privHex)
	fmt.Fprintf(&sb, "listen_port=0\n")
	fmt.Fprintf(&sb, "\n") // blank line separates interface from peer section

	fmt.Fprintf(&sb, "public_key=%s\n", pubHex)

	if wg.PeerPSK != "" {
		if pskHex, err := wgKeyToHex(wg.PeerPSK); err == nil {
			fmt.Fprintf(&sb, "preshared_key=%s\n", pskHex)
		}
	}

	fmt.Fprintf(&sb, "endpoint=%s\n", wg.PeerEndpoint)

	allowedIPs := wg.PeerAllowedIPs
	if allowedIPs == "" {
		allowedIPs = "0.0.0.0/0, ::/0"
	}
	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr != "" {
			fmt.Fprintf(&sb, "allowed_ip=%s\n", cidr)
		}
	}

	if wg.PeerKeepalive > 0 {
		fmt.Fprintf(&sb, "persistent_keepalive_interval=%d\n", wg.PeerKeepalive)
	}

	return sb.String(), nil
}

func wgKeyToHex(b64 string) (string, error) {
	key, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		key, err = base64.RawStdEncoding.DecodeString(b64)
		if err != nil {
			return "", fmt.Errorf("decode base64: %w", err)
		}
	}
	return hex.EncodeToString(key), nil
}

// ── Network helpers ───────────────────────────────

func netshSetAddr(ifName, cidr string) error {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("parse CIDR %q: %w", cidr, err)
	}
	mask := net.IP(ipNet.Mask).String()
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		"name="+ifName, "static", ip.String(), mask)
	hideWindow(cmd)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh set address: %s: %w", strings.TrimSpace(string(out)), err)
	}
	return nil
}

func netshSetDNS(ifName, dns string) error {
	primary := strings.TrimSpace(strings.SplitN(dns, ",", 2)[0])
	cmd := exec.Command("netsh", "interface", "ip", "set", "dns",
		"name="+ifName, "static", primary)
	hideWindow(cmd)
	return cmd.Run()
}

// addWGRoutes adds AllowedIP routes through the WireGuard interface.
// For full-tunnel (0.0.0.0/0) it first pins the VPN server endpoint to
// the existing default gateway so tunnel packets don't recurse.
func addWGRoutes(ifName, endpoint, allowedIPs string) error {
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return err
	}
	ifIdx := strconv.Itoa(iface.Index)

	if strings.Contains(allowedIPs, "0.0.0.0/0") {
		if host, _, ok := splitEndpointHost(endpoint); ok {
			if gw := defaultIPv4Gateway(); gw != "" {
				cmd := exec.Command("route", "add", host, "mask", "255.255.255.255", gw)
				hideWindow(cmd)
				_ = cmd.Run()
			}
		}
	}

	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.Contains(cidr, ":") {
			continue // skip empty / IPv6
		}
		if cidr == "0.0.0.0/0" {
			cmd := exec.Command("route", "add", "0.0.0.0", "mask", "0.0.0.0",
				"0.0.0.0", "metric", "1", "if", ifIdx)
			hideWindow(cmd)
			_ = cmd.Run()
		} else {
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			cmd := exec.Command("route", "add", ip.String(), "mask",
				net.IP(ipNet.Mask).String(), "0.0.0.0", "if", ifIdx)
			hideWindow(cmd)
			_ = cmd.Run()
		}
	}
	return nil
}

func removeWGRoutes(allowedIPs string) {
	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.Contains(cidr, ":") {
			continue
		}
		if cidr == "0.0.0.0/0" {
			cmd := exec.Command("route", "delete", "0.0.0.0", "mask", "0.0.0.0")
			hideWindow(cmd)
			_ = cmd.Run()
		} else {
			ip, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}
			cmd := exec.Command("route", "delete", ip.String(), "mask",
				net.IP(ipNet.Mask).String())
			hideWindow(cmd)
			_ = cmd.Run()
		}
	}
}

func defaultIPv4Gateway() string {
	cmd := exec.Command("cmd", "/c", "route print 0.0.0.0")
	hideWindow(cmd)
	out, _ := cmd.Output()
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "0.0.0.0") {
			if fields := strings.Fields(line); len(fields) >= 3 {
				if gw := fields[2]; net.ParseIP(gw) != nil {
					return gw
				}
			}
		}
	}
	return ""
}

func splitEndpointHost(endpoint string) (host, port string, ok bool) {
	if endpoint == "" {
		return "", "", false
	}
	host, port = splitHost(endpoint)
	return host, port, host != ""
}

// sanitizeName removes characters unsafe for file paths.
func sanitizeName(name string) string {
	var sb strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			sb.WriteRune(r)
		} else {
			sb.WriteRune('-')
		}
	}
	if s := sb.String(); s != "" {
		return s
	}
	return "vpn"
}

// Ensure config package is referenced.
var _ config.Profile
