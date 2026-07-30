//go:build windows

package vpn

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
)

var (
	stMu           sync.Mutex
	stActiveRoutes []string // CIDRs we added via "route add" — cleaned up on disconnect
)

// ApplySplitTunnel sets up routing / firewall rules after the VPN adapter is up.
// For RAS protocols the vpnInterface alias equals p.Name.
// settings carries app-wide routing preferences (LAN bypass, region bypass, DNS).
func ApplySplitTunnel(p config.Profile, settings config.AppSettings) {
	stMu.Lock()
	stActiveRoutes = stActiveRoutes[:0]
	stMu.Unlock()

	gw := getPhysicalGateway(p.Name)

	// ── Global: LAN bypass ───────────────────────────────────────────────────
	if settings.BypassLAN && gw != "" {
		added := applyBypassRoutes(config.RFC1918Prefixes(), gw)
		stMu.Lock()
		stActiveRoutes = append(stActiveRoutes, added...)
		stMu.Unlock()
	}

	// ── Global: region bypass ────────────────────────────────────────────────
	if settings.BypassRegion != "" && gw != "" {
		regionIPs := resolveSTEntries(config.BypassRegionCIDRs(settings.BypassRegion))
		added := applyBypassRoutes(regionIPs, gw)
		stMu.Lock()
		stActiveRoutes = append(stActiveRoutes, added...)
		stMu.Unlock()
	}

	// ── Global: custom VPN DNS ───────────────────────────────────────────────
	if settings.VpnDNS != "" {
		SetVPNAdapterDNS(p.Name, settings.VpnDNS)
	}

	// ── Per-profile split tunnel ──────────────────────────────────────────────
	if p.SplitTunnel == nil || p.SplitTunnel.Mode == config.SplitTunnelOff {
		return
	}
	cfg := p.SplitTunnel
	ips := resolveSTEntries(cfg.Domains)

	switch cfg.Mode {
	case config.SplitTunnelBypass:
		if gw == "" {
			logger.Info("splitTunnel bypass: cannot find physical gateway (skipping IP routes)")
		} else {
			added := applyBypassRoutes(ips, gw)
			stMu.Lock()
			stActiveRoutes = append(stActiveRoutes, added...)
			stMu.Unlock()
		}
		applyBypassAppFirewall(cfg.Apps, p.Name)

	case config.SplitTunnelInclude:
		// For RAS: ensure split tunneling is on at the phonebook level.
		enableRASSplitTunnel(p.Name)
		applyIncludeRoutes(p.Name, ips)
	}
}

// RemoveSplitTunnel cleans up all routes and firewall rules for a profile.
func RemoveSplitTunnel(p config.Profile) {
	if p.SplitTunnel == nil || p.SplitTunnel.Mode == config.SplitTunnelOff {
		return
	}
	stMu.Lock()
	routes := make([]string, len(stActiveRoutes))
	copy(routes, stActiveRoutes)
	stActiveRoutes = stActiveRoutes[:0]
	stMu.Unlock()

	removeBypassRoutes(routes)
	removeAllSplitTunnelFirewall()
}

// GetRunningProcesses returns .exe names of currently running GUI/user processes.
func GetRunningProcesses() []string {
	script := `Get-Process | ` +
		`Where-Object {$_.Name -notmatch "^(svchost|lsass|csrss|smss|wininit|services|dwm|System|Idle|Registry)$"} | ` +
		`Select-Object -ExpandProperty Name -Unique | Sort-Object`
	out, err := runPS(script)
	if err != nil || strings.TrimSpace(out) == "" {
		return nil
	}
	var result []string
	for _, line := range strings.Split(out, "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		if !strings.HasSuffix(strings.ToLower(name), ".exe") {
			name += ".exe"
		}
		result = append(result, name)
	}
	return result
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// resolveSTEntries converts a mixed list of domains, IPs, and CIDRs to a
// deduplicated list of CIDR strings ready for route commands.
func resolveSTEntries(entries []string) []string {
	seen := make(map[string]bool)
	var ips []string

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		// CIDR notation
		if _, ipNet, err := net.ParseCIDR(entry); err == nil {
			cidr := ipNet.String()
			if !seen[cidr] {
				seen[cidr] = true
				ips = append(ips, cidr)
			}
			continue
		}
		// Plain IP
		if ip := net.ParseIP(entry); ip != nil {
			cidr := entry + "/32"
			if !seen[cidr] {
				seen[cidr] = true
				ips = append(ips, cidr)
			}
			continue
		}
		// Domain — resolve with a short timeout
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		addrs, err := net.DefaultResolver.LookupHost(ctx, entry)
		cancel()
		if err != nil {
			logger.Info("splitTunnel: resolve '%s': %v", entry, err)
			continue
		}
		for _, addr := range addrs {
			cidr := addr + "/32"
			if !seen[cidr] {
				seen[cidr] = true
				ips = append(ips, cidr)
				logger.Info("splitTunnel: resolved %s → %s", entry, addr)
			}
		}
	}
	return ips
}

// getPhysicalGateway returns the default-route next-hop on any interface other
// than the active VPN adapter (identified by its alias name).
func getPhysicalGateway(vpnAlias string) string {
	script := fmt.Sprintf(
		`(Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | `+
			`Where-Object {$_.NextHop -ne "0.0.0.0" -and $_.InterfaceAlias -ne '%s'} | `+
			`Sort-Object RouteMetric | Select-Object -First 1).NextHop`,
		psSafe(vpnAlias),
	)
	out, _ := runPS(script)
	return strings.TrimSpace(out)
}

// applyBypassRoutes adds host/network routes for bypass IPs through the
// physical gateway so they skip the VPN default route.
// Returns the list of CIDRs that were successfully added.
func applyBypassRoutes(ips []string, gw string) []string {
	var applied []string
	for _, cidr := range ips {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		mask := ipMaskDotted(ipNet.Mask)
		cmd := exec.Command("route", "add", ipNet.IP.String(), "mask", mask, gw)
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		if out, err := cmd.CombinedOutput(); err != nil {
			logger.Info("splitTunnel: route add %s: %v (%s)", cidr, err, strings.TrimSpace(string(out)))
		} else {
			logger.Info("splitTunnel: bypass route %s via %s", cidr, gw)
			applied = append(applied, cidr)
		}
	}
	return applied
}

func removeBypassRoutes(ips []string) {
	for _, cidr := range ips {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		cmd := exec.Command("route", "delete", ipNet.IP.String())
		cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
		cmd.Run() //nolint:errcheck
		logger.Info("splitTunnel: removed bypass route %s", cidr)
	}
}

// enableRASSplitTunnel flips the VPN connection's SplitTunneling flag to $true
// so that Windows does NOT install a default route through the tunnel, allowing
// include-mode to work (only the explicitly added routes go via VPN).
func enableRASSplitTunnel(connName string) {
	script := fmt.Sprintf(
		`Set-VpnConnection -Name '%s' -SplitTunneling $true -PassThru -ErrorAction SilentlyContinue | Out-Null`,
		psSafe(connName),
	)
	runPS(script) //nolint:errcheck
}

// applyIncludeRoutes uses Add-VpnConnectionRoute to push each CIDR through the
// named RAS connection.
func applyIncludeRoutes(connName string, ips []string) {
	for _, cidr := range ips {
		script := fmt.Sprintf(
			`Add-VpnConnectionRoute -ConnectionName '%s' -DestinationPrefix '%s' -PassThru -ErrorAction SilentlyContinue | Out-Null`,
			psSafe(connName), psSafe(cidr),
		)
		if _, err := runPS(script); err != nil {
			logger.Info("splitTunnel: include route %s: %v", cidr, err)
		} else {
			logger.Info("splitTunnel: include route → %s", cidr)
		}
	}
}

// applyBypassAppFirewall blocks each app exe from sending traffic through the
// VPN adapter, causing Windows to fall back to the physical NIC. All rules are
// created in ONE PowerShell invocation (resolving each exe path inline) so N
// apps cost a single powershell.exe cold start instead of ~3 spawns per app.
func applyBypassAppFirewall(apps []string, vpnAlias string) {
	var b strings.Builder
	n := 0
	for _, app := range apps {
		app = strings.TrimSpace(app)
		if app == "" {
			continue
		}
		ruleName := "JamVPN-bypass-" + stSanitize(app)
		if strings.ContainsAny(app, `/\`) {
			// Full path supplied — use it directly.
			fmt.Fprintf(&b,
				`Remove-NetFirewallRule -Name '%s' -ErrorAction SilentlyContinue; `+
					`New-NetFirewallRule -Name '%s' -DisplayName 'JamVPN bypass: %s' -Program '%s' `+
					`-InterfaceAlias '%s' -Action Block -Direction Outbound -Profile Any -ErrorAction SilentlyContinue | Out-Null; `,
				psSafe(ruleName), psSafe(ruleName), psSafe(app), psSafe(app), psSafe(vpnAlias))
		} else {
			name := strings.TrimSuffix(strings.TrimSuffix(app, ".EXE"), ".exe")
			fmt.Fprintf(&b,
				`$p=(Get-Process -Name '%s' -ErrorAction SilentlyContinue|Select-Object -First 1 -ExpandProperty Path); `+
					`if(-not $p){$p=(Get-Command '%s' -ErrorAction SilentlyContinue).Source}; `+
					`if($p){Remove-NetFirewallRule -Name '%s' -ErrorAction SilentlyContinue; `+
					`New-NetFirewallRule -Name '%s' -DisplayName 'JamVPN bypass: %s' -Program $p -InterfaceAlias '%s' `+
					`-Action Block -Direction Outbound -Profile Any -ErrorAction SilentlyContinue|Out-Null}; `,
				psSafe(name), psSafe(app), psSafe(ruleName), psSafe(ruleName), psSafe(app), psSafe(vpnAlias))
		}
		n++
	}
	if n == 0 {
		return
	}
	if _, err := runPS(b.String()); err != nil {
		logger.Info("splitTunnel: batch bypass firewall rules: %v", err)
	} else {
		logger.Info("splitTunnel: applied %d bypass firewall rule(s) on '%s'", n, vpnAlias)
	}
}

func removeAllSplitTunnelFirewall() {
	script := `Remove-NetFirewallRule -Name 'JamVPN-bypass-*' -ErrorAction SilentlyContinue; ` +
		`Remove-NetFirewallRule -Name 'JamVPN-include-*' -ErrorAction SilentlyContinue`
	runPS(script) //nolint:errcheck
	logger.Info("splitTunnel: all firewall rules removed")
}

func ipMaskDotted(mask net.IPMask) string {
	if len(mask) == 4 {
		return fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])
	}
	return net.IP(mask).String()
}

// stSanitize produces a firewall-rule-safe ASCII identifier from an exe name.
func stSanitize(s string) string {
	s = strings.TrimSuffix(strings.TrimSuffix(s, ".exe"), ".EXE")
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	result := b.String()
	if len(result) > 50 {
		result = result[:50]
	}
	return result
}
