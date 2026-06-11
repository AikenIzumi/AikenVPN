//go:build windows

package vpn

import (
	"fmt"
	"strings"

	"github.com/jamalfa/jamvpn/internal/logger"
)

// SetVPNAdapterDNS sets the DNS server addresses on the named VPN adapter.
// servers is a comma- or space-separated list of IP addresses.
// Pass an empty string to reset to automatic (DHCP/VPN-assigned) DNS.
func SetVPNAdapterDNS(adapterAlias, servers string) {
	servers = strings.TrimSpace(servers)
	var script string
	if servers == "" {
		script = fmt.Sprintf(
			`Set-DnsClientServerAddress -InterfaceAlias '%s' -ResetServerAddresses -ErrorAction SilentlyContinue`,
			psSafe(adapterAlias),
		)
	} else {
		// Convert "1.1.1.1, 8.8.8.8" to PowerShell array literal '1.1.1.1','8.8.8.8'
		parts := strings.FieldsFunc(servers, func(r rune) bool { return r == ',' || r == ' ' })
		var quoted []string
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				quoted = append(quoted, "'"+psSafe(p)+"'")
			}
		}
		script = fmt.Sprintf(
			`Set-DnsClientServerAddress -InterfaceAlias '%s' -ServerAddresses (%s) -ErrorAction SilentlyContinue`,
			psSafe(adapterAlias), strings.Join(quoted, ","),
		)
	}
	if _, err := runPS(script); err != nil {
		logger.Info("vpnDNS '%s': %v (non-fatal)", adapterAlias, err)
	} else {
		logger.Info("vpnDNS '%s' → [%s]", adapterAlias, servers)
	}
}
