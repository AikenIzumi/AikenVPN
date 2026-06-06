package parser

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/jamalfa/jamvpn/internal/config"
)

// fromWireGuardConf parses a WireGuard .conf file
func fromWireGuardConf(s string) (*ParseResult, error) {
	wg := &config.WireGuardConfig{}
	profileName := "WireGuard"

	var section string
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			// Extract name from comment like "# ProfileName"
			if strings.HasPrefix(line, "#") {
				candidate := strings.TrimSpace(strings.TrimPrefix(line, "#"))
				if candidate != "" && !strings.Contains(candidate, "=") {
					profileName = candidate
				}
			}
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}

		key, val, ok := splitKV(line)
		if !ok {
			continue
		}

		switch section {
		case "interface":
			switch key {
			case "privatekey":
				wg.PrivateKey = val
			case "address":
				wg.Address = val
			case "dns":
				wg.DNS = val
			case "mtu":
				if n, err := strconv.Atoi(val); err == nil {
					wg.MTU = n
				}
			}
		case "peer":
			switch key {
			case "publickey":
				wg.PeerPublicKey = val
			case "presharedkey":
				wg.PeerPSK = val
			case "endpoint":
				wg.PeerEndpoint = val
			case "allowedips":
				wg.PeerAllowedIPs = val
			case "persistentkeepalive":
				if n, err := strconv.Atoi(val); err == nil {
					wg.PeerKeepalive = n
				}
			}
		}
	}

	if wg.PrivateKey == "" || wg.PeerPublicKey == "" {
		return nil, fmt.Errorf("invalid WireGuard config: missing PrivateKey or peer PublicKey")
	}
	if wg.PeerAllowedIPs == "" {
		wg.PeerAllowedIPs = "0.0.0.0/0, ::/0"
	}
	if wg.PeerKeepalive == 0 {
		wg.PeerKeepalive = 25
	}

	p := config.Profile{
		ID:         uuid.New().String(),
		Name:       profileName,
		TunnelType: config.TunnelWireGuard,
		WireGuard:  wg,
	}
	return &ParseResult{Profiles: []config.Profile{p}, Source: "wireguard"}, nil
}

// ToWireGuardConf serializes a WireGuard profile back to .conf format
func ToWireGuardConf(p config.Profile) (string, error) {
	wg := p.WireGuard
	if wg == nil {
		return "", fmt.Errorf("not a WireGuard profile")
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s\n", p.Name))
	sb.WriteString("[Interface]\n")
	sb.WriteString(fmt.Sprintf("PrivateKey = %s\n", wg.PrivateKey))
	if wg.Address != "" {
		sb.WriteString(fmt.Sprintf("Address = %s\n", wg.Address))
	}
	if wg.DNS != "" {
		sb.WriteString(fmt.Sprintf("DNS = %s\n", wg.DNS))
	}
	if wg.MTU > 0 {
		sb.WriteString(fmt.Sprintf("MTU = %d\n", wg.MTU))
	}
	sb.WriteString("\n[Peer]\n")
	sb.WriteString(fmt.Sprintf("PublicKey = %s\n", wg.PeerPublicKey))
	if wg.PeerPSK != "" {
		sb.WriteString(fmt.Sprintf("PresharedKey = %s\n", wg.PeerPSK))
	}
	if wg.PeerEndpoint != "" {
		sb.WriteString(fmt.Sprintf("Endpoint = %s\n", wg.PeerEndpoint))
	}
	allowed := wg.PeerAllowedIPs
	if allowed == "" {
		allowed = "0.0.0.0/0, ::/0"
	}
	sb.WriteString(fmt.Sprintf("AllowedIPs = %s\n", allowed))
	if wg.PeerKeepalive > 0 {
		sb.WriteString(fmt.Sprintf("PersistentKeepalive = %d\n", wg.PeerKeepalive))
	}
	return sb.String(), nil
}

func splitKV(line string) (key, val string, ok bool) {
	idx := strings.Index(line, "=")
	if idx < 0 {
		return "", "", false
	}
	key = strings.ToLower(strings.TrimSpace(line[:idx]))
	val = strings.TrimSpace(line[idx+1:])
	return key, val, true
}
