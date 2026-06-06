package parser

import (
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jamalfa/jamvpn/internal/config"
)

// fromOpenVPNConf parses an .ovpn file content
func fromOpenVPNConf(s string) (*ParseResult, error) {
	ovpn := &config.OpenVPNConfig{
		ConfigContent: s,
	}

	profileName := "OpenVPN"
	var server string

	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			if strings.HasPrefix(line, "#") {
				candidate := strings.TrimSpace(strings.TrimPrefix(line, "#"))
				if candidate != "" && !strings.Contains(candidate, " ") {
					profileName = candidate
				}
			}
			continue
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		switch strings.ToLower(fields[0]) {
		case "remote":
			if len(fields) >= 2 {
				server = fields[1]
				if profileName == "OpenVPN" && server != "" {
					profileName = "OpenVPN – " + server
				}
			}
		}
	}

	if server == "" && !strings.Contains(s, "<ca>") {
		return nil, fmt.Errorf("invalid OpenVPN config: no remote directive found")
	}

	p := config.Profile{
		ID:         uuid.New().String(),
		Name:       profileName,
		TunnelType: config.TunnelOpenVPN,
		Server:     server,
		OpenVPN:    ovpn,
	}
	return &ParseResult{Profiles: []config.Profile{p}, Source: "openvpn"}, nil
}
