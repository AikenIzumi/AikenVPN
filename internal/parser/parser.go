// Package parser provides universal VPN configuration parsing.
// Supports: WireGuard (.conf / wireguard:// URI), OpenVPN (.ovpn),
// SSTP/L2TP/IKEv2 JSON, and the app's own JSON export format.
package parser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jamalfa/jamvpn/internal/config"
)

// ParseResult contains one or more imported profiles
type ParseResult struct {
	Profiles []config.Profile
	Source   string // "wireguard", "openvpn", "json", "uri"
}

// FromURL downloads content from a URL and parses it
func FromURL(rawURL string) (*ParseResult, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil {
		return nil, fmt.Errorf("fetch URL: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("сервер вернул HTTP %d", resp.StatusCode)
	}
	const limit = 4 << 20
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if len(data) > limit {
		return nil, fmt.Errorf("размер конфигурации превышает 4 МиБ")
	}
	return FromBytes(data, rawURL)
}

// FromBytes auto-detects format and parses config bytes
func FromBytes(data []byte, hint string) (*ParseResult, error) {
	s := strings.TrimSpace(string(data))

	// Try URI schemes first (single line starting with scheme)
	if looksLikeURI(s) {
		return FromURIString(s)
	}

	// Try our own JSON export format
	if strings.HasPrefix(s, "{") || (strings.HasPrefix(s, "[") && !strings.HasPrefix(s, "[Interface]") && !strings.HasPrefix(s, "[Peer]")) {
		return fromJSON(s)
	}

	// Try WireGuard .conf
	if strings.Contains(s, "[Interface]") {
		return fromWireGuardConf(s)
	}

	// Try OpenVPN .ovpn
	if strings.Contains(s, "client") || strings.Contains(s, "remote ") ||
		strings.Contains(s, "<ca>") || strings.HasSuffix(strings.ToLower(hint), ".ovpn") {
		return fromOpenVPNConf(s)
	}

	return nil, fmt.Errorf("unknown configuration format")
}

func looksLikeURI(s string) bool {
	prefixes := []string{
		"wireguard://", "wg://",
		"vmess://", "vless://", "trojan://",
		"ss://", "ssr://",
		"vpn://",
		"jamvpn://",
	}
	lower := strings.ToLower(s)
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// fromJSON handles the app's own export format
func fromJSON(s string) (*ParseResult, error) {
	var profiles []config.Profile
	if strings.HasPrefix(s, "[") {
		if err := json.Unmarshal([]byte(s), &profiles); err != nil {
			return nil, err
		}
	} else {
		var wrapper struct {
			Profiles json.RawMessage `json:"profiles"`
		}
		if err := json.Unmarshal([]byte(s), &wrapper); err != nil {
			return nil, err
		}
		if wrapper.Profiles != nil {
			if err := json.Unmarshal(wrapper.Profiles, &profiles); err != nil {
				return nil, err
			}
		} else {
			var p config.Profile
			if err := json.Unmarshal([]byte(s), &p); err != nil {
				return nil, err
			}
			profiles = []config.Profile{p}
		}
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("список профилей пуст")
	}
	for i := range profiles {
		p := &profiles[i]
		if strings.TrimSpace(p.Name) == "" || p.TunnelType == "" {
			return nil, fmt.Errorf("профиль %d: укажите name и tunnel_type", i+1)
		}
		if p.ID == "" {
			p.ID = uuid.NewString()
		}
	}
	return &ParseResult{Profiles: profiles, Source: "json"}, nil
}

// FromBase64 decodes base64-encoded config (common in QR codes and share links)
func FromBase64(encoded string) (*ParseResult, error) {
	encoded = strings.TrimSpace(encoded)
	// Try standard then URL-safe base64
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.URLEncoding.DecodeString(encoded)
		if err != nil {
			data, err = base64.RawURLEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("base64 decode: %w", err)
			}
		}
	}
	return FromBytes(data, "")
}
