package parser

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/uuid"
	"github.com/jamalfa/jamvpn/internal/config"
)

// FromURIString parses a URI-encoded VPN config
// Supports: wireguard://, wg://, vmess://, vless://, trojan://, ss://
func FromURIString(s string) (*ParseResult, error) {
	s = strings.TrimSpace(s)

	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, "wireguard://") || strings.HasPrefix(lower, "wg://"):
		return parseWireGuardURI(s)
	case strings.HasPrefix(lower, "vmess://"):
		return parseVmessURI(s)
	case strings.HasPrefix(lower, "vless://"):
		return parseVlessURI(s)
	case strings.HasPrefix(lower, "trojan://"):
		return parseTrojanURI(s)
	case strings.HasPrefix(lower, "ss://"):
		return parseShadowsocksURI(s)
	default:
		return nil, fmt.Errorf("unsupported URI scheme: %s", s[:min(20, len(s))])
	}
}

// parseWireGuardURI handles wireguard:// URIs
// Format: wireguard://privatekey@server:port?publickey=...&address=...&dns=...
func parseWireGuardURI(s string) (*ParseResult, error) {
	// Normalize scheme
	s = strings.Replace(s, "wg://", "wireguard://", 1)
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("parse wireguard URI: %w", err)
	}

	wg := &config.WireGuardConfig{}
	wg.PrivateKey = u.User.Username()
	wg.PeerEndpoint = u.Host
	q := u.Query()
	wg.PeerPublicKey = q.Get("publickey")
	wg.PeerPSK = q.Get("presharedkey")
	wg.Address = q.Get("address")
	wg.DNS = q.Get("dns")
	wg.PeerAllowedIPs = q.Get("allowedips")
	if wg.PeerAllowedIPs == "" {
		wg.PeerAllowedIPs = "0.0.0.0/0, ::/0"
	}

	name := u.Fragment
	if name == "" {
		name = "WireGuard – " + u.Hostname()
	}

	if wg.PrivateKey == "" || wg.PeerPublicKey == "" {
		return nil, fmt.Errorf("wireguard URI missing required fields")
	}

	p := config.Profile{
		ID:         uuid.New().String(),
		Name:       name,
		TunnelType: config.TunnelWireGuard,
		Server:     u.Hostname(),
		WireGuard:  wg,
	}
	return &ParseResult{Profiles: []config.Profile{p}, Source: "uri"}, nil
}

// ToWireGuardURI generates a shareable wireguard:// URI
func ToWireGuardURI(p config.Profile) (string, error) {
	wg := p.WireGuard
	if wg == nil {
		return "", fmt.Errorf("not a WireGuard profile")
	}
	u := url.URL{
		Scheme: "wireguard",
		User:   url.User(wg.PrivateKey),
		Host:   wg.PeerEndpoint,
		Fragment: p.Name,
	}
	q := url.Values{}
	q.Set("publickey", wg.PeerPublicKey)
	if wg.PeerPSK != "" {
		q.Set("presharedkey", wg.PeerPSK)
	}
	if wg.Address != "" {
		q.Set("address", wg.Address)
	}
	if wg.DNS != "" {
		q.Set("dns", wg.DNS)
	}
	if wg.PeerAllowedIPs != "" {
		q.Set("allowedips", wg.PeerAllowedIPs)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// vmess config shape (V2Ray/Xray)
type vmessConfig struct {
	Version string `json:"v"`
	Name    string `json:"ps"`
	Address string `json:"add"`
	Port    any    `json:"port"`
	ID      string `json:"id"`
	Aid     any    `json:"aid"`
	Net     string `json:"net"`
	Type    string `json:"type"`
	Host    string `json:"host"`
	Path    string `json:"path"`
	TLS     string `json:"tls"`
	SNI     string `json:"sni"`
}

func parseVmessURI(s string) (*ParseResult, error) {
	encoded := strings.TrimPrefix(s, "vmess://")
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("vmess base64 decode: %w", err)
		}
	}
	var vm vmessConfig
	if err := json.Unmarshal(data, &vm); err != nil {
		return nil, fmt.Errorf("vmess JSON: %w", err)
	}
	port := fmt.Sprintf("%v", vm.Port)
	server := vm.Address + ":" + port

	name := vm.Name
	if name == "" {
		name = "VMess – " + vm.Address
	}

	p := config.Profile{
		ID:         uuid.New().String(),
		Name:       name,
		TunnelType: config.TunnelXray,
		Server:     server,
		Xray: &config.XrayConfig{
			URI:      s,
			Protocol: "vmess",
		},
	}
	return &ParseResult{Profiles: []config.Profile{p}, Source: "vmess"}, nil
}

func parseVlessURI(s string) (*ParseResult, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	name := u.Fragment
	if name == "" {
		name = "VLESS – " + u.Hostname()
	}
	p := config.Profile{
		ID:         uuid.New().String(),
		Name:       name,
		TunnelType: config.TunnelXray,
		Server:     u.Host,
		Xray: &config.XrayConfig{
			URI:      s,
			Protocol: "vless",
		},
	}
	return &ParseResult{Profiles: []config.Profile{p}, Source: "vless"}, nil
}

func parseTrojanURI(s string) (*ParseResult, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, err
	}
	name := u.Fragment
	if name == "" {
		name = "Trojan – " + u.Hostname()
	}
	p := config.Profile{
		ID:         uuid.New().String(),
		Name:       name,
		TunnelType: config.TunnelXray,
		Server:     u.Host,
		Username:   u.User.Username(),
		Xray: &config.XrayConfig{
			URI:      s,
			Protocol: "trojan",
		},
	}
	return &ParseResult{Profiles: []config.Profile{p}, Source: "trojan"}, nil
}

// ss:// format: ss://method:password@hostname:port#name
// or base64 encoded: ss://BASE64#name
func parseShadowsocksURI(s string) (*ParseResult, error) {
	// Strip fragment for name
	name := "Shadowsocks"
	if idx := strings.LastIndex(s, "#"); idx != -1 {
		rawName, _ := url.QueryUnescape(s[idx+1:])
		if rawName != "" {
			name = rawName
		}
		s = s[:idx]
	}

	rest := strings.TrimPrefix(s, "ss://")

	// Try plain format first (method:password@host:port)
	decoded := rest
	if !strings.Contains(rest, "@") {
		// base64 encoded
		data, err := base64.RawURLEncoding.DecodeString(rest)
		if err != nil {
			data, err = base64.URLEncoding.DecodeString(rest)
			if err != nil {
				return nil, fmt.Errorf("shadowsocks decode: %w", err)
			}
		}
		decoded = string(data)
	}

	var server, username string
	if idx := strings.Index(decoded, "@"); idx != -1 {
		username = decoded[:idx]
		server = decoded[idx+1:]
	} else {
		server = decoded
	}

	p := config.Profile{
		ID:         uuid.New().String(),
		Name:       name,
		TunnelType: config.TunnelXray,
		Server:     server,
		Username:   username,
		Xray: &config.XrayConfig{
			URI:      "ss://" + rest,
			Protocol: "shadowsocks",
		},
	}
	return &ParseResult{Profiles: []config.Profile{p}, Source: "shadowsocks"}, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
