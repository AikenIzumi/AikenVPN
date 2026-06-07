// Package vpn — Xray-core in-process implementation for VMess/VLESS/Trojan/Shadowsocks.
// Xray runs as a goroutine inside the app; no external xray.exe needed.
package vpn

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	// Register all xray-core protocols and features
	_ "github.com/xtls/xray-core/main/distro/all"

	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf/serial"

	"github.com/jamalfa/jamvpn/internal/config"
)

const (
	defaultSOCKSPort = 10808
	defaultHTTPPort  = 10809
)

var (
	xrayInstance *core.Instance
	xrayMu       sync.Mutex
)

// connectXray starts an in-process Xray instance for VMess/VLESS/Trojan/Shadowsocks.
func connectXray(p config.Profile, m *Manager) error {
	xrayMu.Lock()
	defer xrayMu.Unlock()

	if p.Xray == nil || p.Xray.URI == "" {
		return fmt.Errorf("Xray config is empty")
	}

	socksPort := p.Xray.LocalSOCKSPort
	if socksPort == 0 {
		socksPort = defaultSOCKSPort
	}
	httpPort := p.Xray.LocalHTTPPort
	if httpPort == 0 {
		httpPort = defaultHTTPPort
	}

	cfg, err := buildXrayConfig(p.Xray.URI, p.Xray.Protocol, socksPort, httpPort)
	if err != nil {
		return fmt.Errorf("build xray config: %w", err)
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	pbCfg, err := serial.LoadJSONConfig(bytes.NewReader(cfgJSON))
	if err != nil {
		return fmt.Errorf("parse xray config: %w", err)
	}

	inst, err := core.New(pbCfg)
	if err != nil {
		return fmt.Errorf("create xray instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("start xray: %w", err)
	}
	xrayInstance = inst

	// Let inbounds bind their ports before setting system proxy
	time.Sleep(300 * time.Millisecond)

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", httpPort)
	if err := setSystemProxy(proxyAddr); err != nil {
		_ = err // non-fatal: xray is running even if proxy set failed
	}

	m.SetCancelFn(func() {
		xrayMu.Lock()
		defer xrayMu.Unlock()
		stopXray()
	})
	return nil
}

// disconnectXrayActive stops the running xray instance and clears system proxy.
func disconnectXrayActive() error {
	xrayMu.Lock()
	defer xrayMu.Unlock()
	stopXray()
	return nil
}

func stopXray() {
	clearSystemProxy()
	if xrayInstance != nil {
		_ = xrayInstance.Close()
		xrayInstance = nil
	}
}

// ──────────────────────────────────────────────
// Xray JSON config builder
// ──────────────────────────────────────────────

type xrayConfig struct {
	Log       xrayLog        `json:"log"`
	Inbounds  []xrayInbound  `json:"inbounds"`
	Outbounds []xrayOutbound `json:"outbounds"`
	Routing   xrayRouting    `json:"routing"`
}

type xrayLog struct {
	Loglevel string `json:"loglevel"`
}

type xrayInbound struct {
	Tag      string          `json:"tag"`
	Port     int             `json:"port"`
	Listen   string          `json:"listen"`
	Protocol string          `json:"protocol"`
	Settings json.RawMessage `json:"settings"`
	Sniffing xraySniffing    `json:"sniffing"`
}

type xraySniffing struct {
	Enabled      bool     `json:"enabled"`
	DestOverride []string `json:"destOverride"`
}

type xrayOutbound struct {
	Tag            string          `json:"tag"`
	Protocol       string          `json:"protocol"`
	Settings       json.RawMessage `json:"settings,omitempty"`
	StreamSettings json.RawMessage `json:"streamSettings,omitempty"`
}

type xrayRouting struct {
	DomainStrategy string     `json:"domainStrategy"`
	Rules          []xrayRule `json:"rules"`
}

type xrayRule struct {
	Type        string   `json:"type"`
	OutboundTag string   `json:"outboundTag"`
	IP          []string `json:"ip,omitempty"`
}

func buildXrayConfig(uri, protocol string, socksPort, httpPort int) (*xrayConfig, error) {
	socksSettings, _ := json.Marshal(map[string]any{"auth": "noauth", "udp": true, "ip": "127.0.0.1"})
	httpSettings, _ := json.Marshal(map[string]any{})
	sniff := xraySniffing{Enabled: true, DestOverride: []string{"http", "tls"}}

	inbounds := []xrayInbound{
		{Tag: "socks-in", Port: socksPort, Listen: "127.0.0.1", Protocol: "socks", Settings: socksSettings, Sniffing: sniff},
		{Tag: "http-in", Port: httpPort, Listen: "127.0.0.1", Protocol: "http", Settings: httpSettings, Sniffing: sniff},
	}

	outbound, err := buildOutbound(uri, protocol)
	if err != nil {
		return nil, err
	}

	freedomSettings, _ := json.Marshal(map[string]any{"domainStrategy": "UseIP"})
	blockSettings, _ := json.Marshal(map[string]any{})

	routing := xrayRouting{
		DomainStrategy: "IPIfNonMatch",
		Rules:          []xrayRule{{Type: "field", OutboundTag: "direct", IP: []string{"geoip:private"}}},
	}

	return &xrayConfig{
		Log:      xrayLog{Loglevel: "warning"},
		Inbounds: inbounds,
		Outbounds: []xrayOutbound{
			*outbound,
			{Tag: "direct", Protocol: "freedom", Settings: freedomSettings},
			{Tag: "block", Protocol: "blackhole", Settings: blockSettings},
		},
		Routing: routing,
	}, nil
}

func buildOutbound(uri, protocol string) (*xrayOutbound, error) {
	lower := strings.ToLower(uri)
	switch {
	case strings.HasPrefix(lower, "vmess://"):
		return buildVmessOutbound(uri)
	case strings.HasPrefix(lower, "vless://"):
		return buildVlessOutbound(uri)
	case strings.HasPrefix(lower, "trojan://"):
		return buildTrojanOutbound(uri)
	case strings.HasPrefix(lower, "ss://"):
		return buildShadowsocksOutbound(uri)
	default:
		return nil, fmt.Errorf("unsupported protocol URI: %s", protocol)
	}
}

// ── VMess ───────────────────────────────────────

type vmessJSON struct {
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

func buildVmessOutbound(uri string) (*xrayOutbound, error) {
	encoded := strings.TrimPrefix(uri, "vmess://")
	data, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, fmt.Errorf("vmess base64: %w", err)
		}
	}
	var vm vmessJSON
	if err := json.Unmarshal(data, &vm); err != nil {
		return nil, fmt.Errorf("vmess json: %w", err)
	}

	settings := map[string]any{
		"vnext": []map[string]any{{
			"address": vm.Address,
			"port":    toInt(vm.Port),
			"users":   []map[string]any{{"id": vm.ID, "alterId": toInt(vm.Aid), "security": "auto"}},
		}},
	}
	stream := buildStream(vm.Net, vm.Path, vm.Host, vm.TLS, vm.SNI, "", "")
	sRaw, _ := json.Marshal(settings)
	stRaw, _ := json.Marshal(stream)
	return &xrayOutbound{Tag: "proxy", Protocol: "vmess", Settings: sRaw, StreamSettings: stRaw}, nil
}

// ── VLESS ───────────────────────────────────────

func buildVlessOutbound(uri string) (*xrayOutbound, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("vless parse: %w", err)
	}
	q := u.Query()
	host, portStr := splitHost(u.Host)
	port, _ := strconv.Atoi(portStr)

	flow := q.Get("flow")
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	security := q.Get("security")
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"))
	path := q.Get("path")
	wsHost := q.Get("host")
	fp := q.Get("fp")
	pbk := q.Get("pbk")
	sid := q.Get("sid")

	settings := map[string]any{
		"vnext": []map[string]any{{
			"address": host,
			"port":    port,
			"users":   []map[string]any{{"id": u.User.Username(), "encryption": "none", "flow": flow}},
		}},
	}

	var stream map[string]any
	if security == "reality" && pbk != "" {
		stream = buildRealityStream(network, path, sni, fp, pbk, sid)
	} else {
		stream = buildStream(network, path, wsHost, security, sni, fp, "")
	}

	sRaw, _ := json.Marshal(settings)
	stRaw, _ := json.Marshal(stream)
	return &xrayOutbound{Tag: "proxy", Protocol: "vless", Settings: sRaw, StreamSettings: stRaw}, nil
}

// ── Trojan ──────────────────────────────────────

func buildTrojanOutbound(uri string) (*xrayOutbound, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("trojan parse: %w", err)
	}
	q := u.Query()
	host, portStr := splitHost(u.Host)
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 443
	}
	sni := firstNonEmpty(q.Get("sni"), q.Get("peer"), host)
	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	path := q.Get("path")
	wsHost := q.Get("host")

	settings := map[string]any{
		"servers": []map[string]any{
			{"address": host, "port": port, "password": u.User.Username()},
		},
	}
	stream := buildStream(network, path, wsHost, "tls", sni, "", "")
	sRaw, _ := json.Marshal(settings)
	stRaw, _ := json.Marshal(stream)
	return &xrayOutbound{Tag: "proxy", Protocol: "trojan", Settings: sRaw, StreamSettings: stRaw}, nil
}

// ── Shadowsocks ─────────────────────────────────

func buildShadowsocksOutbound(uri string) (*xrayOutbound, error) {
	s := strings.TrimPrefix(uri, "ss://")
	if idx := strings.LastIndex(s, "#"); idx != -1 {
		s = s[:idx]
	}

	var userInfo, serverAddr string
	if idx := strings.Index(s, "@"); idx != -1 {
		userInfo = s[:idx]
		serverAddr = s[idx+1:]
	} else {
		data, err := base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			data, err = base64.URLEncoding.DecodeString(s)
			if err != nil {
				return nil, fmt.Errorf("ss decode: %w", err)
			}
		}
		decoded := string(data)
		if idx := strings.Index(decoded, "@"); idx != -1 {
			userInfo = decoded[:idx]
			serverAddr = decoded[idx+1:]
		} else {
			return nil, fmt.Errorf("ss: cannot parse server address")
		}
	}

	host, portStr := splitHost(serverAddr)
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 8388
	}

	var method, password string
	if idx := strings.Index(userInfo, ":"); idx != -1 {
		method = userInfo[:idx]
		password = userInfo[idx+1:]
	} else {
		if data, err := base64.StdEncoding.DecodeString(userInfo); err == nil {
			parts := strings.SplitN(string(data), ":", 2)
			if len(parts) == 2 {
				method, password = parts[0], parts[1]
			}
		}
	}
	if method == "" {
		method = "aes-256-gcm"
	}

	settings := map[string]any{
		"servers": []map[string]any{
			{"address": host, "port": port, "method": method, "password": password},
		},
	}
	sRaw, _ := json.Marshal(settings)
	return &xrayOutbound{Tag: "proxy", Protocol: "shadowsocks", Settings: sRaw}, nil
}

// ── Stream settings helpers ──────────────────────

func buildStream(network, path, host, security, sni, fp, _ string) map[string]any {
	stream := map[string]any{"network": network}

	switch network {
	case "ws":
		ws := map[string]any{"path": path}
		if host != "" {
			ws["headers"] = map[string]any{"Host": host}
		}
		stream["wsSettings"] = ws
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": path}
	case "h2", "http":
		h2 := map[string]any{"path": path}
		if host != "" {
			h2["host"] = []string{host}
		}
		stream["httpSettings"] = h2
	}

	if security == "tls" {
		tls := map[string]any{"allowInsecure": false}
		if sni != "" {
			tls["serverName"] = sni
		}
		if fp != "" {
			tls["fingerprint"] = fp
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	}

	return stream
}

func buildRealityStream(network, path, sni, fp, pbk, sid string) map[string]any {
	stream := buildStream(network, path, "", "none", "", "", "")
	stream["security"] = "reality"
	stream["realitySettings"] = map[string]any{
		"serverName":  sni,
		"fingerprint": fp,
		"publicKey":   pbk,
		"shortId":     sid,
	}
	delete(stream, "tlsSettings")
	return stream
}

// ── Utilities ────────────────────────────────────

func toInt(v any) int {
	switch x := v.(type) {
	case float64:
		return int(x)
	case int:
		return x
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}

func splitHost(hostport string) (host, port string) {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:]
		}
		if hostport[i] == ']' {
			break
		}
	}
	if len(hostport) > 0 && hostport[0] == '[' {
		if end := strings.Index(hostport, "]"); end != -1 {
			h := hostport[1:end]
			rest := hostport[end+1:]
			if len(rest) > 1 && rest[0] == ':' {
				return h, rest[1:]
			}
			return h, ""
		}
	}
	return hostport, ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
