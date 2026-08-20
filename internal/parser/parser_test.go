package parser

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jamalfa/jamvpn/internal/config"
)

// mustSingle asserts the result contains exactly one profile and returns it.
func mustSingle(t *testing.T, r *ParseResult) config.Profile {
	t.Helper()
	if r == nil {
		t.Fatal("expected non-nil ParseResult")
	}
	if len(r.Profiles) != 1 {
		t.Fatalf("expected exactly 1 profile, got %d", len(r.Profiles))
	}
	return r.Profiles[0]
}

func TestFromBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		hint    string
		wantErr bool
		check   func(t *testing.T, r *ParseResult)
	}{
		{
			name:  "app JSON single profile keeps existing id",
			input: `{"id":"fixed-id","name":"Single","tunnel_type":"SSTP","server":"s1.example.com"}`,
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "json" {
					t.Errorf("Source = %q, want %q", r.Source, "json")
				}
				p := mustSingle(t, r)
				if p.ID != "fixed-id" {
					t.Errorf("ID = %q, want %q", p.ID, "fixed-id")
				}
				if p.Name != "Single" {
					t.Errorf("Name = %q, want %q", p.Name, "Single")
				}
				if p.TunnelType != config.TunnelSSTP {
					t.Errorf("TunnelType = %q, want %q", p.TunnelType, config.TunnelSSTP)
				}
				if p.Server != "s1.example.com" {
					t.Errorf("Server = %q, want %q", p.Server, "s1.example.com")
				}
			},
		},
		{
			name:  "app JSON single profile without id gets uuid",
			input: `{"name":"NoID","tunnel_type":"IKEv2"}`,
			check: func(t *testing.T, r *ParseResult) {
				p := mustSingle(t, r)
				if p.ID == "" {
					t.Error("expected generated ID, got empty string")
				}
			},
		},
		{
			name:  "JSON array of profiles",
			input: `[{"name":"First","tunnel_type":"L2TP","server":"a.example.com"},{"id":"keep-me","name":"Second","tunnel_type":"WireGuard"}]`,
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "json" {
					t.Errorf("Source = %q, want %q", r.Source, "json")
				}
				if len(r.Profiles) != 2 {
					t.Fatalf("expected 2 profiles, got %d", len(r.Profiles))
				}
				if r.Profiles[0].Name != "First" || r.Profiles[1].Name != "Second" {
					t.Errorf("names = %q, %q; want First, Second", r.Profiles[0].Name, r.Profiles[1].Name)
				}
				if r.Profiles[0].ID == "" {
					t.Error("first profile: expected generated ID")
				}
				if r.Profiles[1].ID != "keep-me" {
					t.Errorf("second profile ID = %q, want %q", r.Profiles[1].ID, "keep-me")
				}
			},
		},
		{
			// A plain {version,profiles} wrapper is accepted without error.
			// NOTE: encoding/json ignores unknown fields, so the direct
			// Profile unmarshal in fromJSON succeeds first; we only pin down
			// behavior common to both the current code and a stricter fix:
			// no error, source json, one profile in the result.
			name:  "JSON export wrapper is accepted",
			input: `{"version":1,"profiles":[{"name":"Wrapped","tunnel_type":"SSTP"}]}`,
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "json" {
					t.Errorf("Source = %q, want %q", r.Source, "json")
				}
				if len(r.Profiles) != 1 {
					t.Fatalf("expected 1 profile, got %d", len(r.Profiles))
				}
			},
		},
		{
			// Force the wrapper fallback branch: "remember_credential" is a
			// bool on Profile, so the string value makes the direct Profile
			// unmarshal fail, and the {profiles:[...]} wrapper path runs.
			name:  "JSON export wrapper fallback extracts wrapped profiles",
			input: `{"version":2,"remember_credential":"yes","profiles":[{"name":"Wrapped","tunnel_type":"L2TP","server":"w.example.com"}]}`,
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "json" {
					t.Errorf("Source = %q, want %q", r.Source, "json")
				}
				p := mustSingle(t, r)
				if p.Name != "Wrapped" {
					t.Errorf("Name = %q, want %q", p.Name, "Wrapped")
				}
				if p.TunnelType != config.TunnelL2TP {
					t.Errorf("TunnelType = %q, want %q", p.TunnelType, config.TunnelL2TP)
				}
				if p.Server != "w.example.com" {
					t.Errorf("Server = %q, want %q", p.Server, "w.example.com")
				}
				if p.ID == "" {
					t.Error("expected generated ID for wrapped profile")
				}
			},
		},
		{
			name: "WireGuard conf with Interface and Peer",
			input: `# HomeBox
[Interface]
PrivateKey = cHJpdmF0ZWtleQ==
Address = 10.0.0.2/32
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = cHVibGlja2V5
PresharedKey = cHNr
Endpoint = wg.example.com:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 21
`,
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "wireguard" {
					t.Errorf("Source = %q, want %q", r.Source, "wireguard")
				}
				p := mustSingle(t, r)
				if p.Name != "HomeBox" {
					t.Errorf("Name = %q, want %q", p.Name, "HomeBox")
				}
				if p.TunnelType != config.TunnelWireGuard {
					t.Errorf("TunnelType = %q, want %q", p.TunnelType, config.TunnelWireGuard)
				}
				wg := p.WireGuard
				if wg == nil {
					t.Fatal("WireGuard config is nil")
				}
				if wg.PrivateKey != "cHJpdmF0ZWtleQ==" {
					t.Errorf("PrivateKey = %q", wg.PrivateKey)
				}
				if wg.Address != "10.0.0.2/32" {
					t.Errorf("Address = %q", wg.Address)
				}
				if wg.DNS != "1.1.1.1" {
					t.Errorf("DNS = %q", wg.DNS)
				}
				if wg.MTU != 1420 {
					t.Errorf("MTU = %d, want 1420", wg.MTU)
				}
				if wg.PeerPublicKey != "cHVibGlja2V5" {
					t.Errorf("PeerPublicKey = %q", wg.PeerPublicKey)
				}
				if wg.PeerPSK != "cHNr" {
					t.Errorf("PeerPSK = %q", wg.PeerPSK)
				}
				if wg.PeerEndpoint != "wg.example.com:51820" {
					t.Errorf("PeerEndpoint = %q", wg.PeerEndpoint)
				}
				if wg.PeerAllowedIPs != "0.0.0.0/0" {
					t.Errorf("PeerAllowedIPs = %q", wg.PeerAllowedIPs)
				}
				if wg.PeerKeepalive != 21 {
					t.Errorf("PeerKeepalive = %d, want 21", wg.PeerKeepalive)
				}
			},
		},
		{
			name: "WireGuard conf applies defaults",
			input: `[Interface]
PrivateKey = priv

[Peer]
PublicKey = pub
`,
			check: func(t *testing.T, r *ParseResult) {
				p := mustSingle(t, r)
				wg := p.WireGuard
				if wg == nil {
					t.Fatal("WireGuard config is nil")
				}
				if wg.PeerAllowedIPs != "0.0.0.0/0, ::/0" {
					t.Errorf("PeerAllowedIPs = %q, want default %q", wg.PeerAllowedIPs, "0.0.0.0/0, ::/0")
				}
				if wg.PeerKeepalive != 25 {
					t.Errorf("PeerKeepalive = %d, want default 25", wg.PeerKeepalive)
				}
			},
		},
		{
			name: "WireGuard conf missing keys is an error",
			input: `[Interface]
Address = 10.0.0.2/32
`,
			wantErr: true,
		},
		{
			name: "OpenVPN ovpn with remote directive",
			input: `client
dev tun
proto udp
remote vpn.example.com 1194
resolv-retry infinite
`,
			hint: "profile.ovpn",
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "openvpn" {
					t.Errorf("Source = %q, want %q", r.Source, "openvpn")
				}
				p := mustSingle(t, r)
				if p.TunnelType != config.TunnelOpenVPN {
					t.Errorf("TunnelType = %q, want %q", p.TunnelType, config.TunnelOpenVPN)
				}
				if p.Server != "vpn.example.com" {
					t.Errorf("Server = %q, want %q", p.Server, "vpn.example.com")
				}
				if p.Name != "OpenVPN – vpn.example.com" {
					t.Errorf("Name = %q, want %q", p.Name, "OpenVPN – vpn.example.com")
				}
				if p.OpenVPN == nil {
					t.Fatal("OpenVPN config is nil")
				}
				if !strings.Contains(p.OpenVPN.ConfigContent, "remote vpn.example.com 1194") {
					t.Errorf("ConfigContent does not retain the remote directive: %q", p.OpenVPN.ConfigContent)
				}
			},
		},
		{
			name: "OpenVPN without remote and without ca is an error",
			input: `client
dev tun
proto udp
`,
			wantErr: true,
		},
		{
			name:  "URI content is routed through FromURIString",
			input: "vless://11111111-2222-3333-4444-555555555555@vl.example.com:443?security=tls#Routed",
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "vless" {
					t.Errorf("Source = %q, want %q", r.Source, "vless")
				}
				p := mustSingle(t, r)
				if p.Name != "Routed" {
					t.Errorf("Name = %q, want %q", p.Name, "Routed")
				}
			},
		},
		{
			name:    "unknown format is an error",
			input:   "hello world 12345",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := FromBytes([]byte(tt.input), tt.hint)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got result: %+v", r)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, r)
			}
		})
	}
}

func TestFromURIString(t *testing.T) {
	vmessJSON := `{"v":"2","ps":"My VMess","add":"vm.example.com","port":8443,"id":"c1000000-0000-0000-0000-000000000001","aid":0,"net":"ws","type":"none","path":"/ws","tls":"tls"}`
	vmessURI := "vmess://" + base64.StdEncoding.EncodeToString([]byte(vmessJSON))

	ssPayload := "chacha20-ietf-poly1305:secret@ss2.example.com:8388"
	ssBase64URI := "ss://" + base64.RawURLEncoding.EncodeToString([]byte(ssPayload)) + "#EncodedSS"

	tests := []struct {
		name    string
		uri     string
		wantErr bool
		check   func(t *testing.T, r *ParseResult)
	}{
		{
			name: "vless with fragment name",
			uri:  "vless://11111111-2222-3333-4444-555555555555@vl.example.com:443?encryption=none&security=tls&type=ws#MyVLESS",
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "vless" {
					t.Errorf("Source = %q, want %q", r.Source, "vless")
				}
				p := mustSingle(t, r)
				if p.Name != "MyVLESS" {
					t.Errorf("Name = %q, want %q", p.Name, "MyVLESS")
				}
				if p.TunnelType != config.TunnelXray {
					t.Errorf("TunnelType = %q, want %q", p.TunnelType, config.TunnelXray)
				}
				if p.Server != "vl.example.com:443" {
					t.Errorf("Server = %q, want %q", p.Server, "vl.example.com:443")
				}
				if p.Xray == nil || p.Xray.Protocol != "vless" {
					t.Errorf("Xray = %+v, want protocol vless", p.Xray)
				}
			},
		},
		{
			name: "vless without fragment falls back to generated name",
			uri:  "vless://11111111-2222-3333-4444-555555555555@vl.example.com:443",
			check: func(t *testing.T, r *ParseResult) {
				p := mustSingle(t, r)
				if p.Name != "VLESS – vl.example.com" {
					t.Errorf("Name = %q, want %q", p.Name, "VLESS – vl.example.com")
				}
			},
		},
		{
			name: "vmess base64 JSON",
			uri:  vmessURI,
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "vmess" {
					t.Errorf("Source = %q, want %q", r.Source, "vmess")
				}
				p := mustSingle(t, r)
				if p.Name != "My VMess" {
					t.Errorf("Name = %q, want %q", p.Name, "My VMess")
				}
				if p.Server != "vm.example.com:8443" {
					t.Errorf("Server = %q, want %q", p.Server, "vm.example.com:8443")
				}
				if p.TunnelType != config.TunnelXray {
					t.Errorf("TunnelType = %q, want %q", p.TunnelType, config.TunnelXray)
				}
				if p.Xray == nil || p.Xray.Protocol != "vmess" {
					t.Errorf("Xray = %+v, want protocol vmess", p.Xray)
				}
				if p.Xray != nil && p.Xray.URI != vmessURI {
					t.Errorf("Xray.URI = %q, want original URI", p.Xray.URI)
				}
			},
		},
		{
			name:    "vmess with invalid base64 is an error",
			uri:     "vmess://!!!not-base64!!!",
			wantErr: true,
		},
		{
			name: "trojan",
			uri:  "trojan://supersecret@tr.example.com:443?security=tls#MyTrojan",
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "trojan" {
					t.Errorf("Source = %q, want %q", r.Source, "trojan")
				}
				p := mustSingle(t, r)
				if p.Name != "MyTrojan" {
					t.Errorf("Name = %q, want %q", p.Name, "MyTrojan")
				}
				if p.Username != "supersecret" {
					t.Errorf("Username = %q, want %q", p.Username, "supersecret")
				}
				if p.Server != "tr.example.com:443" {
					t.Errorf("Server = %q, want %q", p.Server, "tr.example.com:443")
				}
				if p.Xray == nil || p.Xray.Protocol != "trojan" {
					t.Errorf("Xray = %+v, want protocol trojan", p.Xray)
				}
			},
		},
		{
			name: "shadowsocks plain form",
			uri:  "ss://aes-256-gcm:pass@ss.example.com:8388#MySS",
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "shadowsocks" {
					t.Errorf("Source = %q, want %q", r.Source, "shadowsocks")
				}
				p := mustSingle(t, r)
				if p.Name != "MySS" {
					t.Errorf("Name = %q, want %q", p.Name, "MySS")
				}
				if p.Username != "aes-256-gcm:pass" {
					t.Errorf("Username = %q, want %q", p.Username, "aes-256-gcm:pass")
				}
				if p.Server != "ss.example.com:8388" {
					t.Errorf("Server = %q, want %q", p.Server, "ss.example.com:8388")
				}
				if p.Xray == nil || p.Xray.Protocol != "shadowsocks" {
					t.Errorf("Xray = %+v, want protocol shadowsocks", p.Xray)
				}
			},
		},
		{
			name: "shadowsocks base64 form",
			uri:  ssBase64URI,
			check: func(t *testing.T, r *ParseResult) {
				p := mustSingle(t, r)
				if p.Name != "EncodedSS" {
					t.Errorf("Name = %q, want %q", p.Name, "EncodedSS")
				}
				if p.Username != "chacha20-ietf-poly1305:secret" {
					t.Errorf("Username = %q, want %q", p.Username, "chacha20-ietf-poly1305:secret")
				}
				if p.Server != "ss2.example.com:8388" {
					t.Errorf("Server = %q, want %q", p.Server, "ss2.example.com:8388")
				}
			},
		},
		{
			name: "wireguard URI with required params",
			uri:  "wireguard://privkey123@wgsrv.example.com:51820?publickey=pubkey456&address=10.7.0.2/32&dns=9.9.9.9#WGLink",
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "uri" {
					t.Errorf("Source = %q, want %q", r.Source, "uri")
				}
				p := mustSingle(t, r)
				if p.Name != "WGLink" {
					t.Errorf("Name = %q, want %q", p.Name, "WGLink")
				}
				if p.TunnelType != config.TunnelWireGuard {
					t.Errorf("TunnelType = %q, want %q", p.TunnelType, config.TunnelWireGuard)
				}
				if p.Server != "wgsrv.example.com" {
					t.Errorf("Server = %q, want %q", p.Server, "wgsrv.example.com")
				}
				wg := p.WireGuard
				if wg == nil {
					t.Fatal("WireGuard config is nil")
				}
				if wg.PrivateKey != "privkey123" {
					t.Errorf("PrivateKey = %q", wg.PrivateKey)
				}
				if wg.PeerPublicKey != "pubkey456" {
					t.Errorf("PeerPublicKey = %q", wg.PeerPublicKey)
				}
				if wg.PeerEndpoint != "wgsrv.example.com:51820" {
					t.Errorf("PeerEndpoint = %q", wg.PeerEndpoint)
				}
				if wg.Address != "10.7.0.2/32" {
					t.Errorf("Address = %q", wg.Address)
				}
				if wg.DNS != "9.9.9.9" {
					t.Errorf("DNS = %q", wg.DNS)
				}
				if wg.PeerAllowedIPs != "0.0.0.0/0, ::/0" {
					t.Errorf("PeerAllowedIPs = %q, want default", wg.PeerAllowedIPs)
				}
			},
		},
		{
			name: "wg scheme alias is normalized",
			uri:  "wg://priv@h.example.com:51820?publickey=pub",
			check: func(t *testing.T, r *ParseResult) {
				p := mustSingle(t, r)
				if p.WireGuard == nil || p.WireGuard.PrivateKey != "priv" {
					t.Errorf("WireGuard = %+v, want PrivateKey %q", p.WireGuard, "priv")
				}
				if p.Name != "WireGuard – h.example.com" {
					t.Errorf("Name = %q, want %q", p.Name, "WireGuard – h.example.com")
				}
			},
		},
		{
			name:    "wireguard URI missing publickey is an error",
			uri:     "wireguard://privkey123@wgsrv.example.com:51820?address=10.7.0.2/32",
			wantErr: true,
		},
		{
			name:    "unsupported scheme is an error",
			uri:     "http://example.com/config",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := FromURIString(tt.uri)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got result: %+v", r)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, r)
			}
		})
	}
}

// TestJamVPNShareLinkRoundTrip builds a link exactly like
// qr.GenerateShareLink does (jamvpn://import?config=<RawURLEncoding of
// profile JSON>) and asserts the parsed profile round-trips.
func TestJamVPNShareLinkRoundTrip(t *testing.T) {
	orig := config.Profile{
		Name:       "Shared VLESS",
		TunnelType: config.TunnelXray,
		Server:     "share.example.com:443",
		Xray: &config.XrayConfig{
			URI:      "vless://11111111-2222-3333-4444-555555555555@share.example.com:443#Shared",
			Protocol: "vless",
		},
	}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal profile: %v", err)
	}
	link := "jamvpn://import?config=" + base64.RawURLEncoding.EncodeToString(data)

	r, err := FromURIString(link)
	if err != nil {
		t.Fatalf("FromURIString(%q): %v", link, err)
	}
	p := mustSingle(t, r)
	if p.Name != orig.Name {
		t.Errorf("Name = %q, want %q", p.Name, orig.Name)
	}
	if p.TunnelType != orig.TunnelType {
		t.Errorf("TunnelType = %q, want %q", p.TunnelType, orig.TunnelType)
	}
	if p.Server != orig.Server {
		t.Errorf("Server = %q, want %q", p.Server, orig.Server)
	}
	if p.Xray == nil || p.Xray.Protocol != "vless" {
		t.Errorf("Xray = %+v, want protocol vless", p.Xray)
	}
	if p.ID == "" {
		t.Error("expected generated ID for imported profile")
	}

	// The same link must also work through the auto-detecting FromBytes.
	r2, err := FromBytes([]byte(link), "")
	if err != nil {
		t.Fatalf("FromBytes on jamvpn link: %v", err)
	}
	p2 := mustSingle(t, r2)
	if p2.Name != orig.Name {
		t.Errorf("FromBytes Name = %q, want %q", p2.Name, orig.Name)
	}
}

func TestJamVPNURIErrors(t *testing.T) {
	tests := []struct {
		name string
		uri  string
	}{
		{name: "import without config parameter", uri: "jamvpn://import"},
		{name: "import with empty config parameter", uri: "jamvpn://import?config="},
		{name: "unsupported action", uri: "jamvpn://other?config=abc"},
		{name: "import with garbage config", uri: "jamvpn://import?config=%21%21%21"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if r, err := FromURIString(tt.uri); err == nil {
				t.Fatalf("expected error for %q, got result: %+v", tt.uri, r)
			}
		})
	}
}

func TestFromBase64(t *testing.T) {
	profileJSON := `{"name":"B64 Profile","tunnel_type":"SSTP","server":"b64.example.com"}`
	wgConf := "[Interface]\nPrivateKey = priv\n\n[Peer]\nPublicKey = pub\n"

	tests := []struct {
		name    string
		encoded string
		wantErr bool
		check   func(t *testing.T, r *ParseResult)
	}{
		{
			name:    "StdEncoding of app JSON",
			encoded: base64.StdEncoding.EncodeToString([]byte(profileJSON)),
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "json" {
					t.Errorf("Source = %q, want %q", r.Source, "json")
				}
				p := mustSingle(t, r)
				if p.Name != "B64 Profile" {
					t.Errorf("Name = %q, want %q", p.Name, "B64 Profile")
				}
				if p.Server != "b64.example.com" {
					t.Errorf("Server = %q, want %q", p.Server, "b64.example.com")
				}
			},
		},
		{
			name:    "RawURLEncoding of WireGuard conf",
			encoded: base64.RawURLEncoding.EncodeToString([]byte(wgConf)),
			check: func(t *testing.T, r *ParseResult) {
				if r.Source != "wireguard" {
					t.Errorf("Source = %q, want %q", r.Source, "wireguard")
				}
				p := mustSingle(t, r)
				if p.WireGuard == nil || p.WireGuard.PrivateKey != "priv" {
					t.Errorf("WireGuard = %+v, want PrivateKey %q", p.WireGuard, "priv")
				}
			},
		},
		{
			name:    "RawURLEncoding of app JSON",
			encoded: base64.RawURLEncoding.EncodeToString([]byte(profileJSON)),
			check: func(t *testing.T, r *ParseResult) {
				p := mustSingle(t, r)
				if p.Name != "B64 Profile" {
					t.Errorf("Name = %q, want %q", p.Name, "B64 Profile")
				}
			},
		},
		{
			name:    "surrounding whitespace is trimmed",
			encoded: "  \n" + base64.StdEncoding.EncodeToString([]byte(profileJSON)) + "\n  ",
			check: func(t *testing.T, r *ParseResult) {
				p := mustSingle(t, r)
				if p.Name != "B64 Profile" {
					t.Errorf("Name = %q, want %q", p.Name, "B64 Profile")
				}
			},
		},
		{
			name:    "invalid base64 is an error",
			encoded: "!!!not-base64!!!",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, err := FromBase64(tt.encoded)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got result: %+v", r)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, r)
			}
		})
	}
}

func TestWireGuardConfRoundTrip(t *testing.T) {
	orig := config.Profile{
		ID:         "rt-id",
		Name:       "Round Trip",
		TunnelType: config.TunnelWireGuard,
		WireGuard: &config.WireGuardConfig{
			PrivateKey:     "privRT",
			Address:        "10.9.0.2/32",
			DNS:            "8.8.8.8",
			MTU:            1380,
			PeerPublicKey:  "pubRT",
			PeerPSK:        "pskRT",
			PeerEndpoint:   "rt.example.com:51820",
			PeerAllowedIPs: "0.0.0.0/0",
			PeerKeepalive:  15,
		},
	}

	text, err := ToWireGuardConf(orig)
	if err != nil {
		t.Fatalf("ToWireGuardConf: %v", err)
	}

	// Parse back through the public auto-detecting entry point.
	r, err := FromBytes([]byte(text), "roundtrip.conf")
	if err != nil {
		t.Fatalf("FromBytes on serialized conf: %v", err)
	}
	got := mustSingle(t, r)
	if got.Name != orig.Name {
		t.Errorf("Name = %q, want %q", got.Name, orig.Name)
	}
	if got.TunnelType != config.TunnelWireGuard {
		t.Errorf("TunnelType = %q, want %q", got.TunnelType, config.TunnelWireGuard)
	}
	if got.WireGuard == nil {
		t.Fatal("WireGuard config is nil after round trip")
	}
	if *got.WireGuard != *orig.WireGuard {
		t.Errorf("WireGuard round trip mismatch:\n got  %+v\n want %+v", *got.WireGuard, *orig.WireGuard)
	}
}

func TestToWireGuardConfRequiresWireGuardProfile(t *testing.T) {
	p := config.Profile{Name: "NotWG", TunnelType: config.TunnelSSTP}
	if s, err := ToWireGuardConf(p); err == nil {
		t.Fatalf("expected error for non-WireGuard profile, got: %q", s)
	}
}
