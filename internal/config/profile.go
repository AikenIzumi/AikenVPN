package config

import "time"

// TunnelType defines supported VPN protocol types
type TunnelType string

const (
	TunnelL2TP        TunnelType = "L2TP"
	TunnelIKEv2       TunnelType = "IKEv2"
	TunnelSSTP        TunnelType = "SSTP"
	TunnelPPTP        TunnelType = "PPTP"
	TunnelWireGuard   TunnelType = "WireGuard"
	TunnelOpenVPN     TunnelType = "OpenVPN"
	TunnelXray        TunnelType = "Xray" // VMess / VLESS / Trojan / Shadowsocks
)

// AuthMethod for Windows RAS based tunnels
type AuthMethod string

const (
	AuthMsChapv2 AuthMethod = "MsChapv2"
	AuthChap     AuthMethod = "Chap"
	AuthPap      AuthMethod = "Pap"
	AuthEap      AuthMethod = "Eap"
)

// Encryption level for Windows RAS
type Encryption string

const (
	EncryptionOptional   Encryption = "Optional"
	EncryptionRequired   Encryption = "Required"
	EncryptionMaxLevel   Encryption = "Maximum"
	EncryptionNoEncrypt  Encryption = "NoEncryption"
)

// WireGuardConfig holds WireGuard specific settings
type WireGuardConfig struct {
	PrivateKey string `json:"private_key"`
	Address    string `json:"address"`
	DNS        string `json:"dns"`
	MTU        int    `json:"mtu,omitempty"`

	PeerPublicKey  string `json:"peer_public_key"`
	PeerPSK        string `json:"peer_psk,omitempty"`
	PeerEndpoint   string `json:"peer_endpoint"`
	PeerAllowedIPs string `json:"peer_allowed_ips"`
	PeerKeepalive  int    `json:"peer_keepalive,omitempty"`
}

// OpenVPNConfig holds OpenVPN specific settings
type OpenVPNConfig struct {
	ConfigContent string `json:"config_content"` // raw .ovpn file content
	Username      string `json:"username,omitempty"`
	Password      string `json:"password,omitempty"`
}

// XrayConfig holds settings for Xray-core based protocols (VMess/VLESS/Trojan/Shadowsocks)
type XrayConfig struct {
	URI            string `json:"uri"`              // original URI (vmess://, vless://, trojan://, ss://)
	Protocol       string `json:"protocol"`          // vmess, vless, trojan, shadowsocks
	LocalSOCKSPort int    `json:"local_socks_port"` // default 10808
	LocalHTTPPort  int    `json:"local_http_port"`  // default 10809
}

// SplitTunnelMode controls which traffic is routed through the VPN.
type SplitTunnelMode string

const (
	SplitTunnelOff     SplitTunnelMode = ""        // no split — all traffic through VPN
	SplitTunnelBypass  SplitTunnelMode = "bypass"  // all through VPN except listed
	SplitTunnelInclude SplitTunnelMode = "include"  // only listed goes through VPN
)

// SplitTunnelConfig holds per-profile split-tunnel rules.
// Domains may be hostnames, bare IPs, or CIDR ranges (e.g. "192.168.0.0/16").
// Apps are .exe filenames or full paths (e.g. "chrome.exe").
type SplitTunnelConfig struct {
	Mode    SplitTunnelMode `json:"mode"`
	Domains []string        `json:"domains,omitempty"`
	Apps    []string        `json:"apps,omitempty"`
}

// Profile represents a VPN connection profile
type Profile struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	TunnelType  TunnelType `json:"tunnel_type"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastUsed    *time.Time `json:"last_used,omitempty"`
	IsFavorite  bool       `json:"is_favorite"`
	Color       string     `json:"color,omitempty"` // accent color hex

	// Common RAS fields (L2TP/IKEv2/SSTP/PPTP)
	Server             string     `json:"server,omitempty"`
	Username           string     `json:"username,omitempty"`
	Password           string     `json:"password,omitempty"`
	PresharedKey       string     `json:"preshared_key,omitempty"`
	AuthMethod         AuthMethod `json:"auth_method,omitempty"`
	Encryption         Encryption `json:"encryption,omitempty"`
	RememberCredential bool       `json:"remember_credential"`
	SplitTunneling     bool       `json:"split_tunneling"`
	SkipCertCheck      bool       `json:"skip_cert_check"`
	UseWinlogonCred    bool       `json:"use_winlogon_cred,omitempty"`

	// Split tunneling rules (all protocols)
	SplitTunnel *SplitTunnelConfig `json:"split_tunnel,omitempty"`

	// Protocol-specific configs
	WireGuard *WireGuardConfig `json:"wireguard,omitempty"`
	OpenVPN   *OpenVPNConfig   `json:"openvpn,omitempty"`
	Xray      *XrayConfig      `json:"xray,omitempty"`
}

// ConnectionState represents the VPN connection state
type ConnectionState string

const (
	StateDisconnected  ConnectionState = "Disconnected"
	StateConnecting    ConnectionState = "Connecting"
	StateConnected     ConnectionState = "Connected"
	StateDisconnecting ConnectionState = "Disconnecting"
	StateError         ConnectionState = "Error"
)

// ConnectionStatus is returned to the frontend
type ConnectionStatus struct {
	ProfileID   string          `json:"profile_id"`
	ProfileName string          `json:"profile_name"`
	State       ConnectionState `json:"state"`
	ErrorMsg    string          `json:"error,omitempty"`
	ConnectedAt *time.Time      `json:"connected_at,omitempty"`
	LocalIP     string          `json:"local_ip,omitempty"`
	ServerIP    string          `json:"server_ip,omitempty"`
	BytesSent   int64           `json:"bytes_sent,omitempty"`
	BytesRecv   int64           `json:"bytes_recv,omitempty"`
}
