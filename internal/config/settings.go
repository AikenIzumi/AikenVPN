package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// AppSettings holds application-wide preferences (not per-profile).
type AppSettings struct {
	// General
	Theme          string `json:"theme"` // "dark" | "light"
	StartAtLogin   bool   `json:"start_at_login"`
	StartMinimized bool   `json:"start_minimized"`
	CloseAction    string `json:"close_action"` // "hide" | "quit"
	AutoConnect    bool   `json:"auto_connect"` // connect last profile on startup

	// Routing
	BypassLAN    bool   `json:"bypass_lan"`    // auto-bypass RFC 1918 (LAN traffic)
	BypassRegion string `json:"bypass_region"` // "" | "ru" | "ua" | "by" — preset bypass list
	BlockAds     bool   `json:"block_ads"`     // (reserved — DNS sinkhole, future)

	// DNS
	VpnDNS    string `json:"vpn_dns"`    // DNS set on VPN adapter after connect, e.g. "1.1.1.1"
	DirectDNS string `json:"direct_dns"` // DNS for direct (non-VPN) traffic, e.g. "8.8.8.8"

	// Logging
	LogLevel string `json:"log_level"` // "debug" | "info" | "warn" | "error"
}

// DefaultSettings returns sensible out-of-the-box values.
func DefaultSettings() AppSettings {
	return AppSettings{
		Theme:       "dark",
		CloseAction: "hide",
		LogLevel:    "info",
	}
}

// SettingsStore manages AppSettings on disk (thread-safe).
type SettingsStore struct {
	mu   sync.RWMutex
	path string
	data AppSettings
}

// NewSettingsStore loads (or creates) settings.json in dir.
func NewSettingsStore(dir string) (*SettingsStore, error) {
	ss := &SettingsStore{
		path: filepath.Join(dir, "settings.json"),
		data: DefaultSettings(),
	}
	raw, err := os.ReadFile(ss.path)
	if os.IsNotExist(err) {
		return ss, ss.save()
	}
	if err != nil {
		return ss, nil // ignore read error, use defaults
	}
	_ = json.Unmarshal(raw, &ss.data)
	return ss, nil
}

// Get returns a copy of the current settings.
func (ss *SettingsStore) Get() AppSettings {
	ss.mu.RLock()
	defer ss.mu.RUnlock()
	return ss.data
}

// Set replaces the current settings and persists them.
func (ss *SettingsStore) Set(s AppSettings) error {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	old := ss.data
	ss.data = s
	if err := ss.save(); err != nil {
		ss.data = old
		return err
	}
	return nil
}

func (ss *SettingsStore) save() error {
	data, err := json.MarshalIndent(ss.data, "", "  ")
	if err != nil {
		return err
	}
	return writeConfigFile(ss.path, data)
}

// BypassRegionCIDRs returns a preset list of CIDR ranges to bypass for a
// region code. Currently only "ru" is populated; other regions return nil.
func BypassRegionCIDRs(region string) []string {
	switch region {
	case "ru":
		// Core Russian address blocks (approximation — add/remove as needed)
		return []string{
			"5.8.0.0/16",
			"5.16.0.0/15",
			"5.45.192.0/18",
			"5.61.0.0/17",
			"5.100.0.0/14",
			"31.13.0.0/16",
			"31.148.0.0/16",
			"31.173.0.0/16",
			"37.9.0.0/16",
			"37.18.64.0/18",
			"45.8.248.0/21",
			"45.84.0.0/14",
			"77.72.0.0/14",
			"77.88.0.0/18",
			"79.137.0.0/17",
			"81.16.0.0/14",
			"81.176.0.0/16",
			"82.138.0.0/16",
			"85.141.0.0/16",
			"87.240.0.0/16",
			"87.250.250.0/24",
			"91.108.4.0/22",    // Telegram
			"91.108.56.0/22",   // Telegram
			"149.154.160.0/20", // Telegram
			"93.184.0.0/15",
			"95.173.128.0/17",
			"178.154.0.0/16",
			"185.30.176.0/22",
			"199.16.156.0/22", // Twitter
			"185.117.64.0/22",
			"213.180.192.0/18", // Yandex
			"213.248.0.0/18",
		}
	case "ua":
		return []string{
			"31.40.0.0/14",
			"46.96.0.0/11",
			"77.48.0.0/14",
			"84.252.0.0/14",
			"91.196.0.0/14",
			"176.36.0.0/14",
			"195.5.0.0/16",
		}
	case "by":
		return []string{
			"5.188.0.0/14",
			"37.214.0.0/15",
			"82.208.0.0/13",
			"178.120.0.0/13",
			"185.134.0.0/15",
		}
	}
	return nil
}

// RFC1918Prefixes returns the standard private / link-local IPv4 blocks.
func RFC1918Prefixes() []string {
	return []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16", // link-local
		"127.0.0.0/8",    // loopback
	}
}
