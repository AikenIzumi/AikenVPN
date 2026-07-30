package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
	"github.com/jamalfa/jamvpn/internal/nettest"
	"github.com/jamalfa/jamvpn/internal/parser"
	"github.com/jamalfa/jamvpn/internal/qr"
	"github.com/jamalfa/jamvpn/internal/vpn"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the main application struct exposed to the Wails frontend
type App struct {
	ctx     context.Context
	store   *config.Store
	settings *config.SettingsStore
	manager *vpn.Manager

	statusTicker         *time.Ticker
	stopTicker           chan struct{}
	selectedTrayProfileID string // last profile selected for tray quick-connect
}

// NewApp creates a new App
func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Init store and logger in %APPDATA%\JamVPN
	appData, _ := os.UserConfigDir()
	storeDir := filepath.Join(appData, "JamVPN")
	logger.Init(storeDir)
	logger.Info("startup: storeDir=%s", storeDir)
	store, err := config.NewStore(storeDir)
	if err != nil {
		wailsruntime.LogErrorf(ctx, "store init: %v", err)
		store, _ = config.NewStore(".")
	}
	a.store = store

	ss, _ := config.NewSettingsStore(storeDir)
	a.settings = ss
	a.manager = vpn.NewManager()
	a.manager.SetSettings(ss.Get())

	// Migrate old profiles.json if present alongside the exe
	a.migrateOldProfiles()

	// On startup, clean up any VPN entries left from previous sessions
	// (in background so it doesn't delay the UI)
	go func() {
		profiles := a.store.GetAll()
		for _, p := range profiles {
			switch p.TunnelType {
			case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
				vpn.ForceCleanupRAS(p.Name)
			}
		}
		logger.Info("startup: VPN entry cleanup done (%d profiles checked)", len(profiles))

		// Auto-connect to last used profile if setting is enabled
		if a.settings.Get().AutoConnect {
			last := lastUsedProfile(profiles)
			if last != nil {
				logger.Info("startup: auto-connect → '%s'", last.Name)
				_ = a.manager.Connect(*last)
				a.store.TouchLastUsed(last.ID)
			}
		}
	}()

	// Init system tray
	initTray(a)

	// Start status polling. Emit the event only when the status actually
	// changes — the old code fired every 2s regardless, which rebuilt the tray
	// menu and pushed an IPC message on every tick, keeping the process from
	// ever reaching idle. The frontend already ignores unchanged status, so
	// change-only emission is transparent to it.
	a.stopTicker = make(chan struct{})
	a.statusTicker = time.NewTicker(2 * time.Second)
	go func() {
		var lastKey string
		first := true
		for {
			select {
			case <-a.statusTicker.C:
				status := a.manager.Status()
				key := statusKey(status)
				if first || key != lastKey {
					wailsruntime.EventsEmit(a.ctx, "vpn:status", status)
					lastKey = key
					first = false
				}
			case <-a.stopTicker:
				return
			}
		}
	}()
}

// statusKey returns a compact fingerprint of the fields the UI/tray react to,
// so the status ticker can skip emitting when nothing meaningful changed.
func statusKey(s config.ConnectionStatus) string {
	at := ""
	if s.ConnectedAt != nil {
		at = s.ConnectedAt.Format(time.RFC3339)
	}
	return string(s.State) + "|" + s.ProfileID + "|" + s.ErrorMsg + "|" +
		s.ServerIP + "|" + s.LocalIP + "|" + at
}

func (a *App) shutdown(ctx context.Context) {
	if a.stopTicker != nil {
		close(a.stopTicker)
	}
	if a.statusTicker != nil {
		a.statusTicker.Stop()
	}
	_ = a.manager.Disconnect()
}

// ─── Profile Management ────────────────────────────────────────────────────

// GetProfiles returns all saved VPN profiles
func (a *App) GetProfiles() []config.Profile {
	return a.store.GetAll()
}

// GetProfile returns a single profile by ID
func (a *App) GetProfile(id string) (*config.Profile, error) {
	p, ok := a.store.GetByID(id)
	if !ok {
		return nil, fmt.Errorf("profile not found: %s", id)
	}
	return p, nil
}

// SaveProfile creates or updates a profile
func (a *App) SaveProfile(p config.Profile) (config.Profile, error) {
	if p.ID == "" {
		return a.store.Add(p)
	}
	if _, ok := a.store.GetByID(p.ID); !ok {
		return a.store.Add(p)
	}
	return p, a.store.Update(p)
}

// DeleteProfile removes a profile by ID
func (a *App) DeleteProfile(id string) error {
	return a.store.Delete(id)
}

// ─── VPN Connection ────────────────────────────────────────────────────────

// Connect establishes a VPN connection for the given profile ID
func (a *App) Connect(id string) error {
	p, ok := a.store.GetByID(id)
	if !ok {
		return fmt.Errorf("profile not found: %s", id)
	}
	a.selectedTrayProfileID = id

	wailsruntime.EventsEmit(a.ctx, "vpn:status", config.ConnectionStatus{
		ProfileID:   p.ID,
		ProfileName: p.Name,
		State:       config.StateConnecting,
	})

	// Connect is non-blocking — status events from the ticker carry success/error.
	a.manager.Connect(*p)
	a.store.TouchLastUsed(id)
	return nil
}

// RepairProfile force-removes any stuck Windows VPN entry for this profile.
// Runs ForceCleanupRAS in the background so it doesn't block the frontend.
func (a *App) RepairProfile(id string) error {
	p, ok := a.store.GetByID(id)
	if !ok {
		return fmt.Errorf("profile not found")
	}
	// Also disconnect in the manager so state is clean
	_ = a.manager.Disconnect()
	// Emit Disconnected immediately so the UI reacts
	wailsruntime.EventsEmit(a.ctx, "vpn:status", config.ConnectionStatus{
		State: config.StateDisconnected,
	})
	// Heavy cleanup in background — doesn't block the IPC call
	go func() {
		switch p.TunnelType {
		case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
			vpn.ForceCleanupRAS(p.Name)
		}
	}()
	return nil
}

// Disconnect terminates the current VPN connection
func (a *App) Disconnect() error {
	err := a.manager.Disconnect()
	wailsruntime.EventsEmit(a.ctx, "vpn:status", config.ConnectionStatus{
		State: config.StateDisconnected,
	})
	return err
}

// GetStatus returns the current VPN connection status
func (a *App) GetStatus() config.ConnectionStatus {
	return a.manager.Status()
}

// ─── Import ───────────────────────────────────────────────────────────────

// ImportFromURL downloads and parses a VPN configuration from a URL
func (a *App) ImportFromURL(rawURL string) ([]config.Profile, error) {
	result, err := parser.FromURL(rawURL)
	if err != nil {
		return nil, fmt.Errorf("import from URL: %w", err)
	}
	return a.saveImportedProfiles(result.Profiles)
}

// ImportFromText parses a VPN configuration from raw text
// (supports: WireGuard .conf, .ovpn, JSON, URI schemes)
func (a *App) ImportFromText(text string) ([]config.Profile, error) {
	result, err := parser.FromBytes([]byte(text), "")
	if err != nil {
		return nil, fmt.Errorf("import from text: %w", err)
	}
	return a.saveImportedProfiles(result.Profiles)
}

// ImportFromJSON parses a JSON VPN configuration (single profile or array)
func (a *App) ImportFromJSON(jsonText string) ([]config.Profile, error) {
	return a.ImportFromText(jsonText)
}

// ImportFromQR parses a VPN configuration from a QR code text content
func (a *App) ImportFromQR(qrText string) ([]config.Profile, error) {
	result, err := qr.ParseFromText(qrText)
	if err != nil {
		return nil, fmt.Errorf("import from QR: %w", err)
	}
	return a.saveImportedProfiles(result.Profiles)
}

// ImportFromFile reads and parses a VPN config file (opens file dialog)
func (a *App) ImportFromFile() ([]config.Profile, error) {
	filePath, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title: "Import VPN Configuration",
		Filters: []wailsruntime.FileFilter{
			{DisplayName: "VPN Configs (*.conf, *.ovpn, *.json)", Pattern: "*.conf;*.ovpn;*.json"},
			{DisplayName: "WireGuard (*.conf)", Pattern: "*.conf"},
			{DisplayName: "OpenVPN (*.ovpn)", Pattern: "*.ovpn"},
			{DisplayName: "JSON (*.json)", Pattern: "*.json"},
			{DisplayName: "All Files (*.*)", Pattern: "*.*"},
		},
	})
	if err != nil || filePath == "" {
		return nil, nil
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}
	result, err := parser.FromBytes(data, filePath)
	if err != nil {
		return nil, fmt.Errorf("parse file: %w", err)
	}
	return a.saveImportedProfiles(result.Profiles)
}

func (a *App) saveImportedProfiles(profiles []config.Profile) ([]config.Profile, error) {
	var saved []config.Profile
	for _, p := range profiles {
		s, err := a.store.Add(p)
		if err != nil {
			return saved, err
		}
		saved = append(saved, s)
	}
	return saved, nil
}

// ─── Export & Sharing ─────────────────────────────────────────────────────

// ExportProfileJSON returns the profile as a JSON string (for manual sharing)
func (a *App) ExportProfileJSON(id string) (string, error) {
	p, ok := a.store.GetByID(id)
	if !ok {
		return "", fmt.Errorf("profile not found")
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// ExportAllJSON exports all profiles as JSON
func (a *App) ExportAllJSON() (string, error) {
	profiles := a.store.GetAll()
	type exportWrapper struct {
		Version  int              `json:"version"`
		Profiles []config.Profile `json:"profiles"`
	}
	data, err := json.MarshalIndent(exportWrapper{Version: 2, Profiles: profiles}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// GenerateQR returns a base64-encoded PNG QR code for the given profile
func (a *App) GenerateQR(id string) (string, error) {
	p, ok := a.store.GetByID(id)
	if !ok {
		return "", fmt.Errorf("profile not found")
	}
	return qr.GeneratePNG(*p, 400)
}

// GenerateShareLink returns a shareable jamvpn:// link for the given profile
func (a *App) GenerateShareLink(id string) (string, error) {
	p, ok := a.store.GetByID(id)
	if !ok {
		return "", fmt.Errorf("profile not found")
	}
	return qr.GenerateShareLink(*p, "")
}

// ExportToFile saves the profile config to a file (opens save dialog)
func (a *App) ExportToFile(id string) error {
	p, ok := a.store.GetByID(id)
	if !ok {
		return fmt.Errorf("profile not found")
	}

	var defaultName, defaultExt string
	var filters []wailsruntime.FileFilter

	switch p.TunnelType {
	case config.TunnelWireGuard:
		defaultName = p.Name + ".conf"
		defaultExt = ".conf"
		filters = []wailsruntime.FileFilter{{DisplayName: "WireGuard Config (*.conf)", Pattern: "*.conf"}}
	case config.TunnelOpenVPN:
		defaultName = p.Name + ".ovpn"
		defaultExt = ".ovpn"
		filters = []wailsruntime.FileFilter{{DisplayName: "OpenVPN Config (*.ovpn)", Pattern: "*.ovpn"}}
	default:
		defaultName = p.Name + ".json"
		defaultExt = ".json"
		filters = []wailsruntime.FileFilter{{DisplayName: "JSON Config (*.json)", Pattern: "*.json"}}
	}

	savePath, err := wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:           "Export VPN Configuration",
		DefaultFilename: defaultName,
		Filters:         filters,
	})
	if err != nil || savePath == "" {
		return nil
	}

	// Generate content based on format
	var content string
	switch {
	case p.TunnelType == config.TunnelWireGuard && (defaultExt == ".conf"):
		content, err = parser.ToWireGuardConf(*p)
	default:
		var data []byte
		data, err = json.MarshalIndent(p, "", "  ")
		content = string(data)
	}
	if err != nil {
		return fmt.Errorf("generate config: %w", err)
	}

	return os.WriteFile(savePath, []byte(content), 0600)
}

// ─── Network Diagnostics ──────────────────────────────────────────────────

// PingServer measures TCP round-trip latency to the given host.
// Uses 5 probes on port 80/443.
func (a *App) PingServer(host string) nettest.PingResult {
	return nettest.Ping(host, 5, 3*time.Second)
}

// RunSpeedTest runs a download+upload speed test via Cloudflare.
// This may take 10–20 seconds.
func (a *App) RunSpeedTest() nettest.SpeedResult {
	return nettest.SpeedTest()
}

// ─── App Info ─────────────────────────────────────────────────────────────

// GetVersion returns the app version
func (a *App) GetVersion() string {
	return "2.2.0"
}

// ─── Migrations ───────────────────────────────────────────────────────────

// migrateOldProfiles imports profiles from the old Python app's vpn_profiles.json
func (a *App) migrateOldProfiles() {
	// Look for old format next to the exe
	candidates := []string{
		"vpn_profiles.json",
		filepath.Join("..", "vpn_profiles.json"),
		filepath.Join("_internal", "vpn_profiles.json"),
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var old struct {
			Version  int `json:"version"`
			Profiles []struct {
				Name               string `json:"name"`
				Server             string `json:"server"`
				TunnelType         string `json:"tunnel_type"`
				PresharedKey       string `json:"preshared_key"`
				Username           string `json:"username"`
				Password           string `json:"password"`
				AuthMethod         string `json:"auth_method"`
				Encryption         string `json:"encryption"`
				RememberCredential bool   `json:"remember_credential"`
				SplitTunneling     bool   `json:"split_tunneling"`
				SkipCertCheck      bool   `json:"skip_cert_check"`
				WgPrivateKey       string `json:"wg_private_key"`
				WgAddress          string `json:"wg_address"`
				WgDNS              string `json:"wg_dns"`
				WgPeerPubkey       string `json:"wg_peer_pubkey"`
				WgPeerPSK          string `json:"wg_peer_psk"`
				WgAllowedIPs       string `json:"wg_allowed_ips"`
				WgKeepalive        int    `json:"wg_keepalive"`
				OvpnConfig         string `json:"ovpn_config"`
			} `json:"profiles"`
		}

		if err := json.Unmarshal(data, &old); err != nil {
			continue
		}

		existing := a.store.GetAll()
		existingNames := make(map[string]bool)
		for _, ep := range existing {
			existingNames[ep.Name] = true
		}

		for _, op := range old.Profiles {
			if existingNames[op.Name] {
				continue
			}

			p := config.Profile{
				Name:               op.Name,
				Server:             op.Server,
				TunnelType:         config.TunnelType(op.TunnelType),
				PresharedKey:       op.PresharedKey,
				Username:           op.Username,
				Password:           op.Password,
				AuthMethod:         config.AuthMethod(op.AuthMethod),
				Encryption:         config.Encryption(op.Encryption),
				RememberCredential: op.RememberCredential,
				SplitTunneling:     op.SplitTunneling,
				SkipCertCheck:      op.SkipCertCheck,
			}

			if op.WgPrivateKey != "" {
				p.TunnelType = config.TunnelWireGuard
				p.WireGuard = &config.WireGuardConfig{
					PrivateKey:     op.WgPrivateKey,
					Address:        op.WgAddress,
					DNS:            op.WgDNS,
					PeerPublicKey:  op.WgPeerPubkey,
					PeerPSK:        op.WgPeerPSK,
					PeerAllowedIPs: op.WgAllowedIPs,
					PeerKeepalive:  op.WgKeepalive,
				}
			}

			if op.OvpnConfig != "" {
				p.TunnelType = config.TunnelOpenVPN
				p.OpenVPN = &config.OpenVPNConfig{
					ConfigContent: op.OvpnConfig,
					Username:      op.Username,
					Password:      op.Password,
				}
			}

			_, _ = a.store.Add(p)
		}
		break // Only migrate from first found
	}
}

// GetRunningApps returns names of currently running processes for the split-tunnel app picker.
func (a *App) GetRunningApps() []string {
	return vpn.GetRunningProcesses()
}

// ─── App Settings ─────────────────────────────────────────────────────────

// GetAppSettings returns the current application settings.
func (a *App) GetAppSettings() config.AppSettings {
	s := a.settings.Get()
	// Sync start_at_login from the registry (source of truth on Windows).
	s.StartAtLogin = vpn.GetAutoStart()
	return s
}

// SaveAppSettings persists new settings and applies side-effects immediately.
func (a *App) SaveAppSettings(s config.AppSettings) error {
	if err := a.settings.Set(s); err != nil {
		return err
	}
	a.manager.SetSettings(s)

	// Apply autostart to Windows registry
	_ = vpn.SetAutoStart(s.StartAtLogin)

	// Apply theme event so the frontend can react
	wailsruntime.EventsEmit(a.ctx, "settings:theme", s.Theme)

	logger.Info("settings: saved (theme=%s autostart=%v bypassLAN=%v region=%s)",
		s.Theme, s.StartAtLogin, s.BypassLAN, s.BypassRegion)
	return nil
}

// ── helpers ──────────────────────────────────────────────────────────────────

func lastUsedProfile(profiles []config.Profile) *config.Profile {
	var best *config.Profile
	for i := range profiles {
		p := &profiles[i]
		if p.LastUsed == nil {
			continue
		}
		if best == nil || p.LastUsed.After(*best.LastUsed) {
			best = p
		}
	}
	return best
}

// GetLogs returns the in-memory application log as a single string (exposed to frontend).
func (a *App) GetLogs() string {
	return logger.GetAll()
}

// GetLogPath returns the path to the log file on disk.
func (a *App) GetLogPath() string {
	return logger.LogPath()
}

// Ensure time is used
var _ = time.Now
