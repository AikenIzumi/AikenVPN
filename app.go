package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/energye/systray"
	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
	"github.com/jamalfa/jamvpn/internal/nettest"
	"github.com/jamalfa/jamvpn/internal/parser"
	"github.com/jamalfa/jamvpn/internal/qr"
	"github.com/jamalfa/jamvpn/internal/vpn"
	"github.com/wailsapp/wails/v2/pkg/options"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// App is the main application struct exposed to the Wails frontend
type App struct {
	ctx     context.Context
	store   *config.Store
	settings *config.SettingsStore
	manager *vpn.Manager

	statusTicker *time.Ticker
	stopTicker   chan struct{}

	trayMu                sync.Mutex
	selectedTrayProfileID string // last profile selected for tray quick-connect

	ready         chan struct{} // closed when startup() has initialised store/manager
	frontendReady chan struct{} // closed on the first OnDomReady (JS listeners registered)
	domReadyOnce  sync.Once

	quitFlow atomic.Bool // a quit attempt (incl. its confirmation dialog) is in progress
	quitting atomic.Bool // quit is committed: disconnect and shutdown are underway
}

// NewApp creates a new App. The settings store is created in main() because
// wails.Run needs StartHidden before startup runs.
func NewApp(settings *config.SettingsStore) *App {
	return &App{
		settings:      settings,
		ready:         make(chan struct{}),
		frontendReady: make(chan struct{}),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Init store in %APPDATA%\JamVPN (logger and settings are set up in main)
	appData, _ := os.UserConfigDir()
	storeDir := filepath.Join(appData, "JamVPN")
	logger.Info("startup: storeDir=%s", storeDir)
	store, err := config.NewStore(storeDir)
	if err != nil {
		wailsruntime.LogErrorf(ctx, "store init: %v", err)
		store, _ = config.NewStore(".")
	}
	a.store = store

	a.manager = vpn.NewManager()
	a.manager.SetSettings(a.settings.Get())

	// Migrate old profiles.json if present alongside the exe
	a.migrateOldProfiles()

	// Store and manager are usable now — unblock the second-instance handler,
	// which Wails starts BEFORE startup and which must not touch nil fields.
	close(a.ready)

	// Config links/files passed on first launch (e.g. jamvpn:// or a .conf).
	// Own goroutine: an http(s) subscription URL can take up to 15s and must
	// not delay the RAS cleanup or auto-connect below.
	go a.importLaunchArgs(os.Args[1:], "")

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

		// Auto-connect to last used profile if setting is enabled.
		// Skip if a quit was committed while cleanup ran — connecting now
		// would leave an orphaned tunnel behind the exiting process.
		if a.settings.Get().AutoConnect && !a.quitting.Load() {
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

// ─── Single Instance & Lifecycle ──────────────────────────────────────────

// showMainWindow restores and focuses the main window (from tray or a second
// launch). The AlwaysOnTop pulse is the reliable way to steal focus on Windows.
func (a *App) showMainWindow() {
	if a.ctx == nil {
		return
	}
	wailsruntime.WindowUnminimise(a.ctx)
	wailsruntime.WindowShow(a.ctx)
	wailsruntime.WindowSetAlwaysOnTop(a.ctx, true)
	wailsruntime.WindowSetAlwaysOnTop(a.ctx, false)
}

// onSecondInstanceLaunch runs in the FIRST instance when the user starts the
// exe again: the second process exits immediately, we surface the window and
// import any config links/files from its command line.
func (a *App) onSecondInstanceLaunch(data options.SecondInstanceData) {
	logger.Info("second instance launched (args=%v) — activating existing window", data.Args)
	// This handler runs concurrently with startup(): Wails starts its
	// processor before OnStartup, so store/manager may not exist yet. Wait
	// for readiness in a goroutine — blocking the processor itself would
	// freeze both instances (its channel send happens inside the hidden
	// window's wndProc) — and only then touch the app. This also means a
	// launch that races startup imports its args instead of dropping them.
	go func() {
		select {
		case <-a.ready:
		case <-time.After(30 * time.Second):
			logger.Error("second instance: startup never became ready — args dropped: %v", data.Args)
			return
		}
		a.showMainWindow()
		a.importLaunchArgs(data.Args, data.WorkingDirectory)
	}()
}

// domReady runs on every WebView2 NavigationCompleted; the first one means
// the page has executed setupWailsEvents and emits will no longer be dropped.
func (a *App) domReady(ctx context.Context) {
	a.domReadyOnce.Do(func() { close(a.frontendReady) })
}

// importLaunchArgs imports VPN configs passed as command-line arguments:
// jamvpn:// share links, protocol URIs (vless://…), http(s) subscription URLs
// and local .conf/.ovpn/.json files. Relative file paths resolve against
// baseDir (the working directory of the instance that received the args).
// Returns the number of imported profiles.
func (a *App) importLaunchArgs(args []string, baseDir string) int {
	var imported []config.Profile

	for _, arg := range args {
		arg = strings.TrimSpace(arg)
		if arg == "" || strings.HasPrefix(arg, "-") {
			continue
		}

		var result *parser.ParseResult
		var err error
		lower := strings.ToLower(arg)
		switch {
		case strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://"):
			result, err = parser.FromURL(arg)
		case strings.Contains(arg, "://"):
			result, err = parser.FromURIString(arg)
		default:
			ext := strings.ToLower(filepath.Ext(arg))
			if ext != ".conf" && ext != ".ovpn" && ext != ".json" {
				continue // not a config file — some unrelated argument
			}
			path := arg
			if baseDir != "" && !filepath.IsAbs(path) {
				path = filepath.Join(baseDir, path)
			}
			var data []byte
			data, err = os.ReadFile(path)
			if err == nil {
				result, err = parser.FromBytes(data, path)
			}
		}
		if err != nil || result == nil {
			logger.Error("import arg %q: %v", arg, err)
			continue
		}

		saved, err := a.saveImportedProfiles(result.Profiles)
		if err != nil {
			logger.Error("import arg %q: save: %v", arg, err)
		}
		imported = append(imported, saved...)
	}

	if len(imported) > 0 {
		names := make([]string, len(imported))
		for i, p := range imported {
			names[i] = p.Name
		}
		logger.Info("imported %d profile(s) from launch args: %s",
			len(imported), strings.Join(names, ", "))
		// Wails does not queue events: an emit before the page registered its
		// listeners is silently lost (cold-start protocol-handler case). Both
		// call sites run on background goroutines, so waiting here is safe.
		select {
		case <-a.frontendReady:
			wailsruntime.EventsEmit(a.ctx, "profiles:imported", map[string]any{
				"count": len(imported),
				"names": names,
			})
		case <-time.After(30 * time.Second):
			logger.Error("import: frontend never became ready — notification skipped")
		}
	}
	return len(imported)
}

// RequestQuit exits the app. If a VPN connection is active it first asks the
// user for confirmation. Safe to call from any goroutine; while one quit flow
// is in progress (including its dialog) further calls are ignored.
// quitFlow only dedupes the attempt — the committed-quit flag (quitting) is
// set in quitGracefully, AFTER confirmation, so closing the window while the
// dialog is open still hides to tray instead of instantly exiting.
func (a *App) RequestQuit() {
	if !a.quitFlow.CompareAndSwap(false, true) {
		return
	}

	st := a.manager.Status()
	if st.State == config.StateConnected || st.State == config.StateConnecting {
		a.showMainWindow() // give the dialog a visible owner window
		choice, err := wailsruntime.MessageDialog(a.ctx, wailsruntime.MessageDialogOptions{
			Type:          wailsruntime.QuestionDialog,
			Title:         "AikenVPN",
			Message:       "VPN подключён. Отключить соединение и выйти?",
			DefaultButton: "No",
		})
		// On Windows a QuestionDialog is a Yes/No MessageBox (OS-localised
		// buttons) and the result is always the string "Yes" or "No".
		if err != nil || choice != "Yes" {
			a.quitFlow.Store(false)
			return
		}
	}

	a.quitGracefully()
}

// quitGracefully tears the VPN down (bounded by a timeout so a stuck
// disconnect can't leave a zombie process), then stops the tray and Wails.
func (a *App) quitGracefully() {
	a.quitting.Store(true) // commit: OnBeforeClose now lets the close proceed
	logger.Info("quit: disconnecting VPN and shutting down")

	done := make(chan struct{})
	go func() {
		if err := a.manager.Disconnect(); err != nil {
			logger.Error("quit: disconnect: %v", err)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(8 * time.Second):
		logger.Error("quit: disconnect timed out after 8s — exiting anyway")
	}

	systray.Quit()
	wailsruntime.Quit(a.ctx)
	// Failsafe for a HUNG teardown only: if the Wails main loop doesn't exit
	// (WebView2 teardown can hang), force-kill so the process never lingers
	// in Task Manager. 15s is far above a normal teardown+OnShutdown, so a
	// regular quit never gets truncated by it.
	time.AfterFunc(15*time.Second, func() { os.Exit(0) })
}

// setSelectedTrayProfile / selectedTrayProfile guard the tray quick-connect
// profile ID, which is written from IPC calls and read from the tray goroutine.
func (a *App) setSelectedTrayProfile(id string) {
	a.trayMu.Lock()
	a.selectedTrayProfileID = id
	a.trayMu.Unlock()
}

func (a *App) selectedTrayProfile() string {
	a.trayMu.Lock()
	defer a.trayMu.Unlock()
	return a.selectedTrayProfileID
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
	if a.quitting.Load() {
		return fmt.Errorf("приложение завершает работу")
	}
	p, ok := a.store.GetByID(id)
	if !ok {
		return fmt.Errorf("profile not found: %s", id)
	}
	a.setSelectedTrayProfile(id)

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
	return "2.4.1"
}

// ─── Migrations ───────────────────────────────────────────────────────────

// migrateOldProfiles imports profiles from the old Python app's vpn_profiles.json.
// Candidate locations are anchored to the exe directory, not the working
// directory — autostart and shortcuts launch the exe with arbitrary CWDs.
func (a *App) migrateOldProfiles() {
	var dirs []string
	if exePath, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exePath)
		dirs = append(dirs, exeDir, filepath.Join(exeDir, "_internal"), filepath.Dir(exeDir))
	}
	if cwd, err := os.Getwd(); err == nil {
		dirs = append(dirs, cwd, filepath.Join(cwd, "_internal"), filepath.Dir(cwd))
	}

	var candidates []string
	seen := make(map[string]bool)
	for _, d := range dirs {
		path := filepath.Join(d, "vpn_profiles.json")
		if !seen[path] {
			seen[path] = true
			candidates = append(candidates, path)
		}
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
