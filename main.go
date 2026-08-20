package main

import (
	"context"
	"embed"
	"os"
	"path/filepath"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed frontend/index.html frontend/wailsjs
var assets embed.FS

// singleInstanceID identifies the app's single-instance mutex system-wide.
// Changing it would let old and new builds run simultaneously.
const singleInstanceID = "jamvpn-3c6f2a1e-9d4b-4a8e-b7c5-1f2e3d4c5b6a"

func main() {
	// Settings and logger are needed before wails.Run: StartHidden must be
	// known up front, and the second-instance callback logs through logger.
	appData, _ := os.UserConfigDir()
	storeDir := filepath.Join(appData, "JamVPN")
	logger.Init(storeDir)
	settings, _ := config.NewSettingsStore(storeDir)

	app := NewApp(settings)

	err := wails.Run(&options.App{
		Title:     "JamVPN",
		Width:     920,
		Height:    640,
		MinWidth:  800,
		MinHeight: 560,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 10, G: 10, B: 18, A: 255},
		OnStartup:        app.startup,
		OnDomReady:       app.domReady,
		OnShutdown:       app.shutdown,

		// Only one JamVPN process may run. A second launch hands its
		// command-line args to this instance and exits; we bring the window
		// to front and import any config links/files it carried.
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               singleInstanceID,
			OnSecondInstanceLaunch: app.onSecondInstanceLaunch,
		},

		// Respect the "close_action" setting: hide to tray (default) or quit.
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			// runtime.Quit re-enters this callback; during a graceful quit the
			// close must proceed, or the process would never exit (the old
			// code papered over this with an os.Exit(0) timer).
			if app.quitting.Load() {
				return false
			}
			if app.settings != nil && app.settings.Get().CloseAction == "quit" {
				// RequestQuit may show a confirmation dialog — run it off the
				// UI thread and keep the window alive until the user decides.
				go app.RequestQuit()
				return true
			}
			runtime.WindowHide(ctx)
			return true
		},

		StartHidden: settings.Get().StartMinimized,

		Bind: []interface{}{
			app,
		},
		Windows: &windows.Options{
			WebviewIsTransparent: false,
			WindowIsTranslucent:  false,
			DisableWindowIcon:    false,
			IsZoomControlEnabled: false,
			DisablePinchZoom:     true,
			Theme:                windows.Dark,
			CustomTheme: &windows.ThemeSettings{
				DarkModeTitleBar:   windows.RGB(10, 10, 18),
				DarkModeTitleText:  windows.RGB(255, 255, 255),
				DarkModeBorder:     windows.RGB(30, 30, 45),
				LightModeTitleBar:  windows.RGB(10, 10, 18),
				LightModeTitleText: windows.RGB(255, 255, 255),
				LightModeBorder:    windows.RGB(30, 30, 45),
			},
		},
		Frameless:       false,
		CSSDragProperty: "--wails-draggable",
		CSSDragValue:    "drag",
	})

	if err != nil {
		logger.Error("wails.Run: %v", err)
	}
}
