package main

import (
	"context"
	"embed"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

//go:embed frontend/index.html frontend/wailsjs
var assets embed.FS

func main() {
	app := NewApp()

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
		OnShutdown:       app.shutdown,

		// Hide window on ✕ instead of quitting — app lives in system tray
		OnBeforeClose: func(ctx context.Context) (prevent bool) {
			runtime.WindowHide(ctx)
			return true // prevent actual close
		},

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
		println("Error:", err.Error())
	}
}
