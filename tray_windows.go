package main

import (
	"sync"

	"github.com/energye/systray"
	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
	"github.com/jamalfa/jamvpn/internal/trayicon"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// initTray starts the system tray in a goroutine.
// Call once after app.startup has set app.ctx.
func initTray(app *App) {
	go systray.Run(
		func() { onTrayReady(app) },
		func() { /* onTrayExit — nothing needed */ },
	)
}

func onTrayReady(app *App) {
	// Accent purple icon (#6c63ff → R=108 G=99 B=255)
	systray.SetIcon(trayicon.Generate(108, 99, 255))
	systray.SetTitle("AikenVPN")
	systray.SetTooltip("AikenVPN — VPN клиент")

	// Left click (single or double) opens the window; right click shows the
	// menu. The right-click handler is set explicitly (instead of relying on
	// the library default) so a ShowMenu failure is visible in the log.
	systray.SetOnClick(func(menu systray.IMenu) { app.showMainWindow() })
	systray.SetOnDClick(func(menu systray.IMenu) { app.showMainWindow() })
	systray.SetOnRClick(func(menu systray.IMenu) {
		if err := menu.ShowMenu(); err != nil {
			logger.Error("tray: ShowMenu: %v", err)
		}
	})

	mOpen := systray.AddMenuItem("Открыть AikenVPN", "Показать главное окно")
	systray.AddSeparator()

	mConnect    := systray.AddMenuItem("Подключить", "Подключиться к выбранному профилю")
	mDisconnect := systray.AddMenuItem("Отключить",  "Разорвать соединение")
	mDisconnect.Hide()

	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Выйти", "Закрыть AikenVPN")

	mOpen.Click(func() { app.showMainWindow() })

	mConnect.Click(func() {
		if id := app.selectedTrayProfile(); id != "" {
			go func() { _ = app.Connect(id) }()
			return
		}
		// Connect to first available profile
		profiles := app.GetProfiles()
		if len(profiles) > 0 {
			go func(id string) { _ = app.Connect(id) }(profiles[0].ID)
		}
	})

	mDisconnect.Click(func() {
		go func() { _ = app.Disconnect() }()
	})

	// Confirmation + graceful disconnect + shutdown live in RequestQuit.
	// Run it off the tray callback so the menu stays responsive while the
	// dialog is open; if the user cancels, the tray keeps working.
	mQuit.Click(func() {
		go app.RequestQuit()
	})

	logger.Info("tray: ready (icon, menu and click handlers installed)")

	// Sync menu state with VPN status events. EventsOn only registers a
	// callback; the callback itself runs on Wails' event goroutines.
	// Go-side emitters deliver the ORIGINAL value: data[0] is the
	// config.ConnectionStatus struct itself, not a JSON map (maps arrive
	// only from JS-emitted events, which never occur for this topic).
	wailsruntime.EventsOn(app.ctx, "vpn:status", func(data ...interface{}) {
		if len(data) == 0 {
			return
		}
		if s, ok := data[0].(config.ConnectionStatus); ok {
			updateTrayMenu(string(s.State), s.ProfileName, mConnect, mDisconnect)
		}
	})
}

// trayState guards against redundant icon/tooltip/menu updates when the
// status hasn't meaningfully changed. Event callbacks run on unordered
// goroutines, so the whole update (dedupe + systray mutations) is one
// critical section — otherwise a stale state could be painted last while
// lastKey remembers the fresh one, freezing the tray on a wrong icon.
var trayState struct {
	sync.Mutex
	lastKey string
}

func updateTrayMenu(
	state string,
	profileName string,
	mConnect, mDisconnect *systray.MenuItem,
) {
	trayState.Lock()
	defer trayState.Unlock()

	key := state + "|" + profileName
	if key == trayState.lastKey {
		return
	}
	trayState.lastKey = key

	switch config.ConnectionState(state) {
	case config.StateConnected:
		mConnect.Hide()
		mDisconnect.Show()
		if profileName != "" {
			systray.SetTooltip("AikenVPN — подключено: " + profileName)
		}
		systray.SetIcon(trayicon.Generate(34, 211, 160)) // green when connected
	case config.StateConnecting:
		mConnect.Hide()
		mDisconnect.Hide()
		systray.SetTooltip("AikenVPN — подключение...")
		systray.SetIcon(trayicon.Generate(245, 200, 66)) // yellow while connecting
	default:
		mConnect.Show()
		mDisconnect.Hide()
		systray.SetTooltip("AikenVPN — отключено")
		systray.SetIcon(trayicon.Generate(108, 99, 255)) // purple when idle
	}
}
