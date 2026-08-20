package main

import (
	"sync"

	"github.com/getlantern/systray"
	"github.com/jamalfa/jamvpn/internal/config"
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
	systray.SetTitle("JamVPN")
	systray.SetTooltip("JamVPN — VPN клиент")

	mOpen := systray.AddMenuItem("Открыть JamVPN", "Показать главное окно")
	systray.AddSeparator()

	mConnect    := systray.AddMenuItem("Подключить", "Подключиться к выбранному профилю")
	mDisconnect := systray.AddMenuItem("Отключить",  "Разорвать соединение")
	mDisconnect.Hide()

	systray.AddSeparator()
	mQuit := systray.AddMenuItem("Выйти", "Закрыть JamVPN")

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

	for {
		select {
		case <-mOpen.ClickedCh:
			app.showMainWindow()

		case <-mConnect.ClickedCh:
			if id := app.selectedTrayProfile(); id != "" {
				go func() { _ = app.Connect(id) }()
			} else {
				// Connect to first available profile
				profiles := app.GetProfiles()
				if len(profiles) > 0 {
					go func(id string) { _ = app.Connect(id) }(profiles[0].ID)
				}
			}

		case <-mDisconnect.ClickedCh:
			go func() { _ = app.Disconnect() }()

		case <-mQuit.ClickedCh:
			// Confirmation + graceful disconnect + shutdown live in
			// RequestQuit. Run it off the tray loop so the menu stays
			// responsive while the dialog is open; if the user cancels,
			// the loop keeps serving clicks.
			go app.RequestQuit()
		}
	}
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
			systray.SetTooltip("JamVPN — подключено: " + profileName)
		}
		systray.SetIcon(trayicon.Generate(34, 211, 160)) // green when connected
	case config.StateConnecting:
		mConnect.Hide()
		mDisconnect.Hide()
		systray.SetTooltip("JamVPN — подключение...")
		systray.SetIcon(trayicon.Generate(245, 200, 66)) // yellow while connecting
	default:
		mConnect.Show()
		mDisconnect.Hide()
		systray.SetTooltip("JamVPN — отключено")
		systray.SetIcon(trayicon.Generate(108, 99, 255)) // purple when idle
	}
}
