package main

import (
	"os"
	"time"

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

	// Sync menu state with VPN status events
	go func() {
		wailsruntime.EventsOn(app.ctx, "vpn:status", func(data ...interface{}) {
			if len(data) == 0 {
				return
			}
			// data[0] is map[string]interface{} coming from JSON
			if m, ok := data[0].(map[string]interface{}); ok {
				state, _ := m["state"].(string)
				name, _  := m["profile_name"].(string)
				updateTrayMenu(state, name, mConnect, mDisconnect)
			}
		})
	}()

	for {
		select {
		case <-mOpen.ClickedCh:
			wailsruntime.WindowShow(app.ctx)
			wailsruntime.WindowSetAlwaysOnTop(app.ctx, true)
			wailsruntime.WindowSetAlwaysOnTop(app.ctx, false)

		case <-mConnect.ClickedCh:
			if app.selectedTrayProfileID != "" {
				go func() {
					if err := app.Connect(app.selectedTrayProfileID); err != nil {
						// no-op; status event will reflect error
					}
				}()
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
			// Disconnect VPN before exit so Windows doesn't leave orphaned entries
			go app.manager.Disconnect() //nolint
			systray.Quit()
			wailsruntime.Quit(app.ctx)
			// Give Wails ~500ms to run OnShutdown, then force-kill the process.
			// Without this the process can linger in Task Manager indefinitely.
			time.AfterFunc(500*time.Millisecond, func() { os.Exit(0) })
			return
		}
	}
}

func updateTrayMenu(
	state string,
	profileName string,
	mConnect, mDisconnect *systray.MenuItem,
) {
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
