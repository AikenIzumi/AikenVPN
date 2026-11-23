package main

import (
	"errors"

	"github.com/jamalfa/jamvpn/internal/logger"
)

type QuickConnectHotkeyStatus struct {
	Key        string `json:"key"`
	Registered bool   `json:"registered"`
	Error      string `json:"error"`
}

func (a *App) startQuickConnectHotkey() {
	a.hotkeyMu.Lock()
	defer a.hotkeyMu.Unlock()
	key, err := normalizeHotkey(a.settings.Get().QuickConnectHotkey)
	if err == nil && key != "" {
		a.hotkey, err = startWindowsHotkey(key, a.onQuickConnectHotkey)
	}
	if err != nil {
		a.hotkeyError = err.Error()
		logger.Error("hotkey: %v", err)
	}
}

func (a *App) stopQuickConnectHotkey() {
	a.hotkeyMu.Lock()
	defer a.hotkeyMu.Unlock()
	a.releaseHotkey(a.hotkey)
	a.hotkey = nil
}

func (a *App) GetQuickConnectHotkey() QuickConnectHotkeyStatus {
	a.hotkeyMu.Lock()
	defer a.hotkeyMu.Unlock()
	status := QuickConnectHotkeyStatus{Key: a.settings.Get().QuickConnectHotkey, Error: a.hotkeyError}
	if a.hotkey != nil {
		select {
		case <-a.hotkey.done:
			status.Error = "Обработчик горячей клавиши остановлен"
		default:
			status.Registered = true
		}
	}
	return status
}

func (a *App) SetQuickConnectHotkey(key string) error {
	key, err := normalizeHotkey(key)
	if err != nil {
		return err
	}
	a.hotkeyMu.Lock()
	defer a.hotkeyMu.Unlock()
	if a.quitting.Load() {
		return errors.New("Приложение завершает работу")
	}
	if a.hotkey != nil && a.hotkey.key == key {
		select {
		case <-a.hotkey.done:
		default:
			return nil
		}
	}

	var next *windowsHotkey
	if key != "" {
		next, err = startWindowsHotkey(key, a.onQuickConnectHotkey)
		if err != nil {
			return err
		}
	}
	settings := a.settings.Get()
	settings.QuickConnectHotkey = key
	if err := a.settings.Set(settings); err != nil {
		if next != nil {
			err = errors.Join(err, next.close())
		}
		return err
	}
	previous := a.hotkey
	a.hotkey = next
	a.hotkeyError = ""
	a.releaseHotkey(previous)
	return nil
}

func (a *App) releaseHotkey(hotkey *windowsHotkey) {
	if hotkey != nil {
		if err := hotkey.close(); err != nil {
			logger.Error("hotkey: release: %v", err)
		}
	}
}

func (a *App) onQuickConnectHotkey(source *windowsHotkey) {
	a.hotkeyMu.Lock()
	active := a.hotkey == source
	a.hotkeyMu.Unlock()
	if active {
		a.quickConnect()
	}
}
