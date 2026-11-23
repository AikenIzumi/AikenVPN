package main

import (
	"testing"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
)

func TestHotkeyDispatchAndConflictPreservesCurrentSetting(t *testing.T) {
	settings, err := config.NewSettingsStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app := NewApp(settings)
	app.store, err = config.NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.stopQuickConnectHotkey)

	presses := make(chan struct{}, 1)
	var blocker *windowsHotkey
	for _, candidate := range []string{"J", "K", "8", "9"} {
		blocker, err = startWindowsHotkey(candidate, func(*windowsHotkey) { presses <- struct{}{} })
		if err == nil {
			break
		}
	}
	if blocker == nil {
		t.Fatalf("could not register a test shortcut: %v", err)
	}
	t.Cleanup(func() {
		if err := blocker.close(); err != nil {
			t.Error(err)
		}
	})
	if ok, _, err := postHotkeyMessage.Call(uintptr(blocker.thread), wmHotkey, hotkeyID, 0); ok == 0 {
		t.Fatal(err)
	}
	select {
	case <-presses:
	case <-time.After(3 * time.Second):
		t.Fatal("hotkey message did not reach its handler")
	}

	for _, candidate := range []string{"U", "I", "6", "7"} {
		if err = app.SetQuickConnectHotkey(candidate); err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("could not apply a test shortcut: %v", err)
	}
	before := app.GetQuickConnectHotkey()
	if !before.Registered {
		t.Fatal("test shortcut was not registered")
	}
	if err := app.SetQuickConnectHotkey(blocker.key); err == nil {
		t.Fatal("registered an occupied shortcut")
	}
	if got := app.GetQuickConnectHotkey(); got != before {
		t.Fatalf("failed registration changed settings: got %+v, want %+v", got, before)
	}
	if err := app.SetQuickConnectHotkey(""); err != nil {
		t.Fatal(err)
	}
	if got := app.GetQuickConnectHotkey(); got.Registered || got.Key != "" {
		t.Fatalf("shortcut was not disabled: %+v", got)
	}
}
