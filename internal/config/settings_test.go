package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSettingsDefaults(t *testing.T) {
	dir := t.TempDir()

	ss, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("NewSettingsStore failed: %v", err)
	}

	got := ss.Get()
	if got.Theme != "dark" {
		t.Errorf("default Theme = %q, want %q", got.Theme, "dark")
	}
	if got.CloseAction != "hide" {
		t.Errorf("default CloseAction = %q, want %q", got.CloseAction, "hide")
	}
	if got.LogLevel != "info" {
		t.Errorf("default LogLevel = %q, want %q", got.LogLevel, "info")
	}
	if got.StartAtLogin || got.StartMinimized || got.AutoConnect {
		t.Errorf("boolean settings should default to false: %+v", got)
	}

	// First open writes settings.json with the defaults.
	if _, err := os.Stat(filepath.Join(dir, "settings.json")); err != nil {
		t.Errorf("settings.json not created on first open: %v", err)
	}
}

func TestSettingsSetPersistsAcrossReopen(t *testing.T) {
	dir := t.TempDir()

	ss, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("NewSettingsStore failed: %v", err)
	}

	want := AppSettings{
		Theme:          "light",
		StartAtLogin:   true,
		StartMinimized: true,
		CloseAction:    "quit",
		AutoConnect:    true,
		BypassLAN:      true,
		BypassRegion:   "ru",
		VpnDNS:         "1.1.1.1",
		DirectDNS:      "8.8.8.8",
		LogLevel:       "debug",
	}
	if err := ss.Set(want); err != nil {
		t.Fatalf("Set failed: %v", err)
	}

	// Get on the same store reflects the change.
	if got := ss.Get(); got != want {
		t.Errorf("Get after Set = %+v, want %+v", got, want)
	}

	// Reopen from disk and check persistence.
	reopened, err := NewSettingsStore(dir)
	if err != nil {
		t.Fatalf("reopen NewSettingsStore failed: %v", err)
	}
	if got := reopened.Get(); got != want {
		t.Errorf("settings after reopen = %+v, want %+v", got, want)
	}
}
