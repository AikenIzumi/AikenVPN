package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestStoreProtectsLegacyProfilesAndReopens(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	profile := Profile{
		ID: "legacy", Name: "Legacy VPN", TunnelType: TunnelL2TP,
		Password: "test-vpn-password", PresharedKey: "test-vpn-preshared-key",
	}
	raw, err := json.Marshal(storeData{Version: 2, Profiles: []Profile{profile}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		store, err := NewStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := store.GetByID(profile.ID)
		if !ok || got.Password != profile.Password || got.PresharedKey != profile.PresharedKey {
			t.Fatal("profile secrets did not survive migration and reload")
		}
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(onDisk, []byte(dpapiProfilePrefix)) ||
		bytes.Contains(onDisk, []byte(profile.Password)) || bytes.Contains(onDisk, []byte(profile.PresharedKey)) {
		t.Fatal("store contains plaintext or is missing the protection marker")
	}
}

func TestUnreadableProtectedStoreIsNotOverwritten(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "profiles.json")
	raw := []byte(dpapiProfilePrefix + "invalid DPAPI blob")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, loadErr := NewStore(dir); loadErr == nil {
		t.Fatal("opened an invalid protected store")
	} else if _, err := NewUnavailableStore(loadErr).Add(Profile{Name: "test"}); err == nil {
		t.Fatal("accepted writes after a load failure")
	}
	onDisk, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(raw, onDisk) {
		t.Fatalf("invalid protected store was changed, read error: %v", err)
	}
}
