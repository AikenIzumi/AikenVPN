package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (*Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore(%q) failed: %v", dir, err)
	}
	return s, dir
}

func TestNewStoreEmptyDir(t *testing.T) {
	s, dir := newTestStore(t)

	if got := s.GetAll(); len(got) != 0 {
		t.Fatalf("expected 0 profiles in fresh store, got %d", len(got))
	}

	// NewStore must create the directory if missing.
	sub := filepath.Join(dir, "nested", "cfg")
	if _, err := NewStore(sub); err != nil {
		t.Fatalf("NewStore should create missing dir: %v", err)
	}
	if fi, err := os.Stat(sub); err != nil || !fi.IsDir() {
		t.Fatalf("expected %q to be a directory, err=%v", sub, err)
	}
}

func TestStoreAddAssignsIDAndTimestamps(t *testing.T) {
	s, _ := newTestStore(t)

	before := time.Now()
	p, err := s.Add(Profile{Name: "test", TunnelType: TunnelIKEv2, Server: "vpn.example.com"})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	after := time.Now()

	if p.ID == "" {
		t.Error("Add did not assign an ID")
	}
	if p.CreatedAt.Before(before) || p.CreatedAt.After(after) {
		t.Errorf("CreatedAt %v not in [%v, %v]", p.CreatedAt, before, after)
	}
	if !p.UpdatedAt.Equal(p.CreatedAt) {
		t.Errorf("UpdatedAt %v should equal CreatedAt %v on Add", p.UpdatedAt, p.CreatedAt)
	}

	// A caller-provided ID is kept.
	p2, err := s.Add(Profile{ID: "my-id", Name: "custom"})
	if err != nil {
		t.Fatalf("Add with explicit ID failed: %v", err)
	}
	if p2.ID != "my-id" {
		t.Errorf("Add replaced explicit ID: got %q, want %q", p2.ID, "my-id")
	}

	if got := s.GetAll(); len(got) != 2 {
		t.Errorf("expected 2 profiles after two Adds, got %d", len(got))
	}
}

func TestStoreGetByID(t *testing.T) {
	s, _ := newTestStore(t)

	added, err := s.Add(Profile{Name: "findme", TunnelType: TunnelL2TP})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	got, ok := s.GetByID(added.ID)
	if !ok {
		t.Fatalf("GetByID(%q) not found", added.ID)
	}
	if got.Name != "findme" || got.TunnelType != TunnelL2TP {
		t.Errorf("GetByID returned wrong profile: %+v", got)
	}

	if _, ok := s.GetByID("no-such-id"); ok {
		t.Error("GetByID for unknown ID reported found")
	}
}

func TestStoreUpdatePreservesCreatedAtBumpsUpdatedAt(t *testing.T) {
	s, _ := newTestStore(t)

	added, err := s.Add(Profile{Name: "orig", TunnelType: TunnelSSTP})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Ensure the clock moves past the Add timestamp (Windows timer resolution).
	time.Sleep(20 * time.Millisecond)

	mod := added
	mod.Name = "renamed"
	mod.CreatedAt = time.Time{} // caller-supplied garbage must be ignored
	if err := s.Update(mod); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	got, ok := s.GetByID(added.ID)
	if !ok {
		t.Fatalf("profile disappeared after Update")
	}
	if got.Name != "renamed" {
		t.Errorf("Update did not apply changes: Name = %q", got.Name)
	}
	if !got.CreatedAt.Equal(added.CreatedAt) {
		t.Errorf("Update changed CreatedAt: got %v, want %v", got.CreatedAt, added.CreatedAt)
	}
	if !got.UpdatedAt.After(added.UpdatedAt) {
		t.Errorf("Update did not bump UpdatedAt: got %v, was %v", got.UpdatedAt, added.UpdatedAt)
	}

	// Updating a nonexistent profile is an error.
	if err := s.Update(Profile{ID: "missing"}); err == nil {
		t.Error("Update of unknown profile should return an error")
	}
}

func TestStoreDelete(t *testing.T) {
	s, _ := newTestStore(t)

	a, _ := s.Add(Profile{Name: "a"})
	b, _ := s.Add(Profile{Name: "b"})

	if err := s.Delete(a.ID); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, ok := s.GetByID(a.ID); ok {
		t.Error("deleted profile still retrievable")
	}
	if _, ok := s.GetByID(b.ID); !ok {
		t.Error("Delete removed the wrong profile")
	}
	if got := s.GetAll(); len(got) != 1 {
		t.Errorf("expected 1 profile after delete, got %d", len(got))
	}

	if err := s.Delete("no-such-id"); err == nil {
		t.Error("Delete of unknown profile should return an error")
	}
}

func TestStoreTouchLastUsed(t *testing.T) {
	s, _ := newTestStore(t)

	added, _ := s.Add(Profile{Name: "used"})
	if added.LastUsed != nil {
		t.Fatalf("fresh profile should have nil LastUsed")
	}

	before := time.Now()
	s.TouchLastUsed(added.ID)
	after := time.Now()

	got, ok := s.GetByID(added.ID)
	if !ok {
		t.Fatalf("profile not found after TouchLastUsed")
	}
	if got.LastUsed == nil {
		t.Fatal("TouchLastUsed did not set LastUsed")
	}
	if got.LastUsed.Before(before) || got.LastUsed.After(after) {
		t.Errorf("LastUsed %v not in [%v, %v]", got.LastUsed, before, after)
	}

	// Unknown ID must be a no-op, not a panic.
	s.TouchLastUsed("no-such-id")
}

func TestStorePersistenceAcrossReopen(t *testing.T) {
	s, dir := newTestStore(t)

	added, err := s.Add(Profile{
		Name:       "persist-me",
		TunnelType: TunnelWireGuard,
		WireGuard: &WireGuardConfig{
			PrivateKey:     "priv",
			Address:        "10.0.0.2/32",
			PeerPublicKey:  "pub",
			PeerEndpoint:   "wg.example.com:51820",
			PeerAllowedIPs: "0.0.0.0/0",
		},
	})
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	s.TouchLastUsed(added.ID)

	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reopen NewStore failed: %v", err)
	}
	all := reopened.GetAll()
	if len(all) != 1 {
		t.Fatalf("expected 1 profile after reopen, got %d", len(all))
	}
	got := all[0]
	if got.ID != added.ID || got.Name != "persist-me" || got.TunnelType != TunnelWireGuard {
		t.Errorf("reopened profile mismatch: %+v", got)
	}
	if got.WireGuard == nil || got.WireGuard.PeerEndpoint != "wg.example.com:51820" {
		t.Errorf("WireGuard config not persisted: %+v", got.WireGuard)
	}
	if got.LastUsed == nil {
		t.Error("LastUsed not persisted")
	}
}

func TestStoreLoadMigratesXrayURIFromOpenVPN(t *testing.T) {
	dir := t.TempDir()
	uri := "vless://11111111-2222-3333-4444-555555555555@example.com:443?security=reality&type=tcp#node"

	sd := storeData{
		Version: 1,
		Profiles: []Profile{
			{
				ID:         "legacy-1",
				Name:       "legacy xray",
				TunnelType: TunnelOpenVPN,
				OpenVPN:    &OpenVPNConfig{ConfigContent: uri},
			},
			{
				ID:         "real-ovpn",
				Name:       "real openvpn",
				TunnelType: TunnelOpenVPN,
				OpenVPN:    &OpenVPNConfig{ConfigContent: "client\ndev tun\nremote example.com 1194\n"},
			},
		},
	}
	raw, err := json.MarshalIndent(sd, "", "  ")
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "profiles.json"), raw, 0600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore over hand-written profiles.json failed: %v", err)
	}

	migrated, ok := s.GetByID("legacy-1")
	if !ok {
		t.Fatal("migrated profile not found")
	}
	if migrated.TunnelType != TunnelXray {
		t.Errorf("TunnelType = %q, want %q", migrated.TunnelType, TunnelXray)
	}
	if migrated.OpenVPN != nil {
		t.Error("migrated profile should have OpenVPN config cleared")
	}
	if migrated.Xray == nil {
		t.Fatal("migrated profile has no Xray config")
	}
	if migrated.Xray.URI != uri {
		t.Errorf("Xray.URI = %q, want %q", migrated.Xray.URI, uri)
	}
	if migrated.Xray.Protocol != "vless" {
		t.Errorf("Xray.Protocol = %q, want %q", migrated.Xray.Protocol, "vless")
	}

	// A genuine OpenVPN profile must be left untouched.
	untouched, ok := s.GetByID("real-ovpn")
	if !ok {
		t.Fatal("real OpenVPN profile not found")
	}
	if untouched.TunnelType != TunnelOpenVPN || untouched.OpenVPN == nil || untouched.Xray != nil {
		t.Errorf("real OpenVPN profile was wrongly migrated: %+v", untouched)
	}

	// Migration is saved back to disk: reopening must show it without re-migrating.
	reopened, err := NewStore(dir)
	if err != nil {
		t.Fatalf("reopen after migration failed: %v", err)
	}
	again, ok := reopened.GetByID("legacy-1")
	if !ok {
		t.Fatal("migrated profile missing after reopen")
	}
	if again.TunnelType != TunnelXray || again.Xray == nil || again.Xray.Protocol != "vless" {
		t.Errorf("migration not persisted to disk: %+v", again)
	}
}

func TestIsXrayURIAndProtocol(t *testing.T) {
	cases := []struct {
		uri      string
		isXray   bool
		protocol string
	}{
		{"vmess://eyJ2IjoiMiJ9", true, "vmess"},
		{"vless://uuid@host:443", true, "vless"},
		{"trojan://password@host:443", true, "trojan"},
		{"ss://YWVzLTI1Ni1nY206cGFzcw==@host:8388", true, "shadowsocks"},
		{"client\ndev tun\n", false, ""},
		{"", false, ""},
		{"http://example.com", false, ""},
	}
	for _, c := range cases {
		if got := isXrayURI(c.uri); got != c.isXray {
			t.Errorf("isXrayURI(%q) = %v, want %v", c.uri, got, c.isXray)
		}
		if c.isXray {
			if got := xrayProtocol(c.uri); got != c.protocol {
				t.Errorf("xrayProtocol(%q) = %q, want %q", c.uri, got, c.protocol)
			}
		}
	}
}
