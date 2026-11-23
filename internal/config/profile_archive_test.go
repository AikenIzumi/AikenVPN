package config

import (
	"bytes"
	"reflect"
	"testing"
	"time"
)

func TestProfileArchiveRoundTripAndAuthentication(t *testing.T) {
	const password = "test archive password"
	profiles := []Profile{{
		ID: "backup-id", Name: "backup-name", Password: "secret-vpn-password",
	}}
	data, err := EncryptProfileArchive(profiles, password)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(profiles[0].Password)) {
		t.Fatal("archive contains plaintext credentials")
	}
	got, err := DecryptProfileArchive(data, password)
	if err != nil || !reflect.DeepEqual(got, profiles) {
		t.Fatalf("round trip did not preserve profiles: %v", err)
	}
	if _, err := DecryptProfileArchive(data, "wrong archive password"); err == nil {
		t.Fatal("accepted wrong password")
	}
	data[len(data)-1] ^= 1
	if _, err := DecryptProfileArchive(data, password); err == nil {
		t.Fatal("accepted modified ciphertext")
	}
}

func TestRestoreArchiveRejectsChangesAfterPreview(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	profile, err := store.Add(Profile{ID: "same-id", Name: "existing"})
	if err != nil {
		t.Fatal(err)
	}
	previewed := map[string]time.Time{profile.ID: profile.UpdatedAt}
	if err := store.Update(Profile{ID: profile.ID, Name: "edited after preview"}); err != nil {
		t.Fatal(err)
	}
	batch := []Profile{{ID: profile.ID, Name: "archive profile"}, {ID: "new-id", Name: "new profile"}}
	if _, err := store.RestoreArchive(batch, previewed); err == nil {
		t.Fatal("restored over an edited profile")
	}
	current, _ := store.GetByID(profile.ID)
	if _, exists := store.GetByID("new-id"); exists || current.Name != "edited after preview" {
		t.Fatal("a rejected restore changed the store")
	}
	previewed[profile.ID] = current.UpdatedAt
	if saved, err := store.RestoreArchive(batch, previewed); err != nil || len(saved) != 2 {
		t.Fatalf("approved restore failed: %v", err)
	}
}
