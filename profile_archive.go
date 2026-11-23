package main

import (
	"errors"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/jamalfa/jamvpn/internal/config"
	wailsruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

var profileArchiveFilters = []wailsruntime.FileFilter{
	{DisplayName: "Архив AikenVPN (*.aikenvpn)", Pattern: "*.aikenvpn"},
}

type ArchivePreviewEntry struct {
	Name         string            `json:"name"`
	TunnelType   config.TunnelType `json:"tunnel_type"`
	ReplacesName *string           `json:"replaces_name"`
}

type ArchivePreview struct {
	Token   string                `json:"token"`
	Entries []ArchivePreviewEntry `json:"entries"`
}

type pendingProfileArchive struct {
	token     string
	profiles  []config.Profile
	previewed map[string]time.Time
}

func (a *App) SaveEncryptedArchive(password string) (bool, error) {
	a.archiveMu.Lock()
	defer a.archiveMu.Unlock()
	if a.storeLoadErr != nil {
		return false, a.storeLoadErr
	}
	path, err := wailsruntime.SaveFileDialog(a.ctx, wailsruntime.SaveDialogOptions{
		Title:           "Сохранить зашифрованный архив",
		DefaultFilename: "AikenVPN.aikenvpn",
		Filters:         profileArchiveFilters,
	})
	if err != nil || path == "" {
		return false, err
	}
	err = config.SaveProfileArchive(path, a.store.GetAll(), password)
	return err == nil, err
}

func (a *App) PreviewEncryptedArchive(password string) (*ArchivePreview, error) {
	a.archiveMu.Lock()
	defer a.archiveMu.Unlock()
	a.pendingArchive = nil
	if a.storeLoadErr != nil {
		return nil, a.storeLoadErr
	}
	path, err := wailsruntime.OpenFileDialog(a.ctx, wailsruntime.OpenDialogOptions{
		Title:   "Открыть зашифрованный архив",
		Filters: profileArchiveFilters,
	})
	if err != nil || path == "" {
		return nil, err
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, config.MaxProfileArchive+1))
	if err != nil {
		return nil, err
	}
	profiles, err := config.DecryptProfileArchive(data, password)
	if err != nil {
		return nil, err
	}

	current := make(map[string]config.Profile)
	for _, profile := range a.store.GetAll() {
		current[profile.ID] = profile
	}
	preview := &ArchivePreview{Token: uuid.NewString(), Entries: make([]ArchivePreviewEntry, 0, len(profiles))}
	pending := &pendingProfileArchive{token: preview.Token, profiles: profiles, previewed: make(map[string]time.Time)}
	for _, profile := range profiles {
		entry := ArchivePreviewEntry{Name: profile.Name, TunnelType: profile.TunnelType}
		if old, exists := current[profile.ID]; exists {
			entry.ReplacesName = &old.Name
			pending.previewed[profile.ID] = old.UpdatedAt
		}
		preview.Entries = append(preview.Entries, entry)
	}
	a.pendingArchive = pending
	return preview, nil
}

func (a *App) RestoreEncryptedArchive(token string) (int, error) {
	a.archiveMu.Lock()
	defer a.archiveMu.Unlock()
	pending := a.pendingArchive
	if pending == nil || pending.token != token {
		return 0, errors.New("Откройте архив для предпросмотра")
	}
	a.pendingArchive = nil
	restored, err := a.store.RestoreArchive(pending.profiles, pending.previewed)
	return len(restored), err
}

func (a *App) CancelEncryptedArchive(token string) {
	a.archiveMu.Lock()
	defer a.archiveMu.Unlock()
	if a.pendingArchive != nil && a.pendingArchive.token == token {
		a.pendingArchive = nil
	}
}
