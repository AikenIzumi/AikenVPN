package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/uuid"
)

type storeData struct {
	Version  int       `json:"version"`
	Profiles []Profile `json:"profiles"`
}

// Store manages VPN profiles on disk
type Store struct {
	mu       sync.RWMutex
	path     string
	profiles []Profile
	loadErr  error
}

// NewStore creates or loads profile store from the given path
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create config dir: %w", err)
	}
	s := &Store{
		path: filepath.Join(dir, "profiles.json"),
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// NewUnavailableStore keeps the app usable after a profile load failure.
// It rejects writes so a failed load cannot be mistaken for an empty store.
func NewUnavailableStore(err error) *Store {
	return &Store{loadErr: err}
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.profiles = []Profile{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read profiles: %w", err)
	}
	plaintext, migrated, err := decodeStoredProfiles(data)
	if err != nil {
		return fmt.Errorf("decrypt profiles: %w", err)
	}
	defer clear(plaintext)
	var sd storeData
	if err := json.Unmarshal(plaintext, &sd); err != nil {
		return fmt.Errorf("parse profiles: %w", err)
	}
	seen := make(map[string]bool)
	for i := range sd.Profiles {
		p := &sd.Profiles[i]
		if seen[p.ID] || p.ID == "" {
			p.ID = uuid.NewString()
			migrated = true
		}
		seen[p.ID] = true
		if p.TunnelType == TunnelOpenVPN && p.OpenVPN != nil {
			raw := p.OpenVPN.ConfigContent
			if isXrayURI(raw) {
				p.TunnelType = TunnelXray
				p.Xray = &XrayConfig{
					URI:      raw,
					Protocol: xrayProtocol(raw),
				}
				p.OpenVPN = nil
				migrated = true
			}
		}
	}
	s.profiles = sd.Profiles
	if migrated {
		return s.commit(sd.Profiles)
	}
	return nil
}

func isXrayURI(s string) bool {
	return len(s) > 8 && (s[:8] == "vmess://" || s[:8] == "vless://" || (len(s) > 9 && s[:9] == "trojan://") || s[:5] == "ss://")
}

func xrayProtocol(uri string) string {
	switch {
	case len(uri) >= 8 && uri[:8] == "vmess://":
		return "vmess"
	case len(uri) >= 8 && uri[:8] == "vless://":
		return "vless"
	case len(uri) >= 9 && uri[:9] == "trojan://":
		return "trojan"
	default:
		return "shadowsocks"
	}
}

func (s *Store) commit(profiles []Profile) error {
	if s.loadErr != nil {
		return fmt.Errorf("хранилище профилей недоступно: %w", s.loadErr)
	}
	sd := storeData{Version: 2, Profiles: profiles}
	plaintext, err := json.Marshal(sd)
	if err != nil {
		return fmt.Errorf("marshal profiles: %w", err)
	}
	defer clear(plaintext)
	data, err := encodeStoredProfiles(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt profiles: %w", err)
	}
	if err := writeConfigFile(s.path, data); err != nil {
		return err
	}
	s.profiles = profiles
	return nil
}

// GetAll returns a copy of all profiles
func (s *Store) GetAll() []Profile {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Profile, len(s.profiles))
	copy(out, s.profiles)
	return out
}

// GetByID returns a profile by ID
func (s *Store) GetByID(id string) (*Profile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.profiles {
		if s.profiles[i].ID == id {
			p := s.profiles[i]
			return &p, true
		}
	}
	return nil, false
}

// Import adds new profiles and updates matching IDs in one disk write.
func (s *Store) Import(batch []Profile) ([]Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.importLocked(batch)
}

// RestoreArchive rejects changes to affected profiles since the preview.
func (s *Store) RestoreArchive(batch []Profile, previewed map[string]time.Time) ([]Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current := make(map[string]time.Time, len(s.profiles))
	for _, profile := range s.profiles {
		current[profile.ID] = profile.UpdatedAt
	}
	for _, profile := range batch {
		now, exists := current[profile.ID]
		before, existed := previewed[profile.ID]
		if exists != existed || !now.Equal(before) {
			return nil, fmt.Errorf("Профили изменились после предпросмотра. Откройте архив повторно")
		}
	}
	return s.importLocked(batch)
}

func (s *Store) importLocked(batch []Profile) ([]Profile, error) {
	next := slices.Clone(s.profiles)
	indices := make(map[string]int, len(next))
	for i, p := range next {
		indices[p.ID] = i
	}
	saved := make([]Profile, 0, len(batch))
	now := time.Now()
	for _, p := range batch {
		if p.ID == "" {
			p.ID = uuid.NewString()
		}
		p.UpdatedAt = now
		if i, ok := indices[p.ID]; ok {
			p.CreatedAt = next[i].CreatedAt
			p.LastUsed = next[i].LastUsed
			next[i] = p
		} else {
			p.CreatedAt = now
			indices[p.ID] = len(next)
			next = append(next, p)
		}
		saved = append(saved, p)
	}
	if err := s.commit(next); err != nil {
		return nil, err
	}
	return saved, nil
}

func (s *Store) Add(p Profile) (Profile, error) {
	saved, err := s.Import([]Profile{p})
	if err != nil {
		return Profile{}, err
	}
	return saved[0], nil
}

func (s *Store) Update(p Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, old := range s.profiles {
		if old.ID == p.ID {
			next := slices.Clone(s.profiles)
			p.CreatedAt = old.CreatedAt
			p.LastUsed = old.LastUsed
			p.UpdatedAt = time.Now()
			next[i] = p
			return s.commit(next)
		}
	}
	return fmt.Errorf("profile %q not found", p.ID)
}

// SetFavorite changes only the favorite flag for an existing profile.
func (s *Store) SetFavorite(id string, favorite bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, profile := range s.profiles {
		if profile.ID == id {
			if profile.IsFavorite == favorite {
				return nil
			}
			next := slices.Clone(s.profiles)
			next[i].IsFavorite = favorite
			next[i].UpdatedAt = time.Now()
			return s.commit(next)
		}
	}
	return fmt.Errorf("profile %q not found", id)
}

// Delete removes a profile by ID
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.profiles {
		if s.profiles[i].ID == id {
			return s.commit(slices.Delete(slices.Clone(s.profiles), i, i+1))
		}
	}
	return fmt.Errorf("profile %q not found", id)
}

// TouchLastUsed updates last used timestamp
func (s *Store) TouchLastUsed(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for i := range s.profiles {
		if s.profiles[i].ID == id {
			next := slices.Clone(s.profiles)
			next[i].LastUsed = &now
			_ = s.commit(next)
			return
		}
	}
}

func writeConfigFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(tmp.Name(), path)
}
