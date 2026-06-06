package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.profiles = []Profile{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read profiles: %w", err)
	}
	var sd storeData
	if err := json.Unmarshal(data, &sd); err != nil {
		return fmt.Errorf("parse profiles: %w", err)
	}
	s.profiles = sd.Profiles
	return nil
}

func (s *Store) save() error {
	sd := storeData{Version: 2, Profiles: s.profiles}
	data, err := json.MarshalIndent(sd, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal profiles: %w", err)
	}
	return os.WriteFile(s.path, data, 0600)
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

// Add inserts a new profile (assigns ID if empty)
func (s *Store) Add(p Profile) (Profile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.ID == "" {
		p.ID = uuid.New().String()
	}
	now := time.Now()
	p.CreatedAt = now
	p.UpdatedAt = now
	s.profiles = append(s.profiles, p)
	return p, s.save()
}

// Update replaces an existing profile
func (s *Store) Update(p Profile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.profiles {
		if s.profiles[i].ID == p.ID {
			p.UpdatedAt = time.Now()
			p.CreatedAt = s.profiles[i].CreatedAt
			s.profiles[i] = p
			return s.save()
		}
	}
	return fmt.Errorf("profile %q not found", p.ID)
}

// Delete removes a profile by ID
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.profiles {
		if s.profiles[i].ID == id {
			s.profiles = append(s.profiles[:i], s.profiles[i+1:]...)
			return s.save()
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
			s.profiles[i].LastUsed = &now
			_ = s.save()
			return
		}
	}
}
