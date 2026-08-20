package main

import (
	"testing"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
)

// ─── statusKey ───────────────────────────────────────────────────────────────

func TestStatusKeyIdenticalStatusesGiveIdenticalKeys(t *testing.T) {
	at := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	s1 := config.ConnectionStatus{
		ProfileID:   "p1",
		ProfileName: "Home",
		State:       config.StateConnected,
		ConnectedAt: &at,
		LocalIP:     "10.0.0.2",
		ServerIP:    "1.2.3.4",
	}
	// Same values but a distinct *time.Time pointer — the key must depend on
	// the value, not the pointer identity.
	at2 := at
	s2 := s1
	s2.ConnectedAt = &at2

	if statusKey(s1) != statusKey(s2) {
		t.Errorf("identical statuses produced different keys:\n  %q\n  %q",
			statusKey(s1), statusKey(s2))
	}
}

func TestStatusKeyDistinguishesStates(t *testing.T) {
	base := config.ConnectionStatus{ProfileID: "p1"}
	states := []config.ConnectionState{
		config.StateDisconnected,
		config.StateConnecting,
		config.StateConnected,
		config.StateDisconnecting,
		config.StateError,
	}
	seen := make(map[string]config.ConnectionState)
	for _, st := range states {
		s := base
		s.State = st
		key := statusKey(s)
		if prev, dup := seen[key]; dup {
			t.Errorf("states %q and %q produced the same key %q", prev, st, key)
		}
		seen[key] = st
	}
}

func TestStatusKeyDistinguishesProfiles(t *testing.T) {
	s1 := config.ConnectionStatus{State: config.StateConnected, ProfileID: "p1"}
	s2 := config.ConnectionStatus{State: config.StateConnected, ProfileID: "p2"}
	if statusKey(s1) == statusKey(s2) {
		t.Errorf("different profiles produced the same key %q", statusKey(s1))
	}
}

func TestStatusKeyDistinguishesErrors(t *testing.T) {
	s1 := config.ConnectionStatus{State: config.StateError, ProfileID: "p1", ErrorMsg: "timeout"}
	s2 := config.ConnectionStatus{State: config.StateError, ProfileID: "p1", ErrorMsg: "auth failed"}
	if statusKey(s1) == statusKey(s2) {
		t.Errorf("different errors produced the same key %q", statusKey(s1))
	}
	s3 := s1
	s3.ErrorMsg = ""
	if statusKey(s1) == statusKey(s3) {
		t.Errorf("error vs no-error produced the same key %q", statusKey(s1))
	}
}

func TestStatusKeyDistinguishesIPs(t *testing.T) {
	s1 := config.ConnectionStatus{State: config.StateConnected, ProfileID: "p1", ServerIP: "1.1.1.1", LocalIP: "10.0.0.2"}

	s2 := s1
	s2.ServerIP = "2.2.2.2"
	if statusKey(s1) == statusKey(s2) {
		t.Errorf("different server IPs produced the same key %q", statusKey(s1))
	}

	s3 := s1
	s3.LocalIP = "10.0.0.3"
	if statusKey(s1) == statusKey(s3) {
		t.Errorf("different local IPs produced the same key %q", statusKey(s1))
	}
}

func TestStatusKeyConnectedAtNilVsSet(t *testing.T) {
	at := time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)
	withTime := config.ConnectionStatus{State: config.StateConnected, ProfileID: "p1", ConnectedAt: &at}
	withoutTime := config.ConnectionStatus{State: config.StateConnected, ProfileID: "p1"}
	if statusKey(withTime) == statusKey(withoutTime) {
		t.Errorf("ConnectedAt nil vs set produced the same key %q", statusKey(withTime))
	}

	later := at.Add(time.Minute)
	withLater := withTime
	withLater.ConnectedAt = &later
	if statusKey(withTime) == statusKey(withLater) {
		t.Errorf("different ConnectedAt times produced the same key %q", statusKey(withTime))
	}
}

// ─── lastUsedProfile ─────────────────────────────────────────────────────────

func TestLastUsedProfileEmptySlice(t *testing.T) {
	if got := lastUsedProfile(nil); got != nil {
		t.Errorf("lastUsedProfile(nil) = %+v, want nil", got)
	}
	if got := lastUsedProfile([]config.Profile{}); got != nil {
		t.Errorf("lastUsedProfile(empty) = %+v, want nil", got)
	}
}

func TestLastUsedProfileAllWithoutLastUsed(t *testing.T) {
	profiles := []config.Profile{
		{ID: "a", Name: "A"},
		{ID: "b", Name: "B"},
	}
	if got := lastUsedProfile(profiles); got != nil {
		t.Errorf("lastUsedProfile(no LastUsed) = %+v, want nil", got)
	}
}

func TestLastUsedProfileSkipsNilAndPicksMostRecent(t *testing.T) {
	t1 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	t2 := time.Date(2026, 8, 15, 0, 0, 0, 0, time.UTC)
	t3 := time.Date(2026, 8, 10, 0, 0, 0, 0, time.UTC)
	profiles := []config.Profile{
		{ID: "old", Name: "Old", LastUsed: &t1},
		{ID: "never", Name: "Never"}, // no LastUsed — must be skipped
		{ID: "newest", Name: "Newest", LastUsed: &t2},
		{ID: "middle", Name: "Middle", LastUsed: &t3},
	}
	got := lastUsedProfile(profiles)
	if got == nil {
		t.Fatal("lastUsedProfile returned nil, want profile 'newest'")
	}
	if got.ID != "newest" {
		t.Errorf("lastUsedProfile picked %q, want %q", got.ID, "newest")
	}
}

func TestLastUsedProfileSingleCandidate(t *testing.T) {
	t1 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	profiles := []config.Profile{
		{ID: "never", Name: "Never"},
		{ID: "only", Name: "Only", LastUsed: &t1},
	}
	got := lastUsedProfile(profiles)
	if got == nil || got.ID != "only" {
		t.Errorf("lastUsedProfile = %+v, want profile 'only'", got)
	}
}

func TestLastUsedProfileReturnsPointerIntoSlice(t *testing.T) {
	// Callers dereference the result (a.manager.Connect(*last)), so the
	// returned pointer must reference an element of the input slice.
	t1 := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	profiles := []config.Profile{{ID: "x", Name: "X", LastUsed: &t1}}
	got := lastUsedProfile(profiles)
	if got != &profiles[0] {
		t.Errorf("lastUsedProfile returned %p, want pointer into input slice %p", got, &profiles[0])
	}
}
