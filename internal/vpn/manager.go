// Package vpn provides the VPN connection manager abstraction.
package vpn

import (
	"fmt"
	"sync"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
)

// Manager manages active VPN connections
type Manager struct {
	mu      sync.RWMutex
	current *activeConn
}

type activeConn struct {
	profile     config.Profile
	state       config.ConnectionState
	connectedAt time.Time
	cancelFn    func() // cleanup function
}

// NewManager creates a VPN manager
func NewManager() *Manager {
	return &Manager{}
}

// Connect establishes a VPN connection for the given profile
func (m *Manager) Connect(p config.Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Disconnect current if any
	if m.current != nil {
		m.disconnectLocked()
	}

	m.current = &activeConn{
		profile: p,
		state:   config.StateConnecting,
	}

	var err error
	switch p.TunnelType {
	case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
		err = connectRAS(p)
	case config.TunnelWireGuard:
		err = connectWireGuard(p)
	case config.TunnelOpenVPN:
		err = connectOpenVPN(p, m)
	case config.TunnelXray:
		err = connectXray(p, m)
	default:
		err = fmt.Errorf("unsupported tunnel type: %s", p.TunnelType)
	}

	if err != nil {
		m.current = nil // reset so status ticker returns Disconnected, not infinite Error
		return err
	}

	m.current.state = config.StateConnected
	m.current.connectedAt = time.Now()
	return nil
}

// Disconnect terminates the current VPN connection
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current == nil {
		return nil
	}
	return m.disconnectLocked()
}

func (m *Manager) disconnectLocked() error {
	if m.current == nil {
		return nil
	}
	m.current.state = config.StateDisconnecting

	var err error
	switch m.current.profile.TunnelType {
	case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
		err = disconnectRAS(m.current.profile.Name)
	case config.TunnelWireGuard:
		err = disconnectWireGuard(m.current.profile)
	case config.TunnelOpenVPN:
		if m.current.cancelFn != nil {
			m.current.cancelFn()
		}
		err = disconnectOpenVPN()
	case config.TunnelXray:
		if m.current.cancelFn != nil {
			m.current.cancelFn()
		} else {
			err = disconnectXrayActive()
		}
	}

	m.current = nil
	return err
}

// Status returns the current connection status
func (m *Manager) Status() config.ConnectionStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.current == nil {
		return config.ConnectionStatus{State: config.StateDisconnected}
	}

	st := config.ConnectionStatus{
		ProfileID:   m.current.profile.ID,
		ProfileName: m.current.profile.Name,
		State:       m.current.state,
	}
	if m.current.state == config.StateConnected {
		t := m.current.connectedAt
		st.ConnectedAt = &t
	}
	return st
}

// IsConnected returns true if there is an active connection
func (m *Manager) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current != nil && m.current.state == config.StateConnected
}

// SetCancelFn stores a cleanup function for the current connection (used by OpenVPN goroutine)
func (m *Manager) SetCancelFn(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		m.current.cancelFn = fn
	}
}
