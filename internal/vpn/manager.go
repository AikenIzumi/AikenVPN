// Package vpn provides the VPN connection manager abstraction.
package vpn

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
)

// Manager manages active VPN connections
type Manager struct {
	mu       sync.RWMutex
	current  *activeConn
	settings config.AppSettings // snapshot updated by SetSettings
}

type activeConn struct {
	profile     config.Profile
	state       config.ConnectionState
	errorMsg    string
	connectedAt time.Time
	cancel      context.CancelFunc // cancels the connect goroutine
	cancelFn    func()             // protocol-specific cleanup (OpenVPN/Xray)
}

// NewManager creates a VPN manager
func NewManager() *Manager {
	return &Manager{}
}

// Connect starts a VPN connection asynchronously and returns immediately.
// Status() / events carry the result.
func (m *Manager) Connect(p config.Profile) error {
	m.mu.Lock()

	if m.current != nil {
		m.disconnectLocked()
	}

	ctx, cancel := context.WithCancel(context.Background())
	m.current = &activeConn{
		profile: p,
		state:   config.StateConnecting,
		cancel:  cancel,
	}
	m.mu.Unlock()

	go m.runConnect(ctx, p)
	return nil
}

func (m *Manager) runConnect(ctx context.Context, p config.Profile) {
	isRAS := p.TunnelType == config.TunnelL2TP ||
		p.TunnelType == config.TunnelIKEv2 ||
		p.TunnelType == config.TunnelSSTP ||
		p.TunnelType == config.TunnelPPTP

	backoff := 5 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		var err error
		switch p.TunnelType {
		case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
			err = connectRAS(ctx, p)
		case config.TunnelWireGuard:
			err = connectWireGuard(p)
		case config.TunnelOpenVPN:
			err = connectOpenVPN(p, m)
		case config.TunnelXray:
			err = connectXray(p, m)
		default:
			err = fmt.Errorf("unsupported tunnel type: %s", p.TunnelType)
		}

		m.mu.Lock()

		// If Disconnect was called while we were connecting, current is nil — just bail.
		if m.current == nil || m.current.profile.ID != p.ID {
			m.mu.Unlock()
			return
		}

		if err != nil {
			if ctx.Err() != nil {
				// Cancelled by user Disconnect — clear silently.
				m.current = nil
			} else {
				logger.Info("connect error [%s]: %v", p.TunnelType, err)
				m.current.state = config.StateError
				m.current.errorMsg = err.Error()
			}
			m.mu.Unlock()
			return
		}

		m.current.state = config.StateConnected
		m.current.connectedAt = time.Now()
		backoff = 5 * time.Second // reset backoff after successful connect
		m.mu.Unlock()

		// Apply split-tunnel + global routing rules in background so UI shows Connected immediately.
		if isRAS {
			m.mu.RLock()
			snap := m.settings
			m.mu.RUnlock()
			go ApplySplitTunnel(p, snap)
		}

		// Non-RAS protocols manage their own lifecycle — nothing more to do here.
		if !isRAS {
			return
		}

		// Monitor for OS-level drops.
		m.monitorRASConnection(ctx, p)

		// If the context was cancelled, the user deliberately disconnected — stop.
		if ctx.Err() != nil {
			return
		}

		// The OS dropped the connection. Schedule an auto-reconnect.
		m.mu.Lock()
		if m.current == nil || m.current.profile.ID != p.ID {
			m.mu.Unlock()
			return
		}
		logger.Info("autoReconnect: reconnecting '%s' in %v", p.Name, backoff)
		m.current.state = config.StateConnecting
		m.current.errorMsg = ""
		m.mu.Unlock()

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff < maxBackoff {
			backoff *= 2
		}
	}
}

// monitorRASConnection polls the RAS connection status every 3 s and marks
// the connection as Error if Windows reports it as gone.
func (m *Manager) monitorRASConnection(ctx context.Context, p config.Profile) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	// Require two consecutive "disconnected" reads before declaring a drop, so
	// a single transient enumeration miss right after connecting doesn't flip
	// the UI to an error while the link is actually stabilising.
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if GetRASConnectionStatus(p.Name) != config.StateDisconnected {
				misses = 0
				continue
			}
			misses++
			if misses < 2 {
				continue
			}
			m.mu.Lock()
			if m.current != nil && m.current.profile.ID == p.ID &&
				m.current.state == config.StateConnected {
				logger.Info("monitorRAS: connection '%s' dropped by OS", p.Name)
				m.current.state = config.StateError
				m.current.errorMsg = "Соединение разорвано"
			}
			m.mu.Unlock()
			return
		}
	}
}

// Disconnect terminates the current VPN connection (or cancels a pending one).
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

	conn := m.current
	m.current = nil

	// Always cancel the context — stops connect goroutine and RAS monitor.
	if conn.cancel != nil {
		conn.cancel()
	}

	// For Error or Connecting states: just cancel the goroutine.
	// connectRAS already calls ForceCleanupRAS at the very start of the NEXT
	// connection attempt (outside the lock), so no cleanup needed here.
	if conn.state == config.StateError || conn.state == config.StateConnecting {
		return nil
	}

	// Full OS-level disconnect for established connections.
	var err error
	switch conn.profile.TunnelType {
	case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
		RemoveSplitTunnel(conn.profile)
		err = disconnectRAS(conn.profile.Name)
	case config.TunnelWireGuard:
		err = disconnectWireGuard(conn.profile)
	case config.TunnelOpenVPN:
		if conn.cancelFn != nil {
			conn.cancelFn()
		}
		err = disconnectOpenVPN()
	case config.TunnelXray:
		if conn.cancelFn != nil {
			conn.cancelFn()
		} else {
			err = disconnectXrayActive()
		}
	}

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
		ErrorMsg:    m.current.errorMsg,
	}
	if m.current.state == config.StateConnected {
		t := m.current.connectedAt
		st.ConnectedAt = &t
		// Expose server address so the frontend can show it
		st.ServerIP = m.current.profile.Server
	}
	return st
}

// SetSettings updates the app-wide settings snapshot used for routing.
func (m *Manager) SetSettings(s config.AppSettings) {
	m.mu.Lock()
	m.settings = s
	m.mu.Unlock()
}

// IsConnected returns true if there is an active connection
func (m *Manager) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.current != nil && m.current.state == config.StateConnected
}

// SetCancelFn stores a cleanup function for the current connection (used by OpenVPN/Xray)
func (m *Manager) SetCancelFn(fn func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		m.current.cancelFn = fn
	}
}
