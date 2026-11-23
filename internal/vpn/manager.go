// Package vpn provides the VPN connection manager abstraction.
package vpn

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
)

// Manager manages active VPN connections
type Manager struct {
	mu        sync.RWMutex
	rasMu     sync.Mutex // serializes RAS setup and cleanup, including routing
	current   *activeConn
	requested bool // a connection command already took precedence over startup
	changes   chan struct{}
	settings  config.AppSettings // snapshot updated by SetSettings
}

type activeConn struct {
	profile        config.Profile
	state          config.ConnectionState
	errorMsg       string
	connectedAt    time.Time
	cancel         context.CancelFunc // cancels the connect goroutine
	openVPNStopped chan struct{}
	rasActive      bool // guarded by Manager.rasMu
}

// NewManager creates a VPN manager
func NewManager() *Manager {
	return &Manager{changes: make(chan struct{}, 1)}
}

// Changes signals that callers should read a fresh status snapshot.
func (m *Manager) Changes() <-chan struct{} { return m.changes }

func (m *Manager) notifyStatusChanged() {
	select {
	case m.changes <- struct{}{}:
	default:
	}
}

// Connect starts a VPN connection asynchronously and returns immediately.
// Status() / events carry the result.
func (m *Manager) Connect(p config.Profile) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requested = true

	if m.current != nil {
		if err := m.disconnectLocked(); err != nil {
			return err
		}
	}
	m.startLocked(p)
	return nil
}

// ConnectOnStartup only starts if no connection command has already run.
func (m *Manager) ConnectOnStartup(p config.Profile) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.requested {
		return false
	}
	m.requested = true
	m.startLocked(p)
	return true
}

// ConnectWhenIdle leaves an active or pending connection alone.
func (m *Manager) ConnectWhenIdle(p config.Profile) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.current != nil {
		if m.current.state != config.StateError {
			return false, nil
		}
		if err := m.disconnectLocked(); err != nil {
			return false, err
		}
	}
	m.requested = true
	m.startLocked(p)
	return true, nil
}

func (m *Manager) startLocked(p config.Profile) {
	ctx, cancel := context.WithCancel(context.Background())
	attempt := &activeConn{
		profile: p,
		state:   config.StateConnecting,
		cancel:  cancel,
	}
	if p.TunnelType == config.TunnelOpenVPN {
		attempt.openVPNStopped = make(chan struct{})
	}
	m.current = attempt
	m.notifyStatusChanged()

	go m.runConnect(ctx, attempt)
}

func (m *Manager) runConnect(ctx context.Context, attempt *activeConn) {
	p := attempt.profile
	isRAS := p.TunnelType == config.TunnelL2TP ||
		p.TunnelType == config.TunnelIKEv2 ||
		p.TunnelType == config.TunnelSSTP ||
		p.TunnelType == config.TunnelPPTP
	isXray := p.TunnelType == config.TunnelXray

	backoff := 5 * time.Second
	const maxBackoff = 60 * time.Second

	for {
		var err error
		var openVPNExit <-chan error
		switch p.TunnelType {
		case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
			err = m.connectRASAttempt(ctx, attempt)
		case config.TunnelWireGuard:
			err = connectWireGuard(ctx, p)
		case config.TunnelOpenVPN:
			openVPNExit, err = connectOpenVPN(ctx, p, attempt.openVPNStopped)
		case config.TunnelXray:
			err = connectXray(ctx, p)
		default:
			err = fmt.Errorf("unsupported tunnel type: %s", p.TunnelType)
		}

		m.mu.Lock()

		// If Disconnect was called while we were connecting, current is nil — just bail.
		if m.current != attempt {
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
			m.notifyStatusChanged()
			m.mu.Unlock()
			return
		}

		m.current.state = config.StateConnected
		m.current.connectedAt = time.Now()
		m.notifyStatusChanged()
		backoff = 5 * time.Second // reset backoff after successful connect
		m.mu.Unlock()

		// Watch the live connection. RAS and Xray get health monitoring and
		// auto-reconnect; WireGuard/OpenVPN manage their own lifecycle.
		switch {
		case openVPNExit != nil:
			err := <-openVPNExit
			m.mu.Lock()
			if m.current == attempt && ctx.Err() == nil {
				attempt.state = config.StateError
				attempt.errorMsg = "Процесс OpenVPN завершился"
				if err != nil {
					attempt.errorMsg += ": " + err.Error()
				}
				m.notifyStatusChanged()
			}
			m.mu.Unlock()
			return
		case isRAS:
			m.monitorRASConnection(ctx, attempt)
		case isXray:
			if err := m.monitorXrayConnection(ctx, attempt); err != nil {
				m.mu.Lock()
				if m.current == attempt && ctx.Err() == nil {
					attempt.state = config.StateError
					attempt.errorMsg = errors.Join(err, disconnectXrayActive()).Error()
					m.notifyStatusChanged()
				}
				m.mu.Unlock()
				return
			}
		default:
			return
		}

		// If the context was cancelled, the user deliberately disconnected — stop.
		if ctx.Err() != nil {
			return
		}

		// The connection dropped. Schedule an auto-reconnect.
		m.mu.Lock()
		if m.current != attempt {
			m.mu.Unlock()
			return
		}
		logger.Info("autoReconnect: reconnecting '%s' in %v", p.Name, backoff)
		m.current.state = config.StateConnecting
		m.current.errorMsg = ""
		m.notifyStatusChanged()
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

func (m *Manager) connectRASAttempt(ctx context.Context, attempt *activeConn) error {
	m.mu.RLock()
	settings := m.settings
	m.mu.RUnlock()

	m.rasMu.Lock()
	defer m.rasMu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if attempt.rasActive {
		RemoveSplitTunnel(attempt.profile)
		attempt.rasActive = false
	}
	if err := connectRAS(ctx, attempt.profile); err != nil {
		return err
	}
	attempt.rasActive = true
	if err := ctx.Err(); err != nil {
		return err
	}
	ApplySplitTunnel(ctx, attempt.profile, settings)
	return ctx.Err()
}

// monitorRASConnection polls the RAS connection status every 3 s and marks
// the connection as Error if Windows reports it as gone.
func (m *Manager) monitorRASConnection(ctx context.Context, attempt *activeConn) {
	p := attempt.profile
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
			if m.current == attempt &&
				m.current.state == config.StateConnected {
				logger.Info("monitorRAS: connection '%s' dropped by OS", p.Name)
				m.current.state = config.StateError
				m.current.errorMsg = "Соединение разорвано"
				m.notifyStatusChanged()
			}
			m.mu.Unlock()
			return
		}
	}
}

// monitorXrayConnection returns an error when the system proxy should no
// longer be managed by AikenVPN. Connectivity failures use auto-reconnect.
func (m *Manager) monitorXrayConnection(ctx context.Context, attempt *activeConn) error {
	p := attempt.profile
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	// Require two consecutive probe failures before declaring a drop so a single
	// transient network blip doesn't trigger a needless reconnect.
	misses := 0
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if !isXrayAlive() {
				logger.Info("monitorXray: instance for '%s' is gone — reconnecting", p.Name)
				return nil
			}
			if err := checkXrayProxy(ctx); err != nil {
				return err
			}
			if xrayProbeOK(ctx) {
				misses = 0
				continue
			}
			misses++
			if misses < 2 {
				continue
			}
			m.mu.Lock()
			dropping := m.current == attempt &&
				m.current.state == config.StateConnected
			m.mu.Unlock()
			if dropping {
				logger.Info("monitorXray: '%s' failed connectivity probe twice — reconnecting", p.Name)
			}
			return nil
		}
	}
}

// Disconnect terminates the current VPN connection (or cancels a pending one).
func (m *Manager) Disconnect() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requested = true
	if m.current == nil {
		return nil
	}
	return m.disconnectLocked()
}

// CleanupStaleRAS removes an unused RAS entry without racing a new connection.
func (m *Manager) CleanupStaleRAS(name string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current != nil && m.current.profile.Name == name {
		return
	}
	m.rasMu.Lock()
	defer m.rasMu.Unlock()
	ForceCleanupRAS(name)
}

func (m *Manager) disconnectLocked() error {
	if m.current == nil {
		return nil
	}

	conn := m.current
	m.current = nil
	m.notifyStatusChanged()

	// Always cancel the context — stops connect goroutine and health monitor.
	if conn.cancel != nil {
		conn.cancel()
	}

	// Xray owns an in-process instance and the machine-global system proxy.
	// OpenVPN's child process is owned by the cancelled attempt context.
	switch conn.profile.TunnelType {
	case config.TunnelXray:
		return disconnectXrayActive()
	case config.TunnelOpenVPN:
		<-conn.openVPNStopped
		return nil
	case config.TunnelWireGuard:
		return disconnectWireGuard(conn.profile)
	case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
		m.rasMu.Lock()
		defer m.rasMu.Unlock()
		if conn.rasActive {
			RemoveSplitTunnel(conn.profile)
			return disconnectRAS(conn.profile.Name)
		}
	}

	return nil
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
