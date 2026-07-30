package vpn

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/registry"
)

const (
	internetSettingsKey = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

	INTERNET_OPTION_SETTINGS_CHANGED = 39
	INTERNET_OPTION_REFRESH          = 37
)

var (
	wininet                  = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW   = wininet.NewProc("InternetSetOptionW")
)

const proxyOverride = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

// setSystemProxy enables the Windows system proxy pointing to addr (e.g. "127.0.0.1:10809").
// It writes to the registry and signals WinInet to refresh immediately.
func setSystemProxy(addr string) error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return fmt.Errorf("set ProxyEnable: %w", err)
	}
	if err := k.SetStringValue("ProxyServer", addr); err != nil {
		return fmt.Errorf("set ProxyServer: %w", err)
	}
	// Bypass localhost and LAN from proxy
	if err := k.SetStringValue("ProxyOverride", proxyOverride); err != nil {
		_ = err // non-fatal
	}

	refreshWinInet()
	return nil
}

// ensureSystemProxy re-asserts the system proxy only if it has drifted from the
// expected value. Something else on the machine (a browser's "auto-detect
// settings", another VPN client, group policy, a network-change event) can
// silently overwrite HKCU Internet Settings, which would send traffic direct
// while the app still reports "Connected". The Xray health monitor calls this
// every few seconds so such overwrites self-heal. Returns true if a correction
// was applied.
func ensureSystemProxy(addr string) bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()

	enabled, _, _ := k.GetIntegerValue("ProxyEnable")
	server, _, _ := k.GetStringValue("ProxyServer")
	if enabled == 1 && server == addr {
		return false // already correct — no registry write, no WinInet refresh
	}
	_ = k.SetDWordValue("ProxyEnable", 1)
	_ = k.SetStringValue("ProxyServer", addr)
	_ = k.SetStringValue("ProxyOverride", proxyOverride)
	refreshWinInet()
	return true
}

// clearSystemProxy disables the Windows system proxy and blanks the server so a
// stale 127.0.0.1:<port> value can't linger and black-hole traffic after the
// local proxy has stopped.
func clearSystemProxy() {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	_ = k.SetDWordValue("ProxyEnable", 0)
	_ = k.SetStringValue("ProxyServer", "")
	refreshWinInet()
}

// refreshWinInet calls InternetSetOption to make WinInet pick up registry changes immediately.
func refreshWinInet() {
	_ = procInternetSetOptionW.Find() // ensure dll is loaded
	procInternetSetOptionW.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	procInternetSetOptionW.Call(0, INTERNET_OPTION_REFRESH, uintptr(unsafe.Pointer(nil)), 0)
}
