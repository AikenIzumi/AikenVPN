//go:build windows

// Package vpn — Windows RAS (L2TP/IKEv2/SSTP/PPTP) via direct rasapi32.dll calls.
// No PowerShell subprocess, no rasdial.exe — pure Win32 API through syscall.
package vpn

import (
	"fmt"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
)

// ── rasapi32.dll lazy-loaded procs ───────────────────────────────────────────

var (
	modRas              = syscall.NewLazyDLL("rasapi32.dll")
	procSetEntryProps   = modRas.NewProc("RasSetEntryPropertiesW")
	procDial            = modRas.NewProc("RasDialW")
	procHangUp          = modRas.NewProc("RasHangUpW")
	procDeleteEntry     = modRas.NewProc("RasDeleteEntryW")
	procEnumConns       = modRas.NewProc("RasEnumConnectionsW")
	procGetConnStatus   = modRas.NewProc("RasGetConnectStatusW")
	procGetErrorString  = modRas.NewProc("RasGetErrorStringW")
	procSetCredentials  = modRas.NewProc("RasSetCredentialsW")
)

// ── Constants (from ras.h / Windows SDK) ─────────────────────────────────────

const (
	rasMaxEntryName   = 256
	rasMaxPhoneNumber = 128
	rasMaxDeviceType  = 16
	rasMaxDeviceName  = 128
	rasMaxAreaCode    = 10
	rasMaxPadType     = 32
	rasMaxX25Addr     = 200
	rasMaxFacilities  = 200
	rasMaxUserData    = 200
	rasMaxDnsSuffix   = 256
	rasMaxCallbackNum = 128
	maxPath           = 260
	unlen             = 256 // UNLEN: max user name length
	pwlen             = 256 // PWLEN: max password length
	dnlen             = 15  // DNLEN: max domain name length

	// dwType
	rasetVPN = 4

	// dwVpnStrategy
	vsDefault   = 0
	vsPPTPOnly  = 1
	vsL2TPOnly  = 3
	vsSSTPoOnly = 5
	vsIKEv2Only = 7

	// dwEncryptionType
	etNone     = 0
	etRequired = 1
	etMax      = 2
	etOptional = 3

	// dwfNetProtocols
	rasnpIP = 0x00000004

	// dwFramingProtocol
	rasfpPPP = 0x00000001

	// dwfOptions
	raseoRemoteDefaultGateway  = 0x00000010
	raseoRequireDataEncryption = 0x00001000
	raseoRequireEncryptedPw    = 0x00000400
	raseoRequireMSEncryptedPw  = 0x00000800

	// dwfOptions2
	raseo2UsePresharedKey   = 0x00000010
	raseo2ReconnectIfDropped = 0x00000100
	raseo2CacheCredentials  = 0x00020000

	// RASCS connection states
	rascsPaused             = 0x1000
	rascsConnected          = 0x2000
	rascsDisconnected       = 0x2001
	rascsOpenPort           = 0
	rascsPortOpened         = 1
	rascsConnectDevice      = 2
	rascsDeviceConnected    = 3
	rascsAllDevicesConnected = 4
	rascsAuthenticate       = 5
	rascsAuthNotify         = 6
	rascsAuthRetry          = 7
	rascsAuthCallback       = 8
	rascsAuthChangePassword = 9
	rascsAuthProject        = 10
	rascsAuthLinkSpeed      = 11
	rascsAuthAck            = 12
	rascsReAuthenticate     = 13
	rascsAuthenticated      = 14
	raschsPrepareForCallback = 15
	rascsWaitForModemReset  = 16
	rascsWaitForCallback    = 17
	rascsProjected          = 18
	rascsStartAuthentication = 19

	// RASCREDENTIALS mask
	rasCMUserName = 0x00000001
	rasCMPassword = 0x00000002
	rasCMDomain   = 0x00000004
	rasCMPreSharedKey = 0x00000010

	// ERROR_SUCCESS
	errorSuccess = 0
)

// ── Windows structs ───────────────────────────────────────────────────────────

// rasIPAddr mirrors RASIPADDR (4 bytes, byte-addressable)
type rasIPAddr struct{ a, b, c, d byte }

// rasEntry mirrors RASENTRYW.  dwSize must equal unsafe.Sizeof(rasEntry{}).
// Field layout must exactly match the C struct from ras.h for the target OS.
type rasEntry struct {
	dwSize                     uint32
	dwfOptions                 uint32
	dwCountryID                uint32
	dwCountryCode              uint32
	szAreaCode                 [rasMaxAreaCode + 1]uint16
	szLocalPhoneNumber         [rasMaxPhoneNumber + 1]uint16
	dwAlternateOffset          uint32
	ipaddr                     rasIPAddr
	ipaddrDns                  rasIPAddr
	ipaddrDnsAlt               rasIPAddr
	ipaddrWins                 rasIPAddr
	ipaddrWinsAlt              rasIPAddr
	dwFrameSize                uint32
	dwfNetProtocols            uint32
	dwFramingProtocol          uint32
	szScript                   [maxPath]uint16
	szAutodialDll              [maxPath]uint16
	szAutodialFunc             [maxPath]uint16
	szDeviceType               [rasMaxDeviceType + 1]uint16
	szDeviceName               [rasMaxDeviceName + 1]uint16
	szX25PadType               [rasMaxPadType + 1]uint16
	szX25Address               [rasMaxX25Addr + 1]uint16
	szX25Facilities            [rasMaxFacilities + 1]uint16
	szX25UserData              [rasMaxUserData + 1]uint16
	dwChannels                 uint32
	dwReserved1                uint32
	dwReserved2                uint32
	dwSubEntries               uint32
	dwDialMode                 uint32
	dwDialExtraPercent         uint32
	dwDialExtraSampleSeconds   uint32
	dwHangUpExtraPercent       uint32
	dwHangUpExtraSampleSeconds uint32
	dwIdleDisconnectSeconds    uint32
	dwType                     uint32
	dwEncryptionType           uint32
	dwCustomAuthKey            uint32
	guidId                     windows.GUID
	szCustomDialDll            [maxPath]uint16
	dwVpnStrategy              uint32
	// Windows XP+
	dwfOptions2                uint32
	dwfOptions3                uint32
	szDnsSuffix                [rasMaxDnsSuffix]uint16
	dwTcpWindowSize            uint32
	szPrerequisitePbk          [maxPath]uint16
	szPrerequisiteEntry        [rasMaxEntryName + 1]uint16
	dwRedialCount              uint32
	dwRedialPause              uint32
	// Windows Vista+
	ipv6addrDns                [16]byte
	ipv6addrDnsAlt             [16]byte
	dwIPv4InterfaceMetric      uint32
	dwIPv6InterfaceMetric      uint32
	ipv6addr                   [16]byte
	dwIPv6PrefixLength         uint32
	dwNetworkOutageTime        uint32
}

// rasDialParams mirrors RASDIALPARAMSW
type rasDialParams struct {
	dwSize          uint32
	szEntryName     [rasMaxEntryName + 1]uint16
	szPhoneNumber   [rasMaxPhoneNumber + 1]uint16
	szCallbackNumber [rasMaxCallbackNum + 1]uint16
	szUserName      [unlen + 1]uint16
	szPassword      [pwlen + 1]uint16
	szDomain        [dnlen + 1]uint16
	dwSubEntry      uint32
	dwCallbackId    uintptr
	dwIfIndex       uint32 // Win8+
}

// rasConn mirrors RASCONNW (used for enumeration / hang-up)
type rasConn struct {
	dwSize      uint32
	hrasconn    uintptr
	szEntryName [rasMaxEntryName + 1]uint16
	szDeviceType [rasMaxDeviceType + 1]uint16
	szDeviceName [rasMaxDeviceName + 1]uint16
	szPhonebook [maxPath]uint16
	dwSubEntry  uint32
	guidEntry   windows.GUID
	dwFlags     uint32
	luid        [8]byte // LUID = two uint32
	guidCorrId  windows.GUID
}

// rasConnStatus mirrors RASCONNSTATUSW
type rasConnStatus struct {
	dwSize          uint32
	rasconnstate    uint32
	dwError         uint32
	szDeviceType    [rasMaxDeviceType + 1]uint16
	szDeviceName    [rasMaxDeviceName + 1]uint16
	szPhoneNumber   [rasMaxPhoneNumber + 1]uint16
}

// rasCredentials mirrors RASCREDENTIALSW
type rasCredentials struct {
	dwSize     uint32
	dwMask     uint32
	szUserName [unlen + 1]uint16
	szPassword [pwlen + 1]uint16
	szDomain   [dnlen + 1]uint16
}

// ── Connect / Disconnect ──────────────────────────────────────────────────────

// connectRAS creates a Windows VPN phonebook entry and dials it — no PowerShell, no rasdial.exe.
func connectRAS(p config.Profile) error {
	ForceCleanupRAS(p.Name)

	if p.TunnelType == config.TunnelL2TP {
		setL2TPNATKey()
	}

	entryNamePtr, _ := windows.UTF16PtrFromString(p.Name)

	entry := rasEntry{}
	entry.dwSize = uint32(unsafe.Sizeof(entry))
	entry.dwType = rasetVPN
	entry.dwfNetProtocols = rasnpIP
	entry.dwFramingProtocol = rasfpPPP
	entry.dwfOptions = raseoRemoteDefaultGateway

	// Encryption
	switch p.Encryption {
	case config.EncryptionRequired:
		entry.dwEncryptionType = etRequired
		entry.dwfOptions |= raseoRequireDataEncryption | raseoRequireMSEncryptedPw
	case config.EncryptionMaxLevel:
		entry.dwEncryptionType = etMax
		entry.dwfOptions |= raseoRequireDataEncryption | raseoRequireMSEncryptedPw
	case config.EncryptionNoEncrypt:
		entry.dwEncryptionType = etNone
	default:
		entry.dwEncryptionType = etOptional
	}

	// VPN strategy (protocol selection)
	switch p.TunnelType {
	case config.TunnelPPTP:
		entry.dwVpnStrategy = vsPPTPOnly
	case config.TunnelL2TP:
		entry.dwVpnStrategy = vsL2TPOnly
		if p.PresharedKey != "" {
			entry.dwfOptions2 |= raseo2UsePresharedKey
		}
	case config.TunnelSSTP:
		entry.dwVpnStrategy = vsSSTPoOnly
	case config.TunnelIKEv2:
		entry.dwVpnStrategy = vsIKEv2Only
	default:
		entry.dwVpnStrategy = vsDefault
	}

	// Server address → szLocalPhoneNumber
	putStr16(entry.szLocalPhoneNumber[:], p.Server)

	// Device type hint
	putStr16(entry.szDeviceType[:], "VPN")

	// Create phonebook entry
	rc, _, _ := procSetEntryProps.Call(
		0, // default phonebook
		uintptr(unsafe.Pointer(entryNamePtr)),
		uintptr(unsafe.Pointer(&entry)),
		uintptr(unsafe.Sizeof(entry)),
		0, 0,
	)
	if rc != errorSuccess {
		return fmt.Errorf("RasSetEntryProperties: %s", rasErrorStr(uint32(rc)))
	}

	// For L2TP: store pre-shared key via RasSetCredentials
	if p.TunnelType == config.TunnelL2TP && p.PresharedKey != "" {
		if err := rasSetPSK(p.Name, p.PresharedKey); err != nil {
			logger.Info("rasSetPSK: %v (non-fatal)", err)
		}
	}

	// Dial
	dp := rasDialParams{}
	dp.dwSize = uint32(unsafe.Sizeof(dp))
	putStr16(dp.szEntryName[:], p.Name)
	if p.Username != "" {
		putStr16(dp.szUserName[:], p.Username)
		putStr16(dp.szPassword[:], p.Password)
	}

	var hConn uintptr
	rc, _, _ = procDial.Call(
		0, // extensions
		0, // default phonebook
		uintptr(unsafe.Pointer(&dp)),
		0,                       // no callback
		0,                       // callback func
		uintptr(unsafe.Pointer(&hConn)),
	)
	if rc != errorSuccess {
		ForceCleanupRAS(p.Name)
		return fmt.Errorf("%s", translateRasError(rasErrorStr(uint32(rc))))
	}

	// Poll until connected or error (max 60 s)
	if err := waitRASConnected(hConn, 60*time.Second); err != nil {
		procHangUp.Call(hConn)
		ForceCleanupRAS(p.Name)
		return err
	}

	return nil
}

// disconnectRAS hangs up and removes the named VPN entry.
func disconnectRAS(name string) error {
	// Enumerate connections to find the handle
	h := findRASHandle(name)
	if h != 0 {
		procHangUp.Call(h)
		time.Sleep(300 * time.Millisecond)
	}
	entryNamePtr, _ := windows.UTF16PtrFromString(name)
	procDeleteEntry.Call(0, uintptr(unsafe.Pointer(entryNamePtr)))
	return nil
}

// ForceCleanupRAS forcefully disconnects and removes a Windows VPN entry.
func ForceCleanupRAS(name string) {
	h := findRASHandle(name)
	if h != 0 {
		procHangUp.Call(h)
		time.Sleep(300 * time.Millisecond)
	}
	entryNamePtr, _ := windows.UTF16PtrFromString(name)
	procDeleteEntry.Call(0, uintptr(unsafe.Pointer(entryNamePtr)))
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// waitRASConnected polls RasGetConnectStatus until the connection is up or fails.
func waitRASConnected(hConn uintptr, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		status := rasConnStatus{}
		status.dwSize = uint32(unsafe.Sizeof(status))
		procGetConnStatus.Call(hConn, uintptr(unsafe.Pointer(&status)))

		switch status.rasconnstate {
		case rascsConnected:
			return nil
		case rascsDisconnected:
			if status.dwError != 0 {
				return fmt.Errorf("%s", translateRasError(rasErrorStr(status.dwError)))
			}
			return fmt.Errorf("соединение разорвано")
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("превышено время ожидания подключения")
}

// findRASHandle returns the HRASCONN for a named active connection, or 0.
func findRASHandle(name string) uintptr {
	var buf [64]rasConn
	buf[0].dwSize = uint32(unsafe.Sizeof(buf[0]))
	bufSize := uint32(unsafe.Sizeof(buf))
	var count uint32

	rc, _, _ := procEnumConns.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&bufSize)),
		uintptr(unsafe.Pointer(&count)),
	)
	if rc != errorSuccess {
		return 0
	}
	for i := uint32(0); i < count; i++ {
		n := windows.UTF16ToString(buf[i].szEntryName[:])
		if strings.EqualFold(n, name) {
			return buf[i].hrasconn
		}
	}
	return 0
}

// rasSetPSK stores the L2TP pre-shared key via RasSetCredentials.
func rasSetPSK(entryName, psk string) error {
	entryPtr, _ := windows.UTF16PtrFromString(entryName)
	cred := rasCredentials{}
	cred.dwSize = uint32(unsafe.Sizeof(cred))
	cred.dwMask = rasCMPreSharedKey
	putStr16(cred.szPassword[:], psk)

	rc, _, _ := procSetCredentials.Call(
		0, // default phonebook
		uintptr(unsafe.Pointer(entryPtr)),
		uintptr(unsafe.Pointer(&cred)),
		0,
	)
	if rc != errorSuccess {
		return fmt.Errorf("RasSetCredentials PSK: %s", rasErrorStr(uint32(rc)))
	}
	return nil
}

// setL2TPNATKey writes the registry value that allows L2TP through NAT.
func setL2TPNATKey() {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\PolicyAgent`, registry.SET_VALUE)
	if err != nil {
		logger.Info("L2TP NAT registry: open key: %v", err)
		return
	}
	defer k.Close()
	if err := k.SetDWordValue("AssumeUDPEncapsulationContextOnSendRule", 2); err != nil {
		logger.Info("L2TP NAT registry: set value: %v", err)
	} else {
		logger.Info("L2TP NAT registry key set")
	}
}

// rasErrorStr calls RasGetErrorStringW to convert an error code to text.
func rasErrorStr(code uint32) string {
	var buf [512]uint16
	rc, _, _ := procGetErrorString.Call(
		uintptr(code),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if rc == errorSuccess {
		return windows.UTF16ToString(buf[:])
	}
	return fmt.Sprintf("RAS error %d", code)
}

// putStr16 copies a Go string into a uint16 slice (UTF-16, null-terminated).
func putStr16(dst []uint16, s string) {
	p, _ := windows.UTF16PtrFromString(s)
	src := (*[1 << 20]uint16)(unsafe.Pointer(p))[:len(dst)]
	copy(dst, src)
}

// translateRasError converts common RAS error messages to human-readable Russian text.
func translateRasError(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "691") || strings.Contains(lower, "access was denied"):
		return "Ошибка 691: неверный логин или пароль"
	case strings.Contains(lower, "800") || strings.Contains(lower, "unable to establish"):
		return "Ошибка 800: не удалось установить соединение с сервером"
	case strings.Contains(lower, "619"):
		return "Ошибка 619: L2TP/IPSec недоступен — проверьте порты UDP 500/4500/1701"
	case strings.Contains(lower, "720"):
		return "Ошибка 720: нет совместимого протокола PPP"
	case strings.Contains(lower, "789") || strings.Contains(lower, "l2tp"):
		return "Ошибка 789: не удалось согласовать L2TP/IPSec — проверьте Pre-Shared Key"
	case strings.Contains(lower, "868") || strings.Contains(lower, "cannot resolve"):
		return "Ошибка 868: не удалось разрешить имя сервера"
	case strings.Contains(lower, "13801") || strings.Contains(lower, "ikev2"):
		return "Ошибка IKEv2: недействительный сертификат или Pre-Shared Key"
	case raw == "":
		return "Нет ответа от RAS — требуются права администратора"
	default:
		return fmt.Sprintf("Ошибка RAS: %s", raw)
	}
}

// GetRASConnectionStatus checks whether a named connection is active.
func GetRASConnectionStatus(name string) config.ConnectionState {
	h := findRASHandle(name)
	if h == 0 {
		return config.StateDisconnected
	}
	status := rasConnStatus{}
	status.dwSize = uint32(unsafe.Sizeof(status))
	procGetConnStatus.Call(h, uintptr(unsafe.Pointer(&status)))
	switch status.rasconnstate {
	case rascsConnected:
		return config.StateConnected
	case rascsDisconnected:
		return config.StateDisconnected
	default:
		return config.StateConnecting
	}
}
