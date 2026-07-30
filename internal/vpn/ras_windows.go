//go:build windows

// Package vpn — Windows RAS (L2TP/SSTP) via PowerShell Add-VpnConnection + rasdial.
// Entry creation and removal use PowerShell cmdlets (reliable, no struct layout issues).
// Dialing uses rasdial.exe (synchronous, well-tested by Microsoft, no 756 race).
// Win32 RasEnumConnectionsW is kept only for fast status polling.
package vpn

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
)

// ── Win32 procs — only for status polling and emergency hang-up ──────────────

var (
	modRas            = syscall.NewLazyDLL("rasapi32.dll")
	procEnumConns     = modRas.NewProc("RasEnumConnectionsW")
	procGetConnStatus = modRas.NewProc("RasGetConnectStatusW")
	procHangUp        = modRas.NewProc("RasHangUpW")
)

// RASCONNW / RASCONNSTATUS are packed to 4-byte alignment in the Windows
// headers (#pragma pack(4)), so the 8-byte HRASCONN sits at offset 4 — not 8 —
// and the entry name at offset 12. A Go struct with natural alignment would be
// 1392 bytes with field offsets 8/16, which makes RasEnumConnectionsW reject
// the buffer with ERROR_INVALID_SIZE (632) and report zero connections. That is
// why the OS-drop monitor always thought live connections were gone. We instead
// drive the API with a raw byte buffer laid out exactly as Windows expects.
const (
	rasMaxEntryName = 256

	errorInvalidSize = 632 // ERROR_INVALID_SIZE — dwSize not recognised

	rasMaxConns         = 64
	rasConnHandleOffset = 4
	rasConnNameOffset   = 12

	rasConnStatusSize  = 564 // RASCONNSTATUS (pack 4)
	rasConnStateOffset = 4   // rasconnstate DWORD

	rascsConnected    = 0x2000
	rascsDisconnected = 0x2001
)

// rasConnSizes are the accepted RASCONNW byte sizes across Windows versions,
// current (largest) first. RasEnumConnectionsW validates dwSize against the
// version it supports, so we probe these until one is accepted.
var rasConnSizes = []uint32{1388, 1372, 1360, 1344, 820}

type rasConnInfo struct {
	handle uintptr
	name   string
}

var (
	rasEnumMu     sync.Mutex
	rasEnumBuf    []byte // reused across calls to avoid a ~88KB alloc every 3s
	rasCachedSize uint32 // last RASCONNW size the OS accepted (0 = not yet known)
)

// enumRASConns returns all active RAS connections (name + handle). It is called
// every few seconds by the drop monitor, so it caches the struct size the OS
// accepted and reuses a single scratch buffer instead of allocating and
// re-probing all candidate sizes on every call.
func enumRASConns() []rasConnInfo {
	rasEnumMu.Lock()
	defer rasEnumMu.Unlock()

	// Probe order: the previously-accepted size first (steady-state polling then
	// makes a single successful syscall with no allocation), then the rest.
	cached := rasCachedSize
	for idx := -1; idx < len(rasConnSizes); idx++ {
		var sz uint32
		if idx == -1 {
			if cached == 0 {
				continue
			}
			sz = cached
		} else {
			sz = rasConnSizes[idx]
			if sz == cached {
				continue // already tried above
			}
		}

		need := int(sz) * rasMaxConns
		if cap(rasEnumBuf) < need {
			rasEnumBuf = make([]byte, need)
		}
		buf := rasEnumBuf[:need]
		*(*uint32)(unsafe.Pointer(&buf[0])) = sz
		cb := uint32(len(buf))
		var count uint32
		rc, _, _ := procEnumConns.Call(
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(unsafe.Pointer(&cb)),
			uintptr(unsafe.Pointer(&count)),
		)
		if rc == errorInvalidSize {
			continue // wrong struct size for this OS — try the next known size
		}
		if rc != 0 {
			return nil
		}
		rasCachedSize = sz
		if count > rasMaxConns {
			count = rasMaxConns
		}
		base := unsafe.Pointer(&buf[0])
		conns := make([]rasConnInfo, 0, count)
		for i := uint32(0); i < count; i++ {
			rec := unsafe.Add(base, uintptr(i)*uintptr(sz))
			h := *(*uintptr)(unsafe.Add(rec, rasConnHandleOffset))
			name := windows.UTF16ToString((*[rasMaxEntryName + 1]uint16)(unsafe.Add(rec, rasConnNameOffset))[:])
			conns = append(conns, rasConnInfo{handle: h, name: name})
		}
		return conns
	}
	return nil
}

// ── Public entry points ───────────────────────────────────────────────────────

// connectRAS creates a Windows VPN entry via PowerShell and dials via rasdial.
func connectRAS(ctx context.Context, p config.Profile) error {
	// Always start from a clean slate to prevent error 756.
	ForceCleanupRAS(p.Name)

	if p.TunnelType == config.TunnelL2TP {
		setL2TPNATKey()
	}
	if p.TunnelType == config.TunnelSSTP && p.SkipCertCheck {
		setSSTPNoCertCheck()
	}

	if err := addVPNConnection(p); err != nil {
		return err
	}

	return dialRAS(ctx, p)
}

// disconnectRAS hangs up and removes the named VPN entry.
func disconnectRAS(name string) error {
	rasdialDisconnect(name)
	hangUpAll(name)
	removeVPNConnection(name)
	return nil
}

// ForceCleanupRAS is called at startup and before every reconnect attempt.
func ForceCleanupRAS(name string) {
	logger.Info("ForceCleanupRAS: '%s'", name)
	rasdialDisconnect(name)
	hangUpAll(name)
	removeVPNConnection(name)
}

// GetRASConnectionStatus returns the OS-level state of a named connection.
func GetRASConnectionStatus(name string) config.ConnectionState {
	h := findRASHandle(name)
	if h == 0 {
		return config.StateDisconnected
	}
	buf := make([]byte, rasConnStatusSize)
	*(*uint32)(unsafe.Pointer(&buf[0])) = rasConnStatusSize
	procGetConnStatus.Call(h, uintptr(unsafe.Pointer(&buf[0])))
	switch *(*uint32)(unsafe.Pointer(&buf[rasConnStateOffset])) {
	case rascsConnected:
		return config.StateConnected
	case rascsDisconnected:
		return config.StateDisconnected
	default:
		return config.StateConnecting
	}
}

// ── VPN entry management via PowerShell ──────────────────────────────────────

// addVPNConnection creates a phonebook entry using Add-VpnConnection.
// Authentication method, encryption level and split-tunneling are taken from
// the profile (the frontend lets the user choose them); for L2TP the PSK is
// embedded directly.
func addVPNConnection(p config.Profile) error {
	tunnelType, ok := psTunnelType(p.TunnelType)
	if !ok {
		return fmt.Errorf("неподдерживаемый тип туннеля: %s", p.TunnelType)
	}

	parts := []string{
		fmt.Sprintf(`Add-VpnConnection -Name '%s' -ServerAddress '%s' -TunnelType %s`,
			psSafe(p.Name), psSafe(p.Server), tunnelType),
	}

	if p.TunnelType == config.TunnelL2TP {
		psk := p.PresharedKey
		if psk == "" {
			psk = "vpn"
		}
		parts = append(parts, fmt.Sprintf(`-L2tpPsk '%s'`, psSafe(psk)))
	}

	parts = append(parts, "-AuthenticationMethod "+psAuthMethod(p))
	if enc := psEncryptionLevel(p); enc != "" {
		parts = append(parts, "-EncryptionLevel "+enc)
	}
	if p.SplitTunneling {
		parts = append(parts, "-SplitTunneling")
	}
	parts = append(parts, "-RememberCredential -Force -PassThru | Out-Null")

	script := strings.Join(parts, " ")
	out, err := runPS(script)
	if err != nil {
		// A leftover entry from a previous attempt makes Add fail with
		// WIN32 183 / ResourceExists. Instead of giving up, align the
		// existing entry's parameters with Set-VpnConnection and proceed.
		if isAlreadyExistsErr(out) {
			logger.Info("addVPNConnection: '%s' уже существует — обновляю параметры", p.Name)
			updateVPNConnection(p)
			return nil
		}
		return fmt.Errorf("Add-VpnConnection (%s): %v — %s", p.TunnelType, err, out)
	}
	logger.Info("addVPNConnection: '%s' (%s, auth=%s) создан", p.Name, p.TunnelType, psAuthMethod(p))
	return nil
}

// isAlreadyExistsErr reports whether Add-VpnConnection failed only because an
// entry with the same name already exists (WIN32 183 / ResourceExists).
func isAlreadyExistsErr(out string) bool {
	lower := strings.ToLower(out)
	return strings.Contains(lower, "already been created") ||
		strings.Contains(lower, "resourceexists") ||
		strings.Contains(lower, "win32 183")
}

// updateVPNConnection aligns an existing phonebook entry's parameters with the
// profile (best-effort — errors are non-fatal since the entry already exists
// and can be dialed regardless).
func updateVPNConnection(p config.Profile) {
	tunnelType, _ := psTunnelType(p.TunnelType)
	parts := []string{
		fmt.Sprintf(`Set-VpnConnection -Name '%s' -ServerAddress '%s' -TunnelType %s`,
			psSafe(p.Name), psSafe(p.Server), tunnelType),
		"-AuthenticationMethod " + psAuthMethod(p),
	}
	if enc := psEncryptionLevel(p); enc != "" {
		parts = append(parts, "-EncryptionLevel "+enc)
	}
	parts = append(parts, fmt.Sprintf("-SplitTunneling $%t", p.SplitTunneling))
	parts = append(parts, "-RememberCredential -Force -PassThru -ErrorAction SilentlyContinue | Out-Null")
	if out, err := runPS(strings.Join(parts, " ")); err != nil {
		logger.Info("updateVPNConnection: '%s' — %v: %s (non-fatal)", p.Name, err, out)
	}
}

// psTunnelType maps a profile tunnel type to the value expected by Add-VpnConnection.
func psTunnelType(t config.TunnelType) (string, bool) {
	switch t {
	case config.TunnelL2TP:
		return "L2tp", true
	case config.TunnelSSTP:
		return "Sstp", true
	case config.TunnelIKEv2:
		return "IKEv2", true
	case config.TunnelPPTP:
		return "Pptp", true
	default:
		return "", false
	}
}

// psAuthMethod maps the profile's auth method to a PowerShell -AuthenticationMethod
// value. Defaults to MSChapv2 when unset.
func psAuthMethod(p config.Profile) string {
	switch p.AuthMethod {
	case config.AuthChap:
		return "Chap"
	case config.AuthPap:
		return "Pap"
	case config.AuthEap:
		return "Eap"
	case config.AuthMsChapv2:
		return "MSChapv2"
	default:
		return "MSChapv2"
	}
}

// psEncryptionLevel maps the profile's encryption setting to a PowerShell
// -EncryptionLevel value. When unset it returns "" so the flag is omitted and
// Windows applies its default (Required) — most SSTP/RRAS and L2TP servers
// require encryption and drop the link a few seconds after connecting if the
// client negotiates none. PAP/CHAP cannot negotiate MPPE, so they are forced
// to Optional (the transport stays encrypted at the TLS/IPsec layer anyway).
func psEncryptionLevel(p config.Profile) string {
	if p.AuthMethod == config.AuthPap || p.AuthMethod == config.AuthChap {
		return "Optional"
	}
	switch p.Encryption {
	case config.EncryptionRequired:
		return "Required"
	case config.EncryptionMaxLevel:
		return "Maximum"
	case config.EncryptionNoEncrypt:
		return "NoEncryption"
	case config.EncryptionOptional:
		return "Optional"
	default:
		return "" // unset → omit flag → Windows default (Required)
	}
}

// removeVPNConnection deletes the phonebook entry via PowerShell.
// Tries both per-user and all-user phonebooks.
func removeVPNConnection(name string) {
	script := fmt.Sprintf(
		`Remove-VpnConnection -Name '%s' -Force -ErrorAction SilentlyContinue;`+
			`Remove-VpnConnection -Name '%s' -Force -AllUserConnection -ErrorAction SilentlyContinue`,
		psSafe(name), psSafe(name),
	)
	runPS(script) //nolint:errcheck
	logger.Info("removeVPNConnection: '%s'", name)
}

// ── Dialing ───────────────────────────────────────────────────────────────────

// dialRAS runs rasdial synchronously in a background goroutine.
// Context cancellation triggers rasdial /DISCONNECT and waits for clean exit.
func dialRAS(ctx context.Context, p config.Profile) error {
	args := []string{p.Name}
	if p.Username != "" {
		args = append(args, p.Username, p.Password)
	}

	cmd := exec.Command("rasdial", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}

	done := make(chan error, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		if err != nil {
			done <- parseDialError(strings.TrimSpace(decodeOEM(out)))
		} else {
			done <- nil
		}
	}()

	select {
	case err := <-done:
		if err != nil {
			logger.Info("dialRAS '%s': %v", p.Name, err)
			ForceCleanupRAS(p.Name)
		} else {
			logger.Info("dialRAS '%s': подключено", p.Name)
		}
		return err

	case <-ctx.Done():
		// User cancelled — disconnect cleanly, then drain the goroutine.
		rasdialDisconnect(p.Name)
		<-done
		return ctx.Err()
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func rasdialDisconnect(name string) {
	cmd := exec.Command("rasdial", name, "/DISCONNECT")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err := cmd.Run(); err != nil {
		logger.Info("rasdialDisconnect '%s': %v (non-fatal)", name, err)
	} else {
		logger.Info("rasdialDisconnect '%s': ok", name)
	}
}

func hangUpAll(name string) {
	for i := 0; i < 3; i++ {
		h := findRASHandle(name)
		if h == 0 {
			break
		}
		procHangUp.Call(h)
		time.Sleep(300 * time.Millisecond)
	}
}

func findRASHandle(name string) uintptr {
	for _, c := range enumRASConns() {
		if strings.EqualFold(c.name, name) {
			return c.handle
		}
	}
	return 0
}

func runPS(script string) (string, error) {
	// Force UTF-8 output so error messages aren't mangled into mojibake when
	// read back as UTF-8 (the default console codepage is OEM, e.g. CP866 on RU).
	full := `[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; ` +
		`$ErrorActionPreference='Continue'; ` + script
	cmd := exec.Command("powershell",
		"-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
		"-Command", full,
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// setL2TPNATKey sets the registry value that allows L2TP through NAT.
// Windows only reads this value at boot, so if it was missing or wrong we
// log that a reboot is required — this is the usual cause of error 789 when
// either the client or server sits behind NAT.
func setL2TPNATKey() {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\PolicyAgent`,
		registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		logger.Info("L2TP NAT registry open: %v (non-fatal)", err)
		return
	}
	defer k.Close()

	if cur, _, err := k.GetIntegerValue("AssumeUDPEncapsulationContextOnSendRule"); err == nil && cur == 2 {
		logger.Info("L2TP NAT registry: already set (=2)")
		return
	}
	if err := k.SetDWordValue("AssumeUDPEncapsulationContextOnSendRule", 2); err != nil {
		logger.Info("L2TP NAT registry set: %v (non-fatal)", err)
	} else {
		logger.Info("L2TP NAT registry: set to 2 — REBOOT REQUIRED for L2TP-behind-NAT to work")
	}
}

// setSSTPNoCertCheck disables the SSTP server-certificate revocation check.
// This is the correct location for SSTP (the previous WinHttp\DisableRevocation
// key had no effect). It handles the common 0x80092013 "revocation server was
// offline" failure when SkipCertCheck is enabled on the profile.
func setSSTPNoCertCheck() {
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\SstpSvc\Parameters`, registry.SET_VALUE)
	if err != nil {
		logger.Info("SSTP NoCertRevocationCheck open: %v (non-fatal)", err)
		return
	}
	defer k.Close()
	if err := k.SetDWordValue("NoCertRevocationCheck", 1); err != nil {
		logger.Info("SSTP NoCertRevocationCheck set: %v (non-fatal)", err)
	} else {
		logger.Info("SSTP NoCertRevocationCheck: ok")
	}
}

// psSafe escapes single quotes for use inside PowerShell single-quoted strings.
func psSafe(s string) string {
	return strings.ReplaceAll(s, "'", "''")
}

// decodeOEM converts bytes from the system OEM code page (CP866 on Russian
// Windows) to a UTF-8 string using the MultiByteToWideChar Win32 API.
// Falls back to raw string conversion if the API is unavailable.
func decodeOEM(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	k32 := syscall.NewLazyDLL("kernel32.dll")
	mbtwc := k32.NewProc("MultiByteToWideChar")
	const cpOEM = 1 // CP_OEMCP
	// Calculate required wide-char buffer size.
	n, _, _ := mbtwc.Call(cpOEM, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), 0, 0)
	if n == 0 {
		return string(b)
	}
	wide := make([]uint16, n)
	mbtwc.Call(cpOEM, 0, uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		uintptr(unsafe.Pointer(&wide[0])), n)
	return windows.UTF16ToString(wide)
}

// parseDialError converts rasdial output to a user-readable Russian error.
func parseDialError(output string) error {
	lower := strings.ToLower(output)
	switch {
	case strings.Contains(lower, "756"):
		return fmt.Errorf("ошибка 756: соединение уже существует — нажмите «Починить»")
	case strings.Contains(lower, "691"):
		return fmt.Errorf("ошибка 691: неверный логин/пароль или метод аутентификации не совпадает с сервером (попробуйте PAP/CHAP)")
	case strings.Contains(lower, "789"):
		return fmt.Errorf("ошибка 789: L2TP/IPSec — проверьте Pre-Shared Key. Если сервер или вы за NAT — перезагрузите Windows (ключ NAT применяется только после перезагрузки)")
	case strings.Contains(lower, "809"):
		return fmt.Errorf("ошибка 809: сервер не отвечает (порты L2TP UDP 500/4500/1701 заблокированы или за NAT — перезагрузите Windows)")
	case strings.Contains(lower, "800"):
		return fmt.Errorf("ошибка 800: сервер недоступен или тип туннеля не совпадает")
	case strings.Contains(lower, "619"):
		return fmt.Errorf("ошибка 619: порт закрыт (L2TP: UDP 500/4500/1701; SSTP: TCP 443)")
	case strings.Contains(lower, "868"):
		return fmt.Errorf("ошибка 868: не удалось разрешить имя сервера (проверьте адрес/DNS)")
	case strings.Contains(lower, "812"):
		return fmt.Errorf("ошибка 812: сервер отклонил метод аутентификации — смените способ аутентификации в профиле")
	case strings.Contains(lower, "13801"):
		return fmt.Errorf("ошибка 13801: IKEv2 — недействительный сертификат")
	case strings.Contains(lower, "0x80092013") || strings.Contains(lower, "revocation"):
		return fmt.Errorf("SSTP: не удалось проверить сертификат сервера — включите «Пропустить проверку сертификата» в профиле")
	case strings.Contains(lower, "cn-") || strings.Contains(output, "CN-") ||
		strings.Contains(lower, "не совпадает") || strings.Contains(lower, "сертифик"):
		return fmt.Errorf("SSTP: имя сертификата сервера не совпадает с адресом подключения — убедитесь, что адрес сервера совпадает с CN сертификата, или используйте другой протокол (L2TP/IKEv2)")
	case strings.Contains(lower, "l2tp"):
		return fmt.Errorf("L2TP/IPSec: ошибка согласования — проверьте Pre-Shared Key")
	case output != "":
		return fmt.Errorf("rasdial: %s", output)
	default:
		return fmt.Errorf("подключение не удалось")
	}
}
