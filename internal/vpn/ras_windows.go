//go:build windows

package vpn

import (
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/logger"
)

// setL2TPNATKey sets the Windows registry key required for L2TP/IPSec through NAT.
// Without it, Windows refuses to negotiate IPSec when either side is behind NAT (error 619/789).
func setL2TPNATKey() {
	const key = `HKLM\SYSTEM\CurrentControlSet\Services\PolicyAgent`
	script := fmt.Sprintf(
		`Set-ItemProperty -Path "Registry::%s" -Name "AssumeUDPEncapsulationContextOnSendRule" -Value 2 -Type DWord -Force`,
		key,
	)
	if err := runPS(script); err != nil {
		logger.Info("L2TP NAT registry key: %v (non-fatal, may require reboot)", err)
	} else {
		logger.Info("L2TP NAT registry key set (AssumeUDPEncapsulationContextOnSendRule=2)")
	}
}

// connectRAS creates and connects a Windows built-in VPN (L2TP/IKEv2/SSTP/PPTP)
func connectRAS(p config.Profile) error {
	// Always force-cleanup any stale entry first (disconnect + remove)
	ForceCleanupRAS(p.Name)

	// L2TP/IPSec requires a registry key to work through NAT
	if p.TunnelType == config.TunnelL2TP {
		setL2TPNATKey()
	}

	// Build Add-VpnConnection command

	// Validate tunnel type — fallback to SSTP which is the most firewall-friendly
	tunnel := string(p.TunnelType)
	switch p.TunnelType {
	case config.TunnelL2TP, config.TunnelIKEv2, config.TunnelSSTP, config.TunnelPPTP:
		// valid
	default:
		tunnel = "Sstp"
		logger.Info("TunnelType '%s' is invalid for RAS, defaulting to Sstp", p.TunnelType)
	}

	// Auth method: IKEv2 uses EAP/MSChapv2 via EAP, SSTP/PPTP/L2TP use MsChapv2.
	// Passing MsChapv2 directly to IKEv2 causes WIN32 87 "conflicting PPP Tunnel types".
	authMethod := string(p.AuthMethod)
	if authMethod == "" {
		switch config.TunnelType(tunnel) {
		case config.TunnelIKEv2:
			authMethod = "EAP"
		default:
			authMethod = "MsChapv2"
		}
	}

	encryption := string(p.Encryption)
	if encryption == "" {
		encryption = "Optional"
	}

	var sb strings.Builder

	// SSTP and IKEv2 manage their own auth negotiation — passing -AuthenticationMethod
	// for these types causes WIN32 87 "conflicting PPP Tunnel types" on many Windows builds.
	// Only PPTP and L2TP need explicit auth method.
	useAuthParam := p.TunnelType == config.TunnelPPTP || p.TunnelType == config.TunnelL2TP

	// Build the command. Boolean switch params use colon syntax (-Param:$true/$false)
	// to avoid PowerShell treating the value as a positional argument.
	remCred := fmt.Sprintf(`-RememberCredential:%s`, boolPS(p.RememberCredential))
	splitTun := fmt.Sprintf(`-SplitTunneling:%s`, boolPS(p.SplitTunneling))

	if useAuthParam {
		sb.WriteString(fmt.Sprintf(
			`Add-VpnConnection -Name "%s" -ServerAddress "%s" -TunnelType %s `+
				`-AuthenticationMethod %s -EncryptionLevel %s `+
				`%s %s -Force -PassThru`,
			p.Name, p.Server, tunnel, authMethod, encryption, remCred, splitTun,
		))
	} else {
		sb.WriteString(fmt.Sprintf(
			`Add-VpnConnection -Name "%s" -ServerAddress "%s" -TunnelType %s `+
				`-EncryptionLevel %s %s %s -Force -PassThru`,
			p.Name, p.Server, tunnel, encryption, remCred, splitTun,
		))
	}

	if p.TunnelType == config.TunnelL2TP && p.PresharedKey != "" {
		sb.WriteString(fmt.Sprintf(` -L2tpPsk "%s"`, p.PresharedKey))
	}

	psCmd := sb.String()
	logger.Info("RAS connect: tunnel=%s auth=%s encrypt=%s server=%s", tunnel, authMethod, encryption, p.Server)
	logger.Info("PS> %s", psCmd)
	if err := runPS(psCmd); err != nil {
		logger.Error("Add-VpnConnection failed: %v", err)
		return fmt.Errorf("не удалось создать VPN-профиль в Windows: %w", err)
	}

	// rasdial to connect (1 attempt — retries hide real errors)
	rasArgs := []string{p.Name}
	if p.Username != "" {
		rasArgs = append(rasArgs, p.Username, p.Password)
	}

	logger.Info("rasdial: name=%s hasUser=%v", p.Name, p.Username != "")
	out, err := hiddenCmd("rasdial", rasArgs...).CombinedOutput()
	if err != nil {
		rawMsg := strings.TrimSpace(string(out))
		logger.Error("rasdial failed: %s", rawMsg)
		friendly := translateRasError(rawMsg)
		// On failure, clean up the created entry so Windows isn't left broken
		ForceCleanupRAS(p.Name)
		return fmt.Errorf("%s", friendly)
	}
	logger.Info("rasdial connected: %s", strings.TrimSpace(string(out)))
	return nil
}

// disconnectRAS disconnects a RAS VPN by name
func disconnectRAS(name string) error {
	out, err := hiddenCmd("rasdial", name, "/disconnect").CombinedOutput()
	if err != nil {
		return fmt.Errorf("rasdial disconnect: %s", strings.TrimSpace(string(out)))
	}
	return nil
}

// ForceCleanupRAS forcefully disconnects + removes a Windows VPN entry.
// Safe to call even if the entry doesn't exist.
func ForceCleanupRAS(name string) {
	logger.Info("ForceCleanupRAS: cleaning up '%s'", name)

	// 1. Force-disconnect via rasdial (ignore error)
	_ = hiddenCmd("rasdial", name, "/disconnect").Run()
	time.Sleep(400 * time.Millisecond)

	// 2. Remove via PowerShell — try both user-scope and all-user-scope
	script := fmt.Sprintf(
		`$n = "%s"; `+
			`$c = Get-VpnConnection -Name $n -ErrorAction SilentlyContinue; `+
			`if ($c) { Remove-VpnConnection -Name $n -Force -ErrorAction SilentlyContinue }; `+
			`$ca = Get-VpnConnection -Name $n -AllUserConnection -ErrorAction SilentlyContinue; `+
			`if ($ca) { Remove-VpnConnection -Name $n -AllUserConnection -Force -ErrorAction SilentlyContinue }; `+
			`exit 0`,
		name,
	)
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		logger.Error("ForceCleanupRAS remove failed: %v — %s", err, strings.TrimSpace(string(out)))
	} else {
		logger.Info("ForceCleanupRAS: removed '%s' ok", name)
	}
	time.Sleep(200 * time.Millisecond)
}

// GetRASConnectionStatus queries the connection status of a named VPN
func GetRASConnectionStatus(name string) config.ConnectionState {
	out, err := hiddenCmd("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`(Get-VpnConnection -Name "%s" -ErrorAction SilentlyContinue).ConnectionStatus`, name)).
		Output()
	if err != nil {
		return config.StateDisconnected
	}
	switch strings.TrimSpace(string(out)) {
	case "Connected":
		return config.StateConnected
	case "Connecting":
		return config.StateConnecting
	case "Disconnecting":
		return config.StateDisconnecting
	default:
		return config.StateDisconnected
	}
}

// translateRasError converts common rasdial error messages to human-readable Russian text.
func translateRasError(raw string) string {
	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "error 691") || strings.Contains(lower, "access was denied"):
		return "Ошибка 691: неверный логин или пароль"
	case strings.Contains(lower, "error 800") || strings.Contains(lower, "unable to establish"):
		return "Ошибка 800: не удалось установить соединение с сервером"
	case strings.Contains(lower, "error 619"):
		return "Ошибка 619: порт L2TP/IPSec недоступен — возможно, требуется перезагрузка после первого подключения, " +
			"или порты UDP 500/4500/1701 заблокированы провайдером/файрволом"
	case strings.Contains(lower, "error 720"):
		return "Ошибка 720: нет совместимого протокола PPP"
	case strings.Contains(lower, "error 789") || strings.Contains(lower, "l2tp"):
		return "Ошибка 789: не удалось согласовать L2TP/IPSec — проверьте Pre-Shared Key"
	case strings.Contains(lower, "error 868") || strings.Contains(lower, "cannot resolve"):
		return "Ошибка 868: не удалось разрешить имя сервера — проверьте адрес"
	case strings.Contains(lower, "error 13801") || strings.Contains(lower, "ikev2"):
		return "Ошибка IKEv2: недействительный сертификат или Pre-Shared Key"
	case strings.Contains(lower, "error 0"):
		return "Подключение прервано (rasdial error 0)"
	case raw == "":
		return "Нет ответа от rasdial — возможно, требуются права администратора"
	default:
		return fmt.Sprintf("Ошибка RAS: %s", raw)
	}
}

func hiddenCmd(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	hideWindow(cmd)
	return cmd
}

func runPS(script string) error {
	cmd := hiddenCmd("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w — %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func boolPS(v bool) string {
	if v {
		return "$true"
	}
	return "$false"
}
