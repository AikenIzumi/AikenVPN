package vpn

import (
	"errors"
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
	wininet                = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptionW = wininet.NewProc("InternetSetOptionW")
)

const proxyOverride = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>"

const proxyAccess = registry.QUERY_VALUE | registry.SET_VALUE

type proxyValue struct {
	kind   uint32
	text   string
	number uint64
}

type proxyChange struct {
	name            string
	before, applied proxyValue
}

type proxyLease struct {
	address string
	changes []proxyChange
}

func setSystemProxy(addr string) (*proxyLease, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, proxyAccess)
	if err != nil {
		return nil, err
	}
	defer k.Close()
	lease, err := installProxy(k, addr)
	refreshWinInet()
	return lease, err
}

func readProxyValue(k registry.Key, name string) (proxyValue, error) {
	var value proxyValue
	var err error
	if name == "ProxyEnable" {
		value.number, value.kind, err = k.GetIntegerValue(name)
	} else {
		value.text, value.kind, err = k.GetStringValue(name)
	}
	if errors.Is(err, registry.ErrNotExist) {
		return proxyValue{}, nil
	}
	return value, err
}

func (v proxyValue) write(k registry.Key, name string) error {
	switch v.kind {
	case registry.DWORD:
		return k.SetDWordValue(name, uint32(v.number))
	case registry.QWORD:
		return k.SetQWordValue(name, v.number)
	case registry.SZ:
		return k.SetStringValue(name, v.text)
	case registry.EXPAND_SZ:
		return k.SetExpandStringValue(name, v.text)
	case 0:
		err := k.DeleteValue(name)
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	default:
		return fmt.Errorf("unsupported registry type %d", v.kind)
	}
}

func installProxy(k registry.Key, addr string) (*proxyLease, error) {
	changes := []proxyChange{
		{name: "ProxyServer", applied: proxyValue{kind: registry.SZ, text: addr}},
		{name: "ProxyOverride", applied: proxyValue{kind: registry.SZ, text: proxyOverride}},
		{name: "ProxyEnable", applied: proxyValue{kind: registry.DWORD, number: 1}},
	}
	for i := range changes {
		before, err := readProxyValue(k, changes[i].name)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", changes[i].name, err)
		}
		changes[i].before = before
	}
	for i, change := range changes {
		if err := change.applied.write(k, change.name); err != nil {
			return nil, errors.Join(fmt.Errorf("write %s: %w", change.name, err), restoreProxyValues(k, changes[:i]))
		}
	}
	return &proxyLease{address: addr, changes: changes}, nil
}

func restoreProxyValues(k registry.Key, changes []proxyChange) error {
	var result error
	for i := len(changes) - 1; i >= 0; i-- {
		change := changes[i]
		current, err := readProxyValue(k, change.name)
		if err == nil && current == change.applied && current != change.before {
			err = change.before.write(k, change.name)
		}
		if err != nil {
			result = errors.Join(result, fmt.Errorf("restore %s: %w", change.name, err))
		}
	}
	return result
}

func (p *proxyLease) checkOwnership() error {
	if p == nil {
		return errors.New("Системный прокси Xray недоступен")
	}
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, registry.QUERY_VALUE)
	if err != nil {
		return fmt.Errorf("не удалось проверить системный прокси: %w", err)
	}
	defer k.Close()
	for _, change := range p.changes {
		value, err := readProxyValue(k, change.name)
		if err != nil {
			return fmt.Errorf("не удалось проверить %s: %w", change.name, err)
		}
		if value != change.applied {
			return errors.New("Настройки системного прокси изменились вне AikenVPN")
		}
	}
	return nil
}

func (p *proxyLease) restore() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, internetSettingsKey, proxyAccess)
	if err != nil {
		return err
	}
	defer k.Close()
	err = p.restoreKey(k)
	refreshWinInet()
	return err
}

func (p *proxyLease) restoreKey(k registry.Key) error {
	server, err := readProxyValue(k, "ProxyServer")
	if err != nil || server.text != p.address {
		return err
	}
	return restoreProxyValues(k, p.changes)
}

// refreshWinInet calls InternetSetOption to make WinInet pick up registry changes immediately.
func refreshWinInet() {
	_ = procInternetSetOptionW.Find() // ensure dll is loaded
	procInternetSetOptionW.Call(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
	procInternetSetOptionW.Call(0, INTERNET_OPTION_REFRESH, uintptr(unsafe.Pointer(nil)), 0)
}
