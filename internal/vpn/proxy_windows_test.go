package vpn

import (
	"testing"

	"github.com/google/uuid"
	"golang.org/x/sys/windows/registry"
)

func TestProxyLeaseRestoresOnlyOwnedSettings(t *testing.T) {
	const local = "127.0.0.1:10809"
	before := map[string]proxyValue{
		"ProxyEnable":   {kind: registry.DWORD, number: 0},
		"ProxyServer":   {kind: registry.EXPAND_SZ, text: "%PROXY_HOST%:8080"},
		"ProxyOverride": {},
	}
	for _, tc := range []struct {
		name, changed string
		value         proxyValue
		want          map[string]proxyValue
	}{
		{name: "restore types and missing values", want: before},
		{
			name: "preserve changed bypass list", changed: "ProxyOverride",
			value: proxyValue{kind: registry.SZ, text: "office.local"},
			want: map[string]proxyValue{
				"ProxyEnable": before["ProxyEnable"], "ProxyServer": before["ProxyServer"],
				"ProxyOverride": {kind: registry.SZ, text: "office.local"},
			},
		},
		{
			name: "preserve replacement proxy", changed: "ProxyServer",
			value: proxyValue{kind: registry.SZ, text: "office.local:3128"},
			want: map[string]proxyValue{
				"ProxyEnable":   {kind: registry.DWORD, number: 1},
				"ProxyServer":   {kind: registry.SZ, text: "office.local:3128"},
				"ProxyOverride": {kind: registry.SZ, text: proxyOverride},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := `Software\AikenVPN-Test-` + uuid.NewString()
			key, _, err := registry.CreateKey(registry.CURRENT_USER, path, proxyAccess)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				_ = key.Close()
				if err := registry.DeleteKey(registry.CURRENT_USER, path); err != nil {
					t.Error(err)
				}
			})
			for name, value := range before {
				if err := value.write(key, name); err != nil {
					t.Fatal(err)
				}
			}
			lease, err := installProxy(key, local)
			if err != nil {
				t.Fatal(err)
			}
			if tc.changed != "" {
				if err := tc.value.write(key, tc.changed); err != nil {
					t.Fatal(err)
				}
			}
			if err := lease.restoreKey(key); err != nil {
				t.Fatal(err)
			}
			for name, want := range tc.want {
				got, err := readProxyValue(key, name)
				if err != nil || got != want {
					t.Errorf("%s got %+v, want %+v, error %v", name, got, want, err)
				}
			}
		})
	}
}
