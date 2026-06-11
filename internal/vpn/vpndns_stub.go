//go:build !windows

package vpn

func SetVPNAdapterDNS(adapterAlias, servers string) {}
