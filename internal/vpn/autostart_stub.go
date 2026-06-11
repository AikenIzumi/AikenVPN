//go:build !windows

package vpn

func SetAutoStart(enable bool) error { return nil }
func GetAutoStart() bool             { return false }
