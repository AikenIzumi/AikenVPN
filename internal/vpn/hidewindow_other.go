//go:build !windows

package vpn

import "os/exec"

func hideWindow(cmd *exec.Cmd) {}
