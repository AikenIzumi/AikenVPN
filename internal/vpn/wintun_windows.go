package vpn

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

//go:embed assets/wintun.dll
var wintunDLLBytes []byte

var wintunOnce sync.Once
var wintunErr error

// ensureWintun extracts wintun.dll next to the running executable so that
// Windows' LOAD_LIBRARY_SEARCH_APPLICATION_DIR flag can find it.
func ensureWintun() error {
	wintunOnce.Do(func() {
		exePath, err := os.Executable()
		if err != nil {
			wintunErr = fmt.Errorf("get executable path: %w", err)
			return
		}
		dllPath := filepath.Join(filepath.Dir(exePath), "wintun.dll")

		// If the file already exists with the right size, skip extraction.
		if info, err := os.Stat(dllPath); err == nil && info.Size() == int64(len(wintunDLLBytes)) {
			return
		}

		if err := os.WriteFile(dllPath, wintunDLLBytes, 0644); err != nil {
			wintunErr = fmt.Errorf("extract wintun.dll: %w", err)
		}
	})
	return wintunErr
}
