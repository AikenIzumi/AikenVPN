// Package logger provides simple file-based logging for JamVPN.
package logger

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	mu      sync.Mutex
	logFile *os.File
	buf     []string // in-memory ring (last 500 lines)
)

// Init opens (or creates) the log file at dir/jamvpn.log.
func Init(dir string) {
	_ = os.MkdirAll(dir, 0o755)
	f, err := os.OpenFile(filepath.Join(dir, "jamvpn.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	mu.Lock()
	logFile = f
	mu.Unlock()
	Info("=== JamVPN started ===")
}

// Info logs an informational message.
func Info(format string, args ...any) { write("INFO", format, args...) }

// Error logs an error message.
func Error(format string, args ...any) { write("ERROR", format, args...) }

func write(level, format string, args ...any) {
	msg := fmt.Sprintf(format, args...)
	line := fmt.Sprintf("[%s] %s  %s", time.Now().Format("2006-01-02 15:04:05"), level, msg)
	mu.Lock()
	defer mu.Unlock()
	buf = append(buf, line)
	if len(buf) > 500 {
		buf = buf[len(buf)-500:]
	}
	if logFile != nil {
		_, _ = fmt.Fprintln(logFile, line)
	}
}

// GetAll returns all buffered log lines as a single string.
func GetAll() string {
	mu.Lock()
	defer mu.Unlock()
	return strings.Join(buf, "\n")
}

// LogPath returns the path to the log file (empty if not initialised).
func LogPath() string {
	mu.Lock()
	defer mu.Unlock()
	if logFile == nil {
		return ""
	}
	return logFile.Name()
}
