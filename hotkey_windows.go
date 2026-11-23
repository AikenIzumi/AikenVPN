package main

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	hotkeyID    = 1
	modAlt      = 0x0001
	modControl  = 0x0002
	modNoRepeat = 0x4000
	wmQuit      = 0x0012
	wmHotkey    = 0x0312
)

var (
	hotkeyUser32      = windows.NewLazySystemDLL("user32.dll")
	registerHotkey    = hotkeyUser32.NewProc("RegisterHotKey")
	unregisterHotkey  = hotkeyUser32.NewProc("UnregisterHotKey")
	peekHotkeyMessage = hotkeyUser32.NewProc("PeekMessageW")
	getHotkeyMessage  = hotkeyUser32.NewProc("GetMessageW")
	postHotkeyMessage = hotkeyUser32.NewProc("PostThreadMessageW")
)

type hotkeyMessage struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	x, y    int32
	private uint32
}

type windowsHotkey struct {
	key    string
	thread uint32
	done   chan struct{}
}

func normalizeHotkey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if key == "" {
		return "", nil
	}
	if len(key) == 1 && (key[0] >= 'a' && key[0] <= 'z' || key[0] >= 'A' && key[0] <= 'Z' || key[0] >= '0' && key[0] <= '9') {
		return strings.ToUpper(key), nil
	}
	return "", errors.New("Выберите латинскую букву или цифру")
}

func startWindowsHotkey(key string, onPress func(*windowsHotkey)) (*windowsHotkey, error) {
	h := &windowsHotkey{key: key, done: make(chan struct{})}
	ready := make(chan error, 1)
	go h.run(ready, onPress)
	if err := <-ready; err != nil {
		return nil, err
	}
	return h, nil
}

func (h *windowsHotkey) run(ready chan<- error, onPress func(*windowsHotkey)) {
	// RegisterHotKey with no window delivers messages to this OS thread.
	// Leaving it locked makes Go discard the thread after its loop exits.
	runtime.LockOSThread()
	defer close(h.done)
	h.thread = windows.GetCurrentThreadId()
	var message hotkeyMessage
	peekHotkeyMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0, 0)
	ok, _, err := registerHotkey.Call(0, hotkeyID, modAlt|modControl|modNoRepeat, uintptr(h.key[0]))
	if ok == 0 {
		if errors.Is(err, windows.ERROR_HOTKEY_ALREADY_REGISTERED) {
			ready <- fmt.Errorf("Ctrl+Alt+%s уже используется в Windows", h.key)
		} else {
			ready <- fmt.Errorf("не удалось зарегистрировать Ctrl+Alt+%s: %w", h.key, err)
		}
		return
	}
	defer unregisterHotkey.Call(0, hotkeyID)
	ready <- nil
	for {
		result, _, _ := getHotkeyMessage.Call(uintptr(unsafe.Pointer(&message)), 0, 0, 0)
		if int32(result) <= 0 {
			return
		}
		if message.message == wmHotkey && message.wParam == hotkeyID {
			go onPress(h)
		}
	}
}

func (h *windowsHotkey) close() error {
	select {
	case <-h.done:
		return nil
	default:
	}
	ok, _, err := postHotkeyMessage.Call(uintptr(h.thread), wmQuit, 0, 0)
	if ok == 0 {
		select {
		case <-h.done:
			return nil
		default:
			return err
		}
	}
	<-h.done
	return nil
}
