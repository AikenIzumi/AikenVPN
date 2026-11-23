package config

import (
	"bytes"
	"errors"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const dpapiProfilePrefix = "AikenVPN-DPAPI-v1\n"

func encodeStoredProfiles(data []byte) ([]byte, error) {
	if len(data) == 0 || uint64(len(data)) > uint64(^uint32(0)) {
		return nil, errors.New("invalid profile data size")
	}
	input := windows.DataBlob{Size: uint32(len(data)), Data: &data[0]}
	var output windows.DataBlob
	err := windows.CryptProtectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	runtime.KeepAlive(data)
	if err != nil {
		return nil, err
	}
	encrypted := unsafe.Slice(output.Data, int(output.Size))
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	return append([]byte(dpapiProfilePrefix), encrypted...), nil
}

func decodeStoredProfiles(data []byte) ([]byte, bool, error) {
	encrypted, protected := bytes.CutPrefix(data, []byte(dpapiProfilePrefix))
	if !protected {
		return data, true, nil
	}
	if len(encrypted) == 0 || uint64(len(encrypted)) > uint64(^uint32(0)) {
		return nil, false, errors.New("invalid encrypted profile data size")
	}
	input := windows.DataBlob{Size: uint32(len(encrypted)), Data: &encrypted[0]}
	var output windows.DataBlob
	err := windows.CryptUnprotectData(&input, nil, nil, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &output)
	runtime.KeepAlive(encrypted)
	if err != nil {
		return nil, false, err
	}
	plaintext := unsafe.Slice(output.Data, int(output.Size))
	defer windows.LocalFree(windows.Handle(uintptr(unsafe.Pointer(output.Data))))
	defer clear(plaintext)
	return bytes.Clone(plaintext), false, nil
}
