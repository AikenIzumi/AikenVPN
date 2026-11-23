//go:build !windows

package config

func encodeStoredProfiles(data []byte) ([]byte, error) { return data, nil }

func decodeStoredProfiles(data []byte) ([]byte, bool, error) { return data, false, nil }
