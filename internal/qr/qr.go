// Package qr handles QR code generation and decoding for VPN config sharing
package qr

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
	"github.com/jamalfa/jamvpn/internal/config"
	"github.com/jamalfa/jamvpn/internal/parser"
)

// GeneratePNG returns a PNG QR code image as base64 string for a VPN profile.
// The QR content is the profile's JSON encoded in base64.
func GeneratePNG(p config.Profile, size int) (string, error) {
	if size <= 0 {
		size = 400
	}

	// For WireGuard, use the .conf format (more compatible with other WG clients)
	var content string
	if p.TunnelType == config.TunnelWireGuard && p.WireGuard != nil {
		conf, err := parser.ToWireGuardConf(p)
		if err == nil {
			content = conf
		}
	}

	// Fallback: JSON export
	if content == "" {
		// Omit sensitive fields if needed; for sharing, keep them
		data, err := json.Marshal(p)
		if err != nil {
			return "", fmt.Errorf("marshal profile: %w", err)
		}
		content = base64.RawURLEncoding.EncodeToString(data)
	}

	png, err := qrcode.Encode(content, qrcode.High, size)
	if err != nil {
		return "", fmt.Errorf("generate QR: %w", err)
	}
	return base64.StdEncoding.EncodeToString(png), nil
}

// GenerateShareLink returns a shareable link + QR code for a profile.
// The link embeds the base64-encoded JSON so it can be imported without a server.
func GenerateShareLink(p config.Profile, baseURL string) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(data)
	if baseURL == "" {
		// Use a jamvpn:// custom URI scheme
		return "jamvpn://import?config=" + encoded, nil
	}
	return baseURL + "?config=" + encoded, nil
}

// ParseFromText tries to interpret text as a VPN configuration (from a scanned QR).
// The text might be a URI, base64-encoded JSON, or raw conf file.
func ParseFromText(text string) (*parser.ParseResult, error) {
	if text == "" {
		return nil, fmt.Errorf("empty QR content")
	}

	// Try direct parsing first
	result, err := parser.FromBytes([]byte(text), "")
	if err == nil {
		return result, nil
	}

	// Try base64 decode
	result, err2 := parser.FromBase64(text)
	if err2 == nil {
		return result, nil
	}

	return nil, fmt.Errorf("could not parse QR content: %v", err)
}
