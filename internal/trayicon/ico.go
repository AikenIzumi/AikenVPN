// Package trayicon generates a minimal valid ICO file for the system tray
// without requiring embedded asset files.
package trayicon

import (
	"bytes"
	"encoding/binary"
)

// Generate creates a 16x16 32-bit ICO with a simple shield/circle design.
// r, g, b are the fill color components.
func Generate(r, g, b uint8) []byte {
	const (
		w = 16
		h = 16
	)

	// AND mask: 1 bit per pixel, rows padded to DWORD (4 bytes)
	andRowBytes := (w + 31) / 32 * 4 // = 4
	andMask := make([]byte, h*andRowBytes)

	// XOR mask: 32bpp BGRA, bottom-up
	var xorBuf bytes.Buffer
	for row := h - 1; row >= 0; row-- {
		for col := 0; col < w; col++ {
			alpha, pr, pg, pb := uint8(255), r, g, b

			// Rounded corners (2px radius)
			corner := (row < 2 || row >= h-2) && (col < 2 || col >= w-2)
			// Inner highlight (top 1/3, center strip)
			highlight := row >= h-5 && row >= h-3 && col >= 5 && col <= 10
			_ = highlight

			if corner {
				alpha = 0
			}

			// Mark transparent pixels in AND mask too
			if alpha == 0 {
				byteIdx := row*andRowBytes + col/8
				bitIdx := uint(7 - uint(col)%8)
				andMask[byteIdx] |= 1 << bitIdx
				xorBuf.Write([]byte{0, 0, 0, 0})
				continue
			}

			// Inner darker area (bottom half of shield body)
			if row < h/2+2 && col >= 3 && col <= w-4 {
				pb2 := clamp(int(pb) - 20)
				pg2 := clamp(int(pg) - 20)
				pr2 := clamp(int(pr) - 20)
				xorBuf.Write([]byte{pb2, pg2, pr2, alpha})
				continue
			}

			xorBuf.Write([]byte{pb, pg, pr, alpha}) // BGRA
		}
	}

	xorBytes := xorBuf.Bytes()
	imgDataSize := 40 + len(xorBytes) + len(andMask)

	var buf bytes.Buffer

	// ICONDIR
	buf.Write([]byte{0, 0, 1, 0, 1, 0})

	// ICONDIRENTRY (16 bytes)
	entry := make([]byte, 16)
	entry[0] = w
	entry[1] = h
	entry[2] = 0
	entry[3] = 0
	binary.LittleEndian.PutUint16(entry[4:], 1)
	binary.LittleEndian.PutUint16(entry[6:], 32)
	binary.LittleEndian.PutUint32(entry[8:], uint32(imgDataSize))
	binary.LittleEndian.PutUint32(entry[12:], 22) // offset = 6+16
	buf.Write(entry)

	// BITMAPINFOHEADER (40 bytes)
	bih := make([]byte, 40)
	binary.LittleEndian.PutUint32(bih[0:], 40)
	binary.LittleEndian.PutUint32(bih[4:], w)
	binary.LittleEndian.PutUint32(bih[8:], h*2) // doubled for ICO
	binary.LittleEndian.PutUint16(bih[12:], 1)
	binary.LittleEndian.PutUint16(bih[14:], 32)
	buf.Write(bih)

	buf.Write(xorBytes)
	buf.Write(andMask)
	return buf.Bytes()
}

func clamp(v int) uint8 {
	if v < 0 {
		return 0
	}
	if v > 255 {
		return 255
	}
	return uint8(v)
}
