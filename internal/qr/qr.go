// Package qr renders QR-code PNGs for the quishing (M9b) delivery vector.
//
// It is a thin, deterministic wrapper over skip2/go-qrcode (pure Go, no CGO, no
// network): the same (content, size, level) always yields byte-identical PNG
// output. The orchestrator uses it to encode each recipient's /t/{token}
// tracking URL on the fly — no QR image is ever stored.
package qr

import (
	"fmt"

	qrcode "github.com/skip2/go-qrcode"
)

// Bounds on the requested pixel size. A non-positive or oversized request is
// clamped rather than rejected, so a misconfigured QR_SIZE degrades gracefully.
const (
	MinSize     = 64
	MaxSize     = 2048
	DefaultSize = 256
)

// Level maps an EC-level string (L|M|Q|H, case-insensitive) to a go-qrcode
// recovery level. Anything else falls back to Medium (the documented default).
func Level(s string) qrcode.RecoveryLevel {
	switch s {
	case "L", "l":
		return qrcode.Low
	case "Q", "q":
		return qrcode.High // "Q" (quartile) maps to go-qrcode's High (~25%).
	case "H", "h":
		return qrcode.Highest
	default: // "M", "m", "" and anything unrecognized
		return qrcode.Medium
	}
}

// clampSize bounds a requested size into [MinSize, MaxSize], substituting the
// default for a non-positive value.
func clampSize(size int) int {
	if size <= 0 {
		size = DefaultSize
	}
	if size < MinSize {
		return MinSize
	}
	if size > MaxSize {
		return MaxSize
	}
	return size
}

// PNG encodes content into a square QR-code PNG of (clamped) size pixels at the
// given EC level. content must be non-empty.
func PNG(content string, size int, level string) ([]byte, error) {
	if content == "" {
		return nil, fmt.Errorf("qr: empty content")
	}
	png, err := qrcode.Encode(content, Level(level), clampSize(size))
	if err != nil {
		return nil, fmt.Errorf("qr: encode: %w", err)
	}
	return png, nil
}
