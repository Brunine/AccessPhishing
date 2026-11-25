package domain

import "time"

// Persisted tls_status values (mirrors the 0017 domains.tls_status CHECK). The
// 'none'/'pending' values are set elsewhere (import/metadata); diagnostics only
// ever derives one of the three below.
const (
	TLSStatusValid    = "valid"
	TLSStatusExpiring = "expiring"
	TLSStatusInvalid  = "invalid"
)

// DeriveTLSStatus maps a live TLS probe onto a persisted tls_status. A dial or
// handshake error yields "invalid"; otherwise a leaf certificate whose NotAfter
// is within threshold of now (including already in the past) yields "expiring",
// and anything further out yields "valid".
//
// It deliberately does NOT consider certificate/domain coverage (that stays a
// diagnostics warning) and never influences the domain lifecycle status.
func DeriveTLSStatus(dialErr error, notAfter time.Time, threshold time.Duration, now time.Time) string {
	if dialErr != nil {
		return TLSStatusInvalid
	}
	if !notAfter.After(now.Add(threshold)) {
		return TLSStatusExpiring
	}
	return TLSStatusValid
}
