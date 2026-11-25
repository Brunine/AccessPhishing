package domain

import (
	"errors"
	"testing"
	"time"
)

func TestDeriveTLSStatus(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	threshold := 30 * 24 * time.Hour

	cases := []struct {
		name      string
		dialErr   error
		notAfter  time.Time
		threshold time.Duration
		want      string
	}{
		{"dial error -> invalid", errors.New("connection refused"), now.Add(365 * 24 * time.Hour), threshold, TLSStatusInvalid},
		{"far future -> valid", nil, now.Add(90 * 24 * time.Hour), threshold, TLSStatusValid},
		{"just past threshold -> valid", nil, now.Add(31 * 24 * time.Hour), threshold, TLSStatusValid},
		{"within threshold -> expiring", nil, now.Add(10 * 24 * time.Hour), threshold, TLSStatusExpiring},
		{"exactly at threshold -> expiring", nil, now.Add(threshold), threshold, TLSStatusExpiring},
		{"already expired -> expiring", nil, now.Add(-24 * time.Hour), threshold, TLSStatusExpiring},
		{"short threshold keeps far cert valid", nil, now.Add(48 * time.Hour), time.Hour, TLSStatusValid},
		{"short threshold flags near cert", nil, now.Add(30 * time.Minute), time.Hour, TLSStatusExpiring},
		// A dial error dominates regardless of NotAfter.
		{"error with future cert still invalid", errors.New("handshake"), now.Add(100 * 24 * time.Hour), threshold, TLSStatusInvalid},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DeriveTLSStatus(c.dialErr, c.notAfter, c.threshold, now); got != c.want {
				t.Errorf("DeriveTLSStatus = %q, want %q", got, c.want)
			}
		})
	}
}
