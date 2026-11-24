package domain

import (
	"testing"
	"time"
)

// allStatuses is every storable status, used to drive the exhaustive matrix.
var allStatuses = []Status{
	StatusCandidate, StatusPendingPurchase, StatusPendingVerification,
	StatusVerified, StatusAuthorized, StatusActive, StatusSuspended,
	StatusExpired, StatusRetired,
}

// expectedMatrix is an independent copy of the allowed stored transitions, so
// the test fails if the production map drifts. Each entry lists the targets
// reachable from the key.
var expectedMatrix = map[Status]map[Status]bool{
	StatusCandidate:           {StatusPendingPurchase: true, StatusPendingVerification: true, StatusRetired: true},
	StatusPendingPurchase:     {StatusPendingVerification: true, StatusRetired: true},
	StatusPendingVerification: {StatusVerified: true, StatusRetired: true},
	StatusVerified:            {StatusAuthorized: true, StatusActive: true, StatusExpired: true, StatusRetired: true},
	StatusAuthorized:          {StatusActive: true, StatusExpired: true, StatusRetired: true},
	StatusActive:              {StatusSuspended: true, StatusExpired: true, StatusRetired: true},
	StatusSuspended:           {StatusActive: true, StatusRetired: true},
	StatusExpired:             {StatusRetired: true},
	StatusRetired:             {},
}

func TestTransitionMatrix(t *testing.T) {
	for _, from := range allStatuses {
		for _, to := range allStatuses {
			want := expectedMatrix[from][to]
			if got := CanTransition(from, to); got != want {
				t.Errorf("CanTransition(%s,%s)=%v want %v", from, to, got, want)
			}
		}
		// A no-op (from==from) is never a transition.
		if CanTransition(from, from) {
			t.Errorf("CanTransition(%s,%s) should be false (no-op)", from, from)
		}
	}
}

func TestGuards(t *testing.T) {
	cases := []struct {
		status                                                                Status
		reqVerify, markVerified, authorize, assign, activate, suspend, retire bool
	}{
		{StatusCandidate, false, false, false, false, false, false, true},
		{StatusPendingPurchase, false, false, false, false, false, false, true},
		{StatusPendingVerification, true, true, false, false, false, false, true},
		{StatusVerified, false, false, true, true, true, false, true},
		{StatusAuthorized, false, false, false, false, true, false, true},
		{StatusActive, false, false, false, true, false, true, true},
		{StatusSuspended, false, false, false, false, true, false, true},
		{StatusExpired, false, false, false, false, false, false, true},
		{StatusRetired, false, false, false, false, false, false, false},
	}
	for _, c := range cases {
		d := Domain{Status: c.status}
		if d.CanRequestVerification() != c.reqVerify {
			t.Errorf("%s CanRequestVerification=%v want %v", c.status, d.CanRequestVerification(), c.reqVerify)
		}
		if d.CanMarkVerified() != c.markVerified {
			t.Errorf("%s CanMarkVerified=%v want %v", c.status, d.CanMarkVerified(), c.markVerified)
		}
		if d.CanAuthorize() != c.authorize {
			t.Errorf("%s CanAuthorize=%v want %v", c.status, d.CanAuthorize(), c.authorize)
		}
		if d.CanAssign() != c.assign {
			t.Errorf("%s CanAssign=%v want %v", c.status, d.CanAssign(), c.assign)
		}
		if d.CanActivate() != c.activate {
			t.Errorf("%s CanActivate=%v want %v", c.status, d.CanActivate(), c.activate)
		}
		if d.CanSuspend() != c.suspend {
			t.Errorf("%s CanSuspend=%v want %v", c.status, d.CanSuspend(), c.suspend)
		}
		if d.CanRetire() != c.retire {
			t.Errorf("%s CanRetire=%v want %v", c.status, d.CanRetire(), c.retire)
		}
	}
}

func TestCanExpire(t *testing.T) {
	now := time.Now().UTC()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	// active + past expiry -> expirable.
	if !(Domain{Status: StatusActive, ExpiresAt: &past}).CanExpire(now) {
		t.Fatal("active + past expiry should be expirable")
	}
	// verified + past expiry -> expirable.
	if !(Domain{Status: StatusVerified, ExpiresAt: &past}).CanExpire(now) {
		t.Fatal("verified + past expiry should be expirable")
	}
	// future expiry -> not yet.
	if (Domain{Status: StatusActive, ExpiresAt: &future}).CanExpire(now) {
		t.Fatal("future expiry should not be expirable")
	}
	// no expiry date -> never.
	if (Domain{Status: StatusActive}).CanExpire(now) {
		t.Fatal("no expires_at should not be expirable")
	}
	// suspended cannot expire (no defined transition).
	if (Domain{Status: StatusSuspended, ExpiresAt: &past}).CanExpire(now) {
		t.Fatal("suspended should not be expirable")
	}
}

func TestCanDelete(t *testing.T) {
	for _, s := range allStatuses {
		want := s != StatusActive
		if (Domain{Status: s}).CanDelete() != want {
			t.Errorf("%s CanDelete=%v want %v", s, (Domain{Status: s}).CanDelete(), want)
		}
	}
}

func TestValidCreateStatus(t *testing.T) {
	ok := []string{"candidate", "pending_purchase", "pending_verification"}
	for _, s := range ok {
		if !ValidCreateStatus(s) {
			t.Errorf("ValidCreateStatus(%q)=false want true", s)
		}
	}
	for _, s := range []string{"verified", "active", "authorized", "suspended", "retired", "expired", "bogus"} {
		if ValidCreateStatus(s) {
			t.Errorf("ValidCreateStatus(%q)=true want false", s)
		}
	}
}

func TestValidNameAndNormalize(t *testing.T) {
	valid := []string{"acme.com", "mail.acme.co.uk", "a-b.example.org", "x1.y2.io"}
	for _, n := range valid {
		if !ValidName(n) {
			t.Errorf("ValidName(%q)=false want true", n)
		}
	}
	invalid := []string{"", "acme", "acme.c", "*.acme.com", "http://acme.com", "acme .com", "-acme.com", "acme-.com", "acme.com/", "a_b.com"}
	for _, n := range invalid {
		if ValidName(n) {
			t.Errorf("ValidName(%q)=true want false", n)
		}
	}
	if NormalizeName("  ACME.CoM ") != "acme.com" {
		t.Fatalf("NormalizeName: got %q", NormalizeName("  ACME.CoM "))
	}
	// Uppercase passes only after normalization.
	if ValidName("ACME.com") {
		t.Fatal("ValidName expects already-normalized input")
	}
	if !ValidName(NormalizeName("ACME.com")) {
		t.Fatal("normalized uppercase should be valid")
	}
}
