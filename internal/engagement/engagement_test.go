package engagement

import (
	"errors"
	"testing"
	"time"
)

func ref[T any](v T) *T { return &v }

func TestValidStatus(t *testing.T) {
	for _, s := range []string{"draft", "pending_authorization", "authorized", "active", "expired", "terminated"} {
		if !ValidStatus(s) {
			t.Errorf("ValidStatus(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "authorised", "cancelled", "pending"} {
		if ValidStatus(s) {
			t.Errorf("ValidStatus(%q) = true, want false", s)
		}
	}
}

func TestIsActiveAndEffective(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name       string
		e          Engagement
		wantActive bool
		wantEff    Status
	}{
		{"draft", Engagement{Status: StatusDraft}, false, StatusDraft},
		{"pending", Engagement{Status: StatusPending}, false, StatusPending},
		{"authorized no expiry", Engagement{Status: StatusAuthorized}, true, StatusActive},
		{"authorized future expiry", Engagement{Status: StatusAuthorized, ExpiresAt: &future}, true, StatusActive},
		{"authorized past expiry", Engagement{Status: StatusAuthorized, ExpiresAt: &past}, false, StatusExpired},
		{"terminated", Engagement{Status: StatusTerminated}, false, StatusTerminated},
		{"terminated with future expiry", Engagement{Status: StatusTerminated, ExpiresAt: &future}, false, StatusTerminated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.e.IsActive(now); got != c.wantActive {
				t.Errorf("IsActive = %v, want %v", got, c.wantActive)
			}
			if got := c.e.Effective(now); got != c.wantEff {
				t.Errorf("Effective = %q, want %q", got, c.wantEff)
			}
		})
	}
}

func TestExpiryBoundaryInclusive(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	// expires_at exactly == now counts as expired (not before now).
	e := Engagement{Status: StatusAuthorized, ExpiresAt: &now}
	if !e.IsExpired(now) {
		t.Fatal("expiry at exactly now should be expired")
	}
	if e.IsActive(now) {
		t.Fatal("engagement expiring exactly now must not be active")
	}
}

func TestCheckCampaignLaunchable(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name string
		e    Engagement
		want error
	}{
		{"authorized ok", Engagement{Status: StatusAuthorized}, nil},
		{"authorized unexpired ok", Engagement{Status: StatusAuthorized, ExpiresAt: &future}, nil},
		{"draft -> not authorized", Engagement{Status: StatusDraft}, ErrEngagementNotAuthorized},
		{"pending -> not authorized", Engagement{Status: StatusPending}, ErrEngagementNotAuthorized},
		{"expired -> expired", Engagement{Status: StatusAuthorized, ExpiresAt: &past}, ErrEngagementExpired},
		{"terminated -> terminated", Engagement{Status: StatusTerminated}, ErrEngagementTerminated},
		{"terminated beats expiry", Engagement{Status: StatusTerminated, ExpiresAt: &past}, ErrEngagementTerminated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.e.CheckCampaignLaunchable(now); !errors.Is(got, c.want) {
				t.Errorf("CheckCampaignLaunchable = %v, want %v", got, c.want)
			}
		})
	}
}

func TestTransitionGuards(t *testing.T) {
	cases := []struct {
		status                                Status
		canRequest, canAuth, canTerm, canEdit bool
	}{
		{StatusDraft, true, false, true, true},
		{StatusPending, true, true, true, true},
		{StatusAuthorized, false, false, true, true},
		{StatusTerminated, false, false, false, false},
	}
	for _, c := range cases {
		t.Run(string(c.status), func(t *testing.T) {
			e := Engagement{Status: c.status}
			if e.CanRequestAuthorization() != c.canRequest {
				t.Errorf("CanRequestAuthorization = %v, want %v", e.CanRequestAuthorization(), c.canRequest)
			}
			if e.CanAuthorize() != c.canAuth {
				t.Errorf("CanAuthorize = %v, want %v", e.CanAuthorize(), c.canAuth)
			}
			if e.CanTerminate() != c.canTerm {
				t.Errorf("CanTerminate = %v, want %v", e.CanTerminate(), c.canTerm)
			}
			if e.CanEdit() != c.canEdit {
				t.Errorf("CanEdit = %v, want %v", e.CanEdit(), c.canEdit)
			}
		})
	}
}

func TestValidateScope(t *testing.T) {
	valid := [][]string{
		{},
		{"acme.com"},
		{"*.acme.com"},
		{"https://acme.com", "http://portal.acme.com/login"},
		{"sub.domain.co.uk", "*.a.b.example.org"},
	}
	for _, s := range valid {
		if err := ValidateScope(s); err != nil {
			t.Errorf("ValidateScope(%v) = %v, want nil", s, err)
		}
	}
	invalid := [][]string{
		{""},
		{"   "},
		{"not a domain"},
		{"http://"},
		{"ftp://acme.com"},
		{"*.*.com"},
		{"acme"},
	}
	for _, s := range invalid {
		if err := ValidateScope(s); err == nil {
			t.Errorf("ValidateScope(%v) = nil, want error", s)
		}
	}
}
