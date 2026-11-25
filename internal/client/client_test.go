package client

import (
	"strings"
	"testing"
)

func ptr(s string) *string { return &s }

func TestValidate(t *testing.T) {
	cases := []struct {
		name    string
		in      Input
		wantErr bool
	}{
		{"ok minimal", Input{Name: "Acme Inc"}, false},
		{"ok with email", Input{Name: "Acme", ContactEmail: ptr("ciso@acme.com")}, false},
		{"ok with named email", Input{Name: "Acme", ContactEmail: ptr("Acme CISO <ciso@acme.com>")}, false},
		{"ok with notes", Input{Name: "Acme", Notes: ptr("priority customer")}, false},
		{"ok at max length", Input{Name: strings.Repeat("a", NameMaxLen)}, false},
		{"empty name", Input{Name: ""}, true},
		{"over max length", Input{Name: strings.Repeat("a", NameMaxLen+1)}, true},
		{"bad email", Input{Name: "Acme", ContactEmail: ptr("not-an-email")}, true},
		{"email missing domain", Input{Name: "Acme", ContactEmail: ptr("ciso@")}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.in.Validate()
			if c.wantErr && err == nil {
				t.Fatalf("Validate(%+v) = nil, want error", c.in)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("Validate(%+v) = %v, want nil", c.in, err)
			}
		})
	}
}

func TestNormalize(t *testing.T) {
	// Name is trimmed.
	if got := (Input{Name: "  Acme  "}).Normalize(); got.Name != "Acme" {
		t.Fatalf("name trim: got %q, want %q", got.Name, "Acme")
	}
	// Empty/whitespace contact_email collapses to nil (stored NULL).
	if got := (Input{Name: "Acme", ContactEmail: ptr("   ")}).Normalize(); got.ContactEmail != nil {
		t.Fatalf("blank email should normalize to nil, got %v", *got.ContactEmail)
	}
	// A real email is trimmed and preserved.
	got := (Input{Name: "Acme", ContactEmail: ptr("  ciso@acme.com  ")}).Normalize()
	if got.ContactEmail == nil || *got.ContactEmail != "ciso@acme.com" {
		t.Fatalf("email trim: got %v, want ciso@acme.com", got.ContactEmail)
	}
	// A nil contact_email stays nil.
	if got := (Input{Name: "Acme"}).Normalize(); got.ContactEmail != nil {
		t.Fatalf("nil email should stay nil")
	}
}

// TestNormalizeThenValidate mirrors the handler flow: a blank-but-present email
// is a no-op (valid), not a parse error.
func TestNormalizeThenValidate(t *testing.T) {
	if err := (Input{Name: "Acme", ContactEmail: ptr("")}).Normalize().Validate(); err != nil {
		t.Fatalf("blank email after normalize should be valid, got %v", err)
	}
}
