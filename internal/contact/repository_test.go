package contact

import "testing"

func TestValidE164(t *testing.T) {
	valid := []string{"+15551234567", "+447911123456", "+5511987654321", "+12025550123"}
	for _, s := range valid {
		if !ValidE164(s) {
			t.Errorf("ValidE164(%q) = false, want true", s)
		}
	}
	invalid := []string{
		"",                  // empty
		"5551234567",        // no +
		"+0123456789",       // leading 0 after +
		"+1",                // too short
		"+1555123",          // too short (< 8 digits)
		"+1234567890123456", // too long (> 15 digits)
		"+1 555 123 4567",   // spaces
		"+1-555-123-4567",   // dashes
		"tel:+15551234567",  // scheme
	}
	for _, s := range invalid {
		if ValidE164(s) {
			t.Errorf("ValidE164(%q) = true, want false", s)
		}
	}
}
