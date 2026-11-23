package user

import "testing"

func TestValidRole(t *testing.T) {
	for _, r := range []string{"admin", "operator", "viewer"} {
		if !ValidRole(r) {
			t.Errorf("ValidRole(%q) = false, want true", r)
		}
	}
	for _, r := range []string{"", "superuser", "Admin", "root", "owner"} {
		if ValidRole(r) {
			t.Errorf("ValidRole(%q) = true, want false", r)
		}
	}
}
