package apikey

import (
	"testing"

	"github.com/google/uuid"
)

func TestParseToken(t *testing.T) {
	id := uuid.New()
	gotID, secret, err := parseToken("pf_" + id.String() + ".deadbeef")
	if err != nil {
		t.Fatalf("valid token: unexpected error %v", err)
	}
	if gotID != id || secret != "deadbeef" {
		t.Fatalf("parsed id=%s secret=%q, want %s/deadbeef", gotID, secret, id)
	}

	bad := []string{
		"",                        // empty
		"deadbeef",                // no prefix
		"pf_",                     // prefix only
		"pf_not-a-uuid.secret",    // bad uuid
		"pf_" + id.String(),       // no dot/secret
		"pf_" + id.String() + ".", // empty secret
		"pf_." + "secret",         // empty id
	}
	for _, tok := range bad {
		if _, _, err := parseToken(tok); err == nil {
			t.Errorf("parseToken(%q): want error, got nil", tok)
		}
	}
}
