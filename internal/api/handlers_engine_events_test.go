package api

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEngineEventsRequiresBearer(t *testing.T) {
	s := &Server{} // bearer check must precede any DB access
	req := httptest.NewRequest("POST", "/api/v1/engines/00000000-0000-0000-0000-000000000001/events",
		strings.NewReader(`{"type":"creds","token":"x"}`))
	rec := httptest.NewRecorder()
	s.engineEvents(rec, req)
	if rec.Code != 401 {
		t.Fatalf("want 401 without bearer, got %d", rec.Code)
	}
}

func TestEngineCallbackTokenHashRoundTrip(t *testing.T) {
	tok, hash, err := newEngineCallbackToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) != 64 || len(hash) != 64 {
		t.Fatalf("unexpected lengths: token=%d hash=%d", len(tok), len(hash))
	}
	sum := sha256.Sum256([]byte(tok))
	if hex.EncodeToString(sum[:]) != hash {
		t.Fatal("hash does not match token")
	}
	tok2, hash2, _ := newEngineCallbackToken()
	if tok == tok2 || hash == hash2 {
		t.Fatal("tokens must be unique per call")
	}
}

func TestSanitizeEnginePayloadStripsValues(t *testing.T) {
	meta, err := sanitizeEnginePayload("creds", []byte(
		`{"fields":{"username":"victim-secret","password":"hunter2","email":"a@b.c"}}`))
	if err != nil {
		t.Fatal(err)
	}
	fields, _ := meta["fields"].([]string)
	if len(fields) != 3 || fields[0] != "email" || fields[1] != "password" || fields[2] != "username" {
		t.Fatalf("want sorted names only, got %v", fields)
	}
	for _, v := range meta {
		if s, ok := v.(string); ok && (s == "victim-secret" || s == "hunter2") {
			t.Fatalf("captured value leaked: %q", s)
		}
	}

	meta, err = sanitizeEnginePayload("session_hijacked", []byte(
		`{"cookies":{"session":"abc123"},"host":"mail.example.com","evil":"drop"}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := meta["evil"]; ok {
		t.Fatal("unknown key must be dropped")
	}
	if meta["host"] != "mail.example.com" {
		t.Fatalf("host should survive: %v", meta)
	}
	if cookies, _ := meta["cookies"].([]string); len(cookies) != 1 || cookies[0] != "session" {
		t.Fatalf("want cookie names only, got %v", meta["cookies"])
	}

	// Capture-only: lifecycle types are rejected by the handler, and the
	// sanitizer must not leak anything for them either.
	meta, err = sanitizeEnginePayload("clicked", []byte(`{"fields":{"a":"b"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(meta) != 0 {
		t.Fatalf("non-capture types must sanitize to empty, got %v", meta)
	}
}