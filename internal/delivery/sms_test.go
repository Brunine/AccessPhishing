package delivery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"phishforge/internal/sendingprofile"
)

func strptr(s string) *string { return &s }

func smsProfile() sendingprofile.Profile {
	return sendingprofile.Profile{
		Channel:     "sms",
		APIClientID: strptr("AC123"),        // Twilio Account SID
		SMSSenderID: strptr("+15550000000"), // From
	}
}

func TestSMSSenderSend(t *testing.T) {
	var gotUser, gotPass, gotTo, gotFrom, gotBody, gotPath string
	hits := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/2010-04-01/Accounts/AC123/Messages.json", func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotPath = r.URL.Path
		gotUser, gotPass, _ = r.BasicAuth()
		_ = r.ParseForm()
		gotTo, gotFrom, gotBody = r.PostForm.Get("To"), r.PostForm.Get("From"), r.PostForm.Get("Body")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"sid":"SM1","status":"queued"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	s := newSMSSender(smsProfile(), SMSConfig{BaseURL: ts.URL, Timeout: 5 * time.Second}, "tok-secret")
	if err := s.Send(context.Background(), "+15551234567", "", "Hi Dana https://x/t/abc"); err != nil {
		t.Fatalf("send: %v", err)
	}
	if hits != 1 {
		t.Fatalf("hits=%d", hits)
	}
	if gotUser != "AC123" || gotPass != "tok-secret" {
		t.Fatalf("basic auth: %q/%q", gotUser, gotPass)
	}
	if gotTo != "+15551234567" || gotFrom != "+15550000000" || !strings.Contains(gotBody, "Hi Dana") {
		t.Fatalf("form: to=%q from=%q body=%q", gotTo, gotFrom, gotBody)
	}
	if gotPath != "/2010-04-01/Accounts/AC123/Messages.json" {
		t.Fatalf("path: %q", gotPath)
	}
}

func TestSMSSender4xxFails(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":21211,"message":"Invalid 'To' phone number"}`))
	}))
	defer ts.Close()
	s := newSMSSender(smsProfile(), SMSConfig{BaseURL: ts.URL, Timeout: 5 * time.Second}, "tok")
	err := s.Send(context.Background(), "+1555", "", "x")
	if err == nil || !strings.Contains(err.Error(), "400") {
		t.Fatalf("want 400 error, got %v", err)
	}
}

func TestSMSSenderMissingCredsFailsFast(t *testing.T) {
	// Empty SID: fails before any network call.
	p := sendingprofile.Profile{Channel: "sms", SMSSenderID: strptr("+1")}
	s := newSMSSender(p, SMSConfig{BaseURL: "http://127.0.0.1:1", Timeout: time.Second}, "")
	if err := s.Send(context.Background(), "+15551234567", "", "x"); err == nil {
		t.Fatal("want error for missing SID/auth token")
	}
}

func TestSMSSenderTimeout(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusCreated)
	}))
	defer ts.Close()
	s := newSMSSender(smsProfile(), SMSConfig{BaseURL: ts.URL, Timeout: 20 * time.Millisecond}, "tok")
	if err := s.Send(context.Background(), "+15551234567", "", "x"); err == nil {
		t.Fatal("want timeout error")
	}
}
