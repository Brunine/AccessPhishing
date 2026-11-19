package delivery

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"phishforge/internal/sendingprofile"
)

func TestGmailSenderSend(t *testing.T) {
	var gotAuth, gotRaw string
	tokenHits := 0

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		tokenHits++
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "rtok" {
			http.Error(w, "bad grant", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok123","expires_in":3600}`))
	})
	mux.HandleFunc("/gmail/v1/users/me/messages/send", func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		var body struct {
			Raw string `json:"raw"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		dec, _ := base64.URLEncoding.DecodeString(body.Raw)
		gotRaw = string(dec)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":"m1"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	fn := "IT"
	p := sendingprofile.Profile{Channel: "gmail", FromAddress: "it@c.test", FromName: &fn}
	gs := newGmailSender(p, GmailConfig{
		TokenURL: ts.URL + "/token", BaseURL: ts.URL,
		ClientID: "cid", ClientSecret: "csec", RefreshToken: "rtok",
	}, "")

	if err := gs.Send(context.Background(), "victim@t.test", "Hello", "<b>hi</b>"); err != nil {
		t.Fatalf("send: %v", err)
	}
	// Second send reuses the cached token (no second token fetch).
	if err := gs.Send(context.Background(), "two@t.test", "Hi2", "<i>y</i>"); err != nil {
		t.Fatalf("send 2: %v", err)
	}
	if tokenHits != 1 {
		t.Fatalf("token fetched %d times, want 1 (cached)", tokenHits)
	}
	if gotAuth != "Bearer tok123" {
		t.Fatalf("auth header: %q", gotAuth)
	}
	for _, want := range []string{"To: two@t.test", "Subject: Hi2", "Content-Type: text/html", "<i>y</i>", "From: IT <it@c.test>"} {
		if !strings.Contains(gotRaw, want) {
			t.Fatalf("raw message missing %q in:\n%s", want, gotRaw)
		}
	}
}

func TestGmailSecretOverridesRefreshToken(t *testing.T) {
	// The per-profile encrypted secret supplies the refresh token.
	gs := newGmailSender(sendingprofile.Profile{FromAddress: "x@y.test"},
		GmailConfig{ClientID: "c", ClientSecret: "s", RefreshToken: "env-rtok"}, "profile-rtok")
	if gs.refreshToken != "profile-rtok" {
		t.Fatalf("refresh token: want profile-rtok, got %q", gs.refreshToken)
	}
}

func TestGmailMissingCredsFailsFast(t *testing.T) {
	gs := newGmailSender(sendingprofile.Profile{FromAddress: "x@y.test"},
		GmailConfig{TokenURL: "http://127.0.0.1:1/token", BaseURL: "http://127.0.0.1:1"}, "")
	if err := gs.Send(context.Background(), "a@b.test", "s", "b"); err == nil {
		t.Fatal("want error for missing client id/secret/refresh token")
	}
}
