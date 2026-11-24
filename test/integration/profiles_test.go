package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/apikey"
	"phishforge/internal/tenant"
)

const validFormProfile = `
version: 1
metadata:
  name: owa-form
  vendor: Microsoft
auth:
  login_path: /owa/auth/logon.aspx
  method: form
  fields:
    - selector: input[name=username]
      upstream_field: username
      capture: true
    - selector: input[name=password]
      upstream_field: password
      capture: true
session:
  success_indicators:
    - type: cookie_set
      name: cadata
  token_locations:
    - in: cookie
      name: cadata
      sensitive: true
mfa:
  mode: none
phishing_facet:
  login_page_url: https://outlook.office.com/owa/auth/logon.aspx
  clone_strategy: mirror
  asset_policy: proxy
`

const reservedOAuthProfile = `
version: 1
metadata:
  name: aad-oauth
auth:
  login_path: /common/oauth2/v2.0/authorize
  method: oauth2_code
  oauth2: {}
session:
  success_indicators:
    - type: cookie_set
      name: ESTSAUTH
  token_locations:
    - in: cookie
      name: ESTSAUTH
      sensitive: true
mfa:
  mode: none
phishing_facet:
  login_page_url: https://login.microsoftonline.com/common/oauth2/v2.0/authorize
  clone_strategy: mirror
  asset_policy: proxy
`

const pushMFAProfile = `
version: 1
metadata:
  name: owa-push
auth:
  login_path: /owa/auth/logon.aspx
  method: form
  fields:
    - selector: input[name=username]
      upstream_field: username
      capture: true
session:
  success_indicators:
    - type: cookie_set
      name: cadata
  token_locations:
    - in: cookie
      name: cadata
mfa:
  mode: push_intercept
phishing_facet:
  login_page_url: https://outlook.office.com/owa/auth/logon.aspx
  clone_strategy: mirror
  asset_policy: proxy
`

// invalidProfile omits auth.method (fail closed: AUTH-METHOD-REQUIRED).
const invalidProfile = `
version: 1
metadata:
  name: broken
auth:
  login_path: /x
session:
  success_indicators:
    - type: cookie_set
      name: c
  token_locations:
    - in: cookie
      name: c
mfa:
  mode: none
phishing_facet:
  login_page_url: https://x.test/
  clone_strategy: mirror
  asset_policy: proxy
`

type profileResp struct {
	ID       uuid.UUID `json:"id"`
	Name     string    `json:"name"`
	Version  int       `json:"version"`
	Checksum string    `json:"checksum"`
}

func TestAppProfilesLifecycle(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tn := mkTenant(t, ctx, pool, "ProfilesCo")
	opID := createUser(t, ctx, pool, tn.ID, "op@prof.test", "operator")
	opTok := mkKey(t, ctx, pool, tn.ID, opID, "op")

	srv, _ := newAPI(t, pool)
	defer srv.Close()

	// --- import a valid profile (JSON envelope) -> version 1 ---
	code, body := do(t, srv.URL, http.MethodPost, "/api/v1/profiles", opTok, map[string]any{"spec_yaml": validFormProfile})
	if code != http.StatusCreated {
		t.Fatalf("create valid profile: want 201, got %d (%s)", code, body)
	}
	var prof profileResp
	mustJSON(t, body, &prof)
	if prof.Version != 1 || len(prof.Checksum) != 64 {
		t.Fatalf("unexpected profile: %+v", prof)
	}

	// re-import the SAME name via raw-YAML /import -> version 2 (N+1).
	code, body = doYAML(t, srv.URL, "/api/v1/profiles/import", opTok, validFormProfile)
	if code != http.StatusCreated {
		t.Fatalf("import v2: want 201, got %d (%s)", code, body)
	}
	var profV2 profileResp
	mustJSON(t, body, &profV2)
	if profV2.Version != 2 {
		t.Fatalf("import must store N+1; want version 2, got %d", profV2.Version)
	}

	// --- invalid profile -> 400 with the exact rule ID ---
	code, body = do(t, srv.URL, http.MethodPost, "/api/v1/profiles", opTok, map[string]any{"spec_yaml": invalidProfile})
	if code != http.StatusBadRequest {
		t.Fatalf("invalid profile: want 400, got %d (%s)", code, body)
	}
	if !bytes.Contains([]byte(body), []byte("AUTH-METHOD-REQUIRED")) {
		t.Fatalf("expected AUTH-METHOD-REQUIRED in violations, got %s", body)
	}

	// --- reserved-method profiles are STORABLE (not import-blocked) ---
	oauthID := mustImport(t, srv.URL, opTok, reservedOAuthProfile)
	pushID := mustImport(t, srv.URL, opTok, pushMFAProfile)

	// --- GET / LIST / tenant isolation ---
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/profiles/"+prof.ID.String(), opTok, nil); code != http.StatusOK {
		t.Fatalf("get profile: want 200, got %d", code)
	}
	code, body = do(t, srv.URL, http.MethodGet, "/api/v1/profiles", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("list: want 200, got %d (%s)", code, body)
	}

	otherTn := mkTenant(t, ctx, pool, "OtherCo")
	otherOp := createUser(t, ctx, pool, otherTn.ID, "op@other.test", "operator")
	otherTok := mkKey(t, ctx, pool, otherTn.ID, otherOp, "op")
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/profiles/"+prof.ID.String(), otherTok, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant get: want 404, got %d", code)
	}

	// --- launch gates: reserved methods refused at launch (storable, not launchable) ---
	engID := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	contactID := createContact(t, ctx, pool, tn.ID, "victim@target.test")

	oauthCamp := mustCampaign(t, srv.URL, opTok, "oauth-camp", engID)
	if code, body := launch(t, srv.URL, opTok, oauthCamp, contactID, &oauthID); code != http.StatusConflict {
		t.Fatalf("oauth launch: want 409 AUTH-METHOD-UNSUPPORTED, got %d (%s)", code, body)
	}
	pushCamp := mustCampaign(t, srv.URL, opTok, "push-camp", engID)
	if code, body := launch(t, srv.URL, opTok, pushCamp, contactID, &pushID); code != http.StatusNotImplemented {
		t.Fatalf("push launch: want 501 MFA-METHOD-UNSUPPORTED, got %d (%s)", code, body)
	}

	// --- happy launch: checksum stamped into the campaign (proof a) ---
	camp := mustCampaign(t, srv.URL, opTok, "owa-camp", engID)
	if code, body := launch(t, srv.URL, opTok, camp, contactID, &prof.ID); code != http.StatusOK {
		t.Fatalf("happy launch: want 200, got %d (%s)", code, body)
	}
	gotChecksum, gotVersion := campaignStamp(t, ctx, pool, camp)
	if gotChecksum != prof.Checksum || gotVersion != 1 {
		t.Fatalf("campaign stamp: want (%s, 1), got (%s, %d)", prof.Checksum, gotChecksum, gotVersion)
	}

	// --- creds event carries profile_checksum/profile_version (proof b) ---
	token := firstRecipientToken(t, srv.URL, opTok, camp)
	engineID, bearer := seedEngineWithToken(t, ctx, pool, tn.ID)
	code, body = postEngineEvents(t, srv.URL, engineID, bearer, token)
	if code != http.StatusOK {
		t.Fatalf("engine events: want 200, got %d (%s)", code, body)
	}
	var evRes struct {
		Accepted int `json:"accepted"`
	}
	mustJSON(t, body, &evRes)
	if evRes.Accepted != 1 {
		t.Fatalf("want 1 accepted creds event, got %d (%s)", evRes.Accepted, body)
	}
	evChecksum, evVersion := credsEventStamp(t, ctx, pool, camp)
	if evChecksum != prof.Checksum || evVersion != 1 {
		t.Fatalf("creds event stamp: want (%s, 1), got (%s, %d)", prof.Checksum, evChecksum, evVersion)
	}

	// --- profile update must NOT mutate the launched campaign's checksum (proof c) ---
	// A cleanly modified spec (adds metadata.product) -> different checksum.
	modified := `
version: 1
metadata:
  name: owa-form
  vendor: Microsoft
  product: Exchange
auth:
  login_path: /owa/auth/logon.aspx
  method: form
  fields:
    - selector: input[name=username]
      upstream_field: username
      capture: true
    - selector: input[name=password]
      upstream_field: password
      capture: true
session:
  success_indicators:
    - type: cookie_set
      name: cadata
  token_locations:
    - in: cookie
      name: cadata
      sensitive: true
mfa:
  mode: none
phishing_facet:
  login_page_url: https://outlook.office.com/owa/auth/logon.aspx
  clone_strategy: mirror
  asset_policy: proxy
`
	code, body = do(t, srv.URL, http.MethodPut, "/api/v1/profiles/"+prof.ID.String(), opTok,
		map[string]any{"spec_yaml": modified})
	if code != http.StatusOK {
		t.Fatalf("update profile: want 200, got %d (%s)", code, body)
	}
	var updated profileResp
	mustJSON(t, body, &updated)
	if updated.Checksum == prof.Checksum {
		t.Fatalf("updated profile checksum should differ from original")
	}
	// The in-flight campaign keeps its launch-time checksum.
	stillChecksum, stillVersion := campaignStamp(t, ctx, pool, camp)
	if stillChecksum != prof.Checksum || stillVersion != 1 {
		t.Fatalf("launched campaign checksum must be frozen: want (%s,1), got (%s,%d)", prof.Checksum, stillChecksum, stillVersion)
	}

	// --- DELETE ---
	if code, _ := do(t, srv.URL, http.MethodDelete, "/api/v1/profiles/"+profV2.ID.String(), opTok, nil); code != http.StatusNoContent {
		t.Fatalf("delete profile: want 204, got %d", code)
	}

	// --- audit: import(3: v1,v2,oauth,push=4) + update(1) + delete(1) ---
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='appprofile.import'`, tn.ID); n != 4 {
		t.Fatalf("appprofile.import audit: want 4, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='appprofile.update'`, tn.ID); n != 1 {
		t.Fatalf("appprofile.update audit: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='appprofile.delete'`, tn.ID); n != 1 {
		t.Fatalf("appprofile.delete audit: want 1, got %d", n)
	}
}

// --- helpers --------------------------------------------------------------

func mustImport(t *testing.T, base, tok, yaml string) uuid.UUID {
	t.Helper()
	code, body := doYAML(t, base, "/api/v1/profiles/import", tok, yaml)
	if code != http.StatusCreated {
		t.Fatalf("import profile: want 201, got %d (%s)", code, body)
	}
	var p profileResp
	mustJSON(t, body, &p)
	return p.ID
}

func mustCampaign(t *testing.T, base, tok, name string, engID uuid.UUID) uuid.UUID {
	t.Helper()
	code, body := do(t, base, http.MethodPost, "/api/v1/campaigns", tok, map[string]any{"name": name, "engagement_id": engID})
	if code != http.StatusCreated {
		t.Fatalf("create campaign %s: want 201, got %d (%s)", name, code, body)
	}
	var c struct {
		ID uuid.UUID `json:"id"`
	}
	mustJSON(t, body, &c)
	return c.ID
}

func launch(t *testing.T, base, tok string, campaignID, contactID uuid.UUID, profileID *uuid.UUID) (int, string) {
	t.Helper()
	payload := map[string]any{"contact_ids": []uuid.UUID{contactID}}
	if profileID != nil {
		payload["app_profile_id"] = *profileID
	}
	return do(t, base, http.MethodPost, "/api/v1/campaigns/"+campaignID.String()+"/launch", tok, payload)
}

func campaignStamp(t *testing.T, ctx context.Context, pool *pgxpool.Pool, campaignID uuid.UUID) (string, int) {
	t.Helper()
	var cs *string
	var ver *int
	if err := pool.QueryRow(ctx, `SELECT profile_checksum, profile_version FROM campaigns WHERE id=$1`, campaignID).Scan(&cs, &ver); err != nil {
		t.Fatalf("read campaign stamp: %v", err)
	}
	if cs == nil || ver == nil {
		t.Fatalf("campaign stamp is null (not stamped at launch)")
	}
	return *cs, *ver
}

func credsEventStamp(t *testing.T, ctx context.Context, pool *pgxpool.Pool, campaignID uuid.UUID) (string, int) {
	t.Helper()
	var cs *string
	var ver *int
	err := pool.QueryRow(ctx,
		`SELECT metadata->>'profile_checksum', (metadata->>'profile_version')::int
		 FROM events WHERE campaign_id=$1 AND type='creds' ORDER BY occurred_at DESC LIMIT 1`,
		campaignID).Scan(&cs, &ver)
	if err != nil {
		t.Fatalf("read creds event stamp: %v", err)
	}
	if cs == nil || ver == nil {
		t.Fatalf("creds event not stamped with profile_checksum/version")
	}
	return *cs, *ver
}

func firstRecipientToken(t *testing.T, base, tok string, campaignID uuid.UUID) string {
	t.Helper()
	code, body := do(t, base, http.MethodGet, "/api/v1/campaigns/"+campaignID.String()+"/links", tok, nil)
	if code != http.StatusOK {
		t.Fatalf("links: want 200, got %d (%s)", code, body)
	}
	var out struct {
		Items []struct {
			Token string `json:"token"`
		} `json:"items"`
	}
	mustJSON(t, body, &out)
	if len(out.Items) == 0 {
		t.Fatal("no recipients")
	}
	return out.Items[0].Token
}

// seedEngineWithToken inserts a running engine row with a known callback bearer
// token and returns the engine id + plaintext token.
func seedEngineWithToken(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID uuid.UUID) (uuid.UUID, string) {
	t.Helper()
	tokBuf := make([]byte, 32)
	for i := range tokBuf {
		tokBuf[i] = byte(i + 1)
	}
	token := hex.EncodeToString(tokBuf)
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO engines (tenant_id, name, config, callback_token_hash, status)
		 VALUES ($1, $2, $3, $4, 'running') RETURNING id`,
		tenantID, "eng-"+short(), "kind: test", hash).Scan(&id)
	if err != nil {
		t.Fatalf("seed engine: %v", err)
	}
	return id, token
}

func postEngineEvents(t *testing.T, base string, engineID uuid.UUID, bearer, recipientToken string) (int, string) {
	t.Helper()
	body := map[string]any{
		"events": []map[string]any{{
			"engine_id":       engineID.String(),
			"recipient_token": recipientToken,
			"kind":            "creds",
			"payload":         map[string]any{"fields": map[string]string{"username": "v", "password": "p"}},
			"ts":              time.Now().UTC().Format(time.RFC3339),
		}},
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, base+"/api/v1/engines/"+engineID.String()+"/events", bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post engine events: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}

func mkTenant(t *testing.T, ctx context.Context, pool *pgxpool.Pool, name string) tenant.Tenant {
	t.Helper()
	tn, err := tenant.NewRepository().Create(ctx, pool, name, "slug-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return tn
}

func mkKey(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, userID uuid.UUID, label string) string {
	t.Helper()
	tok, _, err := apikey.NewService(pool).Create(ctx, tenantID, userID, label)
	if err != nil {
		t.Fatalf("create key: %v", err)
	}
	return tok
}

// doYAML posts a raw YAML body with a text/yaml content type.
func doYAML(t *testing.T, base, path, tok, yaml string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, base+path, bytes.NewReader([]byte(yaml)))
	req.Header.Set("Content-Type", "text/yaml")
	if tok != "" {
		req.Header.Set("X-API-Key", tok)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("doYAML: %v", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(rb)
}
