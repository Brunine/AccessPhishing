package integration

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/api"
	"phishforge/internal/apikey"
	"phishforge/internal/candidate"
	"phishforge/internal/crypto"
	"phishforge/internal/osintclient"
	"phishforge/internal/registrar"
	"phishforge/internal/tenant"
)

// fakeSuggest serves /domains/suggest with a fixed candidate set so the
// collector is exercised deterministically (no network, no real OSINT service).
func fakeSuggest(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/domains/suggest", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OSINT-TOKEN") != "tok" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"domain":"example.com","count":4,"truncated":false,"candidates":[
			{"domain":"examplea.com","fuzzer":"addition","available":true,"status_code":404},
			{"domain":"exampleb.com","fuzzer":"addition","available":true,"status_code":404},
			{"domain":"exarnple.com","fuzzer":"replacement","available":false,"status_code":200},
			{"domain":"conflictme.com","fuzzer":"addition","available":true,"status_code":404}
		]}`))
	})
	return httptest.NewServer(mux)
}

// fakeRegistrar is a deterministic registrar.Provider: cheap for examplea,
// expensive for exampleb, and no price for anything else.
type fakeRegistrar struct{}

func (fakeRegistrar) Name() string { return "testbun" }

func (fakeRegistrar) Quote(_ context.Context, domain string) (registrar.Quote, error) {
	now := time.Now()
	mk := func(first, renew int64) registrar.Quote {
		return registrar.Quote{
			Registrar: "testbun", Domain: domain, TLD: registrar.TLDOf(domain),
			Currency: "USD", FirstYearCents: &first, RenewalCents: &renew, QuotedAt: now,
		}
	}
	switch domain {
	case "examplea.com":
		return mk(500, 500), nil // 3y = 1500
	case "exampleb.com":
		return mk(5000, 5000), nil // 3y = 15000
	default:
		return registrar.Quote{}, fmt.Errorf("testbun: no price for %s", domain)
	}
}

func apiWithOSINTEnq(t *testing.T, pool *pgxpool.Pool, oc api.OSINTClient, enq api.Enqueuer) *httptest.Server {
	t.Helper()
	cip, err := crypto.New(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return httptest.NewServer(api.NewServer(api.Deps{
		Pool: pool, BaseURL: "http://base.local", Cipher: cip, Enqueuer: enq, OSINT: oc,
	}).Router())
}

// seedScopedEngagement inserts an authorized engagement with an authorized_scope
// so candidate discovery has seeds to work from.
func seedScopedEngagement(t *testing.T, ctx context.Context, pool *pgxpool.Pool, tenantID, createdBy uuid.UUID, scope string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pool.QueryRow(ctx,
		`INSERT INTO engagements (tenant_id, name, client_name, status, authorized_scope, authorized_at, authorized_by, created_by)
		 VALUES ($1, $2, $3, 'authorized', $4::jsonb, now(), $5, $5) RETURNING id`,
		tenantID, "Eng "+short(), "Client Co", scope, createdBy).Scan(&id)
	if err != nil {
		t.Fatalf("seed scoped engagement: %v", err)
	}
	return id
}

func TestCandidateDiscoveryLifecycle(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tn, err := tenants.Create(ctx, pool, "Cand Co", "cand-"+short())
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	opID := createUser(t, ctx, pool, tn.ID, "op@cand.test", "operator")
	opTok, _, _ := apikey.NewService(pool).Create(ctx, tn.ID, opID, "op")

	// A domain already in inventory that collides with one suggested candidate.
	if _, err := pool.Exec(ctx,
		`INSERT INTO domains (tenant_id, name, status, created_by) VALUES ($1, 'conflictme.com', 'pending_verification', $2)`,
		tn.ID, opID); err != nil {
		t.Fatalf("seed conflicting domain: %v", err)
	}

	suggest := fakeSuggest(t)
	defer suggest.Close()
	oc := osintclient.New(suggest.URL, "tok", 10*time.Second)

	enq := &fakeEnqueuer{}
	srv := apiWithOSINTEnq(t, pool, oc, enq)
	defer srv.Close()

	// --- gate: a draft (unauthorized) engagement cannot be collected (403) ---
	draftEng := seedEngagementStatus(t, ctx, pool, tn.ID, opID, "draft", nil)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+draftEng.String()+"/candidates/collect", opTok, nil); code != http.StatusForbidden {
		t.Fatalf("collect on draft engagement: want 403, got %d (%s)", code, b)
	}

	// --- gate: authorized but no scope -> 409 ---
	noScope := seedAuthorizedEngagement(t, ctx, pool, tn.ID, opID)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+noScope.String()+"/candidates/collect", opTok, nil); code != http.StatusConflict {
		t.Fatalf("collect without scope: want 409, got %d (%s)", code, b)
	}

	// --- happy enqueue: authorized + scope -> 202, enqueuer records it ---
	engID := seedScopedEngagement(t, ctx, pool, tn.ID, opID, `["https://example.com","*.example.com"]`)
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+engID.String()+"/candidates/collect", opTok, nil); code != http.StatusAccepted {
		t.Fatalf("collect: want 202, got %d (%s)", code, b)
	}
	if enq.candidateCount() != 1 {
		t.Fatalf("enqueuer candidate count: want 1, got %d", enq.candidateCount())
	}

	// --- run the discovery job directly (the worker's transport-independent
	//     core) against the fake OSINT + fake registrar ---
	collector := candidate.NewCollector(candidate.CollectorConfig{
		Pool: pool, OSINT: oc, Registrars: registrar.NewSet(fakeRegistrar{}),
	})
	res, err := collector.Collect(ctx, tn.ID, engID, opID)
	if err != nil {
		t.Fatalf("collect run: %v", err)
	}
	if res.Suggested != 4 || res.Scored != 4 || res.Conflicts != 1 {
		t.Fatalf("collect result: %+v", res)
	}

	// --- list candidates: ranked, with quotes + scores ---
	code, body := do(t, srv.URL, http.MethodGet, "/api/v1/engagements/"+engID.String()+"/candidates", opTok, nil)
	if code != http.StatusOK {
		t.Fatalf("list candidates: %d (%s)", code, body)
	}
	var listed struct {
		Items []struct {
			ID     uuid.UUID         `json:"id"`
			Name   string            `json:"name"`
			Source string            `json:"source"`
			Status string            `json:"status"`
			Rank   *int              `json:"rank"`
			Score  candidate.Score   `json:"score"`
			Quotes []candidate.Quote `json:"quotes"`
		} `json:"items"`
	}
	mustJSON(t, body, &listed)
	if len(listed.Items) != 4 {
		t.Fatalf("want 4 candidates, got %d", len(listed.Items))
	}
	// Results are ordered by rank ascending.
	byName := map[string]int{}
	for _, it := range listed.Items {
		if it.Rank == nil {
			t.Fatalf("candidate %s has no rank", it.Name)
		}
		byName[it.Name] = *it.Rank
	}
	// examplea (available + cheap) outranks exampleb (available + expensive),
	// which outranks exarnple (registered), which outranks conflictme (conflict).
	if !(byName["examplea.com"] < byName["exampleb.com"] &&
		byName["exampleb.com"] < byName["exarnple.com"] &&
		byName["exarnple.com"] < byName["conflictme.com"]) {
		t.Fatalf("ranking wrong: %+v", byName)
	}

	// Inspect the top candidate's score + quote.
	var top struct {
		ID     uuid.UUID
		Score  candidate.Score
		Quotes []candidate.Quote
		Status string
	}
	for _, it := range listed.Items {
		if it.Name == "examplea.com" {
			top.ID = it.ID
			top.Score = it.Score
			top.Quotes = it.Quotes
			top.Status = it.Status
		}
	}
	if top.Status != "scored" {
		t.Fatalf("top status: want scored, got %q", top.Status)
	}
	if top.Score.Available == nil || !*top.Score.Available || top.Score.Conflict {
		t.Fatalf("top score flags: %+v", top.Score)
	}
	if top.Score.MinCost3YCents == nil || *top.Score.MinCost3YCents != 1500 {
		t.Fatalf("top 3y cost: want 1500, got %+v", top.Score.MinCost3YCents)
	}
	if top.Score.Value <= 90 {
		t.Fatalf("top value should be high, got %v", top.Score.Value)
	}
	if len(top.Quotes) != 1 || top.Quotes[0].Registrar != "testbun" || top.Quotes[0].FirstYearCents == nil || *top.Quotes[0].FirstYearCents != 500 {
		t.Fatalf("top quotes: %+v", top.Quotes)
	}

	// The conflicting candidate scores 0 and is flagged.
	for _, it := range listed.Items {
		if it.Name == "conflictme.com" {
			if it.Score.Value != 0 || !it.Score.Conflict {
				t.Fatalf("conflict candidate score: %+v", it.Score)
			}
		}
	}

	// --- operator picks the top candidate and rejects another ---
	if code, b := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+engID.String()+"/candidates/"+top.ID.String()+"/select", opTok, nil); code != http.StatusOK {
		t.Fatalf("select: %d (%s)", code, b)
	}
	if s := candidateStatus(t, ctx, pool, top.ID); s != "selected" {
		t.Fatalf("after select: want selected, got %q", s)
	}

	// Re-collect must not clobber the operator's selection.
	if _, err := collector.Collect(ctx, tn.ID, engID, opID); err != nil {
		t.Fatalf("re-collect: %v", err)
	}
	if s := candidateStatus(t, ctx, pool, top.ID); s != "selected" {
		t.Fatalf("selection clobbered by re-collect: %q", s)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM domain_candidates WHERE engagement_id=$1`, engID); n != 4 {
		t.Fatalf("re-collect should upsert (still 4 rows), got %d", n)
	}

	// --- single candidate GET + reject ---
	var rejectID uuid.UUID
	for _, it := range listed.Items {
		if it.Name == "exampleb.com" {
			rejectID = it.ID
		}
	}
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engagements/"+engID.String()+"/candidates/"+rejectID.String(), opTok, nil); code != http.StatusOK {
		t.Fatalf("get candidate: %d", code)
	}
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+engID.String()+"/candidates/"+rejectID.String()+"/reject", opTok, nil); code != http.StatusOK {
		t.Fatalf("reject: %d", code)
	}
	if s := candidateStatus(t, ctx, pool, rejectID); s != "rejected" {
		t.Fatalf("after reject: want rejected, got %q", s)
	}

	// --- registrar catalog ---
	if code, b := do(t, srv.URL, http.MethodGet, "/api/v1/registrars", opTok, nil); code != http.StatusOK ||
		!strings.Contains(b, "porkbun") || !strings.Contains(b, "namecheap") || !strings.Contains(b, "cloudflare") {
		t.Fatalf("registrars: %d (%s)", code, b)
	}

	// --- audit: one enqueue + two collect runs + select + reject ---
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='candidate.collect'`, tn.ID); n != 2 {
		t.Fatalf("candidate.collect audit: want 2, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action='candidate.collect.enqueue'`, tn.ID); n != 1 {
		t.Fatalf("candidate.collect.enqueue audit: want 1, got %d", n)
	}
	if n := count(t, ctx, pool, `SELECT count(*) FROM audit_log WHERE tenant_id=$1 AND action IN ('candidate.select','candidate.reject')`, tn.ID); n != 2 {
		t.Fatalf("select/reject audit: want 2, got %d", n)
	}
}

func TestCandidateTenantIsolation(t *testing.T) {
	pool := setupDB(t)
	ctx := context.Background()

	tenants := tenant.NewRepository()
	tnA, _ := tenants.Create(ctx, pool, "A", "a-"+short())
	tnB, _ := tenants.Create(ctx, pool, "B", "b-"+short())
	aOp := createUser(t, ctx, pool, tnA.ID, "op@a.test", "operator")
	bOp := createUser(t, ctx, pool, tnB.ID, "op@b.test", "operator")
	aTok, _, _ := apikey.NewService(pool).Create(ctx, tnA.ID, aOp, "a")
	_ = bOp

	bEng := seedScopedEngagement(t, ctx, pool, tnB.ID, bOp, `["example.com"]`)

	srv := apiWithOSINTEnq(t, pool, nil, &fakeEnqueuer{})
	defer srv.Close()

	// A's operator cannot see B's engagement candidates (404, not 403).
	if code, _ := do(t, srv.URL, http.MethodGet, "/api/v1/engagements/"+bEng.String()+"/candidates", aTok, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant candidate list: want 404, got %d", code)
	}
	// Collect against a nil OSINT client -> 503 (feature unconfigured).
	aEng := seedScopedEngagement(t, ctx, pool, tnA.ID, aOp, `["example.com"]`)
	if code, _ := do(t, srv.URL, http.MethodPost, "/api/v1/engagements/"+aEng.String()+"/candidates/collect", aTok, nil); code != http.StatusServiceUnavailable {
		t.Fatalf("collect with nil OSINT: want 503, got %d", code)
	}
}

func candidateStatus(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id uuid.UUID) string {
	t.Helper()
	var s string
	if err := pool.QueryRow(ctx, `SELECT status::text FROM domain_candidates WHERE id=$1`, id).Scan(&s); err != nil {
		t.Fatalf("read candidate status: %v", err)
	}
	return s
}
