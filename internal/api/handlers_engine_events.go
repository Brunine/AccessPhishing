package api

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"phishforge/internal/contact"
	"phishforge/internal/enginerepo"
	"phishforge/internal/events"
	"phishforge/internal/httpx"
	"phishforge/internal/recipient"
)

// newEngineCallbackToken mints a per-run bearer token and its SHA-256 hex
// hash. The plaintext token lives only in the engine process env; the
// orchestrator persists only the hash.
func newEngineCallbackToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err = rand.Read(buf); err != nil {
		return "", "", err
	}
	token = hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// engineEventIn is the ingest body posted by an engine proxy.
type engineEventIn struct {
	Type       string          `json:"type"`
	Token      string          `json:"token"` // the victim's _pft value
	OccurredAt *time.Time      `json:"occurred_at,omitempty"`
	Payload    json.RawMessage `json:"payload,omitempty"`
}

// proxyEventWire is one element of the batched wire format posted by the
// engineproxy reporter (internal/engineproxy Event).
type proxyEventWire struct {
	EngineID string         `json:"engine_id"`
	Token    string         `json:"recipient_token"`
	Kind     string         `json:"kind"` // "creds" | "session"
	Payload  map[string]any `json:"payload"`
	TS       time.Time      `json:"ts"`
}

// proxyBatchWire is the batched envelope: {"events":[...]}.
type proxyBatchWire struct {
	Events []proxyEventWire `json:"events"`
}

// engineEventResult is the per-item outcome in a batch response.
type engineEventResult struct {
	Index  int    `json:"index"`
	Status string `json:"status"` // accepted | unknown_token | invalid | conflict
	Detail string `json:"detail,omitempty"`
}

// engineEvents is the capture-only ingest endpoint engines call with the
// per-run bearer token. It accepts ONLY credential/session capture events;
// lifecycle events (sent/delivered/opened/clicked) remain the orchestrator's
// exclusive domain via the tracking routes.
//
// Wire format: the engineproxy reporter posts a batched envelope
// {"events":[{engine_id, recipient_token, kind, payload, ts}, ...]}.
// A legacy single {type, token, occurred_at, payload} object is also accepted.
//
// The proxy retries the WHOLE batch on any non-2xx, so per-event problems are
// reported in the response body with HTTP 200 — only authentication and
// request-format failures produce error status codes.
//
// Capture-only boundary: raw captured VALUES are never persisted. The
// orchestrator reduces the payload to field/cookie NAMES before Append.
func (s *Server) engineEvents(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="engine-events"`)
		httpx.Problem(w, r, http.StatusUnauthorized, "unauthorized", "missing bearer token")
		return
	}
	presented := strings.TrimSpace(strings.TrimPrefix(authz, prefix))
	if presented == "" {
		httpx.Problem(w, r, http.StatusUnauthorized, "unauthorized", "missing bearer token")
		return
	}

	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		httpx.Problem(w, r, http.StatusNotFound, "not found", "engine not found")
		return
	}
	storedHash, err := s.engineRepo.CallbackHashByID(r.Context(), s.pool, id)
	if errors.Is(err, enginerepo.ErrNotFound) {
		// Same response whether the engine is unknown or simply not running:
		// never reveal which.
		httpx.Problem(w, r, http.StatusUnauthorized, "unauthorized", "invalid token")
		return
	}
	if err != nil {
		httpx.Problem(w, r, http.StatusInternalServerError, "internal error", "load engine token")
		return
	}
	sum := sha256.Sum256([]byte(presented))
	if subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(storedHash)) != 1 {
		httpx.Problem(w, r, http.StatusUnauthorized, "unauthorized", "invalid token")
		return
	}

	// Dual-format decode: batch envelope first, legacy single object second.
	body, err := readBodyCapped(w, r, 1<<20)
	if err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "read body")
		return
	}
	var batch proxyBatchWire
	if err := json.Unmarshal(body, &batch); err == nil && len(batch.Events) > 0 {
		results := make([]engineEventResult, 0, len(batch.Events))
		accepted := 0
		for i, pe := range batch.Events {
			rawPayload, perr := json.Marshal(pe.Payload)
			if perr != nil {
				rawPayload = []byte("null")
			}
			st, detail := s.ingestEngineEvent(r, evTypeFromProxyKind(pe.Kind), pe.Token, pe.TS, rawPayload)
			if st == "accepted" {
				accepted++
			}
			results = append(results, engineEventResult{Index: i, Status: st, Detail: detail})
		}
		httpx.JSON(w, http.StatusOK, map[string]any{
			"accepted": accepted,
			"results":  results,
		})
		return
	}

	// Legacy single-event shape.
	var in engineEventIn
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		httpx.Problem(w, r, http.StatusBadRequest, "invalid request", "body is neither a batch envelope nor a single event")
		return
	}
	st, detail := s.ingestEngineEvent(r, events.Type(in.Type), in.Token, orNow(in.OccurredAt), in.Payload)
	if st != "accepted" {
		code := http.StatusBadRequest
		switch st {
		case "conflict":
			code = http.StatusConflict
		case "unknown_token":
		}
		httpx.Problem(w, r, code, "invalid request", detail)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// evTypeFromProxyKind maps the proxy's event kinds to orchestrator event
// types. Unknown kinds return "" and are reported per-item, never batch-wide.
func evTypeFromProxyKind(kind string) events.Type {
	switch kind {
	case "creds":
		return events.TypeCreds
	case "session":
		return events.TypeSessionHijacked
	default:
		return ""
	}
}

func orNow(t *time.Time) time.Time {
	if t != nil {
		return *t
	}
	return time.Time{} // zero => events.Append applies now()
}

// ingestEngineEvent processes one capture event end-to-end and returns a
// per-item status. It never writes HTTP responses; batch and legacy callers
// translate statuses differently.
func (s *Server) ingestEngineEvent(r *http.Request, evType events.Type, token string, occurredAt time.Time, payload json.RawMessage) (status, detail string) {
	if evType == "" || (evType != events.TypeCreds && evType != events.TypeSessionHijacked) {
		return "invalid", "kind must be creds or session (engines are capture-only)"
	}
	if token == "" {
		return "invalid", "recipient_token is required"
	}

	rec, err := s.recipients.GetByToken(r.Context(), s.pool, token)
	if errors.Is(err, recipient.ErrNotFound) {
		// Per-item soft-fail: the proxy cannot fix a stale token and must not
		// be made to retry the batch forever.
		return "unknown_token", "unknown recipient token"
	}
	if err != nil {
		return "error", "resolve recipient"
	}

	// Integrity check: the recipient's contact must still exist in the
	// recipient's tenant (defense against stale snapshots).
	if rec.ContactID != uuid.Nil {
		if _, err := s.contacts.GetByID(r.Context(), s.pool, rec.TenantID, rec.ContactID); err != nil {
			if errors.Is(err, contact.ErrNotFound) {
				return "unknown_token", "recipient contact no longer exists"
			}
			return "error", "resolve contact"
		}
	}

	raw := payload
	meta, err := sanitizeEnginePayload(evType, raw)
	if err != nil {
		return "invalid", err.Error()
	}
	meta["source"] = "engine"

	ev := events.NewEvent{
		TenantID:   rec.TenantID,
		CampaignID: rec.CampaignID,
		ContactID:  rec.ContactID,
		Type:       evType,
		Metadata:   meta,
	}
	if !occurredAt.IsZero() {
		ev.OccurredAt = occurredAt
	}
	if _, err := s.events.Append(r.Context(), ev); err != nil {
		if errors.Is(err, events.ErrInvalidTransition) {
			return "conflict", "event not allowed from the target's current state"
		}
		return "error", "append event"
	}
	return "accepted", ""
}

// readBodyCapped reads the request body up to limit bytes.
func readBodyCapped(w http.ResponseWriter, r *http.Request, limit int64) ([]byte, error) {
	return io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
}

// sanitizeEnginePayload enforces the capture-only boundary. Captured values
// never reach the events table; only NAMES (form fields, cookie names) and a
// non-secret host survive. Unknown keys are dropped.
func sanitizeEnginePayload(evType events.Type, raw json.RawMessage) (map[string]any, error) {
	out := map[string]any{}
	if len(raw) == 0 {
		return out, nil
	}
	var in map[string]json.RawMessage
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, errors.New("payload must be a JSON object")
	}

	switch evType {
	case events.TypeCreds:
		var fields map[string]string
		if f, ok := in["fields"]; ok && len(f) > 0 {
			if err := json.Unmarshal(f, &fields); err != nil {
				return nil, errors.New("payload.fields must be an object of name=value")
			}
			names := make([]string, 0, len(fields))
			for name := range fields {
				names = append(names, name)
			}
			sort.Strings(names)
			out["fields"] = names
		}
	case events.TypeSessionHijacked:
		var cookies map[string]string
		if c, ok := in["cookies"]; ok && len(c) > 0 {
			if err := json.Unmarshal(c, &cookies); err != nil {
				return nil, errors.New("payload.cookies must be an object of name=value")
			}
			names := make([]string, 0, len(cookies))
			for name := range cookies {
				names = append(names, name)
			}
			sort.Strings(names)
			out["cookies"] = names
		}
		var host string
		if h, ok := in["host"]; ok {
			_ = json.Unmarshal(h, &host)
			if host != "" && len(host) <= 253 {
				out["host"] = host
			}
		}
	}
	return out, nil
}
