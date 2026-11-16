// Package httpx provides HTTP response helpers: RFC 7807 problem+json errors
// and a small JSON writer used across API handlers.
package httpx

import (
	"encoding/json"
	"net/http"
)

// ProblemDetails is an RFC 7807 problem+json body.
type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// Problem writes an RFC 7807 application/problem+json error response.
func Problem(w http.ResponseWriter, r *http.Request, status int, title, detail string) {
	pd := ProblemDetails{
		Type:     "about:blank",
		Title:    title,
		Status:   status,
		Detail:   detail,
		Instance: r.URL.Path,
	}
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(pd)
}

// JSON writes v as an application/json response with the given status code.
func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}
