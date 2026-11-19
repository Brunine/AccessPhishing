// Package osintclient is a Go client for the Python OSINT microservice
// (services/osint-py). It performs only passive public-info aggregation — the
// orchestrator never scans anything itself; it delegates to the service, which
// wraps crt.sh/subfinder, native lookalike generation, and RDAP lookups.
//
// Auth note: the service authenticates with the X-OSINT-TOKEN header (see
// services/osint-py/app/deps.py), so this client sends OSINT_API_KEY in that
// header rather than as an Authorization: Bearer token.
package osintclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const (
	maxResponseBytes = 8 << 20 // 8 MiB
	// availabilityCap bounds how many generated lookalikes we RDAP-check per
	// collect, keeping the aggregate job fast and polite.
	availabilityCap = 50
)

// Candidate mirrors the service's lookalike candidate.
type Candidate struct {
	Domain string `json:"domain"`
	Fuzzer string `json:"fuzzer"`
}

// AvailabilityResult mirrors the service's RDAP availability result.
type AvailabilityResult struct {
	Domain     string `json:"domain"`
	Available  *bool  `json:"available"`
	StatusCode *int   `json:"status_code,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Result is the aggregated collection for a domain. It composes the service's
// own response shapes (subdomains, lookalike candidates, RDAP availability).
type Result struct {
	Domain          string               `json:"domain"`
	SubdomainSource string               `json:"subdomain_source"`
	Subdomains      []string             `json:"subdomains"`
	Lookalikes      []Candidate          `json:"lookalikes"`
	Availability    []AvailabilityResult `json:"availability"`
}

// Client talks to the OSINT service. Safe for concurrent use.
type Client struct {
	http    *http.Client
	baseURL string
	apiKey  string
	timeout time.Duration
}

// New builds a client for baseURL (e.g. http://osint:8099). It returns nil when
// baseURL is empty so callers can treat the feature as disabled.
func New(baseURL, apiKey string, timeout time.Duration) *Client {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{
		http:    &http.Client{Timeout: timeout},
		baseURL: strings.TrimRight(baseURL, "/"),
		apiKey:  apiKey,
		timeout: timeout,
	}
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("osint: marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, reader)
	if err != nil {
		return fmt.Errorf("osint: build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("X-OSINT-TOKEN", c.apiKey)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("osint: request failed: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return fmt.Errorf("osint: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("osint: %s %s -> %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return fmt.Errorf("osint: decode response: %w", err)
		}
	}
	return nil
}

// Health checks service reachability via GET /health.
func (c *Client) Health(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	return c.do(ctx, http.MethodGet, "/health", nil, nil)
}

type subdomainsResp struct {
	Domain     string   `json:"domain"`
	Source     string   `json:"source"`
	Subdomains []string `json:"subdomains"`
}

type generateResp struct {
	Candidates []Candidate `json:"candidates"`
}

type availabilityResp struct {
	Results []AvailabilityResult `json:"results"`
}

// Collect runs the passive aggregation pipeline for a domain: subdomain
// enumeration, lookalike generation, and RDAP availability of the generated
// lookalikes (capped). It applies the client timeout across the whole job.
func (c *Client) Collect(ctx context.Context, domain string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	res := Result{Domain: domain}

	var subs subdomainsResp
	if err := c.do(ctx, http.MethodPost, "/recon/subdomains", map[string]any{"domain": domain}, &subs); err != nil {
		return Result{}, err
	}
	res.SubdomainSource = subs.Source
	res.Subdomains = subs.Subdomains

	var gen generateResp
	if err := c.do(ctx, http.MethodPost, "/domains/generate", map[string]any{"domain": domain}, &gen); err != nil {
		return Result{}, err
	}
	res.Lookalikes = gen.Candidates

	// RDAP-check up to availabilityCap generated lookalikes.
	if len(gen.Candidates) > 0 {
		limit := len(gen.Candidates)
		if limit > availabilityCap {
			limit = availabilityCap
		}
		domains := make([]string, 0, limit)
		for _, cand := range gen.Candidates[:limit] {
			domains = append(domains, cand.Domain)
		}
		var avail availabilityResp
		if err := c.do(ctx, http.MethodPost, "/domains/availability", map[string]any{"domains": domains}, &avail); err != nil {
			return Result{}, err
		}
		res.Availability = avail.Results
	}

	return res, nil
}
