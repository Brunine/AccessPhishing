package registrar

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// porkbunPricingPath is Porkbun's public, unauthenticated per-TLD price table.
const porkbunPricingPath = "/api/json/v3/pricing/get"

// pricingTTL bounds how long a fetched price table is reused before refetching.
const pricingTTL = 6 * time.Hour

// Porkbun quotes against Porkbun's public pricing API. The price table is the
// same for every domain, so it is fetched once and cached (TTL-bounded). No
// credentials are required; this adapter is always available.
type Porkbun struct {
	http *http.Client
	base string

	mu      sync.Mutex
	table   map[string]tldPrice
	fetched time.Time
}

// NewPorkbun builds a Porkbun adapter. baseURL defaults to the public endpoint;
// timeout defaults to 15s. It never returns nil — Porkbun needs no credentials.
func NewPorkbun(baseURL string, timeout time.Duration) *Porkbun {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://api.porkbun.com"
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Porkbun{
		http: &http.Client{Timeout: timeout},
		base: strings.TrimRight(baseURL, "/"),
	}
}

// Name implements Provider.
func (p *Porkbun) Name() string { return "porkbun" }

type porkbunPricingResponse struct {
	Status  string              `json:"status"`
	Message string              `json:"message"`
	Pricing map[string]tldPrice `json:"pricing"`
}

// pricing returns the cached price table, fetching it if missing or stale.
func (p *Porkbun) pricing(ctx context.Context) (map[string]tldPrice, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.table != nil && time.Since(p.fetched) < pricingTTL {
		return p.table, nil
	}
	// Porkbun's pricing endpoint is a POST with an empty JSON body.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+porkbunPricingPath, strings.NewReader("{}"))
	if err != nil {
		return nil, fmt.Errorf("registrar: porkbun build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registrar: porkbun request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("registrar: porkbun read: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("registrar: porkbun %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var pr porkbunPricingResponse
	if err := json.Unmarshal(raw, &pr); err != nil {
		return nil, fmt.Errorf("registrar: porkbun decode: %w", err)
	}
	if !strings.EqualFold(pr.Status, "SUCCESS") {
		return nil, fmt.Errorf("registrar: porkbun status %q: %s", pr.Status, pr.Message)
	}
	// Normalize TLD keys to lowercase.
	table := make(map[string]tldPrice, len(pr.Pricing))
	for k, v := range pr.Pricing {
		table[strings.ToLower(strings.TrimPrefix(k, "."))] = v
	}
	p.table = table
	p.fetched = time.Now()
	return table, nil
}

// Quote implements Provider.
func (p *Porkbun) Quote(ctx context.Context, domain string) (Quote, error) {
	tld := TLDOf(domain)
	if tld == "" {
		return Quote{}, fmt.Errorf("registrar: porkbun: %q has no TLD", domain)
	}
	table, err := p.pricing(ctx)
	if err != nil {
		return Quote{}, err
	}
	price, ok := table[tld]
	if !ok {
		return Quote{}, fmt.Errorf("registrar: porkbun has no price for .%s", tld)
	}
	return price.toQuote(p.Name(), domain, "USD", p.fetched), nil
}
