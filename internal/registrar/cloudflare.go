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

// Cloudflare quotes against an operator-provided per-TLD price table.
//
// Cloudflare Registrar sells domains at wholesale/at-cost and does NOT publish
// a public price-list API for unowned domains, so there is no endpoint to scrape
// or query the way Porkbun exposes one. Instead, an operator points
// CLOUDFLARE_PRICING_URL at an exported price table (the same per-TLD JSON shape
// Porkbun returns, under a top-level "pricing" object, or a bare TLD->price map)
// — e.g. a static file published internally from Cloudflare's dashboard figures.
// This keeps the adapter honest (no invented endpoint, no scraping) while still
// letting Cloudflare participate in the comparison when a price list exists.
type Cloudflare struct {
	http     *http.Client
	url      string
	currency string

	mu      sync.Mutex
	table   map[string]tldPrice
	fetched time.Time
}

// NewCloudflare builds a Cloudflare adapter from a pricing-table URL. It returns
// nil (feature disabled) when the URL is empty, mirroring the osint/llm
// optional-client pattern.
func NewCloudflare(pricingURL string, timeout time.Duration) *Cloudflare {
	if strings.TrimSpace(pricingURL) == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &Cloudflare{
		http:     &http.Client{Timeout: timeout},
		url:      strings.TrimSpace(pricingURL),
		currency: "USD",
	}
}

// Name implements Provider.
func (c *Cloudflare) Name() string { return "cloudflare" }

// cloudflarePricing accepts either {"pricing": {tld: {...}}} or a bare
// {tld: {...}} map.
type cloudflarePricing struct {
	Pricing map[string]tldPrice `json:"pricing"`
}

func (c *Cloudflare) pricing(ctx context.Context) (map[string]tldPrice, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.table != nil && time.Since(c.fetched) < pricingTTL {
		return c.table, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url, nil)
	if err != nil {
		return nil, fmt.Errorf("registrar: cloudflare build request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("registrar: cloudflare request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("registrar: cloudflare read: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("registrar: cloudflare %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	table := map[string]tldPrice{}
	var wrapped cloudflarePricing
	if err := json.Unmarshal(raw, &wrapped); err == nil && len(wrapped.Pricing) > 0 {
		table = wrapped.Pricing
	} else if err := json.Unmarshal(raw, &table); err != nil {
		return nil, fmt.Errorf("registrar: cloudflare decode: %w", err)
	}
	norm := make(map[string]tldPrice, len(table))
	for k, v := range table {
		norm[strings.ToLower(strings.TrimPrefix(k, "."))] = v
	}
	c.table = norm
	c.fetched = time.Now()
	return norm, nil
}

// Quote implements Provider.
func (c *Cloudflare) Quote(ctx context.Context, domain string) (Quote, error) {
	tld := TLDOf(domain)
	if tld == "" {
		return Quote{}, fmt.Errorf("registrar: cloudflare: %q has no TLD", domain)
	}
	table, err := c.pricing(ctx)
	if err != nil {
		return Quote{}, err
	}
	price, ok := table[tld]
	if !ok {
		return Quote{}, fmt.Errorf("registrar: cloudflare has no price for .%s", tld)
	}
	return price.toQuote(c.Name(), domain, c.currency, c.fetched), nil
}
