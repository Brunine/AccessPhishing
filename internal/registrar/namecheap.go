package registrar

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// NamecheapConfig carries the credentials the Namecheap API requires. All four
// fields plus a base URL are mandatory; the caller's IP must also be on
// Namecheap's API allowlist for live calls.
type NamecheapConfig struct {
	BaseURL  string // e.g. https://api.namecheap.com (sandbox: api.sandbox.namecheap.com)
	APIUser  string
	APIKey   string
	Username string
	ClientIP string
	Timeout  time.Duration
}

func (c NamecheapConfig) complete() bool {
	return strings.TrimSpace(c.APIUser) != "" && strings.TrimSpace(c.APIKey) != "" &&
		strings.TrimSpace(c.Username) != "" && strings.TrimSpace(c.ClientIP) != ""
}

// Namecheap quotes against the documented namecheap.users.getPricing XML API.
// It is credential-gated: NewNamecheap returns nil when the credentials are not
// fully configured (the adapter is then simply absent from the Set).
type Namecheap struct {
	http *http.Client
	cfg  NamecheapConfig

	mu    sync.Mutex
	cache map[string]cachedTLD
}

type cachedTLD struct {
	price tldPrice
	at    time.Time
}

// NewNamecheap builds a Namecheap adapter, or returns nil when not fully
// configured (mirroring the osint/llm optional-client pattern).
func NewNamecheap(cfg NamecheapConfig) *Namecheap {
	if !cfg.complete() {
		return nil
	}
	if strings.TrimSpace(cfg.BaseURL) == "" {
		cfg.BaseURL = "https://api.namecheap.com"
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return &Namecheap{
		http:  &http.Client{Timeout: cfg.Timeout},
		cfg:   cfg,
		cache: map[string]cachedTLD{},
	}
}

// Name implements Provider.
func (n *Namecheap) Name() string { return "namecheap" }

// Quote implements Provider.
func (n *Namecheap) Quote(ctx context.Context, domain string) (Quote, error) {
	tld := TLDOf(domain)
	if tld == "" {
		return Quote{}, fmt.Errorf("registrar: namecheap: %q has no TLD", domain)
	}

	n.mu.Lock()
	if c, ok := n.cache[tld]; ok && time.Since(c.at) < pricingTTL {
		price := c.price
		n.mu.Unlock()
		return price.toQuote(n.Name(), domain, "USD", c.at), nil
	}
	n.mu.Unlock()

	q := url.Values{}
	q.Set("ApiUser", n.cfg.APIUser)
	q.Set("ApiKey", n.cfg.APIKey)
	q.Set("UserName", n.cfg.Username)
	q.Set("ClientIp", n.cfg.ClientIP)
	q.Set("Command", "namecheap.users.getPricing")
	q.Set("ProductType", "DOMAIN")
	q.Set("ProductName", tld)

	reqURL := n.cfg.BaseURL + "/xml.response?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Quote{}, fmt.Errorf("registrar: namecheap build request: %w", err)
	}
	resp, err := n.http.Do(req)
	if err != nil {
		return Quote{}, fmt.Errorf("registrar: namecheap request: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return Quote{}, fmt.Errorf("registrar: namecheap read: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return Quote{}, fmt.Errorf("registrar: namecheap %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	price, err := parseNamecheapPricing(raw, tld)
	if err != nil {
		return Quote{}, err
	}

	at := time.Now()
	n.mu.Lock()
	n.cache[tld] = cachedTLD{price: price, at: at}
	n.mu.Unlock()
	return price.toQuote(n.Name(), domain, "USD", at), nil
}

// --- XML parsing (documented namecheap.users.getPricing shape) --------------

type ncAPIResponse struct {
	XMLName  xml.Name  `xml:"ApiResponse"`
	Status   string    `xml:"Status,attr"`
	Errors   []ncError `xml:"Errors>Error"`
	Response ncCommand `xml:"CommandResponse"`
}

type ncError struct {
	Number string `xml:"Number,attr"`
	Text   string `xml:",chardata"`
}

type ncCommand struct {
	Result ncPricingResult `xml:"UserGetPricingResult"`
}

type ncPricingResult struct {
	ProductTypes []ncProductType `xml:"ProductType"`
}

type ncProductType struct {
	Name       string         `xml:"Name,attr"`
	Categories []ncProductCat `xml:"ProductCategory"`
}

type ncProductCat struct {
	Name     string      `xml:"Name,attr"`
	Products []ncProduct `xml:"Product"`
}

type ncProduct struct {
	Name   string    `xml:"Name,attr"`
	Prices []ncPrice `xml:"Price"`
}

type ncPrice struct {
	Duration     string `xml:"Duration,attr"`
	DurationType string `xml:"DurationType,attr"`
	Price        string `xml:"Price,attr"`
	YourPrice    string `xml:"YourPrice,attr"`
}

// parseNamecheapPricing extracts the register/renew/transfer one-year prices for
// tld from a getPricing response. It prefers the one-year YEAR duration and the
// customer's effective price (YourPrice), falling back to Price.
func parseNamecheapPricing(raw []byte, tld string) (tldPrice, error) {
	var r ncAPIResponse
	if err := xml.Unmarshal(raw, &r); err != nil {
		return tldPrice{}, fmt.Errorf("registrar: namecheap decode: %w", err)
	}
	if !strings.EqualFold(r.Status, "OK") {
		if len(r.Errors) > 0 {
			return tldPrice{}, fmt.Errorf("registrar: namecheap error %s: %s", r.Errors[0].Number, strings.TrimSpace(r.Errors[0].Text))
		}
		return tldPrice{}, fmt.Errorf("registrar: namecheap status %q", r.Status)
	}

	pick := func(cat string) string {
		for _, pt := range r.Response.Result.ProductTypes {
			for _, c := range pt.Categories {
				if !strings.EqualFold(c.Name, cat) {
					continue
				}
				for _, prod := range c.Products {
					if !strings.EqualFold(prod.Name, tld) {
						continue
					}
					return oneYearPrice(prod.Prices)
				}
			}
		}
		return ""
	}

	out := tldPrice{
		Registration: pick("register"),
		Renewal:      pick("renew"),
		Transfer:     pick("transfer"),
	}
	if out.Registration == "" && out.Renewal == "" && out.Transfer == "" {
		return tldPrice{}, fmt.Errorf("registrar: namecheap returned no pricing for .%s", tld)
	}
	return out, nil
}

// oneYearPrice returns the effective one-year price from a product's price list,
// preferring YourPrice over Price and the Duration=1/YEAR row.
func oneYearPrice(prices []ncPrice) string {
	best := ""
	for _, p := range prices {
		val := p.YourPrice
		if strings.TrimSpace(val) == "" {
			val = p.Price
		}
		if strings.TrimSpace(val) == "" {
			continue
		}
		if p.Duration == "1" && strings.EqualFold(p.DurationType, "YEAR") {
			return val
		}
		if best == "" {
			best = val
		}
	}
	return best
}
