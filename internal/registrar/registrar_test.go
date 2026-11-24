package registrar

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParsePriceCents(t *testing.T) {
	cases := []struct {
		in      string
		want    int64
		wantErr bool
	}{
		{"9.68", 968, false},
		{"12", 1200, false},
		{"0.99", 99, false},
		{"$10.00", 1000, false},
		{"1,299.00", 129900, false},
		{"9.6", 960, false},   // single fractional digit padded
		{"9.689", 968, false}, // extra fractional digits truncated
		{"9.", 900, false},
		{".99", 99, false},
		{"", 0, true},
		{"-5.00", 0, true},
		{"abc", 0, true},
	}
	for _, c := range cases {
		got, err := ParsePriceCents(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParsePriceCents(%q): want error, got %d", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePriceCents(%q): unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParsePriceCents(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestTLDOf(t *testing.T) {
	cases := map[string]string{
		"example.com":   "com",
		"a.b.co.uk":     "uk",
		"EXAMPLE.ORG":   "org",
		"trailing.net.": "net",
		"nodot":         "",
		"":              "",
		"ends.":         "",
	}
	for in, want := range cases {
		if got := TLDOf(in); got != want {
			t.Errorf("TLDOf(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestQuoteCost3Y(t *testing.T) {
	fy, rn := int64(1000), int64(1200)
	q := Quote{FirstYearCents: &fy, RenewalCents: &rn}
	if c, ok := q.Cost3Y(); !ok || c != 1000+2*1200 {
		t.Fatalf("Cost3Y = %d,%v want %d,true", c, ok, 1000+2400)
	}
	// Missing renewal => not computable.
	q2 := Quote{FirstYearCents: &fy}
	if _, ok := q2.Cost3Y(); ok {
		t.Fatalf("Cost3Y with no renewal: want ok=false")
	}
}

// fakeProvider is a deterministic Provider for Set tests.
type fakeProvider struct {
	name string
	q    Quote
	err  error
}

func (f fakeProvider) Name() string { return f.name }
func (f fakeProvider) Quote(_ context.Context, domain string) (Quote, error) {
	if f.err != nil {
		return Quote{}, f.err
	}
	q := f.q
	q.Domain = domain
	return q, nil
}

func TestSetQuoteAggregatesAndCollectsErrors(t *testing.T) {
	fy := int64(900)
	rn := int64(1000)
	good := fakeProvider{name: "good", q: Quote{Registrar: "good", Currency: "USD", FirstYearCents: &fy, RenewalCents: &rn}}
	bad := fakeProvider{name: "bad", err: errors.New("boom")}
	set := NewSet(good, nil, bad) // nil provider is skipped

	if set.Len() != 2 {
		t.Fatalf("Len = %d, want 2 (nil skipped)", set.Len())
	}
	quotes, errs := set.Quote(context.Background(), "x.com")
	if len(quotes) != 1 || quotes[0].Registrar != "good" || quotes[0].Domain != "x.com" {
		t.Fatalf("quotes = %+v", quotes)
	}
	if errs["bad"] == "" {
		t.Fatalf("expected error recorded for bad provider, got %+v", errs)
	}
}

func TestPorkbunQuote(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != porkbunPricingPath {
			http.Error(w, "nope", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"SUCCESS","pricing":{"com":{"registration":"9.68","renewal":"11.06","transfer":"9.68"},"io":{"registration":"33.00","renewal":"39.00","transfer":"33.00"}}}`))
	}))
	defer srv.Close()

	p := NewPorkbun(srv.URL, 5*time.Second)
	q, err := p.Quote(context.Background(), "victim.com")
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if q.Registrar != "porkbun" || q.TLD != "com" {
		t.Fatalf("quote meta: %+v", q)
	}
	if q.FirstYearCents == nil || *q.FirstYearCents != 968 {
		t.Fatalf("first year: %+v", q.FirstYearCents)
	}
	if c, ok := q.Cost3Y(); !ok || c != 968+2*1106 {
		t.Fatalf("cost3y = %d,%v", c, ok)
	}
	// Unknown TLD => error.
	if _, err := p.Quote(context.Background(), "victim.zzz"); err == nil {
		t.Fatalf("expected error for unknown tld")
	}
}

func TestCloudflareDisabledWithoutURL(t *testing.T) {
	if c := NewCloudflare("", 0); c != nil {
		t.Fatalf("NewCloudflare(\"\") should be nil (disabled)")
	}
}

func TestCloudflareQuoteFromPriceTable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pricing":{"com":{"registration":"8.57","renewal":"8.57","transfer":"8.57"}}}`))
	}))
	defer srv.Close()

	c := NewCloudflare(srv.URL, 5*time.Second)
	if c == nil {
		t.Fatal("NewCloudflare returned nil for configured URL")
	}
	q, err := c.Quote(context.Background(), "phish.com")
	if err != nil {
		t.Fatalf("Quote: %v", err)
	}
	if q.FirstYearCents == nil || *q.FirstYearCents != 857 || q.Registrar != "cloudflare" {
		t.Fatalf("quote: %+v", q)
	}
}

func TestNamecheapDisabledWithoutCreds(t *testing.T) {
	if n := NewNamecheap(NamecheapConfig{BaseURL: "https://x"}); n != nil {
		t.Fatalf("NewNamecheap without creds should be nil")
	}
}

func TestParseNamecheapPricing(t *testing.T) {
	const fixture = `<?xml version="1.0" encoding="utf-8"?>
<ApiResponse Status="OK" xmlns="http://api.namecheap.com/xml.response">
  <Errors />
  <CommandResponse Type="namecheap.users.getPricing">
    <UserGetPricingResult>
      <ProductType Name="domains">
        <ProductCategory Name="register">
          <Product Name="com">
            <Price Duration="1" DurationType="YEAR" Price="10.69" YourPrice="9.06" Currency="USD" />
            <Price Duration="2" DurationType="YEAR" Price="21.38" YourPrice="18.12" Currency="USD" />
          </Product>
        </ProductCategory>
        <ProductCategory Name="renew">
          <Product Name="com">
            <Price Duration="1" DurationType="YEAR" Price="12.88" YourPrice="12.88" Currency="USD" />
          </Product>
        </ProductCategory>
        <ProductCategory Name="transfer">
          <Product Name="com">
            <Price Duration="1" DurationType="YEAR" Price="9.06" YourPrice="9.06" Currency="USD" />
          </Product>
        </ProductCategory>
      </ProductType>
    </UserGetPricingResult>
  </CommandResponse>
</ApiResponse>`

	price, err := parseNamecheapPricing([]byte(fixture), "com")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// YourPrice preferred, one-year row.
	if price.Registration != "9.06" || price.Renewal != "12.88" || price.Transfer != "9.06" {
		t.Fatalf("parsed: %+v", price)
	}
	q := price.toQuote("namecheap", "x.com", "USD", time.Now())
	if q.FirstYearCents == nil || *q.FirstYearCents != 906 {
		t.Fatalf("first year cents: %+v", q.FirstYearCents)
	}

	// Error response surfaces the error text.
	const errXML = `<ApiResponse Status="ERROR" xmlns="http://api.namecheap.com/xml.response">
  <Errors><Error Number="1011150">Parameter ApiKey is missing</Error></Errors>
  <CommandResponse />
</ApiResponse>`
	if _, err := parseNamecheapPricing([]byte(errXML), "com"); err == nil {
		t.Fatalf("expected error for ERROR status")
	}
}
