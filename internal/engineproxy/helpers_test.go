package engineproxy

import (
	"net"
	"net/url"
	"testing"
)

func listenFree() (net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	return ln, nil
}

func splitHostPort(t *testing.T, hostPort string) (string, int) {
	t.Helper()
	h, p, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("split %q: %v", hostPort, err)
	}
	n := 0
	for _, c := range p {
		n = n*10 + int(c-'0')
	}
	return h, n
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
