package api

import (
	"net"
	"net/http"
	"sync"
	"time"

	"phishforge/internal/httpx"
)

// rateLimiter is a fixed-window, per-IP limiter for the public tracking routes.
// It is intentionally simple and in-process; a distributed deployment would use
// Redis. Windows are pruned lazily on access.
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*ipWindow
}

type ipWindow struct {
	count int
	reset time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	return &rateLimiter{limit: limit, window: window, hits: make(map[string]*ipWindow)}
}

// allow reports whether the key may proceed, advancing its window counter.
func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.hits[key]
	if !ok || now.After(w.reset) {
		l.hits[key] = &ipWindow{count: 1, reset: now.Add(l.window)}
		l.pruneLocked(now)
		return true
	}
	if w.count >= l.limit {
		return false
	}
	w.count++
	return true
}

// pruneLocked drops expired windows; cheap and bounded by distinct recent IPs.
func (l *rateLimiter) pruneLocked(now time.Time) {
	for k, w := range l.hits {
		if now.After(w.reset) {
			delete(l.hits, k)
		}
	}
}

// middleware returns a chi-compatible middleware enforcing the limit per client IP.
func (l *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !l.allow(clientIP(r), time.Now()) {
			httpx.Problem(w, r, http.StatusTooManyRequests, "too many requests", "rate limit exceeded")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
