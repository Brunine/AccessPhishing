package engine

import "sync"

// ring is a fixed-size byte buffer that keeps the most recent bytes written
// to it (used for bounded stdout/stderr capture).
type ring struct {
	mu   sync.Mutex
	buf  []byte
	next int
	full bool
}

func newRing(size int) *ring {
	return &ring{buf: make([]byte, size)}
}

// Write implements io.Writer, storing at most len(buf) latest bytes.
func (r *ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := len(p)
	for len(p) > 0 {
		c := copy(r.buf[r.next:], p)
		p = p[c:]
		r.next += c
		if r.next == len(r.buf) {
			r.next = 0
			r.full = true
		}
	}
	return n, nil
}

// bytes returns the buffered bytes in write order (oldest first).
func (r *ring) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.full {
		out := make([]byte, r.next)
		copy(out, r.buf[:r.next])
		return out
	}
	out := make([]byte, len(r.buf))
	copy(out, r.buf[r.next:])
	copy(out[len(r.buf)-r.next:], r.buf[:r.next])
	return out
}