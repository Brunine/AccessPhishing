package qr

import (
	"bytes"
	"crypto/sha256"
	"image/png"
	"testing"
)

// pngHeader is the 8-byte PNG magic signature.
var pngHeader = []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}

const sampleURL = "http://base.local/t/abc123DEF456ghi789JKL"

// We assert non-trivial, decodable PNG bytes of the requested dimensions plus
// deterministic output for a fixed input (a decode round-trip via gozxing was
// the documented alternative; we deliberately avoid the extra test-only
// dependency, per the task's stated choice).
func TestPNGIsDecodablePNGOfRequestedSize(t *testing.T) {
	got, err := PNG(sampleURL, 256, "M")
	if err != nil {
		t.Fatalf("PNG: %v", err)
	}
	if len(got) < 100 {
		t.Fatalf("PNG too small to be real: %d bytes", len(got))
	}
	if !bytes.HasPrefix(got, pngHeader) {
		t.Fatalf("missing PNG header: % x", got[:8])
	}
	img, err := png.Decode(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("decode png: %v", err)
	}
	if b := img.Bounds(); b.Dx() != 256 || b.Dy() != 256 {
		t.Fatalf("size: got %dx%d, want 256x256", b.Dx(), b.Dy())
	}
}

func TestPNGDeterministic(t *testing.T) {
	a, err := PNG(sampleURL, 256, "M")
	if err != nil {
		t.Fatalf("PNG a: %v", err)
	}
	b, err := PNG(sampleURL, 256, "M")
	if err != nil {
		t.Fatalf("PNG b: %v", err)
	}
	if sha256.Sum256(a) != sha256.Sum256(b) {
		t.Fatal("identical input produced different PNG bytes")
	}
	// A different payload must produce different output.
	c, err := PNG(sampleURL+"x", 256, "M")
	if err != nil {
		t.Fatalf("PNG c: %v", err)
	}
	if bytes.Equal(a, c) {
		t.Fatal("different content produced identical PNG bytes")
	}
}

func TestPNGEmptyContent(t *testing.T) {
	if _, err := PNG("", 256, "M"); err == nil {
		t.Fatal("empty content: want error, got nil")
	}
}

func TestClampSize(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, DefaultSize}, {-5, DefaultSize}, {10, MinSize}, {64, 64},
		{256, 256}, {5000, MaxSize},
	}
	for _, c := range cases {
		if got := clampSize(c.in); got != c.want {
			t.Fatalf("clampSize(%d): got %d want %d", c.in, got, c.want)
		}
	}
	// A clamped tiny request still decodes at the clamped size.
	img, err := PNG(sampleURL, 10, "H")
	if err != nil {
		t.Fatalf("PNG tiny: %v", err)
	}
	if !bytes.HasPrefix(img, pngHeader) {
		t.Fatal("clamped PNG missing header")
	}
}

func TestLevel(t *testing.T) {
	// Spot-check the mapping is stable (and distinct levels change the output).
	if Level("L") == Level("H") {
		t.Fatal("L and H map to the same recovery level")
	}
	low, _ := PNG(sampleURL, 256, "L")
	high, _ := PNG(sampleURL, 256, "H")
	if bytes.Equal(low, high) {
		t.Fatal("L and H EC levels produced identical PNGs")
	}
}
