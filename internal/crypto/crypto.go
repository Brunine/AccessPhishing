// Package crypto provides per-tenant AES-256-GCM encryption for secrets at rest
// (e.g. SMTP passwords). A single master key (hex, 32 bytes) is loaded from the
// environment; per-tenant keys are derived with HKDF-SHA256 so tenants never
// share key material. Ciphertext is stored as a versioned base64 envelope.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/google/uuid"
	"golang.org/x/crypto/hkdf"
)

// envelopeVersion is the leading byte of every ciphertext envelope.
const envelopeVersion = 0x01

// Cipher derives per-tenant keys from a master key and performs AEAD.
type Cipher struct {
	master []byte
}

// New builds a Cipher from a 32-byte master key encoded as 64 hex chars
// (generate: openssl rand -hex 32).
func New(masterHex string) (*Cipher, error) {
	key, err := hex.DecodeString(masterHex)
	if err != nil {
		return nil, fmt.Errorf("crypto: master key not valid hex: %w", err)
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: master key must be 32 bytes, got %d", len(key))
	}
	return &Cipher{master: key}, nil
}

func (c *Cipher) aead(tenantID uuid.UUID) (cipher.AEAD, error) {
	r := hkdf.New(sha256.New, c.master, nil, append([]byte("phishforge:tenant:"), tenantID[:]...))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("crypto: derive tenant key: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: new gcm: %w", err)
	}
	return gcm, nil
}

// Encrypt seals plaintext under the tenant's derived key and returns a base64
// envelope: version(1) || nonce(12) || ciphertext+tag.
func (c *Cipher) Encrypt(tenantID uuid.UUID, plaintext []byte) (string, error) {
	gcm, err := c.aead(tenantID)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("crypto: nonce: %w", err)
	}
	sealed := gcm.Seal(nil, nonce, plaintext, nil)
	env := make([]byte, 0, 1+len(nonce)+len(sealed))
	env = append(env, envelopeVersion)
	env = append(env, nonce...)
	env = append(env, sealed...)
	return base64.StdEncoding.EncodeToString(env), nil
}

// Decrypt opens an envelope produced by Encrypt for the same tenant.
func (c *Cipher) Decrypt(tenantID uuid.UUID, envelope string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(envelope)
	if err != nil {
		return nil, fmt.Errorf("crypto: envelope not base64: %w", err)
	}
	gcm, err := c.aead(tenantID)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(raw) < 1+ns+gcm.Overhead() {
		return nil, fmt.Errorf("crypto: envelope too short")
	}
	if raw[0] != envelopeVersion {
		return nil, fmt.Errorf("crypto: unsupported envelope version %d", raw[0])
	}
	nonce := raw[1 : 1+ns]
	ct := raw[1+ns:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt: %w", err)
	}
	return pt, nil
}
