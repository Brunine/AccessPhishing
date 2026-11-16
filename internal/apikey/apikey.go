// Package apikey issues and verifies hashed API keys.
//
// A token has the form "pf_<keyID>.<secret>". Only a bcrypt hash of the secret
// is stored; the plaintext token is returned once at creation. Verification
// looks the row up by keyID (O(1)) and compares the secret against the hash.
package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"

	"phishforge/internal/audit"
)

const tokenPrefix = "pf_"

// ErrInvalidKey is returned for any missing, malformed, revoked, or
// non-matching key. It is deliberately uniform to avoid leaking which part
// of the token was wrong.
var ErrInvalidKey = errors.New("apikey: invalid or revoked key")

// Identity is the principal data bound to a verified key.
type Identity struct {
	TenantID uuid.UUID
	UserID   uuid.UUID
	Email    string
	Role     string
}

// Key is a stored key record (without secret material).
type Key struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	UserID    uuid.UUID `json:"user_id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Service issues and verifies API keys over a pool.
type Service struct {
	pool *pgxpool.Pool
}

// NewService returns an API-key service backed by pool.
func NewService(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// Create generates a key for a user, stores only its bcrypt hash, writes an
// audit entry, and returns the one-time plaintext token plus the record.
func (s *Service) Create(ctx context.Context, tenantID, userID uuid.UUID, name string) (string, Key, error) {
	if name == "" {
		return "", Key{}, fmt.Errorf("apikey: name is required")
	}
	secret, err := randomSecret()
	if err != nil {
		return "", Key{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		return "", Key{}, fmt.Errorf("apikey: hash: %w", err)
	}
	id := uuid.New()

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return "", Key{}, fmt.Errorf("apikey: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	var k Key
	const ins = `
INSERT INTO api_keys (id, tenant_id, user_id, name, key_hash)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, tenant_id, user_id, name, created_at`
	if err := tx.QueryRow(ctx, ins, id, tenantID, userID, name, string(hash)).
		Scan(&k.ID, &k.TenantID, &k.UserID, &k.Name, &k.CreatedAt); err != nil {
		return "", Key{}, fmt.Errorf("apikey: insert: %w", err)
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		TenantID:   tenantID,
		ActorID:    userID,
		Action:     "apikey.create",
		TargetType: "api_key",
		TargetID:   id.String(),
		Metadata:   map[string]any{"name": name},
	}); err != nil {
		return "", Key{}, err
	}

	if err := tx.Commit(ctx); err != nil {
		return "", Key{}, fmt.Errorf("apikey: commit: %w", err)
	}
	return tokenPrefix + id.String() + "." + secret, k, nil
}

// Verify resolves a token to its bound identity, rejecting missing, revoked,
// or inactive-user keys. On success it best-effort updates last_used_at.
func (s *Service) Verify(ctx context.Context, token string) (Identity, error) {
	id, secret, err := parseToken(token)
	if err != nil {
		return Identity{}, err
	}

	var (
		keyHash  string
		revoked  *time.Time
		tenantID uuid.UUID
		userID   uuid.UUID
		email    string
		role     string
		status   string
	)
	const q = `
SELECT k.key_hash, k.revoked_at, k.tenant_id, k.user_id, u.email, u.role::text, u.status
FROM api_keys k
JOIN users u ON u.id = k.user_id
WHERE k.id = $1`
	err = s.pool.QueryRow(ctx, q, id).Scan(&keyHash, &revoked, &tenantID, &userID, &email, &role, &status)
	if errors.Is(err, pgx.ErrNoRows) {
		return Identity{}, ErrInvalidKey
	}
	if err != nil {
		return Identity{}, fmt.Errorf("apikey: lookup: %w", err)
	}
	if revoked != nil || status != "active" {
		return Identity{}, ErrInvalidKey
	}
	if err := bcrypt.CompareHashAndPassword([]byte(keyHash), []byte(secret)); err != nil {
		return Identity{}, ErrInvalidKey
	}

	_, _ = s.pool.Exec(ctx, `UPDATE api_keys SET last_used_at = now() WHERE id = $1`, id)

	return Identity{TenantID: tenantID, UserID: userID, Email: email, Role: role}, nil
}

// Revoke marks a tenant's key revoked and writes an audit entry.
func (s *Service) Revoke(ctx context.Context, tenantID, actorID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("apikey: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`UPDATE api_keys SET revoked_at = now() WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL`,
		tenantID, id)
	if err != nil {
		return fmt.Errorf("apikey: revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrInvalidKey
	}

	if err := audit.Write(ctx, tx, audit.Entry{
		TenantID:   tenantID,
		ActorID:    actorID,
		Action:     "apikey.revoke",
		TargetType: "api_key",
		TargetID:   id.String(),
	}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func randomSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("apikey: rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func parseToken(token string) (uuid.UUID, string, error) {
	if !strings.HasPrefix(token, tokenPrefix) {
		return uuid.Nil, "", ErrInvalidKey
	}
	body := strings.TrimPrefix(token, tokenPrefix)
	i := strings.IndexByte(body, '.')
	if i <= 0 || i >= len(body)-1 {
		return uuid.Nil, "", ErrInvalidKey
	}
	id, err := uuid.Parse(body[:i])
	if err != nil {
		return uuid.Nil, "", ErrInvalidKey
	}
	return id, body[i+1:], nil
}
