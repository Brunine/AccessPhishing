// Package recipient holds the per-campaign recipient snapshot and the public
// tracking tokens used in links and pixels.
package recipient

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a token resolves to no recipient.
var ErrNotFound = errors.New("recipient: not found")

// Recipient is a frozen campaign target with its public tracking token.
type Recipient struct {
	ID         uuid.UUID  `json:"id"`
	TenantID   uuid.UUID  `json:"tenant_id"`
	CampaignID uuid.UUID  `json:"campaign_id"`
	ContactID  uuid.UUID  `json:"contact_id"`
	GroupID    *uuid.UUID `json:"group_id,omitempty"`
	Token      string     `json:"token"`
	CreatedAt  time.Time  `json:"created_at"`
}

// Target identifies a contact to snapshot (with its originating group).
type Target struct {
	ContactID uuid.UUID
	GroupID   *uuid.UUID
}

// Repository provides recipient persistence. Stateless; each method takes a
// db.Querier. Tenant-scoped methods require a tenant id; token lookup is global
// because the token is itself the (unguessable) credential.
type Repository struct{}

// NewRepository returns a recipient repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, campaign_id, contact_id, group_id, token, created_at`

func scanRecipient(row pgx.Row) (Recipient, error) {
	var (
		rec Recipient
		gid uuid.NullUUID
	)
	if err := row.Scan(&rec.ID, &rec.TenantID, &rec.CampaignID, &rec.ContactID, &gid, &rec.Token, &rec.CreatedAt); err != nil {
		return Recipient{}, err
	}
	if gid.Valid {
		id := gid.UUID
		rec.GroupID = &id
	}
	return rec, nil
}

// NewToken returns a 16-byte URL-safe random token (22 chars, unpadded).
func NewToken() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("recipient: token rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Snapshot inserts recipients for the given targets, generating a fresh token
// for each. Existing (campaign, contact) pairs are skipped. It returns the
// number created and must run inside the caller's transaction.
func (r *Repository) Snapshot(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID, targets []Target) (int, error) {
	created := 0
	for _, t := range targets {
		token, err := NewToken()
		if err != nil {
			return created, err
		}
		var groupArg any
		if t.GroupID != nil {
			groupArg = *t.GroupID
		}
		var id uuid.UUID
		err = q.QueryRow(ctx,
			`INSERT INTO recipients (tenant_id, campaign_id, contact_id, group_id, token)
			 VALUES ($1, $2, $3, $4, $5)
			 ON CONFLICT (campaign_id, contact_id) DO NOTHING
			 RETURNING id`,
			tenantID, campaignID, t.ContactID, groupArg, token).Scan(&id)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			// already a recipient; skip
		case err != nil:
			return created, fmt.Errorf("recipient: snapshot insert: %w", err)
		default:
			created++
		}
	}
	return created, nil
}

// ListByCampaign returns a campaign's recipients within a tenant.
func (r *Repository) ListByCampaign(ctx context.Context, q db.Querier, tenantID, campaignID uuid.UUID) ([]Recipient, error) {
	const sql = `SELECT ` + cols + ` FROM recipients WHERE tenant_id = $1 AND campaign_id = $2 ORDER BY created_at`
	rows, err := q.Query(ctx, sql, tenantID, campaignID)
	if err != nil {
		return nil, fmt.Errorf("recipient: list: %w", err)
	}
	defer rows.Close()

	out := make([]Recipient, 0)
	for rows.Next() {
		rec, err := scanRecipient(rows)
		if err != nil {
			return nil, fmt.Errorf("recipient: scan: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recipient: iterate: %w", err)
	}
	return out, nil
}

// GetByToken resolves a public token to its recipient (global lookup), or
// ErrNotFound. The token is the credential, so no tenant scoping is applied.
func (r *Repository) GetByToken(ctx context.Context, q db.Querier, token string) (Recipient, error) {
	const sql = `SELECT ` + cols + ` FROM recipients WHERE token = $1`
	rec, err := scanRecipient(q.QueryRow(ctx, sql, token))
	if errors.Is(err, pgx.ErrNoRows) {
		return Recipient{}, ErrNotFound
	}
	if err != nil {
		return Recipient{}, fmt.Errorf("recipient: get by token: %w", err)
	}
	return rec, nil
}
