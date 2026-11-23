// Package contact holds the contact model and its tenant-scoped repository,
// including suppression-aware bulk import.
package contact

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a contact does not exist within the tenant.
var ErrNotFound = errors.New("contact: not found")

// Contact is a target person within a tenant.
type Contact struct {
	ID         uuid.UUID      `json:"id"`
	TenantID   uuid.UUID      `json:"tenant_id"`
	GroupID    *uuid.UUID     `json:"group_id,omitempty"`
	Email      string         `json:"email"`
	FirstName  *string        `json:"first_name,omitempty"`
	LastName   *string        `json:"last_name,omitempty"`
	Phone      *string        `json:"phone,omitempty"`
	PhoneE164  *string        `json:"phone_e164,omitempty"`
	Attributes map[string]any `json:"attributes,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
	UpdatedAt  time.Time      `json:"updated_at"`
}

// Input carries the mutable fields of a contact.
type Input struct {
	Email      string
	FirstName  string
	LastName   string
	Phone      string
	PhoneE164  string
	GroupID    *uuid.UUID
	Attributes map[string]any
}

// e164Re matches an E.164 phone number (leading +, 8..15 digits total).
var e164Re = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

// ValidE164 reports whether s is a well-formed E.164 number.
func ValidE164(s string) bool { return e164Re.MatchString(s) }

// ImportResult summarizes a bulk import.
type ImportResult struct {
	Created    int         `json:"created"`
	Duplicates int         `json:"duplicates"`
	Suppressed int         `json:"suppressed"`
	CreatedIDs []uuid.UUID `json:"created_ids,omitempty"`
}

// Repository provides contact persistence. Stateless; each method takes a
// db.Querier. All queries are scoped by tenant_id.
type Repository struct{}

// NewRepository returns a contact repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, group_id, email, first_name, last_name, phone, phone_e164, attributes, created_at, updated_at`

func scanContact(row pgx.Row) (Contact, error) {
	var (
		c     Contact
		gid   uuid.NullUUID
		attrs []byte
	)
	if err := row.Scan(&c.ID, &c.TenantID, &gid, &c.Email, &c.FirstName, &c.LastName, &c.Phone, &c.PhoneE164, &attrs, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return Contact{}, err
	}
	if gid.Valid {
		id := gid.UUID
		c.GroupID = &id
	}
	if len(attrs) > 0 {
		if err := json.Unmarshal(attrs, &c.Attributes); err != nil {
			return Contact{}, fmt.Errorf("contact: decode attributes: %w", err)
		}
	}
	return c, nil
}

func attrsJSON(m map[string]any) (string, error) {
	if m == nil {
		return "{}", nil
	}
	b, err := json.Marshal(m)
	if err != nil {
		return "", fmt.Errorf("contact: encode attributes: %w", err)
	}
	return string(b), nil
}

func groupArg(g *uuid.UUID) any {
	if g == nil {
		return nil
	}
	return *g
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// Create inserts a contact and returns the stored row.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID uuid.UUID, in Input) (Contact, error) {
	attrs, err := attrsJSON(in.Attributes)
	if err != nil {
		return Contact{}, err
	}
	const sql = `INSERT INTO contacts (tenant_id, group_id, email, first_name, last_name, phone, phone_e164, attributes)
	             VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb) RETURNING ` + cols
	c, err := scanContact(q.QueryRow(ctx, sql, tenantID, groupArg(in.GroupID), in.Email,
		nullIfEmpty(in.FirstName), nullIfEmpty(in.LastName), nullIfEmpty(in.Phone), nullIfEmpty(in.PhoneE164), attrs))
	if err != nil {
		return Contact{}, fmt.Errorf("contact: create: %w", err)
	}
	return c, nil
}

// GetByID loads a contact within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (Contact, error) {
	const sql = `SELECT ` + cols + ` FROM contacts WHERE tenant_id = $1 AND id = $2`
	c, err := scanContact(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Contact{}, ErrNotFound
	}
	if err != nil {
		return Contact{}, fmt.Errorf("contact: get by id: %w", err)
	}
	return c, nil
}

// List returns a tenant's contacts, optionally filtered by group, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID, groupID *uuid.UUID, limit, offset int) ([]Contact, error) {
	var (
		rows pgx.Rows
		err  error
	)
	if groupID != nil {
		const sql = `SELECT ` + cols + ` FROM contacts WHERE tenant_id = $1 AND group_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
		rows, err = q.Query(ctx, sql, tenantID, *groupID, limit, offset)
	} else {
		const sql = `SELECT ` + cols + ` FROM contacts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		rows, err = q.Query(ctx, sql, tenantID, limit, offset)
	}
	if err != nil {
		return nil, fmt.Errorf("contact: list: %w", err)
	}
	defer rows.Close()

	out := make([]Contact, 0)
	for rows.Next() {
		c, err := scanContact(rows)
		if err != nil {
			return nil, fmt.Errorf("contact: scan: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("contact: iterate: %w", err)
	}
	return out, nil
}

// Update replaces a contact's mutable fields within a tenant, or ErrNotFound.
func (r *Repository) Update(ctx context.Context, q db.Querier, tenantID, id uuid.UUID, in Input) (Contact, error) {
	attrs, err := attrsJSON(in.Attributes)
	if err != nil {
		return Contact{}, err
	}
	const sql = `UPDATE contacts
	             SET group_id = $3, email = $4, first_name = $5, last_name = $6, phone = $7,
	                 phone_e164 = $8, attributes = $9::jsonb, updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 RETURNING ` + cols
	c, err := scanContact(q.QueryRow(ctx, sql, tenantID, id, groupArg(in.GroupID), in.Email,
		nullIfEmpty(in.FirstName), nullIfEmpty(in.LastName), nullIfEmpty(in.Phone), nullIfEmpty(in.PhoneE164), attrs))
	if errors.Is(err, pgx.ErrNoRows) {
		return Contact{}, ErrNotFound
	}
	if err != nil {
		return Contact{}, fmt.Errorf("contact: update: %w", err)
	}
	return c, nil
}

// Delete removes a contact within a tenant, or ErrNotFound.
func (r *Repository) Delete(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) error {
	const sql = `DELETE FROM contacts WHERE tenant_id = $1 AND id = $2`
	tag, err := q.Exec(ctx, sql, tenantID, id)
	if err != nil {
		return fmt.Errorf("contact: delete: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// BulkImport inserts many contacts in one pass, skipping suppressed emails and
// counting duplicates (existing tenant+email). It must run inside the caller's
// transaction so the whole import and its audit entry commit atomically.
func (r *Repository) BulkImport(ctx context.Context, q db.Querier, tenantID uuid.UUID, items []Input) (ImportResult, error) {
	var res ImportResult
	for _, in := range items {
		var suppressed bool
		if err := q.QueryRow(ctx,
			`SELECT EXISTS (SELECT 1 FROM suppression_lists WHERE tenant_id = $1 AND lower(email) = lower($2))`,
			tenantID, in.Email).Scan(&suppressed); err != nil {
			return ImportResult{}, fmt.Errorf("contact: import suppression check: %w", err)
		}
		if suppressed {
			res.Suppressed++
			continue
		}

		attrs, err := attrsJSON(in.Attributes)
		if err != nil {
			return ImportResult{}, err
		}
		var id uuid.UUID
		err = q.QueryRow(ctx,
			`INSERT INTO contacts (tenant_id, group_id, email, first_name, last_name, phone, phone_e164, attributes)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
			 ON CONFLICT (tenant_id, email) DO NOTHING
			 RETURNING id`,
			tenantID, groupArg(in.GroupID), in.Email,
			nullIfEmpty(in.FirstName), nullIfEmpty(in.LastName), nullIfEmpty(in.Phone), nullIfEmpty(in.PhoneE164), attrs).Scan(&id)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			res.Duplicates++
		case err != nil:
			return ImportResult{}, fmt.Errorf("contact: import insert: %w", err)
		default:
			res.Created++
			res.CreatedIDs = append(res.CreatedIDs, id)
		}
	}
	return res, nil
}
