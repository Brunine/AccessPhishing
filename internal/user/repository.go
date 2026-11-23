// Package user holds the operator-user model and its tenant-scoped repository.
// Users are key-based (no password): a user row is created active with a role,
// and gains access when an API key is minted for it (see internal/apikey).
// Deactivating a user (status != 'active') disables all of its keys at verify
// time.
package user

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
)

// ErrNotFound is returned when a user does not exist within the tenant.
var ErrNotFound = errors.New("user: not found")

// ValidRole reports whether r is a valid user_role enum value.
func ValidRole(r string) bool {
	switch r {
	case "admin", "operator", "viewer":
		return true
	default:
		return false
	}
}

// User is an operator account within a tenant. Active is derived from status.
type User struct {
	ID        uuid.UUID `json:"id"`
	TenantID  uuid.UUID `json:"tenant_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
}

// Repository provides user persistence. Stateless; tenant-scoped.
type Repository struct{}

// NewRepository returns a user repository.
func NewRepository() *Repository { return &Repository{} }

const cols = `id, tenant_id, email, role::text, status, created_at`

func scanUser(row pgx.Row) (User, error) {
	var (
		u      User
		status string
	)
	if err := row.Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &status, &u.CreatedAt); err != nil {
		return User{}, err
	}
	u.Active = status == "active"
	return u, nil
}

// Create inserts an active, key-based user (no password), mirroring the seed
// tool. A duplicate (tenant, lower(email)) surfaces as a unique violation for
// the caller to map to 409.
func (r *Repository) Create(ctx context.Context, q db.Querier, tenantID uuid.UUID, email, role string) (User, error) {
	const sql = `INSERT INTO users (tenant_id, email, role) VALUES ($1, $2, $3::user_role) RETURNING ` + cols
	u, err := scanUser(q.QueryRow(ctx, sql, tenantID, email, role))
	if err != nil {
		return User{}, fmt.Errorf("user: create: %w", err)
	}
	return u, nil
}

// List returns a tenant's users, newest first.
func (r *Repository) List(ctx context.Context, q db.Querier, tenantID uuid.UUID) ([]User, error) {
	const sql = `SELECT ` + cols + ` FROM users WHERE tenant_id = $1 ORDER BY created_at DESC`
	rows, err := q.Query(ctx, sql, tenantID)
	if err != nil {
		return nil, fmt.Errorf("user: list: %w", err)
	}
	defer rows.Close()
	out := make([]User, 0)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, fmt.Errorf("user: scan: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("user: iterate: %w", err)
	}
	return out, nil
}

// GetByID loads a user within a tenant, or ErrNotFound.
func (r *Repository) GetByID(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (User, error) {
	const sql = `SELECT ` + cols + ` FROM users WHERE tenant_id = $1 AND id = $2`
	u, err := scanUser(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("user: get by id: %w", err)
	}
	return u, nil
}

// Deactivate sets a user's status to 'inactive' (only from active), returning
// the updated row, or ErrNotFound when no active user matched.
func (r *Repository) Deactivate(ctx context.Context, q db.Querier, tenantID, id uuid.UUID) (User, error) {
	const sql = `UPDATE users SET status = 'inactive', updated_at = now()
	             WHERE tenant_id = $1 AND id = $2 AND status = 'active' RETURNING ` + cols
	u, err := scanUser(q.QueryRow(ctx, sql, tenantID, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("user: deactivate: %w", err)
	}
	return u, nil
}

// CountActiveAdmins counts active admins in a tenant, excluding excludeID.
func (r *Repository) CountActiveAdmins(ctx context.Context, q db.Querier, tenantID, excludeID uuid.UUID) (int, error) {
	const sql = `SELECT count(*) FROM users
	             WHERE tenant_id = $1 AND status = 'active' AND role = 'admin' AND id <> $2`
	var n int
	if err := q.QueryRow(ctx, sql, tenantID, excludeID).Scan(&n); err != nil {
		return 0, fmt.Errorf("user: count active admins: %w", err)
	}
	return n, nil
}
