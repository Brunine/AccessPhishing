// Command seed provisions local dev data: a tenant, a user, and an API key,
// printing the plaintext key token once. Dev/local use only — it talks to
// DATABASE_URL directly and mints a usable credential.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"

	"phishforge/internal/apikey"
	"phishforge/internal/config"
	"phishforge/internal/db"
)

func main() {
	tenantName := flag.String("tenant", "Dev Tenant", "tenant name")
	tenantSlug := flag.String("slug", "dev", "tenant slug (unique)")
	email := flag.String("email", "admin@dev.local", "user email")
	role := flag.String("role", "admin", "user role: admin|operator|viewer")
	keyName := flag.String("key-name", "seed-key", "API key name")
	flag.Parse()

	if !validRole(*role) {
		fmt.Fprintf(os.Stderr, "seed: invalid role %q (want admin|operator|viewer)\n", *role)
		os.Exit(2)
	}

	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}

	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		fatal(err)
	}
	defer pool.Close()

	tenantID, err := upsertTenant(ctx, pool, *tenantName, *tenantSlug)
	if err != nil {
		fatal(err)
	}
	userID, err := upsertUser(ctx, pool, tenantID, *email, *role)
	if err != nil {
		fatal(err)
	}

	token, key, err := apikey.NewService(pool).Create(ctx, tenantID, userID, *keyName)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("tenant   %s  (%s)\n", tenantID, *tenantSlug)
	fmt.Printf("user     %s  (%s, %s)\n", userID, *email, *role)
	fmt.Printf("key      %s  (%s)\n\n", key.ID, key.Name)
	fmt.Println("API key (shown once — store it now):")
	fmt.Println("  " + token)
	fmt.Printf("\nTry: curl -s -H \"X-API-Key: %s\" http://localhost:8080/api/v1/campaigns\n", token)
}

func upsertTenant(ctx context.Context, pool db.Querier, name, slug string) (uuid.UUID, error) {
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenants (name, slug) VALUES ($1, $2) ON CONFLICT (slug) DO NOTHING`,
		name, slug); err != nil {
		return uuid.Nil, fmt.Errorf("seed: upsert tenant: %w", err)
	}
	var id uuid.UUID
	if err := pool.QueryRow(ctx, `SELECT id FROM tenants WHERE slug = $1`, slug).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("seed: load tenant: %w", err)
	}
	return id, nil
}

func upsertUser(ctx context.Context, pool db.Querier, tenantID uuid.UUID, email, role string) (uuid.UUID, error) {
	if _, err := pool.Exec(ctx,
		`INSERT INTO users (tenant_id, email, role) VALUES ($1, $2, $3::user_role)
		 ON CONFLICT (tenant_id, lower(email)) DO NOTHING`,
		tenantID, email, role); err != nil {
		return uuid.Nil, fmt.Errorf("seed: upsert user: %w", err)
	}
	var id uuid.UUID
	if err := pool.QueryRow(ctx,
		`SELECT id FROM users WHERE tenant_id = $1 AND lower(email) = lower($2)`,
		tenantID, email).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("seed: load user: %w", err)
	}
	return id, nil
}

func validRole(r string) bool {
	return r == "admin" || r == "operator" || r == "viewer"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "seed:", err)
	os.Exit(1)
}
