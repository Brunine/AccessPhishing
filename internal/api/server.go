// Package api wires the chi router, middleware, auth, and HTTP handlers.
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/apikey"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/httpx"
	"phishforge/internal/tenant"
)

// Server holds dependencies shared by HTTP handlers.
type Server struct {
	pool      *pgxpool.Pool
	tenants   *tenant.Repository
	campaigns *campaign.Repository
	keys      *apikey.Service
}

// NewServer constructs an API server over the given pool.
func NewServer(pool *pgxpool.Pool) *Server {
	return &Server{
		pool:      pool,
		tenants:   tenant.NewRepository(),
		campaigns: campaign.NewRepository(),
		keys:      apikey.NewService(pool),
	}
}

// Router builds the root http.Handler with base middleware and routes.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.health)

		// Authenticated area.
		r.Group(func(r chi.Router) {
			r.Use(auth.Authenticate(s.identifier()))

			// Platform-level: tenant administration (admin only).
			r.With(auth.RequireRole(auth.RoleAdmin)).Route("/tenants", func(r chi.Router) {
				r.Post("/", s.createTenant)
				r.Get("/", s.listTenants)
				r.Get("/{id}", s.getTenant)
			})

			// Campaigns, scoped to the principal's tenant (operator or above).
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/campaigns", func(r chi.Router) {
				r.Post("/", s.createCampaign)
				r.Get("/", s.listCampaigns)
				r.Get("/{id}", s.getCampaign)
				r.Patch("/{id}", s.patchCampaignStatus)
			})
		})
	})

	return r
}

// identifier resolves a principal from the X-API-Key header.
func (s *Server) identifier() auth.Identifier {
	return func(r *http.Request) (auth.Principal, error) {
		token := r.Header.Get("X-API-Key")
		if token == "" {
			return auth.Principal{}, errors.New("missing X-API-Key header")
		}
		id, err := s.keys.Verify(r.Context(), token)
		if err != nil {
			return auth.Principal{}, err
		}
		return auth.Principal{
			UserID:   id.UserID,
			TenantID: id.TenantID,
			Email:    id.Email,
			Role:     auth.Role(id.Role),
		}, nil
	}
}

// health reports liveness and database connectivity.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	status, dbStatus, code := "ok", "ok", http.StatusOK
	if err := s.pool.Ping(ctx); err != nil {
		status, dbStatus, code = "degraded", "down", http.StatusServiceUnavailable
	}

	httpx.JSON(w, code, map[string]any{
		"status": status,
		"db":     dbStatus,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}
