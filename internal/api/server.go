// Package api wires the chi router, middleware, and HTTP handlers.
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/httpx"
)

// Server holds dependencies shared by HTTP handlers.
type Server struct {
	pool *pgxpool.Pool
}

// NewServer constructs an API server over the given pool.
func NewServer(pool *pgxpool.Pool) *Server { return &Server{pool: pool} }

// Router builds the root http.Handler with base middleware and routes.
func (s *Server) Router() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	r.Route("/api/v1", func(r chi.Router) {
		r.Get("/health", s.health)
	})

	return r
}

// health reports liveness and database connectivity.
func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	status, db, code := "ok", "ok", http.StatusOK
	if err := s.pool.Ping(ctx); err != nil {
		status, db, code = "degraded", "down", http.StatusServiceUnavailable
	}

	httpx.JSON(w, code, map[string]any{
		"status": status,
		"db":     db,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}
