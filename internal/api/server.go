// Package api wires the chi router, middleware, auth, and HTTP handlers.
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/apikey"
	"phishforge/internal/approval"
	"phishforge/internal/auth"
	"phishforge/internal/campaign"
	"phishforge/internal/contact"
	"phishforge/internal/crypto"
	"phishforge/internal/engagement"
	"phishforge/internal/engine"
	"phishforge/internal/enginerepo"
	"phishforge/internal/events"
	"phishforge/internal/group"
	"phishforge/internal/httpx"
	"phishforge/internal/llmdraft"
	"phishforge/internal/osintclient"
	"phishforge/internal/osintresult"
	"phishforge/internal/prompttpl"
	"phishforge/internal/recipient"
	"phishforge/internal/report"
	"phishforge/internal/sendingprofile"
	"phishforge/internal/suppression"
	tmpl "phishforge/internal/template"
	"phishforge/internal/tenant"
	"phishforge/internal/user"
)

// Enqueuer schedules background tasks (implemented by internal/tasks.Client).
type Enqueuer interface {
	EnqueueCampaignSend(ctx context.Context, tenantID, campaignID uuid.UUID) error
}

// LLMClient drafts message content. Implemented by internal/llm.Client; a nil
// value means the feature is disabled (generate returns 503). Output is treated
// as data (stored as a draft), never executed.
type LLMClient interface {
	Generate(ctx context.Context, prompt string) (string, error)
	Ping(ctx context.Context) error
	Model() string
}

// OSINTClient aggregates passive public info via the OSINT microservice. A nil
// value means the feature is disabled (osint endpoints return 503).
type OSINTClient interface {
	Health(ctx context.Context) error
	Collect(ctx context.Context, domain string) (osintclient.Result, error)
}

// Deps are the dependencies required to build a Server.
type Deps struct {
	Pool     *pgxpool.Pool
	BaseURL  string
	Cipher   *crypto.Cipher
	Enqueuer Enqueuer
	LLM      LLMClient
	Engines  *engine.Manager
	OSINT    OSINTClient
}

// Server holds dependencies shared by HTTP handlers.
type Server struct {
	pool         *pgxpool.Pool
	baseURL      string
	cipher       *crypto.Cipher
	enqueuer     Enqueuer
	llm          LLMClient
	drafts       *llmdraft.Repository
	prompttpls   *prompttpl.Repository
	tenants      *tenant.Repository
	campaigns    *campaign.Repository
	engagements  *engagement.Repository
	contacts     *contact.Repository
	groups       *group.Repository
	suppressions *suppression.Repository
	recipients   *recipient.Repository
	events       *events.Repository
	templates    *tmpl.Repository
	profiles     *sendingprofile.Repository
	approvals    *approval.Repository
	keys         *apikey.Service
	engines      *engine.Manager
	engineRepo   *enginerepo.Repository
	reports      *report.Repository
	osint        OSINTClient
	osintResults *osintresult.Repository
	users        *user.Repository
}

// NewServer constructs an API server from its dependencies.
func NewServer(d Deps) *Server {
	return &Server{
		pool:         d.Pool,
		baseURL:      d.BaseURL,
		cipher:       d.Cipher,
		enqueuer:     d.Enqueuer,
		llm:          d.LLM,
		drafts:       llmdraft.NewRepository(),
		prompttpls:   prompttpl.NewRepository(),
		tenants:      tenant.NewRepository(),
		campaigns:    campaign.NewRepository(),
		engagements:  engagement.NewRepository(),
		contacts:     contact.NewRepository(),
		groups:       group.NewRepository(),
		suppressions: suppression.NewRepository(),
		recipients:   recipient.NewRepository(),
		events:       events.NewRepository(d.Pool),
		templates:    tmpl.NewRepository(),
		profiles:     sendingprofile.NewRepository(),
		approvals:    approval.NewRepository(),
		keys:         apikey.NewService(d.Pool),
		engines:      d.Engines,
		engineRepo:   enginerepo.NewRepository(),
		reports:      report.NewRepository(),
		osint:        d.OSINT,
		osintResults: osintresult.NewRepository(),
		users:        user.NewRepository(),
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

			// Platform-level tenant administration (admin only), plus the M8
			// per-tenant report rollup (operator, own tenant only). Kept in one
			// route group so /tenants/{id}/summary is not shadowed by the mount;
			// roles are applied per-route, not to the whole group.
			r.Route("/tenants", func(r chi.Router) {
				r.With(auth.RequireRole(auth.RoleAdmin)).Post("/", s.createTenant)
				r.With(auth.RequireRole(auth.RoleAdmin)).Get("/", s.listTenants)
				r.With(auth.RequireRole(auth.RoleAdmin)).Get("/{id}", s.getTenant)
				r.With(auth.RequireRole(auth.RoleOperator)).Get("/{id}/summary", s.tenantSummary)
				r.With(auth.RequireRole(auth.RoleOperator)).Get("/{id}/summary.pdf", s.tenantSummaryPDF)
			})

			// Campaigns, scoped to the principal's tenant (operator or above).
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/campaigns", func(r chi.Router) {
				r.Post("/", s.createCampaign)
				r.Get("/", s.listCampaigns)
				r.Get("/{id}", s.getCampaign)
				r.Patch("/{id}", s.patchCampaign)
				r.Post("/{id}/launch", s.launchCampaign)
				r.Get("/{id}/links", s.campaignLinks)
				r.Get("/{id}/targets", s.campaignTargets)
				r.Post("/{id}/send", s.sendCampaign)
				r.Post("/{id}/engine", s.bindEngine)
				r.Get("/{id}/engine", s.getEngineForCampaign)
				// M8 reporting: read-only KPI aggregates (operator).
				r.Get("/{id}/report", s.campaignReport)
				r.Get("/{id}/report.csv", s.campaignReportCSV)
				r.Get("/{id}/report.pdf", s.campaignReportPDF)
			})

			// M8a engagements: the authorization container for campaigns. List/
			// create/get/patch + request-authorization are operator; authorize and
			// terminate require admin (self-authorization is impossible — the
			// operator cannot reach the authorize route). Roles are per-route so
			// the two admin actions coexist with the operator CRUD under one mount.
			r.Route("/engagements", func(r chi.Router) {
				r.With(auth.RequireRole(auth.RoleOperator)).Get("/", s.listEngagements)
				r.With(auth.RequireRole(auth.RoleOperator)).Post("/", s.createEngagement)
				r.With(auth.RequireRole(auth.RoleOperator)).Get("/{id}", s.getEngagement)
				r.With(auth.RequireRole(auth.RoleOperator)).Patch("/{id}", s.patchEngagement)
				r.With(auth.RequireRole(auth.RoleOperator)).Post("/{id}/request-authorization", s.requestEngagementAuthorization)
				r.With(auth.RequireRole(auth.RoleAdmin)).Post("/{id}/authorize", s.authorizeEngagement)
				r.With(auth.RequireRole(auth.RoleAdmin)).Post("/{id}/terminate", s.terminateEngagement)
			})

			// Dashboard activity feed: recent audit entries + events (operator).
			r.With(auth.RequireRole(auth.RoleOperator)).Get("/activity", s.activity)

			// M7 OSINT orchestration: passive public-info aggregation via the
			// OSINT microservice (operator). No scanning from the API side.
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/osint", func(r chi.Router) {
				r.Get("/status", s.osintStatus)
				r.Post("/collect", s.osintCollect)
				r.Get("/results", s.osintResultsList)
			})

			// M6 LLM: generate drafts, promote approved drafts to templates
			// (operator). Draft approval uses the existing /approvals flow with
			// subject_type 'llm_draft'; there is no new decision path here.
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/llm", func(r chi.Router) {
				r.Post("/generate", s.llmGenerate)
				r.Get("/drafts", s.listDrafts)
				r.Get("/drafts/{id}", s.getDraft)
				r.Post("/drafts/{id}/promote", s.promoteDraft)
				r.Post("/drafts/{id}/discard", s.discardDraft)
			})

			// M6 prompt-template library (operator). Templates feed
			// /llm/generate via an optional template_id; /{id}/render is a
			// no-LLM dry run.
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/prompt-templates", func(r chi.Router) {
				r.Post("/", s.createPromptTemplate)
				r.Get("/", s.listPromptTemplates)
				r.Get("/{id}", s.getPromptTemplate)
				r.Patch("/{id}", s.updatePromptTemplate)
				r.Delete("/{id}", s.deletePromptTemplate)
				r.Post("/{id}/render", s.renderPromptTemplate)
			})

			// Operator self-service API key management (tenant-scoped).
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/api-keys", func(r chi.Router) {
				r.Get("/", s.listAPIKeys)
				r.Post("/", s.createAPIKey)
				r.Post("/{id}/revoke", s.revokeAPIKey)
			})

			// Operator user management (tenant-scoped). List is operator;
			// create + deactivate require admin.
			r.Route("/users", func(r chi.Router) {
				r.With(auth.RequireRole(auth.RoleOperator)).Get("/", s.listUsers)
				r.With(auth.RequireRole(auth.RoleAdmin)).Post("/", s.createUser)
				r.With(auth.RequireRole(auth.RoleAdmin)).Post("/{id}/deactivate", s.deactivateUser)
			})

			// Platform-admin cross-tenant oversight (admin = platform-level in
			// this internal, self-hosted deployment; read-only KPI rollups).
			r.With(auth.RequireRole(auth.RoleAdmin)).Route("/platform", func(r chi.Router) {
				r.Get("/tenants", s.platformTenants)
				r.Get("/tenants/{id}/summary", s.platformTenantSummary)
				r.Get("/tenants/{id}/summary.pdf", s.platformTenantSummaryPDF)
			})

			// M3 delivery: templates, sending profiles, approvals (operator).
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/templates", func(r chi.Router) {
				r.Post("/", s.createTemplate)
				r.Get("/", s.listTemplates)
				r.Get("/{id}", s.getTemplate)
				r.Patch("/{id}", s.updateTemplate)
				r.Delete("/{id}", s.deleteTemplate)
			})
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/sending-profiles", func(r chi.Router) {
				r.Post("/", s.createSendingProfile)
				r.Get("/", s.listSendingProfiles)
				r.Get("/{id}", s.getSendingProfile)
				r.Delete("/{id}", s.deleteSendingProfile)
			})
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/approvals", func(r chi.Router) {
				r.Post("/", s.requestApproval)
				r.Get("/", s.listApprovals)
				// Decisions require admin.
				r.With(auth.RequireRole(auth.RoleAdmin)).Post("/{id}/approve", s.approveApproval)
				r.With(auth.RequireRole(auth.RoleAdmin)).Post("/{id}/reject", s.rejectApproval)
			})

			// M2 target management (operator or above, tenant-scoped).
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/contacts", func(r chi.Router) {
				r.Post("/", s.createContact)
				r.Get("/", s.listContacts)
				r.Post("/import", s.importContacts)
				r.Get("/{id}", s.getContact)
				r.Patch("/{id}", s.updateContact)
				r.Delete("/{id}", s.deleteContact)
			})
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/contact-groups", func(r chi.Router) {
				r.Post("/", s.createGroup)
				r.Get("/", s.listGroups)
				r.Get("/{id}", s.getGroup)
				r.Delete("/{id}", s.deleteGroup)
			})
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/suppressions", func(r chi.Router) {
				r.Post("/", s.addSuppression)
				r.Get("/", s.listSuppressions)
				r.Delete("/", s.deleteSuppression)
			})

			// M5 part 1: managed engine lifecycle (operator).
			r.With(auth.RequireRole(auth.RoleOperator)).Route("/engines", func(r chi.Router) {
				r.Post("/", s.createEngine)
				r.Get("/", s.listEngines)
				r.Get("/{id}", s.getEngine)
				r.Post("/{id}/start", s.startEngine)
				r.Post("/{id}/stop", s.stopEngine)
				r.Get("/{id}/logs", s.engineLogs)
				r.Delete("/{id}", s.deleteEngine)
			})
		})

		// Public engine ingest (per-run bearer token, capture-only). Separate
		// group from tracking: engines post in batches, so a larger budget.
		r.Group(func(r chi.Router) {
			r.Use(newRateLimiter(600, time.Minute).middleware)
			r.Post("/api/v1/engines/{id}/events", s.engineEvents)
		})

	})

	// Public tracking (token-authenticated via path; no auth middleware),
	// behind a per-IP rate limit. Separate group mounted at root.
	r.Group(func(r chi.Router) {
		r.Use(newRateLimiter(60, time.Minute).middleware)
		r.Get("/t/{token}", s.trackClick)
		r.Get("/px/{token}", s.trackOpen)
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
			KeyID:    id.KeyID,
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

	// LLM is an optional sub-check: an unreachable host does not fail health,
	// so the API keeps serving even when the model host is down.
	llmStatus := "disabled"
	if s.llm != nil {
		if err := s.llm.Ping(ctx); err != nil {
			llmStatus = "down"
		} else {
			llmStatus = "ok"
		}
	}

	httpx.JSON(w, code, map[string]any{
		"status": status,
		"db":     dbStatus,
		"llm":    llmStatus,
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}
