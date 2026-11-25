// Command worker runs the Asynq background consumer for PhishForge.
// It processes "campaign:send" tasks by delivering the campaign over SMTP.
package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"

	"github.com/hibiken/asynq"

	"phishforge/internal/bounce"
	"phishforge/internal/candidate"
	"phishforge/internal/config"
	"phishforge/internal/crypto"
	"phishforge/internal/db"
	"phishforge/internal/delivery"
	"phishforge/internal/domain"
	"phishforge/internal/engagement"
	"phishforge/internal/enginehealth"
	"phishforge/internal/events"
	"phishforge/internal/llm"
	"phishforge/internal/osintclient"
	"phishforge/internal/registrar"
	"phishforge/internal/tasks"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	ctx := context.Background()
	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	if cfg.ArtifactEncKey == "" {
		logger.Error("ARTIFACT_ENC_KEY is required for the worker")
		os.Exit(1)
	}
	cipher, err := crypto.New(cfg.ArtifactEncKey)
	if err != nil {
		logger.Error("invalid ARTIFACT_ENC_KEY", "err", err)
		os.Exit(1)
	}

	sender := delivery.NewSender(pool, cipher, cfg.BaseURL, cfg.SendConcurrency)
	sender.UseGraph(delivery.GraphConfig{
		LoginBaseURL: cfg.LoginBaseURL,
		GraphBaseURL: cfg.GraphBaseURL,
		TenantID:     cfg.GraphTenantID,
		ClientID:     cfg.GraphClientID,
		ClientSecret: cfg.GraphClientSecret,
	})
	sender.UseGmail(delivery.GmailConfig{
		TokenURL:     cfg.GoogleTokenURL,
		BaseURL:      cfg.GmailBaseURL,
		ClientID:     cfg.GmailClientID,
		ClientSecret: cfg.GmailClientSecret,
		RefreshToken: cfg.GmailRefreshToken,
	})
	sender.UseSMS(delivery.SMSConfig{
		BaseURL: cfg.TwilioBaseURL,
		Timeout: cfg.TwilioTimeout,
	})

	bounces := bounce.NewRepository(events.NewRepository(pool))

	// M8d candidate discovery collector. OSINT is required (suggestions come
	// from it); registrar adapters price the candidates (Porkbun is always on,
	// Namecheap/Cloudflare are optional). An optional LLM namer may propose
	// extra candidate NAMES only — it never affects availability, price, or rank.
	osintClient := osintclient.New(cfg.OSINTBaseURL, cfg.OSINTAPIKey, cfg.OSINTTimeout)
	regSet := registrar.NewSet(
		registrar.NewPorkbun(cfg.PorkbunBaseURL, cfg.RegistrarTimeout),
		registrar.NewCloudflare(cfg.CloudflarePricingURL, cfg.RegistrarTimeout),
		registrar.NewNamecheap(registrar.NamecheapConfig{
			BaseURL: cfg.NamecheapBaseURL, APIUser: cfg.NamecheapAPIUser, APIKey: cfg.NamecheapAPIKey,
			Username: cfg.NamecheapUsername, ClientIP: cfg.NamecheapClientIP, Timeout: cfg.RegistrarTimeout,
		}),
	)
	var namer candidate.NameSuggester
	if cfg.CandidateLLMNaming {
		if lc := llm.New(cfg.LLMBaseURL, cfg.LLMModel, cfg.LLMTimeout); lc != nil {
			namer = candidate.NewLLMNamer(lc)
			logger.Info("candidate LLM naming enabled", "model", cfg.LLMModel)
		} else {
			logger.Warn("CANDIDATE_LLM_NAMING set but LLM_BASE_URL is empty; LLM naming disabled")
		}
	}
	var collector *candidate.Collector
	if osintClient != nil {
		collector = candidate.NewCollector(candidate.CollectorConfig{
			Pool: pool, OSINT: osintClient, Registrars: regSet, Names: namer,
			MaxCandidates: cfg.CandidateMaxCandidates, Logger: logger,
		})
		logger.Info("candidate discovery enabled", "registrars", regSet.Names())
	} else {
		logger.Warn("OSINT_BASE_URL not set; candidate:collect tasks will be dropped")
	}

	mux := asynq.NewServeMux()
	mux.HandleFunc(tasks.TypeCampaignSend, func(ctx context.Context, t *asynq.Task) error {
		p, err := tasks.ParseCampaignSend(t)
		if err != nil {
			return err
		}
		res, err := sender.SendCampaign(ctx, p.TenantID, p.CampaignID)
		if err != nil {
			logger.Error("campaign send failed", "campaign", p.CampaignID, "err", err)
			return err
		}
		logger.Info("campaign sent", "campaign", p.CampaignID, "sent", res.Sent, "failed", res.Failed)
		return nil
	})
	mux.HandleFunc(tasks.TypeBounceIngest, func(ctx context.Context, t *asynq.Task) error {
		p, err := tasks.ParseBounceIngest(t)
		if err != nil {
			return err
		}
		processed, skipped, err := bounces.Process(ctx, pool, p.TenantID, 200)
		if err != nil {
			logger.Error("bounce ingest failed", "tenant", p.TenantID, "err", err)
			return err
		}
		logger.Info("bounces ingested", "tenant", p.TenantID, "processed", processed, "skipped", skipped)
		return nil
	})
	mux.HandleFunc(tasks.TypeCandidateCollect, func(ctx context.Context, t *asynq.Task) error {
		p, err := tasks.ParseCandidateCollect(t)
		if err != nil {
			return err
		}
		if collector == nil {
			logger.Error("candidate collect task but collector disabled (no OSINT)", "engagement", p.EngagementID)
			return nil // drop: cannot process without OSINT; retrying will not help
		}
		res, err := collector.Collect(ctx, p.TenantID, p.EngagementID, p.RequestedBy)
		if err != nil {
			if isPermanentCollectErr(err) {
				logger.Warn("candidate collect skipped", "engagement", p.EngagementID, "reason", err)
				return nil // engagement no longer eligible; drop without retry
			}
			logger.Error("candidate collect failed", "engagement", p.EngagementID, "err", err)
			return err
		}
		logger.Info("candidate collect done", "engagement", p.EngagementID,
			"suggested", res.Suggested, "scored", res.Scored, "conflicts", res.Conflicts)
		return nil
	})

	// IMAP bounce poller: when configured, poll the mailbox on an interval,
	// fetching + ingesting NDRs. Disabled (no-op) when IMAP_HOST is unset.
	imapCfg := bounce.IMAPConfig{Host: cfg.IMAPHost, Port: cfg.IMAPPort, Username: cfg.IMAPUsername,
		Password: cfg.IMAPPassword, Mailbox: cfg.IMAPMailbox, UseTLS: cfg.IMAPUseTLS}
	if imapCfg.Enabled() {
		poller := bounce.NewPoller(imapCfg, pool, bounces)
		go func() {
			ticker := time.NewTicker(2 * time.Minute)
			defer ticker.Stop()
			for {
				fetched, enqueued, err := poller.PollOnce(ctx)
				if err != nil {
					logger.Error("bounce poll failed", "err", err)
				} else if fetched > 0 {
					logger.Info("bounce poll", "fetched", fetched, "enqueued", enqueued)
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
		logger.Info("IMAP bounce poller started", "host", imapCfg.Host, "mailbox", imapCfg.Mailbox)
	}

	// Engine health poller: records a durable heartbeat (last_poll_at) and a
	// best-effort status for every engine on a fixed cadence. Always on — it
	// is a no-op when the inventory is empty. Mirrors the IMAP poller's
	// goroutine-ticker pattern above.
	healthPoller := enginehealth.NewPoller(pool)
	go func() {
		ticker := time.NewTicker(cfg.EngineHealthPollInterval)
		defer ticker.Stop()
		for {
			n, err := healthPoller.PollOnce(ctx)
			if err != nil {
				logger.Error("engine health poll failed", "err", err)
			} else if n > 0 {
				logger.Info("engine health polled", "engines", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	logger.Info("engine health poller started", "interval", cfg.EngineHealthPollInterval)

	// Domain expiry roll: periodically roll domains whose registration has
	// lapsed (expires_at past) to 'expired', tenant-wide, with a per-row audit
	// entry. Mirrors the pollers' goroutine-ticker pattern; disableable via
	// DOMAIN_EXPIRY_ROLL_DISABLED.
	if cfg.DomainExpiryRollDisabled {
		logger.Info("domain expiry roll disabled")
	} else {
		roller := domain.NewRoller(pool)
		go func() {
			ticker := time.NewTicker(cfg.DomainExpiryRollInterval)
			defer ticker.Stop()
			for {
				n, err := roller.RollOnce(ctx)
				if err != nil {
					logger.Error("domain expiry roll failed", "err", err)
				} else if n > 0 {
					logger.Info("domain expiry roll", "expired", n)
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
		logger.Info("domain expiry roll started", "interval", cfg.DomainExpiryRollInterval)
	}

	srv := asynq.NewServer(
		asynq.RedisClientOpt{Addr: cfg.RedisAddr},
		asynq.Config{Concurrency: cfg.SendConcurrency},
	)

	logger.Info("worker starting", "redis", cfg.RedisAddr, "concurrency", cfg.SendConcurrency)
	if err := srv.Run(mux); err != nil {
		logger.Error("worker stopped", "err", err)
		os.Exit(1)
	}
}

// isPermanentCollectErr reports whether a candidate-collect error is permanent
// (the engagement is gone or no longer eligible), so the task should be dropped
// rather than retried. Transient DB/network errors are not permanent.
func isPermanentCollectErr(err error) bool {
	switch {
	case errors.Is(err, engagement.ErrNotFound),
		errors.Is(err, engagement.ErrEngagementNotAuthorized),
		errors.Is(err, engagement.ErrEngagementExpired),
		errors.Is(err, engagement.ErrEngagementTerminated),
		errors.Is(err, candidate.ErrNoScope):
		return true
	default:
		return false
	}
}
