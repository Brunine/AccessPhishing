// Command worker runs the Asynq background consumer for PhishForge.
// It processes "campaign:send" tasks by delivering the campaign over SMTP.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/hibiken/asynq"

	"phishforge/internal/bounce"
	"phishforge/internal/config"
	"phishforge/internal/crypto"
	"phishforge/internal/db"
	"phishforge/internal/delivery"
	"phishforge/internal/events"
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

	bounces := bounce.NewRepository(events.NewRepository(pool))

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

	// The IMAP bounce-mailbox transport is deferred to M3 part 2; only note it.
	imapCfg := bounce.IMAPConfig{Host: cfg.IMAPHost, Port: cfg.IMAPPort, Username: cfg.IMAPUsername,
		Password: cfg.IMAPPassword, Mailbox: cfg.IMAPMailbox, UseTLS: cfg.IMAPUseTLS}
	if imapCfg.Enabled() {
		logger.Warn("IMAP bounce mailbox configured but poller not yet wired (M3 part 2)",
			"host", imapCfg.Host, "err", bounce.ErrIMAPNotWired.Error())
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
