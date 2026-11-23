// Command worker runs the Asynq background consumer for PhishForge.
// It processes "campaign:send" tasks by delivering the campaign over SMTP.
package main

import (
	"context"
	"log/slog"
	"os"
	"time"

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
