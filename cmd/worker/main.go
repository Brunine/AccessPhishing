// Command worker runs the Asynq background consumer for PhishForge.
// It processes "campaign:send" tasks by delivering the campaign over SMTP.
package main

import (
	"context"
	"log/slog"
	"os"

	"github.com/hibiken/asynq"

	"phishforge/internal/config"
	"phishforge/internal/crypto"
	"phishforge/internal/db"
	"phishforge/internal/delivery"
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
