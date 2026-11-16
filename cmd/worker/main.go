// Command worker runs background jobs for PhishForge.
//
// M1 scope: the worker loads config, holds the database pool, and shuts down
// cleanly on signal. The Asynq/Redis consumer is wired in M3+.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"phishforge/internal/config"
	"phishforge/internal/db"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	cfg, err := config.Load()
	if err != nil {
		logger.Error("config load failed", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.NewPool(ctx, cfg.DatabaseURL)
	if err != nil {
		logger.Error("database connect failed", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	logger.Info("worker started", "redis", cfg.RedisAddr, "env", cfg.Env)

	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("worker shutdown complete")
			return
		case <-ticker.C:
			logger.Debug("worker heartbeat")
		}
	}
}
