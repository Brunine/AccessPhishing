// Command api is the PhishForge orchestrator HTTP service.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"phishforge/internal/api"
	"phishforge/internal/config"
	"phishforge/internal/crypto"
	"phishforge/internal/db"
	"phishforge/internal/llm"
	"phishforge/internal/tasks"
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

	var cipher *crypto.Cipher
	if cfg.ArtifactEncKey != "" {
		cipher, err = crypto.New(cfg.ArtifactEncKey)
		if err != nil {
			logger.Error("invalid ARTIFACT_ENC_KEY", "err", err)
			os.Exit(1)
		}
	} else {
		logger.Warn("ARTIFACT_ENC_KEY not set; sending-profile endpoints disabled")
	}

	enqueuer := tasks.NewClient(cfg.RedisAddr)
	defer enqueuer.Close()

	// Build the LLM client only when configured; keep the Deps field an untyped
	// nil interface when disabled so handlers see s.llm == nil (no typed-nil).
	var llmClient api.LLMClient
	if c := llm.New(cfg.LLMBaseURL, cfg.LLMModel, cfg.LLMTimeout); c != nil {
		llmClient = c
		logger.Info("llm enabled", "base", cfg.LLMBaseURL, "model", cfg.LLMModel)
	} else {
		logger.Warn("LLM_BASE_URL not set; /llm/generate disabled")
	}

	srv := &http.Server{
		Addr: cfg.APIAddr,
		Handler: api.NewServer(api.Deps{
			Pool:     pool,
			BaseURL:  cfg.BaseURL,
			Cipher:   cipher,
			Enqueuer: enqueuer,
			LLM:      llmClient,
		}).Router(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		logger.Info("api listening", "addr", cfg.APIAddr, "env", cfg.Env)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server error", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	logger.Info("shutdown signal received")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "err", err)
		os.Exit(1)
	}
	logger.Info("shutdown complete")
}
