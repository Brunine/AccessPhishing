// Command engineproxy is the traffic-handling engine binary. The orchestrator
// supervises it as a child process and passes the materialized config path
// via -config. Event reporting is enabled only when ORCHESTRATOR_CALLBACK_URL
// is set in the environment (injected by the orchestrator at spawn time).
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"phishforge/internal/engineconfig"
	"phishforge/internal/engineproxy"
)

func main() {
	configPath := flag.String("config", "", "path to the materialized engine config YAML")
	flag.Parse()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	if *configPath == "" {
		logger.Error("-config is required")
		os.Exit(2)
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		logger.Error("read config", "err", err)
		os.Exit(1)
	}
	cfg, err := engineconfig.Parse(raw)
	if err != nil {
		logger.Error("invalid config", "err", err)
		os.Exit(1)
	}

	// Event reporting: enabled when the orchestrator injected a callback URL.
	// The interceptor is nil when the config has no capture section, so a
	// plain reverse-proxy deployment does zero interception.
	reporter := engineproxy.NewReporter(
		os.Getenv("ORCHESTRATOR_CALLBACK_URL"),
		os.Getenv("ENGINE_CALLBACK_TOKEN"),
		1024,
	)
	interceptor := engineproxy.NewInterceptor(cfg, os.Getenv("ENGINE_ID"), reporter)

	srv, err := engineproxy.New(cfg, logger, interceptor)
	if err != nil {
		logger.Error("build proxy", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if reporter != nil {
		go reporter.Run(ctx)
	}

	if err := srv.Start(ctx); err != nil {
		logger.Error("proxy exited with error", "err", err)
		os.Exit(1)
	}
	logger.Info("engineproxy stopped cleanly")
}