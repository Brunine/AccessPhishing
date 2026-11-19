// Package config loads runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds process-wide settings resolved at startup.
type Config struct {
	APIAddr           string
	DatabaseURL       string
	RedisAddr         string
	BaseURL           string
	ArtifactEncKey    string
	SendConcurrency   int
	LLMBaseURL        string
	LLMModel          string
	LLMTimeout        time.Duration
	Env               string
	EngineBinaryPath  string
	EngineMaxRestarts int
	EngineBackoff     time.Duration
	EngineDataDir     string

	// Microsoft Graph delivery channel (all optional; missing => SMTP-only).
	LoginBaseURL      string
	GraphBaseURL      string
	GraphTenantID     string
	GraphClientID     string
	GraphClientSecret string

	// Gmail API delivery channel (all optional). The per-profile encrypted
	// secret may supply the refresh token instead of GmailRefreshToken.
	GoogleTokenURL    string
	GmailBaseURL      string
	GmailClientID     string
	GmailClientSecret string
	GmailRefreshToken string

	// OSINT microservice (all optional; missing => /osint endpoints 503).
	OSINTBaseURL string
	OSINTAPIKey  string
	OSINTTimeout time.Duration

	// Bounce mailbox (IMAP). Optional; missing => no bounce polling.
	IMAPHost     string
	IMAPPort     int
	IMAPUsername string
	IMAPPassword string
	IMAPMailbox  string
	IMAPUseTLS   bool
}

// Load reads configuration from environment variables, applying defaults.
// It returns an error when a required value is missing.
func Load() (Config, error) {
	c := Config{
		APIAddr:           getenv("API_ADDR", ":8080"),
		DatabaseURL:       os.Getenv("DATABASE_URL"),
		RedisAddr:         getenv("REDIS_ADDR", "localhost:6379"),
		BaseURL:           getenv("BASE_URL", "http://localhost:8080"),
		ArtifactEncKey:    os.Getenv("ARTIFACT_ENC_KEY"),
		SendConcurrency:   getenvInt("SEND_CONCURRENCY", 10),
		LLMBaseURL:        os.Getenv("LLM_BASE_URL"),
		LLMModel:          getenv("LLM_MODEL", "llama3.1:8b"),
		LLMTimeout:        getenvDuration("LLM_TIMEOUT", 120*time.Second),
		Env:               getenv("APP_ENV", "dev"),
		EngineBinaryPath:  os.Getenv("ENGINE_BINARY_PATH"),
		EngineMaxRestarts: getenvInt("ENGINE_MAX_RESTARTS", 3),
		EngineBackoff:     getenvDuration("ENGINE_BACKOFF", 1*time.Second),
		EngineDataDir:     getenv("ENGINE_DATA_DIR", "data/engines"),

		LoginBaseURL:      getenv("LOGIN_BASE_URL", "https://login.microsoftonline.com"),
		GraphBaseURL:      getenv("GRAPH_BASE_URL", "https://graph.microsoft.com"),
		GraphTenantID:     os.Getenv("GRAPH_TENANT_ID"),
		GraphClientID:     os.Getenv("GRAPH_CLIENT_ID"),
		GraphClientSecret: os.Getenv("GRAPH_CLIENT_SECRET"),

		GoogleTokenURL:    getenv("GOOGLE_TOKEN_URL", "https://oauth2.googleapis.com/token"),
		GmailBaseURL:      getenv("GMAIL_BASE_URL", "https://gmail.googleapis.com"),
		GmailClientID:     os.Getenv("GMAIL_CLIENT_ID"),
		GmailClientSecret: os.Getenv("GMAIL_CLIENT_SECRET"),
		GmailRefreshToken: os.Getenv("GMAIL_REFRESH_TOKEN"),

		OSINTBaseURL: os.Getenv("OSINT_BASE_URL"),
		OSINTAPIKey:  os.Getenv("OSINT_API_KEY"),
		OSINTTimeout: getenvDuration("OSINT_TIMEOUT", 30*time.Second),

		IMAPHost:     os.Getenv("IMAP_HOST"),
		IMAPPort:     getenvInt("IMAP_PORT", 993),
		IMAPUsername: os.Getenv("IMAP_USERNAME"),
		IMAPPassword: os.Getenv("IMAP_PASSWORD"),
		IMAPMailbox:  getenv("IMAP_MAILBOX", "INBOX"),
		IMAPUseTLS:   getenv("IMAP_USE_TLS", "true") == "true",
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: DATABASE_URL is required")
	}
	return c, nil
}

func getenvInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// getenvDuration parses a duration from key. A bare integer is read as seconds
// (e.g. "120"); otherwise a Go duration string is accepted (e.g. "90s", "2m").
func getenvDuration(key string, def time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	if n, err := strconv.Atoi(v); err == nil {
		if n > 0 {
			return time.Duration(n) * time.Second
		}
		return def
	}
	if d, err := time.ParseDuration(v); err == nil && d > 0 {
		return d
	}
	return def
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
