// Package config loads runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config holds process-wide settings resolved at startup.
type Config struct {
	APIAddr        string
	DatabaseURL    string
	RedisAddr      string
	BaseURL        string
	ArtifactEncKey string
	SendConcurrency int
	Env            string
}

// Load reads configuration from environment variables, applying defaults.
// It returns an error when a required value is missing.
func Load() (Config, error) {
	c := Config{
		APIAddr:         getenv("API_ADDR", ":8080"),
		DatabaseURL:     os.Getenv("DATABASE_URL"),
		RedisAddr:       getenv("REDIS_ADDR", "localhost:6379"),
		BaseURL:         getenv("BASE_URL", "http://localhost:8080"),
		ArtifactEncKey:  os.Getenv("ARTIFACT_ENC_KEY"),
		SendConcurrency: getenvInt("SEND_CONCURRENCY", 10),
		Env:             getenv("APP_ENV", "dev"),
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

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
