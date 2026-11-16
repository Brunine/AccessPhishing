// Package config loads runtime configuration from the environment.
package config

import (
	"fmt"
	"os"
)

// Config holds process-wide settings resolved at startup.
type Config struct {
	APIAddr     string
	DatabaseURL string
	RedisAddr   string
	Env         string
}

// Load reads configuration from environment variables, applying defaults.
// It returns an error when a required value is missing.
func Load() (Config, error) {
	c := Config{
		APIAddr:     getenv("API_ADDR", ":8080"),
		DatabaseURL: os.Getenv("DATABASE_URL"),
		RedisAddr:   getenv("REDIS_ADDR", "localhost:6379"),
		Env:         getenv("APP_ENV", "dev"),
	}
	if c.DatabaseURL == "" {
		return Config{}, fmt.Errorf("config: DATABASE_URL is required")
	}
	return c, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
