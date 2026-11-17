// Package llm is a minimal client for an Ollama-compatible HTTP API. It is used
// to draft message content for the approval pipeline; model output is always
// treated as data (stored as a draft), never executed or auto-sent.
package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxResponseBytes caps a single completion read, bounding memory use even if
// the model streams an unexpectedly large body.
const maxResponseBytes = 1 << 20 // 1 MiB

// Client talks to an Ollama host. It is safe for concurrent use.
type Client struct {
	http    *http.Client
	baseURL string
	model   string
	timeout time.Duration
}

// New builds a client for baseURL (e.g. http://192.168.2.164:11434) and model
// (e.g. llama3.1:8b). timeout bounds a single Generate call end-to-end. New
// returns nil when baseURL is empty so callers can treat the feature as
// disabled.
func New(baseURL, model string, timeout time.Duration) *Client {
	if strings.TrimSpace(baseURL) == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &Client{
		http:    &http.Client{Timeout: timeout},
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		timeout: timeout,
	}
}

// Model reports the configured model name (stored alongside generated drafts).
func (c *Client) Model() string { return c.model }

type generateRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
	Stream bool   `json:"stream"`
}

type generateResponse struct {
	Response string `json:"response"`
	Error    string `json:"error,omitempty"`
}

// Generate sends prompt to the model and returns the completion text. It uses
// stream:false and enforces the client timeout. Connection and non-2xx errors
// are returned (wrapped) rather than panicking, so the API stays up when the
// LLM host is unreachable.
func (c *Client) Generate(ctx context.Context, prompt string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	body, err := json.Marshal(generateRequest{Model: c.model, Prompt: prompt, Stream: false})
	if err != nil {
		return "", fmt.Errorf("llm: marshal request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("llm: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return "", fmt.Errorf("llm: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("llm: host returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var gr generateResponse
	if err := json.Unmarshal(raw, &gr); err != nil {
		return "", fmt.Errorf("llm: decode response: %w", err)
	}
	if gr.Error != "" {
		return "", fmt.Errorf("llm: model error: %s", gr.Error)
	}
	out := strings.TrimSpace(gr.Response)
	if out == "" {
		return "", fmt.Errorf("llm: empty completion")
	}
	return out, nil
}

// Ping checks reachability via GET /api/tags. It is used by the health check
// and never blocks the API from serving.
func (c *Client) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/api/tags", nil)
	if err != nil {
		return fmt.Errorf("llm: build ping: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("llm: ping failed: %w", err)
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("llm: ping status %d", resp.StatusCode)
	}
	return nil
}
