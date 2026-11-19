// Package tasks defines the Asynq task types shared by the API (enqueue) and
// the worker (process), plus a Redis-backed enqueuer client.
package tasks

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
	"github.com/hibiken/asynq"
)

// TypeCampaignSend is the Asynq task type for delivering a campaign.
const TypeCampaignSend = "campaign:send"

// TypeBounceIngest is the Asynq task type for processing pending NDRs for a
// tenant. (Enqueued by the bounce poller once the IMAP transport is wired.)
const TypeBounceIngest = "bounce:ingest"

// CampaignSendPayload is the JSON payload for a campaign send task.
type CampaignSendPayload struct {
	TenantID   uuid.UUID `json:"tenant_id"`
	CampaignID uuid.UUID `json:"campaign_id"`
}

// NewCampaignSendTask builds the Asynq task for a campaign send.
func NewCampaignSendTask(tenantID, campaignID uuid.UUID) (*asynq.Task, error) {
	b, err := json.Marshal(CampaignSendPayload{TenantID: tenantID, CampaignID: campaignID})
	if err != nil {
		return nil, fmt.Errorf("tasks: marshal payload: %w", err)
	}
	return asynq.NewTask(TypeCampaignSend, b), nil
}

// ParseCampaignSend decodes a campaign send task payload.
func ParseCampaignSend(t *asynq.Task) (CampaignSendPayload, error) {
	var p CampaignSendPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return CampaignSendPayload{}, fmt.Errorf("tasks: unmarshal payload: %w", err)
	}
	return p, nil
}

// BounceIngestPayload is the JSON payload for a bounce ingest task.
type BounceIngestPayload struct {
	TenantID uuid.UUID `json:"tenant_id"`
}

// NewBounceIngestTask builds the Asynq task for processing a tenant's NDRs.
func NewBounceIngestTask(tenantID uuid.UUID) (*asynq.Task, error) {
	b, err := json.Marshal(BounceIngestPayload{TenantID: tenantID})
	if err != nil {
		return nil, fmt.Errorf("tasks: marshal bounce payload: %w", err)
	}
	return asynq.NewTask(TypeBounceIngest, b), nil
}

// ParseBounceIngest decodes a bounce ingest task payload.
func ParseBounceIngest(t *asynq.Task) (BounceIngestPayload, error) {
	var p BounceIngestPayload
	if err := json.Unmarshal(t.Payload(), &p); err != nil {
		return BounceIngestPayload{}, fmt.Errorf("tasks: unmarshal bounce payload: %w", err)
	}
	return p, nil
}

// Client enqueues tasks to Redis. It satisfies the API's Enqueuer interface.
type Client struct {
	c *asynq.Client
}

// NewClient opens an Asynq client against the given Redis address.
func NewClient(redisAddr string) *Client {
	return &Client{c: asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})}
}

// EnqueueCampaignSend enqueues a campaign send task.
func (c *Client) EnqueueCampaignSend(ctx context.Context, tenantID, campaignID uuid.UUID) error {
	t, err := NewCampaignSendTask(tenantID, campaignID)
	if err != nil {
		return err
	}
	if _, err := c.c.EnqueueContext(ctx, t); err != nil {
		return fmt.Errorf("tasks: enqueue: %w", err)
	}
	return nil
}

// Close releases the underlying client.
func (c *Client) Close() error { return c.c.Close() }
