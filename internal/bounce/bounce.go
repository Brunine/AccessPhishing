// Package bounce ingests non-delivery reports (NDRs) and records a 'bounced'
// event for the matched recipient. Ingestion is idempotent per (tenant,
// message_id): a duplicate NDR is never counted twice. The IMAP transport that
// fetches NDRs into ndr_messages is a separate, config-gated poller (see
// internal/bounce/imap.go); the parsing + processing here is independently
// testable by seeding ndr_messages rows.
package bounce

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"phishforge/internal/db"
	"phishforge/internal/events"
)

// NDRMessage is one fetched bounce notification.
type NDRMessage struct {
	MessageID      string
	RecipientEmail string
	CampaignID     *uuid.UUID // optional attribution hint
	Raw            string
}

var emailRe = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)

// finalRecipientRe matches RFC 3464 "Final-Recipient: rfc822; user@host".
var finalRecipientRe = regexp.MustCompile(`(?i)(?:Final|Original)-Recipient:\s*(?:rfc822;)?\s*([^\s<>]+@[^\s<>]+)`)

// ParseNDR extracts the failed recipient and a stable message id from a raw NDR
// (best-effort). It prefers the RFC 3464 Final/Original-Recipient field, then
// falls back to the first email in the body. The message id is the NDR's own
// Message-ID header (or a hash-like fallback derived from the body).
func ParseNDR(raw string) (recipientEmail, messageID string, ok bool) {
	// Headers (for Message-ID).
	if msg, err := mail.ReadMessage(strings.NewReader(raw)); err == nil {
		messageID = strings.Trim(strings.TrimSpace(msg.Header.Get("Message-ID")), "<>")
	}

	if m := finalRecipientRe.FindStringSubmatch(raw); len(m) == 2 {
		recipientEmail = strings.ToLower(strings.Trim(m[1], "<>"))
	} else if m := emailRe.FindString(raw); m != "" {
		recipientEmail = strings.ToLower(m)
	}

	if messageID == "" {
		// Deterministic fallback so dedupe still works without a Message-ID.
		messageID = "ndr:" + recipientEmail + ":" + fmt.Sprintf("%x", simpleHash(raw))
	}
	ok = recipientEmail != ""
	return recipientEmail, messageID, ok
}

func isNoRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }

func simpleHash(s string) uint64 {
	var h uint64 = 1469598103934665603
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return h
}

// Repository ingests and processes NDRs.
type Repository struct {
	events *events.Repository
}

// NewRepository returns a bounce repository backed by the events repository.
func NewRepository(ev *events.Repository) *Repository { return &Repository{events: ev} }

// Enqueue stores a fetched NDR, deduped per (tenant, message_id). It reports
// whether a new row was inserted (false = duplicate, already seen).
func (r *Repository) Enqueue(ctx context.Context, q db.Querier, tenantID uuid.UUID, m NDRMessage) (bool, error) {
	var campaignArg any
	if m.CampaignID != nil {
		campaignArg = *m.CampaignID
	}
	var id uuid.UUID
	err := q.QueryRow(ctx, `
INSERT INTO ndr_messages (tenant_id, message_id, recipient_email, campaign_id, raw)
VALUES ($1, $2, lower($3), $4, $5)
ON CONFLICT (tenant_id, message_id) DO NOTHING
RETURNING id`, tenantID, m.MessageID, m.RecipientEmail, campaignArg, m.Raw).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // duplicate
	}
	if err != nil {
		return false, fmt.Errorf("bounce: enqueue: %w", err)
	}
	return true, nil
}

// pendingRow is one ndr_messages row to process.
type pendingRow struct {
	id             uuid.UUID
	recipientEmail string
	campaignID     *uuid.UUID
}

// Process handles up to limit pending NDRs for a tenant: it resolves each to a
// recipient, appends a 'bounced' event (which advances campaign_targets), and
// marks the row processed (or skipped when no recipient matches). It returns
// the counts. Idempotency comes from the status transition (a row is only
// processed while 'pending') plus the unique (tenant, message_id) at ingest.
func (r *Repository) Process(ctx context.Context, pool db.Querier, tenantID uuid.UUID, limit int) (processed, skipped int, err error) {
	rows, err := pool.Query(ctx, `
SELECT id, recipient_email, campaign_id
FROM ndr_messages
WHERE tenant_id = $1 AND status = 'pending'
ORDER BY created_at
LIMIT $2`, tenantID, limit)
	if err != nil {
		return 0, 0, fmt.Errorf("bounce: list pending: %w", err)
	}
	var batch []pendingRow
	for rows.Next() {
		var pr pendingRow
		if err := rows.Scan(&pr.id, &pr.recipientEmail, &pr.campaignID); err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("bounce: scan pending: %w", err)
		}
		batch = append(batch, pr)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, 0, fmt.Errorf("bounce: iterate pending: %w", err)
	}

	for _, pr := range batch {
		campaignID, contactID, found, err := r.resolve(ctx, pool, tenantID, pr.recipientEmail, pr.campaignID)
		if err != nil {
			return processed, skipped, err
		}
		if !found {
			if _, err := pool.Exec(ctx, `UPDATE ndr_messages SET status='skipped', processed_at=now() WHERE id=$1`, pr.id); err != nil {
				return processed, skipped, fmt.Errorf("bounce: mark skipped: %w", err)
			}
			skipped++
			continue
		}
		// Append bounced (best-effort: an out-of-range transition is tolerated;
		// the NDR is still marked processed so it is not retried forever).
		_, _ = r.events.Append(ctx, events.NewEvent{
			TenantID: tenantID, CampaignID: campaignID, ContactID: contactID,
			Type: events.TypeBounced, Metadata: map[string]any{"email": pr.recipientEmail, "source": "ndr"},
		})
		if _, err := pool.Exec(ctx, `UPDATE ndr_messages SET status='processed', processed_at=now() WHERE id=$1`, pr.id); err != nil {
			return processed, skipped, fmt.Errorf("bounce: mark processed: %w", err)
		}
		processed++
	}
	return processed, skipped, nil
}

// resolve finds the recipient (campaign_id, contact_id) for an email, scoped to
// a campaign when provided, otherwise the most recent membership.
func (r *Repository) resolve(ctx context.Context, q db.Querier, tenantID uuid.UUID, email string, campaignID *uuid.UUID) (uuid.UUID, uuid.UUID, bool, error) {
	var campArg any
	if campaignID != nil {
		campArg = *campaignID
	}
	var camp, contact uuid.UUID
	err := q.QueryRow(ctx, `
SELECT r.campaign_id, r.contact_id
FROM recipients r
JOIN contacts c ON c.id = r.contact_id
WHERE r.tenant_id = $1 AND lower(c.email) = lower($2)
  AND ($3::uuid IS NULL OR r.campaign_id = $3::uuid)
ORDER BY r.created_at DESC
LIMIT 1`, tenantID, email, campArg).Scan(&camp, &contact)
	if errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, uuid.Nil, false, nil
	}
	if err != nil {
		return uuid.Nil, uuid.Nil, false, fmt.Errorf("bounce: resolve recipient: %w", err)
	}
	return camp, contact, true, nil
}
