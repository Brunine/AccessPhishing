// Package delivery renders approved templates per recipient and sends them over
// SMTP, recording a 'sent' or 'failed' event for each. It is invoked by the
// worker's "campaign:send" task handler and is directly testable.
package delivery

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"text/template"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"phishforge/internal/campaign"
	"phishforge/internal/crypto"
	"phishforge/internal/events"
	"phishforge/internal/sendingprofile"
	tmpl "phishforge/internal/template"
)

// Result summarizes a campaign send.
type Result struct {
	Sent   int
	Failed int
}

// Sender wires the dependencies needed to deliver a campaign.
type Sender struct {
	pool        *pgxpool.Pool
	cipher      *crypto.Cipher
	events      *events.Repository
	campaigns   *campaign.Repository
	templates   *tmpl.Repository
	profiles    *sendingprofile.Repository
	baseURL     string
	concurrency int
	graph       GraphConfig
	gmail       GmailConfig
	sms         SMSConfig
}

// NewSender constructs a Sender.
func NewSender(pool *pgxpool.Pool, cipher *crypto.Cipher, baseURL string, concurrency int) *Sender {
	if concurrency < 1 {
		concurrency = 1
	}
	return &Sender{
		pool:        pool,
		cipher:      cipher,
		events:      events.NewRepository(pool),
		campaigns:   campaign.NewRepository(),
		templates:   tmpl.NewRepository(),
		profiles:    sendingprofile.NewRepository(),
		baseURL:     baseURL,
		concurrency: concurrency,
	}
}

type target struct {
	recipientID uuid.UUID
	contactID   uuid.UUID
	token       string
	email       string
	phoneE164   *string
	firstName   *string
	lastName    *string
}

// SendCampaign renders and sends to every recipient of a scheduled campaign.
func (s *Sender) SendCampaign(ctx context.Context, tenantID, campaignID uuid.UUID) (Result, error) {
	camp, err := s.campaigns.GetByID(ctx, s.pool, tenantID, campaignID)
	if err != nil {
		return Result{}, fmt.Errorf("delivery: load campaign: %w", err)
	}
	if camp.TemplateID == nil {
		return Result{}, fmt.Errorf("delivery: campaign has no template")
	}
	if camp.SendingProfileID == nil {
		return Result{}, fmt.Errorf("delivery: campaign has no sending profile")
	}

	tpl, err := s.templates.GetByID(ctx, s.pool, tenantID, *camp.TemplateID)
	if err != nil {
		return Result{}, fmt.Errorf("delivery: load template: %w", err)
	}
	profile, err := s.profiles.GetByID(ctx, s.pool, tenantID, *camp.SendingProfileID)
	if err != nil {
		return Result{}, fmt.Errorf("delivery: load profile: %w", err)
	}

	chSender, err := s.resolveSender(tenantID, profile)
	if err != nil {
		return Result{}, err
	}

	isSMS := profile.Channel == "sms"

	// SMS renders the (plain-text) body only; email also renders a subject.
	var subjectTpl *template.Template
	if !isSMS {
		subjectTpl, err = template.New("subject").Option("missingkey=zero").Parse(deref(tpl.Subject))
		if err != nil {
			return Result{}, fmt.Errorf("delivery: parse subject template: %w", err)
		}
	}
	bodyTpl, err := template.New("body").Option("missingkey=zero").Parse(tpl.Body)
	if err != nil {
		return Result{}, fmt.Errorf("delivery: parse body template: %w", err)
	}

	targets, err := s.loadTargets(ctx, campaignID)
	if err != nil {
		return Result{}, err
	}

	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		res Result
		sem = make(chan struct{}, s.concurrency)
	)
	for _, t := range targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t target) {
			defer wg.Done()
			defer func() { <-sem }()

			data := map[string]any{
				"first_name": deref(t.firstName),
				"last_name":  deref(t.lastName),
				"email":      t.email,
				"link":       s.baseURL + "/t/" + t.token,
				"pixel":      s.baseURL + "/px/" + t.token,
				"token":      t.token,
			}
			var body strings.Builder
			evType := events.TypeSent
			meta := map[string]any{}

			if isSMS {
				phone := deref(t.phoneE164)
				meta["phone"] = phone
				if phone == "" {
					// Missing phone on an SMS recipient is a clean per-recipient
					// failure, not a crash.
					evType = events.TypeFailed
					meta["error"] = "recipient has no phone number"
				} else if err := bodyTpl.Execute(&body, data); err != nil {
					evType = events.TypeFailed
				} else if err := chSender.Send(ctx, phone, "", body.String()); err != nil {
					evType = events.TypeFailed
					meta["error"] = err.Error()
				}
			} else {
				meta["email"] = t.email
				var subj strings.Builder
				if err := subjectTpl.Execute(&subj, data); err != nil {
					evType = events.TypeFailed
				} else if err := bodyTpl.Execute(&body, data); err != nil {
					evType = events.TypeFailed
				} else if err := chSender.Send(ctx, t.email, subj.String(), body.String()); err != nil {
					evType = events.TypeFailed
				}
			}

			_, _ = s.events.Append(ctx, events.NewEvent{
				TenantID:   tenantID,
				CampaignID: campaignID,
				ContactID:  t.contactID,
				Type:       evType,
				Channel:    events.ChannelEmail,
				Metadata:   meta,
			})

			mu.Lock()
			if evType == events.TypeSent {
				res.Sent++
			} else {
				res.Failed++
			}
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	return res, nil
}

func (s *Sender) loadTargets(ctx context.Context, campaignID uuid.UUID) ([]target, error) {
	const sql = `SELECT r.id, r.contact_id, r.token, c.email, c.phone_e164, c.first_name, c.last_name
	             FROM recipients r JOIN contacts c ON c.id = r.contact_id
	             WHERE r.campaign_id = $1 ORDER BY r.created_at`
	rows, err := s.pool.Query(ctx, sql, campaignID)
	if err != nil {
		return nil, fmt.Errorf("delivery: load targets: %w", err)
	}
	defer rows.Close()
	var out []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.recipientID, &t.contactID, &t.token, &t.email, &t.phoneE164, &t.firstName, &t.lastName); err != nil {
			return nil, fmt.Errorf("delivery: scan target: %w", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("delivery: iterate targets: %w", err)
	}
	return out, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
