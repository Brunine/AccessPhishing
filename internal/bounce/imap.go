package bounce

import (
	"context"
	"fmt"
	"net"
	"strconv"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/google/uuid"

	"phishforge/internal/db"
)

// IMAPConfig configures the bounce mailbox poller. When Host is empty the
// poller is disabled and the worker runs SMTP-only.
type IMAPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	Mailbox  string // default "INBOX"
	UseTLS   bool
}

// Enabled reports whether an IMAP bounce mailbox is configured.
func (c IMAPConfig) Enabled() bool { return c.Host != "" }

func (c IMAPConfig) addr() string {
	port := c.Port
	if port == 0 {
		if c.UseTLS {
			port = 993
		} else {
			port = 143
		}
	}
	return net.JoinHostPort(c.Host, strconv.Itoa(port))
}

func (c IMAPConfig) mailbox() string {
	if c.Mailbox == "" {
		return "INBOX"
	}
	return c.Mailbox
}

// Poller fetches NDRs from a shared IMAP mailbox into ndr_messages and
// processes them. It discovers the owning tenant of each bounce from the failed
// recipient's campaign membership, so one mailbox can serve many tenants.
type Poller struct {
	cfg  IMAPConfig
	pool db.Querier
	repo *Repository
}

// NewPoller builds a poller.
func NewPoller(cfg IMAPConfig, pool db.Querier, repo *Repository) *Poller {
	return &Poller{cfg: cfg, pool: pool, repo: repo}
}

// ingestRaw parses, attributes, enqueues, and processes a batch of raw NDR
// messages. It returns the count successfully enqueued and the set of tenants
// touched. It is the IMAP-independent core (directly testable).
func (p *Poller) ingestRaw(ctx context.Context, raws []string) (enqueued int, tenants map[uuid.UUID]struct{}, err error) {
	tenants = map[uuid.UUID]struct{}{}
	for _, raw := range raws {
		email, msgID, ok := ParseNDR(raw)
		if !ok {
			continue
		}
		tenantID, campaignID, found, err := resolveTenantByEmail(ctx, p.pool, email)
		if err != nil {
			return enqueued, tenants, err
		}
		if !found {
			continue // bounce for an address we never sent to; leave it alone
		}
		var campArg *uuid.UUID
		if campaignID != uuid.Nil {
			c := campaignID
			campArg = &c
		}
		if _, err := p.repo.Enqueue(ctx, p.pool, tenantID, NDRMessage{
			MessageID: msgID, RecipientEmail: email, CampaignID: campArg, Raw: raw,
		}); err != nil {
			return enqueued, tenants, err
		}
		enqueued++
		tenants[tenantID] = struct{}{}
	}
	return enqueued, tenants, nil
}

// IngestRaw parses, attributes, enqueues, and processes a batch of raw NDR
// messages without any IMAP (no-op transport). It returns the number enqueued.
// It is the transport-independent entry point — used by the IMAP poller, a
// future Graph inbox webhook, and tests.
func (p *Poller) IngestRaw(ctx context.Context, raws []string) (int, error) {
	n, tenants, err := p.ingestRaw(ctx, raws)
	if err != nil {
		return n, err
	}
	if err := p.processTenants(ctx, tenants); err != nil {
		return n, err
	}
	return n, nil
}

// processTenants runs Process for every tenant touched by an ingest.
func (p *Poller) processTenants(ctx context.Context, tenants map[uuid.UUID]struct{}) error {
	for t := range tenants {
		if _, _, err := p.repo.Process(ctx, p.pool, t, 200); err != nil {
			return err
		}
	}
	return nil
}

// PollOnce connects to the mailbox, fetches unseen messages, enqueues each
// parseable + attributable NDR (marking a message \Seen only after a successful
// enqueue), then processes the affected tenants. It is a no-op when disabled.
func (p *Poller) PollOnce(ctx context.Context) (fetched, enqueued int, err error) {
	if !p.cfg.Enabled() {
		return 0, 0, nil
	}

	var c *imapclient.Client
	if p.cfg.UseTLS {
		c, err = imapclient.DialTLS(p.cfg.addr(), nil)
	} else {
		c, err = imapclient.DialInsecure(p.cfg.addr(), nil)
	}
	if err != nil {
		return 0, 0, fmt.Errorf("bounce: imap dial: %w", err)
	}
	defer c.Close()

	if err := c.Login(p.cfg.Username, p.cfg.Password).Wait(); err != nil {
		return 0, 0, fmt.Errorf("bounce: imap login: %w", err)
	}
	if _, err := c.Select(p.cfg.mailbox(), nil).Wait(); err != nil {
		return 0, 0, fmt.Errorf("bounce: imap select: %w", err)
	}

	searchData, err := c.Search(&imap.SearchCriteria{
		NotFlag: []imap.Flag{imap.FlagSeen},
	}, nil).Wait()
	if err != nil {
		return 0, 0, fmt.Errorf("bounce: imap search: %w", err)
	}
	seqNums := searchData.AllSeqNums()
	if len(seqNums) == 0 {
		return 0, 0, nil
	}

	tenants := map[uuid.UUID]struct{}{}
	section := &imap.FetchItemBodySection{}
	for _, seq := range seqNums {
		set := imap.SeqSetNum(seq)
		msgs, ferr := c.Fetch(set, &imap.FetchOptions{
			BodySection: []*imap.FetchItemBodySection{section},
		}).Collect()
		if ferr != nil {
			return fetched, enqueued, fmt.Errorf("bounce: imap fetch: %w", ferr)
		}
		for _, msg := range msgs {
			fetched++
			raw := msg.FindBodySection(section)
			if len(raw) == 0 {
				continue
			}
			n, touched, ierr := p.ingestRaw(ctx, []string{string(raw)})
			if ierr != nil {
				return fetched, enqueued, ierr
			}
			if n == 0 {
				continue // not enqueued -> leave unseen per spec
			}
			enqueued += n
			for t := range touched {
				tenants[t] = struct{}{}
			}
			// Mark \Seen only after a successful enqueue. STORE returns a fetch
			// command; Close() runs it and discards the returned flag data.
			if err := c.Store(set, &imap.StoreFlags{
				Op:    imap.StoreFlagsAdd,
				Flags: []imap.Flag{imap.FlagSeen},
			}, nil).Close(); err != nil {
				return fetched, enqueued, fmt.Errorf("bounce: imap store seen: %w", err)
			}
		}
	}

	if err := p.processTenants(ctx, tenants); err != nil {
		return fetched, enqueued, err
	}
	return fetched, enqueued, nil
}

// resolveTenantByEmail finds the tenant (and most recent campaign) that targeted
// an email, across all tenants — the bounce mailbox is shared.
func resolveTenantByEmail(ctx context.Context, q db.Querier, email string) (tenantID, campaignID uuid.UUID, found bool, err error) {
	err = q.QueryRow(ctx, `
SELECT r.tenant_id, r.campaign_id
FROM recipients r
JOIN contacts c ON c.id = r.contact_id
WHERE lower(c.email) = lower($1)
ORDER BY r.created_at DESC
LIMIT 1`, email).Scan(&tenantID, &campaignID)
	if err != nil {
		if isNoRows(err) {
			return uuid.Nil, uuid.Nil, false, nil
		}
		return uuid.Nil, uuid.Nil, false, fmt.Errorf("bounce: resolve tenant: %w", err)
	}
	return tenantID, campaignID, true, nil
}
