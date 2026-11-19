package delivery

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"phishforge/internal/sendingprofile"
)

// channelSender delivers one rendered HTML message over a specific transport.
type channelSender interface {
	Send(ctx context.Context, to, subject, htmlBody string) error
}

// GraphConfig holds process-wide defaults for the Microsoft Graph channel. A
// profile may override tenant/client/secret; empty values fall back to these.
type GraphConfig struct {
	LoginBaseURL string // e.g. https://login.microsoftonline.com
	GraphBaseURL string // e.g. https://graph.microsoft.com
	TenantID     string
	ClientID     string
	ClientSecret string
}

// UseGraph sets the Graph channel configuration on the sender.
func (s *Sender) UseGraph(cfg GraphConfig) { s.graph = cfg }

// smtpSender adapts the existing SMTP path to the channelSender interface.
type smtpSender struct {
	profile  sendingprofile.Profile
	password string
}

func (s *smtpSender) Send(_ context.Context, to, subject, htmlBody string) error {
	return sendMail(s.profile, s.password, to, subject, htmlBody)
}

// resolveSender builds the transport for a profile, decrypting its secret once.
func (s *Sender) resolveSender(tenantID uuid.UUID, p sendingprofile.Profile) (channelSender, error) {
	secret := ""
	if p.PassEncrypted != nil && *p.PassEncrypted != "" {
		pt, err := s.cipher.Decrypt(tenantID, *p.PassEncrypted)
		if err != nil {
			return nil, fmt.Errorf("delivery: decrypt profile secret: %w", err)
		}
		secret = string(pt)
	}

	channel := p.Channel
	if channel == "" {
		channel = "smtp"
	}
	switch channel {
	case "smtp":
		return &smtpSender{profile: p, password: secret}, nil
	case "graph":
		return newGraphSender(p, s.graph, secret), nil
	case "gmail":
		return &gmailSender{}, nil
	default:
		return nil, fmt.Errorf("delivery: unknown channel %q", channel)
	}
}

func orElse(ptr *string, fallback string) string {
	if ptr != nil && *ptr != "" {
		return *ptr
	}
	return fallback
}
