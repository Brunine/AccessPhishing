package delivery

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"

	"phishforge/internal/sendingprofile"
)

// sendMail delivers one HTML message via the profile's SMTP server, honoring
// its TLS mode (none | starttls | smtps) and optional auth.
func sendMail(p sendingprofile.Profile, password, to, subject, body string) error {
	addr := net.JoinHostPort(p.SMTPHost, fmt.Sprintf("%d", p.SMTPPort))
	tlsCfg := &tls.Config{ServerName: p.SMTPHost, MinVersion: tls.VersionTLS12}

	var (
		client *smtp.Client
		err    error
	)
	switch p.TLSMode {
	case "smtps":
		conn, derr := tls.DialWithDialer(&net.Dialer{Timeout: 15 * time.Second}, "tcp", addr, tlsCfg)
		if derr != nil {
			return fmt.Errorf("smtp: tls dial: %w", derr)
		}
		client, err = smtp.NewClient(conn, p.SMTPHost)
	default:
		client, err = dialPlain(addr)
	}
	if err != nil {
		return fmt.Errorf("smtp: connect: %w", err)
	}
	defer client.Close()

	if p.TLSMode == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsCfg); err != nil {
				return fmt.Errorf("smtp: starttls: %w", err)
			}
		}
	}

	if p.SMTPUser != nil && *p.SMTPUser != "" {
		auth := smtp.PlainAuth("", *p.SMTPUser, password, p.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp: auth: %w", err)
		}
	}

	if err := client.Mail(p.FromAddress); err != nil {
		return fmt.Errorf("smtp: mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp: rcpt: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp: data: %w", err)
	}
	if _, err := wc.Write([]byte(buildMessage(p, to, subject, body))); err != nil {
		return fmt.Errorf("smtp: write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp: close data: %w", err)
	}
	return client.Quit()
}

func dialPlain(addr string) (*smtp.Client, error) {
	conn, err := net.DialTimeout("tcp", addr, 15*time.Second)
	if err != nil {
		return nil, err
	}
	host, _, _ := net.SplitHostPort(addr)
	return smtp.NewClient(conn, host)
}

func buildMessage(p sendingprofile.Profile, to, subject, body string) string {
	from := p.FromAddress
	if p.FromName != nil && *p.FromName != "" {
		from = fmt.Sprintf("%s <%s>", *p.FromName, p.FromAddress)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.String()
}
