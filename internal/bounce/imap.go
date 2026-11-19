package bounce

import "errors"

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

// ErrIMAPNotWired marks the IMAP transport as deferred to M3 part 2. The NDR
// parsing and processing (ParseNDR, Enqueue, Process) are complete and tested;
// only the mailbox fetch that feeds ndr_messages is outstanding. A future
// implementation connects to the mailbox, fetches unseen NDRs, calls ParseNDR +
// Enqueue, then Process — or switches to a Graph inbox webhook.
var ErrIMAPNotWired = errors.New("bounce: IMAP poller not wired yet (M3 part 2); NDR parse/ingest/process are complete and usable via ndr_messages")

// PollOnce is the placeholder fetch step. It is intentionally not implemented:
// wiring a real IMAP client is deferred so this increment stays dependency-free
// and fully tested. Callers should check Enabled() and log ErrIMAPNotWired.
func PollOnce(_ IMAPConfig) error {
	return ErrIMAPNotWired
}
