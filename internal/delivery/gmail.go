package delivery

import (
	"context"
	"errors"
)

// ErrGmailNotImplemented is returned by the Gmail channel until it is wired in
// M3 part 2 (OAuth2 + POST /gmail/v1/users/{userId}/messages/send).
var ErrGmailNotImplemented = errors.New("delivery: gmail channel not implemented yet (M3 part 2)")

// gmailSender is a placeholder satisfying channelSender. It fails every send
// with a clear error, so a gmail-channel campaign records 'failed' events
// rather than silently doing nothing.
type gmailSender struct{}

func (g *gmailSender) Send(_ context.Context, _, _, _ string) error {
	return ErrGmailNotImplemented
}
