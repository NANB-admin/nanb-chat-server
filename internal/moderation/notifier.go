package moderation

import "context"

// Notifier delivers an out-of-band alert when a new report lands (e.g. an email
// to the operator). It is best-effort: the report is already persisted before
// the notifier runs, and notifier errors never fail the request.
type Notifier interface {
	NotifyNewReport(ctx context.Context, r Report) error
}

// NoopNotifier is the default when no notification channel is configured. The
// report is still stored in the moderation queue for out-of-band review.
type NoopNotifier struct{}

func (NoopNotifier) NotifyNewReport(context.Context, Report) error { return nil }
