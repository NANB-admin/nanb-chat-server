package moderation

import (
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

// Report is a stored user-abuse report — one moderation-queue row. The reporter
// is always identified (authenticated); the reported user and any forwarded
// evidence come from the report body. Reports are reviewed out-of-band; there is
// no in-app admin surface.
type Report struct {
	ID                string
	ReporterAccountID string
	ReporterDeviceID  string
	ReportedAccountID string
	ReportedUsername  string
	ConversationID    string
	Reason            string
	Note              string
	Messages          []proto.ReportedMessage
	CreatedAt         time.Time
}
