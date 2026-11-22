package moderation

import (
	"context"
	"log"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/nanb/nanb-server/internal/proto"
)

// Clock and IDGen mirror the small seams the other services use, so main can
// pass the same realClock{} / uuidGen{}.
type Clock interface{ Now() time.Time }

type IDGen interface{ Next() string }

// Defensive caps on forwarded evidence so a client can't push an unbounded
// payload into the moderation queue. Excess is truncated, never rejected, so a
// report is never lost over a cosmetic limit.
const (
	maxEvidenceMessages = 50
	maxMessageBodyLen   = 4000
	maxNoteLen          = 2000
)

// allowedReasons is the canonical report-reason set. The client enum mirrors
// these wire values exactly.
var allowedReasons = map[string]bool{
	"spam":           true,
	"harassment":     true,
	"threats":        true,
	"sexual_content": true,
	"child_safety":   true,
	"impersonation":  true,
	"other":          true,
}

type ServiceDeps struct {
	Store    Store
	Notifier Notifier
	Clock    Clock
	IDGen    IDGen
}

type Service struct {
	store    Store
	notifier Notifier
	clock    Clock
	idgen    IDGen
}

func NewService(d ServiceDeps) *Service {
	n := d.Notifier
	if n == nil {
		n = NoopNotifier{}
	}
	return &Service{store: d.Store, notifier: n, clock: d.Clock, idgen: d.IDGen}
}

// CreateReport validates and persists a report, then fires the best-effort
// notifier. reporterAccountID/reporterDeviceID come from the authenticated JWT.
func (s *Service) CreateReport(ctx context.Context, reporterAccountID, reporterDeviceID string, req proto.ReportRequest) (proto.ReportResponse, error) {
	reason := strings.TrimSpace(req.Reason)
	if !allowedReasons[reason] {
		return proto.ReportResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid report reason"}
	}
	reportedID := strings.TrimSpace(req.ReportedAccountID)
	if _, err := uuid.Parse(reportedID); err != nil {
		return proto.ReportResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "invalid reported account id"}
	}
	if reportedID == reporterAccountID {
		return proto.ReportResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "cannot report yourself"}
	}

	report := Report{
		ID:                s.idgen.Next(),
		ReporterAccountID: reporterAccountID,
		ReporterDeviceID:  reporterDeviceID,
		ReportedAccountID: reportedID,
		ReportedUsername:  strings.TrimSpace(req.ReportedUsername),
		ConversationID:    req.ConversationID,
		Reason:            reason,
		Note:              truncate(req.Note, maxNoteLen),
		Messages:          sanitizeMessages(req.Messages),
		CreatedAt:         s.clock.Now(),
	}

	if err := s.store.InsertReport(ctx, report); err != nil {
		log.Printf("moderation: insert report failed: %v", err)
		return proto.ReportResponse{}, proto.APIError{Code: proto.ErrCodeInternal, Message: "internal"}
	}

	// Best-effort: the report is already durable; a failed notification must not
	// fail the request (the report still sits in the moderation queue).
	if err := s.notifier.NotifyNewReport(ctx, report); err != nil {
		log.Printf("moderation: report %s stored but notify failed: %v", report.ID, err)
	}

	return proto.ReportResponse{OK: true, ReportID: report.ID}, nil
}

// sanitizeMessages keeps only the most recent maxEvidenceMessages and truncates
// each body, so a misbehaving client can't bloat the queue.
func sanitizeMessages(in []proto.ReportedMessage) []proto.ReportedMessage {
	if len(in) > maxEvidenceMessages {
		in = in[len(in)-maxEvidenceMessages:]
	}
	out := make([]proto.ReportedMessage, 0, len(in))
	for _, m := range in {
		m.Body = truncate(m.Body, maxMessageBodyLen)
		out = append(out, m)
	}
	return out
}

// truncate caps a string to max runes (not bytes), so the result is always
// valid UTF-8 — required because evidence is stored in a JSONB column.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max])
}
