package moderation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

const (
	reporterID = "11111111-1111-1111-1111-111111111111"
	reportedID = "22222222-2222-2222-2222-222222222222"
)

type fakeStore struct {
	inserted []Report
	err      error
}

func (f *fakeStore) InsertReport(_ context.Context, r Report) error {
	if f.err != nil {
		return f.err
	}
	f.inserted = append(f.inserted, r)
	return nil
}

type fakeNotifier struct {
	notified []Report
}

func (f *fakeNotifier) NotifyNewReport(_ context.Context, r Report) error {
	f.notified = append(f.notified, r)
	return nil
}

type fixedClock struct{ t time.Time }

func (c fixedClock) Now() time.Time { return c.t }

type fixedID struct{ id string }

func (g fixedID) Next() string { return g.id }

func newServiceUnderTest(store Store, n Notifier) *Service {
	return NewService(ServiceDeps{
		Store:    store,
		Notifier: n,
		Clock:    fixedClock{t: time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)},
		IDGen:    fixedID{id: "report-1"},
	})
}

func validRequest() proto.ReportRequest {
	return proto.ReportRequest{
		ReportedAccountID: reportedID,
		ReportedUsername:  "alice",
		Reason:            "harassment",
	}
}

func assertBadRequest(t *testing.T, err error) {
	t.Helper()
	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeBadRequest {
		t.Fatalf("expected bad_request, got %v", err)
	}
}

func TestCreateReportStoresReport(t *testing.T) {
	store := &fakeStore{}
	svc := newServiceUnderTest(store, &fakeNotifier{})

	resp, err := svc.CreateReport(context.Background(), reporterID, "device-1", validRequest())

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resp.OK || resp.ReportID != "report-1" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if len(store.inserted) != 1 {
		t.Fatalf("expected 1 stored report, got %d", len(store.inserted))
	}
	got := store.inserted[0]
	if got.ReporterAccountID != reporterID || got.ReportedAccountID != reportedID {
		t.Fatalf("report identity mismatch: %+v", got)
	}
}

func TestCreateReportNotifiesOnSuccess(t *testing.T) {
	notifier := &fakeNotifier{}
	svc := newServiceUnderTest(&fakeStore{}, notifier)

	if _, err := svc.CreateReport(context.Background(), reporterID, "device-1", validRequest()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(notifier.notified) != 1 {
		t.Fatalf("expected 1 notification, got %d", len(notifier.notified))
	}
}

func TestCreateReportRejectsInvalidReason(t *testing.T) {
	store := &fakeStore{}
	svc := newServiceUnderTest(store, &fakeNotifier{})

	req := validRequest()
	req.Reason = "i-dont-like-them"
	_, err := svc.CreateReport(context.Background(), reporterID, "device-1", req)

	assertBadRequest(t, err)
	if len(store.inserted) != 0 {
		t.Fatalf("invalid report should not be stored")
	}
}

func TestCreateReportRejectsSelfReport(t *testing.T) {
	svc := newServiceUnderTest(&fakeStore{}, &fakeNotifier{})

	req := validRequest()
	req.ReportedAccountID = reporterID
	_, err := svc.CreateReport(context.Background(), reporterID, "device-1", req)

	assertBadRequest(t, err)
}

func TestCreateReportRejectsBadAccountID(t *testing.T) {
	svc := newServiceUnderTest(&fakeStore{}, &fakeNotifier{})

	req := validRequest()
	req.ReportedAccountID = "not-a-uuid"
	_, err := svc.CreateReport(context.Background(), reporterID, "device-1", req)

	assertBadRequest(t, err)
}

func TestCreateReportCapsExcessEvidence(t *testing.T) {
	store := &fakeStore{}
	svc := newServiceUnderTest(store, &fakeNotifier{})

	req := validRequest()
	for i := 0; i < maxEvidenceMessages+10; i++ {
		req.Messages = append(req.Messages, proto.ReportedMessage{Body: "x", Kind: "text"})
	}
	if _, err := svc.CreateReport(context.Background(), reporterID, "device-1", req); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := len(store.inserted[0].Messages); got != maxEvidenceMessages {
		t.Fatalf("expected evidence capped to %d, got %d", maxEvidenceMessages, got)
	}
}

func TestCreateReportReturnsInternalOnStoreError(t *testing.T) {
	store := &fakeStore{err: errors.New("db down")}
	svc := newServiceUnderTest(store, &fakeNotifier{})

	_, err := svc.CreateReport(context.Background(), reporterID, "device-1", validRequest())

	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeInternal {
		t.Fatalf("expected internal error, got %v", err)
	}
}
