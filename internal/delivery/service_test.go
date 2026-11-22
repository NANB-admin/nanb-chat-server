package delivery_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/delivery"
	"github.com/nanb/nanb-server/internal/proto"
)

type fixedClock struct{ t time.Time }

func (f fixedClock) Now() time.Time { return f.t }

type seqIDs struct {
	values []string
	i      int
}

func (s *seqIDs) Next() string {
	v := s.values[s.i]
	s.i++
	return v
}

const testSenderDeviceID = "sender-dev-1"

func newServiceForTest() (*delivery.Service, *delivery.StoreInMemory, *seqIDs) {
	ids := &seqIDs{values: []string{"env-1", "env-2", "env-3", "env-4", "env-5", "env-6"}}
	clock := fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}
	// The store's expiry filter must read the SAME fixed clock the service
	// inserts with; otherwise envelopes look expired against wall-clock once
	// real time passes insert_time + retention (a date-dependent time-bomb).
	store := delivery.NewStoreInMemoryWithClock(clock.Now)
	hub := delivery.NewHub()

	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             clock,
		IDGen:             ids,
		Hub:               hub,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})
	return svc, store, ids
}

func validRequest() proto.SubmitMessageRequest {
	return proto.SubmitMessageRequest{
		ConversationID:     "conv-1",
		EnvelopeType:       proto.EnvelopeTypeMLSApplication,
		RecipientAccountID: "recipient-acc-1",
		RecipientDeviceID:  "recipient-dev-1",
		Ciphertext:         []byte("opaque-ciphertext"),
	}
}

// fakeResolver marks specific device ids dead; everything else is live and owned
// by a deterministic "acct-<deviceID>" account (the server-derived value the
// service now stores instead of the client-supplied recipient_account_id).
type fakeResolver struct{ dead map[string]bool }

func (f fakeResolver) RecipientLive(_ context.Context, deviceID string) (bool, error) {
	return !f.dead[deviceID], nil
}

func (f fakeResolver) AccountForDevice(_ context.Context, deviceID string) (string, bool, error) {
	if f.dead[deviceID] {
		return "", false, nil
	}
	return "acct-" + deviceID, true, nil
}

func newServiceWithResolver(dead ...string) (*delivery.Service, *delivery.StoreInMemory) {
	store := delivery.NewStoreInMemory()
	deadSet := map[string]bool{}
	for _, d := range dead {
		deadSet[d] = true
	}
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)},
		IDGen:             &seqIDs{values: []string{"env-1", "env-2", "env-3"}},
		Hub:               delivery.NewHub(),
		Recipients:        fakeResolver{dead: deadSet},
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})
	return svc, store
}

func newServiceForReceiptTest() (*delivery.Service, *delivery.StoreInMemory, *delivery.Hub) {
	store := delivery.NewStoreInMemory()
	hub := delivery.NewHub()
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               hub,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})
	return svc, store, hub
}

func seedReceiptEnvelope(store *delivery.StoreInMemory) {
	store.SeedEnvelope(proto.Envelope{
		EnvelopeID:        "env-1",
		ConversationID:    "conv-1",
		SenderDeviceID:    "sender-dev-1",
		RecipientDeviceID: "recipient-dev-1",
	})
}

func TestConfirmReceived_RelaysToSenderOnFirstConfirmation(t *testing.T) {
	svc, store, hub := newServiceForReceiptTest()
	seedReceiptEnvelope(store)
	senderConn := &fakeConn{}
	hub.Register("sender-dev-1", senderConn)

	resp, err := svc.ConfirmReceived(context.Background(), "recipient-dev-1", "env-1")
	require.NoError(t, err)
	assert.True(t, resp.Relayed)

	got := senderConn.snapshot()
	require.Len(t, got, 1)
	assert.Equal(t, proto.EnvelopeTypeDeliveryStatus, got[0].EnvelopeType)
	assert.Equal(t, "conv-1", got[0].ConversationID)
	// Frame is addressed back to the ORIGINAL sender and carries the delivered
	// envelope id so the client matches it to the outgoing message.
	assert.Equal(t, "sender-dev-1", got[0].RecipientDeviceID)
	assert.Equal(t, "env-1", string(got[0].Ciphertext))
}

func TestConfirmReceived_DuplicateDoesNotRelayAgain(t *testing.T) {
	svc, store, hub := newServiceForReceiptTest()
	seedReceiptEnvelope(store)
	senderConn := &fakeConn{}
	hub.Register("sender-dev-1", senderConn)

	_, err := svc.ConfirmReceived(context.Background(), "recipient-dev-1", "env-1")
	require.NoError(t, err)
	resp, err := svc.ConfirmReceived(context.Background(), "recipient-dev-1", "env-1")
	require.NoError(t, err)
	assert.False(t, resp.Relayed)
	assert.Len(t, senderConn.snapshot(), 1, "a redelivered push must not re-notify the sender")
}

func TestConfirmReceived_WrongRecipientIsNoOp(t *testing.T) {
	svc, store, hub := newServiceForReceiptTest()
	seedReceiptEnvelope(store)
	senderConn := &fakeConn{}
	hub.Register("sender-dev-1", senderConn)

	resp, err := svc.ConfirmReceived(context.Background(), "attacker-dev", "env-1")
	require.NoError(t, err)
	assert.False(t, resp.Relayed)
	assert.Empty(t, senderConn.snapshot(), "a device that doesn't own the envelope can't trigger a relay")
}

func TestConfirmReceived_SenderOfflineNotRelayed(t *testing.T) {
	svc, store, _ := newServiceForReceiptTest()
	seedReceiptEnvelope(store)
	// No connection registered for sender-dev-1 → Broadcast returns false.
	resp, err := svc.ConfirmReceived(context.Background(), "recipient-dev-1", "env-1")
	require.NoError(t, err)
	assert.False(t, resp.Relayed, "offline sender → not relayed; the end-to-end receipt is the backstop")
}

func TestConfirmReceived_EmptyEnvelopeID_BadRequest(t *testing.T) {
	svc, _, _ := newServiceForReceiptTest()
	_, err := svc.ConfirmReceived(context.Background(), "recipient-dev-1", "")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSubmitMessage_RejectsDeadSender(t *testing.T) {
	svc, store := newServiceWithResolver(testSenderDeviceID)

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeUnauthorized, apiErr.Code)
	assert.Empty(t, store.SnapshotForRecipient("recipient-dev-1"))
}

func TestSubmitMessage_RejectsDeadSingularRecipient(t *testing.T) {
	svc, store := newServiceWithResolver("recipient-dev-1")

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
	assert.Empty(t, store.SnapshotForRecipient("recipient-dev-1"))
}

func TestSubmitMessage_LiveSingularRecipientPassesResolver(t *testing.T) {
	svc, store := newServiceWithResolver("someone-else")

	resp, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	require.NoError(t, err)
	assert.Equal(t, "env-1", resp.EnvelopeID)
	assert.Len(t, store.SnapshotForRecipient("recipient-dev-1"), 1)
}

func TestSubmitMessage_FanoutSkipsDeadRecipients(t *testing.T) {
	svc, store := newServiceWithResolver("dead-dev")
	req := validRequest()
	req.RecipientDeviceID = ""
	req.RecipientDeviceIDs = []string{"live-dev", "dead-dev"}

	resp, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	require.NoError(t, err)
	assert.Len(t, resp.EnvelopeIDs, 1)
	assert.Len(t, store.SnapshotForRecipient("live-dev"), 1)
	assert.Empty(t, store.SnapshotForRecipient("dead-dev"))
}

func TestSubmitMessage_FanoutAllDeadFails(t *testing.T) {
	svc, _ := newServiceWithResolver("dead-1", "dead-2")
	req := validRequest()
	req.RecipientDeviceID = ""
	req.RecipientDeviceIDs = []string{"dead-1", "dead-2"}

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeAccountNotFound, apiErr.Code)
}

func TestSubmitMessage_HappyPath(t *testing.T) {
	svc, store, _ := newServiceForTest()

	resp, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	require.NoError(t, err)

	assert.Equal(t, "env-1", resp.EnvelopeID)
	assert.Equal(t, time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC), resp.ServerTS)
	assert.Len(t, store.SnapshotForRecipient("recipient-dev-1"), 1)
}

func TestSubmitMessage_RejectsEmptyConversation(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := validRequest()
	req.ConversationID = ""

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSubmitMessage_RejectsEmptyRecipientAccount(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := validRequest()
	req.RecipientAccountID = ""

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSubmitMessage_RejectsEmptyRecipientDevice(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := validRequest()
	req.RecipientDeviceID = ""

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSubmitMessage_RejectsEmptyCiphertext(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := validRequest()
	req.Ciphertext = nil

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSubmitMessage_RejectsOversizedCiphertext(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := validRequest()
	req.Ciphertext = make([]byte, (1<<20)+1)

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodePayloadTooLarge, apiErr.Code)
}

func TestSubmitMessage_RejectsUnknownEnvelopeType(t *testing.T) {
	svc, _, _ := newServiceForTest()
	req := validRequest()
	req.EnvelopeType = "made_up_type"

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSubmitMessage_AcceptsMLSWelcomeEnvelope(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID,
		proto.SubmitMessageRequest{
			ConversationID:     "1to1:x",
			EnvelopeType:       proto.EnvelopeTypeMLSWelcome,
			RecipientAccountID: "acct-bob",
			RecipientDeviceID:  "dev-bob",
			Ciphertext:         []byte("welcome"),
		})
	if err != nil {
		t.Fatalf("expected accepted, got %v", err)
	}
}

func TestSubmitMessage_AcceptsTextLegacyEnvelope(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID,
		proto.SubmitMessageRequest{
			ConversationID:     "1to1:x",
			EnvelopeType:       proto.EnvelopeTypeTextLegacy,
			RecipientAccountID: "acct-bob",
			RecipientDeviceID:  "dev-bob",
			Ciphertext:         []byte("legacy"),
		})
	if err != nil {
		t.Fatalf("expected accepted, got %v", err)
	}
}

func newServiceWithStore(store delivery.Store, cap int) *delivery.Service {
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	return delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1", "env-2", "env-3", "env-4", "env-5"}},
		Hub:               delivery.NewHub(),
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   cap,
		MaxCiphertextSize: 1 << 20,
	})
}

type errStore struct {
	delivery.Store
	failInsert  error
	failCatchup error
	failAck     error
	failCount   error
	getEnvErr   error
}

func (e *errStore) InsertEnvelope(ctx context.Context, env proto.Envelope, expiresAt time.Time) error {
	if e.failInsert != nil {
		return e.failInsert
	}
	return e.Store.InsertEnvelope(ctx, env, expiresAt)
}

func (e *errStore) CatchupForDevice(ctx context.Context, deviceID string, since time.Time, limit int) ([]proto.Envelope, error) {
	if e.failCatchup != nil {
		return nil, e.failCatchup
	}
	return e.Store.CatchupForDevice(ctx, deviceID, since, limit)
}

func (e *errStore) AckEnvelopes(ctx context.Context, deviceID string, envelopeIDs []string, now time.Time) (int, error) {
	if e.failAck != nil {
		return 0, e.failAck
	}
	return e.Store.AckEnvelopes(ctx, deviceID, envelopeIDs, now)
}

func (e *errStore) CountForConversation(ctx context.Context, recipientAccountID, conversationID string) (int, error) {
	if e.failCount != nil {
		return 0, e.failCount
	}
	return e.Store.CountForConversation(ctx, recipientAccountID, conversationID)
}

// The non-sealed path caps per (device, conversation), so the count fault
// injection must hook the device-scoped method it actually calls.
func (e *errStore) CountForDeviceConversation(ctx context.Context, recipientDeviceID, conversationID string) (int, error) {
	if e.failCount != nil {
		return 0, e.failCount
	}
	return e.Store.CountForDeviceConversation(ctx, recipientDeviceID, conversationID)
}

func TestSubmitMessage_SealedStoresNoConversationOrSender(t *testing.T) {
	store := delivery.NewStoreInMemory()
	// Future-dated clock so the stored envelope hasn't expired by real "now"
	// when CatchupForDevice (which filters expires_at > now()) reads it back.
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)},
		IDGen:             &seqIDs{values: []string{"e1"}},
		Hub:               delivery.NewHub(),
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})
	req := proto.SubmitMessageRequest{
		EnvelopeType:       proto.EnvelopeTypeSealed,
		RecipientAccountID: "recipient-acc-1",
		RecipientDeviceID:  "recipient-dev-1",
		Ciphertext:         []byte("opaque-sealed-blob"),
		// ConversationID intentionally empty — it's hidden inside the payload.
	}
	resp, err := svc.SubmitMessage(context.Background(), "sender-dev-1", req)
	require.NoError(t, err)
	require.NotEmpty(t, resp.EnvelopeID)

	// Sealed-at-rest: the stored envelope must carry NO conversation and NO
	// sender (the sender was JWT-authenticated at submit; we just don't persist
	// it). recipient + ciphertext are retained — the server needs them to deliver.
	got, err := store.CatchupForDevice(context.Background(), "recipient-dev-1", time.Time{}, 10)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, proto.EnvelopeTypeSealed, got[0].EnvelopeType)
	// The UUID columns hold the constant zero-UUID sentinel (not the real
	// conversation/sender) — valid for the `uuid NOT NULL` columns, no info.
	assert.Equal(t, proto.SealedSentinelUUID, got[0].ConversationID,
		"sealed: server stores no real conversation")
	assert.Equal(t, proto.SealedSentinelUUID, got[0].SenderDeviceID,
		"sealed: server stores no real sender")
	assert.NotEqual(t, "sender-dev-1", got[0].SenderDeviceID,
		"the real (JWT) sender must not be persisted")
	assert.Equal(t, "recipient-dev-1", got[0].RecipientDeviceID)
	assert.Equal(t, []byte("opaque-sealed-blob"), got[0].Ciphertext)
}

func TestSubmitMessage_SealedAllowsEmptyConversation(t *testing.T) {
	svc, _ := newServiceWithResolver()

	// A non-sealed envelope still requires a conversation_id.
	bad := validRequest()
	bad.ConversationID = ""
	_, err := svc.SubmitMessage(context.Background(), "sender-dev-1", bad)
	require.Error(t, err, "non-sealed envelope must carry a conversation_id")

	// A sealed one may omit it.
	sealedReq := proto.SubmitMessageRequest{
		EnvelopeType:       proto.EnvelopeTypeSealed,
		RecipientAccountID: "recipient-acc-1",
		RecipientDeviceID:  "recipient-dev-1",
		Ciphertext:         []byte("blob"),
	}
	_, err = svc.SubmitMessage(context.Background(), "sender-dev-1", sealedReq)
	require.NoError(t, err, "sealed envelope may omit conversation_id")
}

// capClock is the fixed "now" every mailbox-cap test runs at. The store must
// read the same clock as the service, or the envelopes it inserts look expired
// (and so uncounted) against the wall clock.
var capClock = fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)}

func newCapStore() *delivery.StoreInMemory {
	return delivery.NewStoreInMemoryWithClock(capClock.Now)
}

func newSealedCapService(store delivery.Store, cap int) *delivery.Service {
	return delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)},
		IDGen:             &seqIDs{values: []string{"e1", "e2", "e3", "e4"}},
		Hub:               delivery.NewHub(),
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   cap,
		MaxCiphertextSize: 1 << 20,
	})
}

func sealedTo(device string) proto.SubmitMessageRequest {
	return proto.SubmitMessageRequest{
		EnvelopeType:       proto.EnvelopeTypeSealed,
		RecipientAccountID: "recipient-acc-1",
		RecipientDeviceID:  device,
		Ciphertext:         []byte("blob"),
	}
}

func TestSubmitMessage_SealedAtCap_RefusesTheNewEnvelope(t *testing.T) {
	svc := newSealedCapService(newCapStore(), 2)
	ctx := context.Background()
	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("recipient-dev-1"))
	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("recipient-dev-1"))

	_, err := svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("recipient-dev-1"))

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMailboxFull, apiErr.Code)
}

// The eviction attack: any authenticated sender floods a victim device with
// sealed envelopes. Its genuinely-undelivered envelopes must all survive.
func TestSubmitMessage_SealedFlood_NeverDeletesQueuedEnvelopes(t *testing.T) {
	store := newCapStore()
	svc := newSealedCapService(store, 2)
	ctx := context.Background()
	_, _ = svc.SubmitMessage(ctx, "friend-dev", sealedTo("recipient-dev-1"))
	_, _ = svc.SubmitMessage(ctx, "friend-dev", sealedTo("recipient-dev-1"))

	for i := 0; i < 2; i++ {
		_, _ = svc.SubmitMessage(ctx, "attacker-dev", sealedTo("recipient-dev-1"))
	}

	ids := []string{}
	for _, e := range store.SnapshotForRecipient("recipient-dev-1") {
		ids = append(ids, e.EnvelopeID)
	}
	assert.ElementsMatch(t, []string{"e1", "e2"}, ids)
}

func TestSubmitMessage_SealedCapIsPerDevice(t *testing.T) {
	svc := newSealedCapService(newCapStore(), 1)
	ctx := context.Background()
	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("recipient-dev-1"))

	_, err := svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("recipient-dev-2"))

	require.NoError(t, err, "a full device must not block another device's delivery")
}

func TestSubmitMessage_PropagatesInsertError(t *testing.T) {
	es := &errStore{Store: delivery.NewStoreInMemory(), failInsert: errors.New("db down")}
	svc := newServiceWithStore(es, 5000)

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestSubmitMessage_PropagatesCountError(t *testing.T) {
	es := &errStore{Store: delivery.NewStoreInMemory(), failCount: errors.New("db down")}
	svc := newServiceWithStore(es, 5000)

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestCatchupMessages_ReturnsUnacked(t *testing.T) {
	svc, _, _ := newServiceForTest()

	for i := 0; i < 3; i++ {
		_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
		require.NoError(t, err)
	}

	resp, err := svc.CatchupMessages(context.Background(), "recipient-dev-1", proto.CatchupRequest{})
	require.NoError(t, err)
	assert.Len(t, resp.Envelopes, 3)
	assert.Equal(t, "env-1", resp.Envelopes[0].EnvelopeID)
}

func TestCatchupMessages_RespectsLimit(t *testing.T) {
	svc, _, _ := newServiceForTest()

	for i := 0; i < 3; i++ {
		_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
		require.NoError(t, err)
	}

	resp, err := svc.CatchupMessages(context.Background(), "recipient-dev-1", proto.CatchupRequest{Limit: 2})
	require.NoError(t, err)
	assert.Len(t, resp.Envelopes, 2)
}

func TestCatchupMessages_PropagatesStoreError(t *testing.T) {
	es := &errStore{Store: delivery.NewStoreInMemory(), failCatchup: errors.New("db down")}
	svc := newServiceWithStore(es, 5000)

	_, err := svc.CatchupMessages(context.Background(), "dev-1", proto.CatchupRequest{})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestAckMessages_HappyPath(t *testing.T) {
	svc, store, _ := newServiceForTest()

	for i := 0; i < 3; i++ {
		_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
		require.NoError(t, err)
	}

	resp, err := svc.AckMessages(context.Background(), "recipient-dev-1", proto.AckRequest{
		EnvelopeIDs: []string{"env-1", "env-2"},
	})
	require.NoError(t, err)
	assert.Equal(t, 2, resp.AckedCount)
	assert.Len(t, store.SnapshotForRecipient("recipient-dev-1"), 1)
}

func TestAckMessages_DeletesTheAckedEnvelope(t *testing.T) {
	svc, store, _ := newServiceForTest()
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	require.NoError(t, err)

	_, err = svc.AckMessages(context.Background(), "recipient-dev-1", proto.AckRequest{
		EnvelopeIDs: []string{"env-1"},
	})
	require.NoError(t, err)

	_, stored := store.ExpiryOf("env-1")
	assert.False(t, stored)
}

func TestAckMessages_RejectsEmptyList(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.AckMessages(context.Background(), "recipient-dev-1", proto.AckRequest{})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestAckMessages_PropagatesStoreError(t *testing.T) {
	es := &errStore{Store: delivery.NewStoreInMemory(), failAck: errors.New("db down")}
	svc := newServiceWithStore(es, 5000)

	_, err := svc.AckMessages(context.Background(), "dev-1", proto.AckRequest{EnvelopeIDs: []string{"env-1"}})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

// sharedAcctResolver reports every device as live and owned by the SAME
// account, so the per-device FIFO scoping is exercised in the worst case: two
// different devices of one account sharing a conversation id. Before the fix the
// cap grouped by (recipient_account_id, conversation_id), so a flood addressed to
// one device evicted the OTHER device's undelivered envelopes.
type sharedAcctResolver struct{}

func (sharedAcctResolver) RecipientLive(context.Context, string) (bool, error) { return true, nil }
func (sharedAcctResolver) AccountForDevice(context.Context, string) (string, bool, error) {
	return "shared-acct", true, nil
}

func TestSubmitMessage_DeviceFloodCannotEvictAnotherDevicesQueue(t *testing.T) {
	store := newCapStore()
	ids := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		ids = append(ids, fmt.Sprintf("env-%d", i))
	}
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)},
		IDGen:             &seqIDs{values: ids},
		Hub:               delivery.NewHub(),
		Recipients:        sharedAcctResolver{},
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   3,
		MaxCiphertextSize: 1 << 20,
	})
	ctx := context.Background()
	req := func(dev string) proto.SubmitMessageRequest {
		return proto.SubmitMessageRequest{
			ConversationID:     "conv-shared",
			EnvelopeType:       proto.EnvelopeTypeMLSApplication,
			RecipientAccountID: "shared-acct",
			RecipientDeviceID:  dev,
			Ciphertext:         []byte("x"),
		}
	}

	// Victim device B accumulates 3 undelivered envelopes (exactly the cap).
	for i := 0; i < 3; i++ {
		_, err := svc.SubmitMessage(ctx, "sender", req("dev-B"))
		require.NoError(t, err)
	}
	require.Len(t, store.SnapshotForRecipient("dev-B"), 3)

	// Attacker floods device A in the SAME conversation of the SAME account
	// (refused once A is full).
	for i := 0; i < 20; i++ {
		_, _ = svc.SubmitMessage(ctx, "sender", req("dev-A"))
	}

	// Device A stops at the cap; device B's queue is untouched.
	assert.Len(t, store.SnapshotForRecipient("dev-A"), 3)
	assert.Len(t, store.SnapshotForRecipient("dev-B"), 3,
		"one device's flood must not evict another device's undelivered envelopes")
}

// limitRecorderStore captures the limit the service hands the store so the
// catchup clamp can be asserted without seeding hundreds of rows.
type limitRecorderStore struct {
	delivery.Store
	lastLimit int
}

func (s *limitRecorderStore) CatchupForDevice(ctx context.Context, deviceID string, since time.Time, limit int) ([]proto.Envelope, error) {
	s.lastLimit = limit
	return s.Store.CatchupForDevice(ctx, deviceID, since, limit)
}

func TestCatchupMessages_ClampsLimitToCeiling(t *testing.T) {
	rec := &limitRecorderStore{Store: delivery.NewStoreInMemory()}
	svc := newServiceWithStore(rec, 5000)

	_, err := svc.CatchupMessages(context.Background(), "dev-1", proto.CatchupRequest{Limit: 100000})
	require.NoError(t, err)
	assert.Equal(t, 500, rec.lastLimit, "an oversized catchup limit must be clamped to the ceiling")
}

func TestSubmitMessage_AtCap_RefusesTheNewEnvelope(t *testing.T) {
	svc := newServiceWithStore(newCapStore(), 2)
	ctx := context.Background()
	_, _ = svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())
	_, _ = svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())

	_, err := svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMailboxFull, apiErr.Code)
}

func TestSubmitMessage_AtCap_KeepsTheQueuedEnvelopes(t *testing.T) {
	store := newCapStore()
	svc := newServiceWithStore(store, 2)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		_, _ = svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())
	}

	ids := []string{}
	for _, e := range store.SnapshotForRecipient("recipient-dev-1") {
		ids = append(ids, e.EnvelopeID)
	}
	assert.ElementsMatch(t, []string{"env-1", "env-2"}, ids)
}

func TestSubmitMessage_AtCap_AckedEnvelopesFreeRoom(t *testing.T) {
	svc := newServiceWithStore(newCapStore(), 1)
	ctx := context.Background()
	first, _ := svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())
	_, err := svc.AckMessages(ctx, "recipient-dev-1", proto.AckRequest{EnvelopeIDs: []string{first.EnvelopeID}})
	require.NoError(t, err)

	_, err = svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())

	require.NoError(t, err)
}

func TestSubmitMessage_PluralFanout_SkipsOnlyTheFullDevice(t *testing.T) {
	svc := newSealedCapService(newCapStore(), 1)
	ctx := context.Background()
	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("full-dev"))
	req := sealedTo("")
	req.RecipientDeviceIDs = []string{"full-dev", "free-dev"}

	resp, err := svc.SubmitMessage(ctx, "sender-dev-1", req)

	require.NoError(t, err)
	assert.Len(t, resp.EnvelopeIDs, 1)
}

func TestSubmitMessage_PluralFanout_FreeDeviceStillGetsItsCopy(t *testing.T) {
	store := newCapStore()
	svc := newSealedCapService(store, 1)
	ctx := context.Background()
	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("full-dev"))
	req := sealedTo("")
	req.RecipientDeviceIDs = []string{"full-dev", "free-dev"}

	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", req)

	assert.Len(t, store.SnapshotForRecipient("free-dev"), 1)
}

func TestSubmitMessage_PluralFanout_AllFullIsMailboxFull(t *testing.T) {
	svc := newSealedCapService(newCapStore(), 1)
	ctx := context.Background()
	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("full-1"))
	_, _ = svc.SubmitMessage(ctx, "sender-dev-1", sealedTo("full-2"))
	req := sealedTo("")
	req.RecipientDeviceIDs = []string{"full-1", "full-2"}

	_, err := svc.SubmitMessage(ctx, "sender-dev-1", req)

	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeMailboxFull, apiErr.Code)
}

type fakePusher struct {
	calls []string
	err   error
}

func (f *fakePusher) DispatchWakeup(_ context.Context, deviceID, _, _, _ string, _ []byte) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, deviceID)
	return nil
}

func TestSubmitMessage_FiresPushWhenNotDelivered(t *testing.T) {
	store := delivery.NewStoreInMemory()
	pusher := &fakePusher{}
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               delivery.NewHub(), // empty: no registration
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	require.NoError(t, err)
	assert.Equal(t, []string{"recipient-dev-1"}, pusher.calls)
}

// ctxPusher records whether the context it was handed was already cancelled.
type ctxPusher struct {
	ctxErrs []error
}

func (f *ctxPusher) DispatchWakeup(ctx context.Context, _, _, _, _ string, _ []byte) error {
	f.ctxErrs = append(f.ctxErrs, ctx.Err())
	return nil
}

// The envelope is stored before the wakeup is sent, so a sender that hangs up
// (Tor circuit drop, client timeout) must not take the recipient's notification
// down with its request: a cancelled ctx failed both the send and the retry
// queue insert.
func TestSubmitMessage_WakeupSurvivesTheSenderHangingUp(t *testing.T) {
	pusher := &ctxPusher{}
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             delivery.NewStoreInMemory(),
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               delivery.NewHub(),
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())

	require.NoError(t, err)
	assert.Equal(t, []error{nil}, pusher.ctxErrs)
}

func TestSubmitMessage_PushesEvenWhenDelivered(t *testing.T) {
	store := delivery.NewStoreInMemory()
	pusher := &fakePusher{}
	hub := delivery.NewHub()
	conn := &fakeConn{}
	hub.Register("recipient-dev-1", conn)

	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               hub,
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	require.NoError(t, err)
	// A registered socket does NOT mean a live app: a backgrounded iOS app
	// keeps its socket while the OS suspends the process, so suppressing the
	// push here meant no notification at all until the user next opened the
	// app. Pushes are data-only and there is no onMessage listener, so a
	// genuinely foreground app still displays nothing.
	assert.Len(t, pusher.calls, 1, "must still wake a possibly-suspended app")
}

func TestSubmitMessage_SilentControlSkipsPushWhenNotDelivered(t *testing.T) {
	// A control/protocol envelope (read receipt, reaction, pin, MLS Welcome,
	// access-key share) rides push_kind="silent". Even with the recipient
	// offline (empty hub → not delivered), it must NOT fire a wakeup: opening a
	// chat sends a read receipt, which otherwise buzzed the peer with a phantom
	// "new message". The recipient applies it on the next foreground catchup.
	store := delivery.NewStoreInMemory()
	pusher := &fakePusher{}
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               delivery.NewHub(), // empty: recipient offline
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})

	req := validRequest()
	req.PushKind = "silent"
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	require.NoError(t, err)
	assert.Empty(t, pusher.calls, "a silent control envelope must never wake a closed device")
}

func TestSubmitMessage_GroupManagementEnvelopesNeverPush(t *testing.T) {
	// A Commit or Welcome (linking a device, adding a member) carries no
	// user-visible content. Sent with no push hint it used to be pushed as a
	// generic "New message" to every member device — a notification for a message
	// that does not exist.
	for _, envelopeType := range []string{proto.EnvelopeTypeMLSHandshake, proto.EnvelopeTypeMLSWelcome} {
		t.Run(envelopeType, func(t *testing.T) {
			store := delivery.NewStoreInMemory()
			pusher := &fakePusher{}
			t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
			svc := delivery.NewService(delivery.ServiceDeps{
				Store:             store,
				Clock:             fixedClock{t: t0},
				IDGen:             &seqIDs{values: []string{"env-1"}},
				Hub:               delivery.NewHub(), // empty: recipient offline
				Pusher:            pusher,
				EnvelopeRetention: 30 * 24 * time.Hour,
				ConversationCap:   5000,
				MaxCiphertextSize: 1 << 20,
			})

			req := validRequest()
			req.EnvelopeType = envelopeType
			_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
			require.NoError(t, err)
			assert.Empty(t, pusher.calls, "protocol-only group traffic must never raise a notification")
		})
	}
}

func TestSubmitMessage_ApplicationEnvelopeStillPushes(t *testing.T) {
	store := delivery.NewStoreInMemory()
	pusher := &fakePusher{}
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               delivery.NewHub(),
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})

	req := validRequest()
	req.EnvelopeType = proto.EnvelopeTypeMLSApplication
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	require.NoError(t, err)
	assert.Len(t, pusher.calls, 1, "a real message must still wake the recipient")
}

func TestSubmitMessage_CallAlwaysPushesEvenWhenDelivered(t *testing.T) {
	// A call invite (push_kind="call") MUST ring the callee even when the WS hub
	// reports the in-band frame delivered (the socket can be dead-but-not-yet
	// detected, or backgrounded with no UI to ring). Guards that the silent
	// carve-out didn't disturb the call-always-push rule.
	store := delivery.NewStoreInMemory()
	pusher := &fakePusher{}
	hub := delivery.NewHub()
	hub.Register("recipient-dev-1", &fakeConn{})

	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               hub,
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})

	req := validRequest()
	req.PushKind = "call"
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	require.NoError(t, err)
	assert.Equal(t, []string{"recipient-dev-1"}, pusher.calls, "a call wakeup fires even when delivered")
}

func TestSubmitMessage_PushErrorIsNonFatal(t *testing.T) {
	store := delivery.NewStoreInMemory()
	pusher := &fakePusher{err: errors.New("apns down")}

	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               delivery.NewHub(),
		Pusher:            pusher,
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	assert.NoError(t, err) // push failure is best-effort, not fatal
}

func TestSubmitMessage_NilPusherIsAllowed(t *testing.T) {
	store := delivery.NewStoreInMemory()
	t0 := time.Date(2026, 5, 7, 12, 0, 0, 0, time.UTC)
	svc := delivery.NewService(delivery.ServiceDeps{
		Store:             store,
		Clock:             fixedClock{t: t0},
		IDGen:             &seqIDs{values: []string{"env-1"}},
		Hub:               delivery.NewHub(),
		Pusher:            nil, // optional
		EnvelopeRetention: 30 * 24 * time.Hour,
		ConversationCap:   5000,
		MaxCiphertextSize: 1 << 20,
	})

	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	assert.NoError(t, err)
}

func TestSubmitMessage_PluralPath_InsertsN(t *testing.T) {
	svc, store, _ := newServiceForTest()
	resp, err := svc.SubmitMessage(context.Background(), testSenderDeviceID,
		proto.SubmitMessageRequest{
			ConversationID:     "group:abc",
			EnvelopeType:       proto.EnvelopeTypeMLSApplication,
			RecipientAccountID: "acct-bob",
			RecipientDeviceIDs: []string{"dev-bob1", "dev-bob2", "dev-bob3"},
			Ciphertext:         []byte("hello"),
		})
	require.NoError(t, err)
	assert.Len(t, resp.EnvelopeIDs, 3)
	assert.Empty(t, resp.EnvelopeID, "singular EnvelopeID should be empty in plural path")
	assert.Len(t, store.SnapshotForRecipient("dev-bob1"), 1)
	assert.Len(t, store.SnapshotForRecipient("dev-bob2"), 1)
	assert.Len(t, store.SnapshotForRecipient("dev-bob3"), 1)
}

func TestSubmitMessage_BothFields_Rejects(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID,
		proto.SubmitMessageRequest{
			ConversationID:     "1to1:x",
			EnvelopeType:       proto.EnvelopeTypeMLSApplication,
			RecipientAccountID: "acct-bob",
			RecipientDeviceID:  "dev-bob",
			RecipientDeviceIDs: []string{"dev-bob", "dev-bob2"},
			Ciphertext:         []byte("hello"),
		})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestSubmitMessage_NeitherField_Rejects(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID,
		proto.SubmitMessageRequest{
			ConversationID:     "1to1:x",
			EnvelopeType:       proto.EnvelopeTypeMLSApplication,
			RecipientAccountID: "acct-bob",
			Ciphertext:         []byte("hello"),
		})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func (e *errStore) GetEnvelopeByID(ctx context.Context, envID, devID string) (proto.Envelope, error) {
	if e.getEnvErr != nil {
		return proto.Envelope{}, e.getEnvErr
	}
	return e.Store.GetEnvelopeByID(ctx, envID, devID)
}

func TestGetEnvelopeByID_StoreErrorReturnsInternal(t *testing.T) {
	es := &errStore{Store: delivery.NewStoreInMemory(), getEnvErr: errors.New("disk fire")}
	svc := newServiceWithStore(es, 5000)
	_, err := svc.GetEnvelopeByIDForRecipient(context.Background(), "env-x", "dev-y")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestSubmitMessage_EmptyPluralList_Rejects(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.SubmitMessage(context.Background(), testSenderDeviceID,
		proto.SubmitMessageRequest{
			ConversationID:     "group:abc",
			EnvelopeType:       proto.EnvelopeTypeMLSApplication,
			RecipientAccountID: "acct-bob",
			RecipientDeviceIDs: []string{},
			Ciphertext:         []byte("hello"),
		})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestGetEnvelopeByID_HappyReturnsEnvelope(t *testing.T) {
	svc, store, _ := newServiceForTest()
	env := proto.Envelope{
		EnvelopeID:        "env-1",
		ConversationID:    "1to1:x",
		SenderDeviceID:    "dev-alice",
		RecipientDeviceID: "dev-bob",
		EnvelopeType:      proto.EnvelopeTypeMLSApplication,
		Ciphertext:        []byte("hi"),
	}
	store.SeedEnvelope(env)

	got, err := svc.GetEnvelopeByIDForRecipient(context.Background(), "env-1", "dev-bob")
	require.NoError(t, err)
	assert.Equal(t, "env-1", got.EnvelopeID)
}

func TestGetEnvelopeByID_WrongRecipient_Returns404(t *testing.T) {
	svc, store, _ := newServiceForTest()
	store.SeedEnvelope(proto.Envelope{
		EnvelopeID:        "env-1",
		RecipientDeviceID: "dev-bob",
	})
	_, err := svc.GetEnvelopeByIDForRecipient(context.Background(), "env-1", "dev-mallory")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeEnvelopeNotFound, apiErr.Code)
}

func TestGetEnvelopeByID_Missing_Returns404(t *testing.T) {
	svc, _, _ := newServiceForTest()
	_, err := svc.GetEnvelopeByIDForRecipient(context.Background(), "env-missing", "dev-bob")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeEnvelopeNotFound, apiErr.Code)
}

// --- Per-envelope TTL (sender retention preference) ---

func TestSubmitMessage_TTLSecondsShortensExpiry(t *testing.T) {
	svc, store, _ := newServiceForTest()
	req := validRequest()
	req.TTLSeconds = 7 * 24 * 3600 // one week, below the 30-day default

	resp, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	require.NoError(t, err)

	exp, ok := store.ExpiryOf(resp.EnvelopeID)
	require.True(t, ok)
	want := time.Date(2026, 5, 14, 12, 0, 0, 0, time.UTC) // fixed clock +7d
	assert.Equal(t, want, exp)
}

func TestSubmitMessage_TTLSecondsCannotExceedServerCeiling(t *testing.T) {
	svc, store, _ := newServiceForTest()
	req := validRequest()
	req.TTLSeconds = 90 * 24 * 3600 // above the ceiling - must be ignored

	resp, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, req)
	require.NoError(t, err)

	exp, ok := store.ExpiryOf(resp.EnvelopeID)
	require.True(t, ok)
	want := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC) // fixed clock +30d
	assert.Equal(t, want, exp)
}

func TestSubmitMessage_NoTTLUsesServerDefault(t *testing.T) {
	svc, store, _ := newServiceForTest()

	resp, err := svc.SubmitMessage(context.Background(), testSenderDeviceID, validRequest())
	require.NoError(t, err)

	exp, ok := store.ExpiryOf(resp.EnvelopeID)
	require.True(t, ok)
	want := time.Date(2026, 6, 6, 12, 0, 0, 0, time.UTC) // fixed clock +30d
	assert.Equal(t, want, exp)
}

func TestService_DeleteExpired_SweepsExpiredEnvelopes(t *testing.T) {
	svc, store, _ := newServiceForTest()
	ctx := context.Background()

	// One already-expired row (manual insert with a past expiry) and one
	// live row submitted through the service.
	past := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	require.NoError(t, store.InsertEnvelope(ctx,
		envFor("env-expired", "dev-X", "acc-X", "c-x", past), past.Add(time.Hour)))
	_, err := svc.SubmitMessage(ctx, testSenderDeviceID, validRequest())
	require.NoError(t, err)

	deleted, err := svc.DeleteExpired(ctx, 100)
	require.NoError(t, err)
	assert.Equal(t, 1, deleted)

	// The expired row is gone entirely; the live one survives.
	_, ok := store.ExpiryOf("env-expired")
	assert.False(t, ok)
}
func TestService_AckMessages_RejectsMoreThanMaxIDs(t *testing.T) {
	svc, _, _ := newServiceForTest()
	ids := make([]string, delivery.MaxAckIDs+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("env-%d", i)
	}

	_, err := svc.AckMessages(context.Background(), "dev-1", proto.AckRequest{EnvelopeIDs: ids})

	var apiErr proto.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != proto.ErrCodeBadRequest {
		t.Fatalf("err = %v, want bad_request", err)
	}
}
