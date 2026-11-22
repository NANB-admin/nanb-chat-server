package push_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/push"
)

type fakeClient struct {
	calls       []push.Token
	err         error
	LastPayload map[string]string
}

func (f *fakeClient) SendWakeup(_ context.Context, t push.Token, payload map[string]string) error {
	if f.err != nil {
		return f.err
	}
	f.calls = append(f.calls, t)
	f.LastPayload = payload
	return nil
}

type errStore struct {
	push.Store
	failUpsert error
	failGet    error
	failDelete error
}

func (e *errStore) Upsert(ctx context.Context, t push.Token) error {
	if e.failUpsert != nil {
		return e.failUpsert
	}
	return e.Store.Upsert(ctx, t)
}

func (e *errStore) GetByDeviceID(ctx context.Context, deviceID string) (push.Token, error) {
	if e.failGet != nil {
		return push.Token{}, e.failGet
	}
	return e.Store.GetByDeviceID(ctx, deviceID)
}

func (e *errStore) Delete(ctx context.Context, deviceID string) error {
	if e.failDelete != nil {
		return e.failDelete
	}
	return e.Store.Delete(ctx, deviceID)
}

func newSvc(client push.PushClient) (*push.Service, *push.StoreInMemory) {
	store := push.NewStoreInMemory()
	svc := push.NewService(push.ServiceDeps{Store: store, Client: client})
	return svc, store
}

func TestRegisterToken_HappyPath_APNS(t *testing.T) {
	svc, store := newSvc(&fakeClient{})

	err := svc.RegisterToken(context.Background(), "acc-1", "dev-1", proto.RegisterPushTokenRequest{
		Platform: "apns",
		Token:    "raw-token",
	})
	require.NoError(t, err)

	got, err := store.GetByDeviceID(context.Background(), "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "apns", got.Platform)
	assert.Equal(t, "raw-token", got.Token)
}

func TestRegisterToken_HappyPath_FCM(t *testing.T) {
	svc, _ := newSvc(&fakeClient{})

	err := svc.RegisterToken(context.Background(), "acc-1", "dev-1", proto.RegisterPushTokenRequest{
		Platform: "fcm",
		Token:    "raw-token",
	})
	assert.NoError(t, err)
}

// One app install = one provider token. When the same install re-registers
// under a new device id (signed out / erased offline, then signed in again), the
// old device's row must stop pushing at this phone.
func TestRegisterToken_ReleasesTheTokenFromAPreviousDevice(t *testing.T) {
	svc, store := newSvc(&fakeClient{})
	ctx := context.Background()
	require.NoError(t, svc.RegisterToken(ctx, "acc-old", "dev-old", proto.RegisterPushTokenRequest{
		Platform: "fcm", Token: "install-token",
	}))

	require.NoError(t, svc.RegisterToken(ctx, "acc-new", "dev-new", proto.RegisterPushTokenRequest{
		Platform: "fcm", Token: "install-token",
	}))

	_, err := store.GetByDeviceID(ctx, "dev-old")
	assert.ErrorIs(t, err, push.ErrNotFound)
}

func TestRegisterToken_RejectsUnknownPlatform(t *testing.T) {
	svc, _ := newSvc(&fakeClient{})
	err := svc.RegisterToken(context.Background(), "acc-1", "dev-1", proto.RegisterPushTokenRequest{
		Platform: "made-up",
		Token:    "raw-token",
	})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestRegisterToken_RejectsEmptyToken(t *testing.T) {
	svc, _ := newSvc(&fakeClient{})
	err := svc.RegisterToken(context.Background(), "acc-1", "dev-1", proto.RegisterPushTokenRequest{
		Platform: "apns",
		Token:    "",
	})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeBadRequest, apiErr.Code)
}

func TestRegisterToken_PropagatesStoreError(t *testing.T) {
	es := &errStore{Store: push.NewStoreInMemory(), failUpsert: errors.New("db down")}
	svc := push.NewService(push.ServiceDeps{Store: es, Client: &fakeClient{}})

	err := svc.RegisterToken(context.Background(), "acc-1", "dev-1", proto.RegisterPushTokenRequest{
		Platform: "apns",
		Token:    "x",
	})
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestDeleteToken_HappyPath(t *testing.T) {
	svc, store := newSvc(&fakeClient{})
	require.NoError(t, store.Upsert(context.Background(), push.Token{DeviceID: "dev-1", Platform: "apns", Token: "x"}))

	err := svc.DeleteToken(context.Background(), "dev-1")
	require.NoError(t, err)

	_, err = store.GetByDeviceID(context.Background(), "dev-1")
	assert.ErrorIs(t, err, push.ErrNotFound)
}

func TestDeleteToken_PropagatesStoreError(t *testing.T) {
	es := &errStore{Store: push.NewStoreInMemory(), failDelete: errors.New("db down")}
	svc := push.NewService(push.ServiceDeps{Store: es, Client: &fakeClient{}})

	err := svc.DeleteToken(context.Background(), "dev-1")
	var apiErr proto.APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, proto.ErrCodeInternal, apiErr.Code)
}

func TestDispatchWakeup_HappyPath(t *testing.T) {
	client := &fakeClient{}
	svc, store := newSvc(client)
	require.NoError(t, store.Upsert(context.Background(), push.Token{DeviceID: "dev-1", Platform: "apns", Token: "raw"}))

	err := svc.DispatchWakeup(context.Background(), "dev-1", "env-1", "conv-1", "", nil)
	require.NoError(t, err)
	assert.Len(t, client.calls, 1)
}

func TestDispatchWakeup_NoTokenSkips(t *testing.T) {
	client := &fakeClient{}
	svc, _ := newSvc(client)

	err := svc.DispatchWakeup(context.Background(), "dev-no-token", "env-1", "conv-1", "", nil)
	require.NoError(t, err)
	assert.Empty(t, client.calls)
}

func TestDispatchWakeup_PropagatesStoreError(t *testing.T) {
	es := &errStore{Store: push.NewStoreInMemory(), failGet: errors.New("db down")}
	svc := push.NewService(push.ServiceDeps{Store: es, Client: &fakeClient{}})

	err := svc.DispatchWakeup(context.Background(), "dev-1", "env-1", "conv-1", "", nil)
	assert.Error(t, err)
}

func TestDispatchWakeup_PropagatesClientError(t *testing.T) {
	client := &fakeClient{err: errors.New("apns down")}
	svc, store := newSvc(client)
	require.NoError(t, store.Upsert(context.Background(), push.Token{DeviceID: "dev-1", Platform: "apns", Token: "raw"}))

	err := svc.DispatchWakeup(context.Background(), "dev-1", "env-1", "conv-1", "", nil)
	assert.Error(t, err)
}

func TestCompositeClient_RoutesAPNS(t *testing.T) {
	apns := &fakeClient{}
	fcm := &fakeClient{}
	c := &push.CompositeClient{APNS: apns, FCM: fcm}

	err := c.SendWakeup(context.Background(), push.Token{Platform: "apns"}, map[string]string{"envelope_id": "env-1"})
	require.NoError(t, err)
	assert.Len(t, apns.calls, 1)
	assert.Empty(t, fcm.calls)
}

func TestCompositeClient_RoutesFCM(t *testing.T) {
	apns := &fakeClient{}
	fcm := &fakeClient{}
	c := &push.CompositeClient{APNS: apns, FCM: fcm}

	err := c.SendWakeup(context.Background(), push.Token{Platform: "fcm"}, map[string]string{"envelope_id": "env-1"})
	require.NoError(t, err)
	assert.Len(t, fcm.calls, 1)
	assert.Empty(t, apns.calls)
}

func TestCompositeClient_APNSNotConfigured(t *testing.T) {
	c := &push.CompositeClient{APNS: nil, FCM: &fakeClient{}}
	err := c.SendWakeup(context.Background(), push.Token{Platform: "apns"}, map[string]string{"envelope_id": "env-1"})
	assert.ErrorIs(t, err, push.ErrPushNotConfigured)
}

func TestCompositeClient_FCMNotConfigured(t *testing.T) {
	c := &push.CompositeClient{APNS: &fakeClient{}, FCM: nil}
	err := c.SendWakeup(context.Background(), push.Token{Platform: "fcm"}, map[string]string{"envelope_id": "env-1"})
	assert.ErrorIs(t, err, push.ErrPushNotConfigured)
}

func TestCompositeClient_UnknownPlatform(t *testing.T) {
	c := &push.CompositeClient{APNS: &fakeClient{}, FCM: &fakeClient{}}
	err := c.SendWakeup(context.Background(), push.Token{Platform: "made-up"}, map[string]string{"envelope_id": "env-1"})
	assert.ErrorIs(t, err, push.ErrUnknownPlatform)
}

func TestDispatchWakeup_IncludesEnvelopeIDAndConversationID(t *testing.T) {
	client := &fakeClient{}
	svc, store := newSvc(client)
	require.NoError(t, store.Upsert(context.Background(), push.Token{DeviceID: "dev-bob", Platform: "apns", Token: "raw"}))

	err := svc.DispatchWakeup(context.Background(), "dev-bob", "envelope-123", "conv-456", "call", nil)
	require.NoError(t, err)

	got := client.LastPayload
	if got["envelope_id"] != "envelope-123" {
		t.Fatalf("envelope_id = %v, want envelope-123", got["envelope_id"])
	}
	if got["conversation_id"] != "conv-456" {
		t.Fatalf("conversation_id = %v, want conv-456", got["conversation_id"])
	}
	if got["push_kind"] != "call" {
		t.Fatalf("push_kind = %v, want call", got["push_kind"])
	}
	if _, hasCiphertext := got["ciphertext"]; hasCiphertext {
		t.Fatal("push payload must not contain ciphertext")
	}
}

// TestDispatchWakeup_PayloadShapeIsAnExactAllowList is a metadata-leak canary.
// Everything the server puts in the push DATA map is plaintext to Google/FCM
// (data messages are not encrypted to FCM). We deliberately ship ONLY the
// identifiers the client cannot operate without, and this test pins that exact
// set so a future change can't silently widen what we expose:
//
//   - envelope_id     — REQUIRED. The Android background isolate fires the
//     transport-"delivered" beacon (delivery.ConfirmReceived) keyed on this
//     id WITHOUT decrypting. Dropping it regresses the sender's double-check.
//   - conversation_id — REQUIRED. The background isolate posts the wake
//     notification DIRECTLY from the push (it never decrypts — decrypting in
//     the background would consume the forward-secret ratchet generation and
//     lose the message). conversation_id is the only thing it has to: dedup
//     the notification (id = conversationId.hashCode), honour mute/block,
//     resolve the call ring's caller name, and set the deep-link tap target.
//   - push_kind       — kept only when non-empty ("call"). A category, not a
//     stable per-thread/per-device identifier; needed so a call wakeup rings.
//
//   - sealed_payload  — OPTIONAL, sealed-sender only. The opaque OUTER sealed
//     blob, inlined so the recipient's background isolate can send a closed-app
//     "delivered" receipt without an identity-revealing fetch (see
//     push.DispatchWakeup). Deliberately relaxes the old "no ciphertext in the
//     push" rule, but the exposure is bounded: the bytes are E2EE inside the
//     seal (Google cannot read them) and the length is bucket-padded (reveals
//     no size class). Omitted entirely when absent or over the FCM budget.
//
// See nanb-mobile/docs/fcm-metadata.md for the residual-exposure analysis and
// the redesign that would let conversation_id be dropped.
func TestDispatchWakeup_PayloadShapeIsAnExactAllowList(t *testing.T) {
	client := &fakeClient{}
	svc, store := newSvc(client)
	require.NoError(t, store.Upsert(context.Background(), push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "raw"}))

	t.Run("normal message wakeup omits push_kind and sealed_payload", func(t *testing.T) {
		require.NoError(t, svc.DispatchWakeup(context.Background(), "dev-1", "env-1", "conv-1", "", nil))
		got := client.LastPayload
		// Exactly these keys, nothing more (push_kind + sealed_payload absent).
		assert.Equal(t, map[string]string{
			"envelope_id":     "env-1",
			"conversation_id": "conv-1",
		}, got)
	})

	t.Run("call wakeup adds push_kind and nothing else", func(t *testing.T) {
		require.NoError(t, svc.DispatchWakeup(context.Background(), "dev-1", "env-2", "conv-2", "call", nil))
		got := client.LastPayload
		assert.Equal(t, map[string]string{
			"envelope_id":     "env-2",
			"conversation_id": "conv-2",
			"push_kind":       "call",
		}, got)
	})

	t.Run("sealed wakeup inlines the blob (base64) and nothing else", func(t *testing.T) {
		blob := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02}
		require.NoError(t, svc.DispatchWakeup(context.Background(), "dev-1", "env-3", "conv-3", "", blob))
		assert.Equal(t, map[string]string{
			"envelope_id":     "env-3",
			"conversation_id": "conv-3",
			"sealed_payload":  base64.StdEncoding.EncodeToString(blob),
		}, client.LastPayload)
	})

	t.Run("over-budget sealed blob is dropped (push still sent)", func(t *testing.T) {
		huge := make([]byte, 4096) // base64 ~5462 > maxPushSealedB64
		require.NoError(t, svc.DispatchWakeup(context.Background(), "dev-1", "env-4", "conv-4", "", huge))
		_, has := client.LastPayload["sealed_payload"]
		assert.False(t, has, "an over-budget sealed blob must be omitted, not truncated")
		assert.Equal(t, "env-4", client.LastPayload["envelope_id"])
	})
}
