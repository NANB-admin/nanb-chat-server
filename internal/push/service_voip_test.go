package push_test

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/push"
)

type fakeVoipClient struct {
	sent []push.VoipToken
	err  error
	last map[string]string
}

func (f *fakeVoipClient) SendVoipWakeup(_ context.Context, t push.VoipToken, payload map[string]string) error {
	if f.err != nil {
		return f.err
	}
	f.sent = append(f.sent, t)
	f.last = payload
	return nil
}

func newVoipSvc(client push.PushClient, voip push.VoipPushClient) (
	*push.Service, *push.StoreInMemory, *push.VoipStoreInMemory,
) {
	store := push.NewStoreInMemory()
	vstore := push.NewVoipStoreInMemory()
	svc := push.NewService(push.ServiceDeps{
		Store:      store,
		Client:     client,
		VoipStore:  vstore,
		VoipClient: voip,
	})
	return svc, store, vstore
}

// A PushKit token must land in its OWN table: the same iPhone also registers an
// FCM alert token, and push_tokens holds one row per device — so storing it
// alongside would evict whichever registered first.
func TestRegisterToken_VoipGoesToItsOwnStore(t *testing.T) {
	svc, store, vstore := newVoipSvc(&fakeClient{}, &fakeVoipClient{})
	ctx := context.Background()

	require.NoError(t, svc.RegisterToken(ctx, "acc-1", "dev-1",
		proto.RegisterPushTokenRequest{Platform: "fcm", Token: "alert-tok"}))
	require.NoError(t, svc.RegisterToken(ctx, "acc-1", "dev-1",
		proto.RegisterPushTokenRequest{Platform: push.PlatformVoip, Token: "voip-tok"}))

	alert, err := store.GetByDeviceID(ctx, "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "alert-tok", alert.Token, "the alert token must survive")

	voip, err := vstore.GetByDeviceID(ctx, "dev-1")
	require.NoError(t, err)
	assert.Equal(t, "voip-tok", voip.Token)
}

func TestRegisterToken_VoipIsANoOpWhenUnconfigured(t *testing.T) {
	svc, _ := newSvc(&fakeClient{}) // no VoipStore wired
	err := svc.RegisterToken(context.Background(), "acc-1", "dev-1",
		proto.RegisterPushTokenRequest{Platform: push.PlatformVoip, Token: "voip-tok"})
	assert.NoError(t, err, "a deployment without VoIP must not fail the client's registration")
}

// "Stop pushing at me" has to cover BOTH tokens, or the phone keeps ringing
// after the user turns push off.
func TestDeleteToken_DropsTheVoipTokenToo(t *testing.T) {
	svc, _, vstore := newVoipSvc(&fakeClient{}, &fakeVoipClient{})
	ctx := context.Background()
	require.NoError(t, svc.RegisterToken(ctx, "acc-1", "dev-1",
		proto.RegisterPushTokenRequest{Platform: push.PlatformVoip, Token: "voip-tok"}))

	require.NoError(t, svc.DeleteToken(ctx, "dev-1"))

	_, err := vstore.GetByDeviceID(ctx, "dev-1")
	assert.ErrorIs(t, err, push.ErrNotFound)
}

func TestDispatchWakeup_CallRingsOverVoipWhenRegistered(t *testing.T) {
	alert := &fakeClient{}
	voip := &fakeVoipClient{}
	svc, store, vstore := newVoipSvc(alert, voip)
	ctx := context.Background()
	require.NoError(t, store.Upsert(ctx, push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "alert-tok"}))
	require.NoError(t, vstore.Upsert(ctx, push.VoipToken{DeviceID: "dev-1", Token: "voip-tok"}))

	require.NoError(t, svc.DispatchWakeup(ctx, "dev-1", "env-1", "conv-1", "call", nil))

	require.Len(t, voip.sent, 1)
	assert.Equal(t, "voip-tok", voip.sent[0].Token)
	assert.Equal(t, "call", voip.last["push_kind"])
	assert.Empty(t, alert.calls, "a VoIP ring must not ALSO fire the banner push")
}

// Only a ring is worth a VoIP push; a chat message must stay on the alert path
// (iOS terminates an app that takes VoIP pushes it doesn't report to CallKit).
func TestDispatchWakeup_MessagesStayOnTheAlertPath(t *testing.T) {
	alert := &fakeClient{}
	voip := &fakeVoipClient{}
	svc, store, vstore := newVoipSvc(alert, voip)
	ctx := context.Background()
	require.NoError(t, store.Upsert(ctx, push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "alert-tok"}))
	require.NoError(t, vstore.Upsert(ctx, push.VoipToken{DeviceID: "dev-1", Token: "voip-tok"}))

	require.NoError(t, svc.DispatchWakeup(ctx, "dev-1", "env-1", "conv-1", "", nil))

	assert.Empty(t, voip.sent)
	assert.Len(t, alert.calls, 1)
}

// A "stop ringing" cancel must reach an iPhone that is showing a CallKit ring,
// and only a VoIP push can wake a suspended one — so it takes the PushKit route
// when the device has a token. (The native side reports and ends a throwaway
// call for it, as iOS requires of every VoIP push.)
func TestDispatchWakeup_CallCancelGoesOverVoipWhenEnabledAndRegistered(t *testing.T) {
	alert := &fakeClient{}
	voip := &fakeVoipClient{}
	store := push.NewStoreInMemory()
	vstore := push.NewVoipStoreInMemory()
	svc := push.NewService(push.ServiceDeps{
		Store: store, Client: alert, VoipStore: vstore, VoipClient: voip,
		VoipCancelEnabled: true,
	})
	ctx := context.Background()
	require.NoError(t, store.Upsert(ctx, push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "alert-tok"}))
	require.NoError(t, vstore.Upsert(ctx, push.VoipToken{DeviceID: "dev-1", Token: "voip-tok"}))

	require.NoError(t, svc.DispatchWakeup(ctx, "dev-1", "env-1", "conv-1", "call_cancel", nil))

	require.Len(t, voip.sent, 1)
	assert.Equal(t, "call_cancel", voip.last["push_kind"])
	assert.Empty(t, alert.calls, "a VoIP cancel must not ALSO fire the data push")
}

// Off by default: an iOS build that predates the cancel handling would report a
// VoIP cancel to CallKit as a NEW incoming call and ring for it, so the cancel
// stays on the silent data push until the operator turns VoIP cancels on.
func TestDispatchWakeup_CallCancelStaysOnTheDataPushByDefault(t *testing.T) {
	alert := &fakeClient{}
	voip := &fakeVoipClient{}
	svc, store, vstore := newVoipSvc(alert, voip)
	ctx := context.Background()
	require.NoError(t, store.Upsert(ctx, push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "alert-tok"}))
	require.NoError(t, vstore.Upsert(ctx, push.VoipToken{DeviceID: "dev-1", Token: "voip-tok"}))

	require.NoError(t, svc.DispatchWakeup(ctx, "dev-1", "env-1", "conv-1", "call_cancel", nil))

	assert.Empty(t, voip.sent, "an older iPhone build must not be handed a VoIP cancel")
	require.Len(t, alert.calls, 1)
}

// Android (and an iPhone with no VoIP token) still gets the silent data push
// that its background handler uses to dismiss the ring.
func TestDispatchWakeup_CallCancelWithoutAVoipTokenUsesTheDataPush(t *testing.T) {
	alert := &fakeClient{}
	voip := &fakeVoipClient{}
	svc, store, _ := newVoipSvc(alert, voip)
	ctx := context.Background()
	require.NoError(t, store.Upsert(ctx, push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "alert-tok"}))

	require.NoError(t, svc.DispatchWakeup(ctx, "dev-1", "env-1", "conv-1", "call_cancel", nil))

	assert.Empty(t, voip.sent)
	require.Len(t, alert.calls, 1)
}

func TestDispatchWakeup_NoVoipTokenFallsBackToTheAlertRing(t *testing.T) {
	alert := &fakeClient{}
	voip := &fakeVoipClient{}
	svc, store, _ := newVoipSvc(alert, voip)
	ctx := context.Background()
	require.NoError(t, store.Upsert(ctx, push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "alert-tok"}))

	require.NoError(t, svc.DispatchWakeup(ctx, "dev-1", "env-1", "conv-1", "call", nil))

	assert.Empty(t, voip.sent)
	require.Len(t, alert.calls, 1, "an Android device must still ring the old way")
}

// A stale VoIP token must never SWALLOW the ring: the callee still gets the
// banner, and the dead token is pruned so we stop trying it.
func TestDispatchWakeup_AVoipFailureFallsBackAndPrunesADeadToken(t *testing.T) {
	alert := &fakeClient{}
	voip := &fakeVoipClient{err: errors.Join(errors.New("BadDeviceToken"), push.ErrTokenInvalid)}
	svc, store, vstore := newVoipSvc(alert, voip)
	ctx := context.Background()
	require.NoError(t, store.Upsert(ctx, push.Token{DeviceID: "dev-1", Platform: "fcm", Token: "alert-tok"}))
	require.NoError(t, vstore.Upsert(ctx, push.VoipToken{DeviceID: "dev-1", Token: "voip-tok"}))

	require.NoError(t, svc.DispatchWakeup(ctx, "dev-1", "env-1", "conv-1", "call", nil))

	assert.Len(t, alert.calls, 1, "the ring must still reach the callee")
	_, err := vstore.GetByDeviceID(ctx, "dev-1")
	assert.ErrorIs(t, err, push.ErrNotFound, "a dead VoIP token must be pruned")
}
