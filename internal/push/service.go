package push

import (
	"context"
	"encoding/base64"
	"errors"
	"log"
	"time"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/proto"
)

// maxPushSealedB64 caps the base64 length of a sealed blob we inline into the
// FCM data payload. FCM data messages are limited to ~4 KiB total; staying well
// under it (room for the other fields + FCM framing) means a larger sealed
// message simply ships WITHOUT the inlined blob — the push still wakes the
// device, it just can't trigger the closed-app "delivered" receipt for that
// one (the end-to-end receipt on next foreground remains the backstop).
const maxPushSealedB64 = 3000

// encodeSealedPayload base64s a sealed outer blob for the provider data map, or
// returns "" when there is none or it exceeds the FCM budget (the push still
// wakes the device; it just can't drive the closed-app "delivered" receipt).
// Shared so a queued retry ships the SAME payload as the original attempt.
func encodeSealedPayload(sealed []byte) string {
	if len(sealed) == 0 {
		return ""
	}
	b64 := base64.StdEncoding.EncodeToString(sealed)
	if len(b64) > maxPushSealedB64 {
		return ""
	}
	return b64
}

// firstRetryDelay is how long after a failed first send the retry worker tries
// again. Short enough that a notification arriving late is still useful, long
// enough to ride out the blip that caused the failure.
const firstRetryDelay = 15 * time.Second

type ServiceDeps struct {
	Store  Store
	Client PushClient
	// VoipStore / VoipClient carry the iOS CallKit ring. Both optional: nil
	// leaves every push on the ordinary alert path, which is what Android uses
	// and what iOS falls back to when a device has no PushKit token yet.
	VoipStore  VoipStore
	VoipClient VoipPushClient
	// VoipCancelEnabled sends a "stop ringing" cancel to an iPhone as a VoIP push
	// too. OFF by default: an iOS build that predates the cancel handling would
	// report that push to CallKit as a brand-new incoming call and RING for it,
	// so this is switched on (NANB_VOIP_CANCEL=true) only once every iPhone is on
	// a build that understands it. Android is unaffected (its data push is silent).
	VoipCancelEnabled bool
	// Outbox durably queues a push whose first send failed so the retry worker
	// can try again. Optional: nil keeps the pre-outbox behaviour (one attempt,
	// failure is logged and lost).
	Outbox Outbox
	// Now is injectable so retry scheduling is testable. Defaults to time.Now.
	Now func() time.Time
}

type Service struct {
	deps ServiceDeps
}

func NewService(deps ServiceDeps) *Service {
	if deps.Now == nil {
		deps.Now = time.Now
	}
	return &Service{deps: deps}
}

func (s *Service) RegisterToken(ctx context.Context, accountID, deviceID string, req proto.RegisterPushTokenRequest) error {
	if req.Platform != "apns" && req.Platform != "fcm" && req.Platform != PlatformVoip {
		return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "unknown platform"}
	}
	if req.Token == "" {
		return proto.APIError{Code: proto.ErrCodeBadRequest, Message: "empty token"}
	}
	// A PushKit token lives in its own table: the SAME device also registers an
	// FCM alert token, and push_tokens holds one row per device.
	if req.Platform == PlatformVoip {
		if s.deps.VoipStore == nil {
			// VoIP isn't configured on this deployment. Not an error the client can
			// act on — it keeps its alert token and rings the old way.
			return nil
		}
		if err := s.deps.VoipStore.Upsert(ctx, VoipToken{
			DeviceID:  deviceID,
			AccountID: accountID,
			Token:     req.Token,
		}); err != nil {
			return apierr.Internal(err)
		}
		return nil
	}
	if err := s.deps.Store.Upsert(ctx, Token{
		DeviceID:  deviceID,
		AccountID: accountID,
		Platform:  req.Platform,
		Token:     req.Token,
	}); err != nil {
		return apierr.Internal(err)
	}
	return nil
}

func (s *Service) DeleteToken(ctx context.Context, deviceID string) error {
	// Drop BOTH of the device's tokens: "stop pushing at me" must not leave the
	// VoIP one behind, or the phone would still ring after the user turned push
	// off (and a re-registered device would ring under a stale token).
	if s.deps.VoipStore != nil {
		if err := s.deps.VoipStore.Delete(ctx, deviceID); err != nil {
			log.Printf("push: delete voip token for device %s: %v", deviceID, err)
		}
	}
	if err := s.deps.Store.Delete(ctx, deviceID); err != nil {
		return apierr.Internal(err)
	}
	return nil
}

// DispatchWakeup looks up the token for `deviceID` and fires a push.
// "No token registered" is not an error; we simply skip.
// The payload includes envelope_id and conversation_id so the receiver can act
// on the wakeup without decrypting.
//
// For a sealed-sender envelope, [sealedPayload] is the opaque outer blob. When
// it fits the FCM budget we inline it (base64) so the recipient's background
// isolate can open the OUTER seal (a static X25519 unwrap — it does NOT advance
// the forward-secret ratchet) to learn the sender and send a sealed "delivered"
// receipt back, WITHOUT an authenticated fetch that would tie its IP to its
// identity for us. The blob is unreadable to Google (E2EE inside the seal) and
// its length is bucket-padded, so this leaks no content or size class. Pass nil
// for non-sealed envelopes to keep the push a pure beacon.
func (s *Service) DispatchWakeup(ctx context.Context, deviceID, envelopeID, conversationID, pushKind string, sealedPayload []byte) error {
	payload := map[string]string{
		"envelope_id":     envelopeID,
		"conversation_id": conversationID,
	}
	// A non-encrypted hint so a call-invite wakeup rings instead of showing a
	// generic "new message". Empty for normal messages.
	if pushKind != "" {
		payload["push_kind"] = pushKind
	}
	if b64 := encodeSealedPayload(sealedPayload); b64 != "" {
		payload["sealed_payload"] = b64
	}
	// A RING goes out over PushKit when the device has a VoIP token, because
	// only a VoIP push can reach a suspended/never-launched iPhone and be handed
	// to CallKit — which is what makes a locked phone actually ring rather than
	// show a banner. Falls through to the ordinary alert push when the device
	// has no VoIP token (Android, or an iPhone that hasn't registered one yet)
	// or when the VoIP send fails, so the callee still gets *something*.
	// A "stop ringing" cancel takes the same PushKit route: only a VoIP push can
	// reach a suspended iPhone that is showing a CallKit ring, so it is the only
	// way to stop that ring. A device with no VoIP token falls through to the
	// ordinary silent data push below.
	if (pushKind == "call" || (pushKind == pushKindCallCancel && s.deps.VoipCancelEnabled)) && s.tryVoipRing(ctx, deviceID, payload) {
		return nil
	}
	item := OutboxItem{
		DeviceID:       deviceID,
		EnvelopeID:     envelopeID,
		ConversationID: conversationID,
		PushKind:       pushKind,
		SealedPayload:  sealedPayload,
	}
	t, err := s.deps.Store.GetByDeviceID(ctx, deviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		// The token lookup itself failed (DB blip) — we don't know whether the
		// device has a token, so queue the push: the retry worker re-reads the
		// token and simply drops the item if there turns out to be none.
		// Returning without queueing was a notification silently lost.
		s.queueRetry(ctx, item)
		return err
	}
	err = s.deps.Client.SendWakeup(ctx, t, payload)
	if err == nil {
		return nil
	}
	s.handleSendFailure(ctx, t, item, err)
	return err
}

// tryVoipRing sends the CallKit ring over PushKit, reporting whether it landed.
//
// Every failure returns false so the caller falls back to the alert push: a
// callee who sees "Incoming call" as a banner is far better off than one who
// gets nothing because their VoIP token had gone stale. A token APNs rejects as
// dead is pruned here, so the fallback becomes permanent until the device
// re-registers (which it does on every connect).
func (s *Service) tryVoipRing(ctx context.Context, deviceID string, payload map[string]string) bool {
	if s.deps.VoipStore == nil || s.deps.VoipClient == nil {
		return false
	}
	vt, err := s.deps.VoipStore.GetByDeviceID(ctx, deviceID)
	if err != nil {
		if !errors.Is(err, ErrNotFound) {
			log.Printf("push: voip token lookup for device %s: %v", deviceID, err)
		}
		return false
	}
	if err := s.deps.VoipClient.SendVoipWakeup(ctx, vt, payload); err != nil {
		log.Printf("push: voip ring for device %s failed: %v", deviceID, err)
		if IsDeadTokenError(err) {
			if delErr := s.deps.VoipStore.Delete(ctx, deviceID); delErr != nil {
				log.Printf("push: prune dead voip token for device %s: %v", deviceID, delErr)
			}
		}
		return false
	}
	return true
}

// handleSendFailure decides what a failed send means for the device and the
// retry queue. A dead token is pruned (and its queue drained) so we stop
// pushing at a device that will never answer; anything else is queued for the
// retry worker, because dropping it is a notification the user never sees.
//
// Best-effort throughout: the caller already returns the send error, so a
// bookkeeping failure here must not mask it.
func (s *Service) handleSendFailure(ctx context.Context, t Token, item OutboxItem, err error) {
	if IsDeadTokenError(err) {
		if delErr := s.deps.Store.Delete(ctx, t.DeviceID); delErr != nil {
			log.Printf("push: prune dead token for device %s: %v", t.DeviceID, delErr)
		}
		if s.deps.Outbox != nil {
			if qErr := s.deps.Outbox.DeleteForDevice(ctx, t.DeviceID); qErr != nil {
				log.Printf("push: drain queue for dead device %s: %v", t.DeviceID, qErr)
			}
		}
		return
	}
	if IsPermanentSendError(err) {
		return
	}
	s.queueRetry(ctx, item)
}

// queueRetry hands a push whose first attempt failed to the retry worker.
// Best-effort: a no-op without an outbox, and a queueing failure is logged
// rather than masking the send error the caller already returns.
func (s *Service) queueRetry(ctx context.Context, item OutboxItem) {
	if s.deps.Outbox == nil {
		return
	}
	now := s.deps.Now()
	item.Attempts = 1
	item.NextAttemptAt = now.Add(firstRetryDelay)
	// Stamped here (Postgres also defaults it) so the worker's age checks — in
	// particular the call-ring window — measure from the original send.
	item.CreatedAt = now
	if qErr := s.deps.Outbox.Enqueue(ctx, item); qErr != nil {
		log.Printf("push: queue retry for device %s: %v", item.DeviceID, qErr)
	}
}
