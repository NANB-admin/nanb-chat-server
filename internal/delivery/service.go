package delivery

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/nanb/nanb-server/internal/apierr"
	"github.com/nanb/nanb-server/internal/proto"
)

// Clock returns "now". Tests inject a fixed implementation.
type Clock interface {
	Now() time.Time
}

// IDGenerator returns a fresh opaque identifier (uuid in production).
type IDGenerator interface {
	Next() string
}

// HubAPI is the subset of Hub the Service depends on. Full Hub lives in hub.go.
type HubAPI interface {
	Broadcast(deviceID string, env proto.Envelope) bool
}

// wakeupDispatchTimeout bounds one recipient's wakeup push (token lookup,
// provider send, and — on failure — the retry-queue insert), which runs on a
// context detached from the sender's request.
const wakeupDispatchTimeout = 10 * time.Second

// Pusher is the subset of push.Service the delivery package depends on.
// Production wires *push.Service; tests inject a fake. Optional — may be nil.
type Pusher interface {
	DispatchWakeup(ctx context.Context, deviceID, envelopeID, conversationID, pushKind string, sealedPayload []byte) error
}

// RecipientResolver reports whether a recipient device is live — an active
// (non-revoked) device on a non-deleted account. Production wires the
// identity store; optional — nil skips the check. Without it, sends to
// deleted accounts are silently accepted into a black hole: the envelope
// is stored for a device that will never fetch it, and the sender sees a
// server ack and assumes delivery.
type RecipientResolver interface {
	RecipientLive(ctx context.Context, deviceID string) (bool, error)

	// AccountForDevice returns the server-authoritative owning account id for an
	// active device (live==true). live==false — with accountID=="" — means the
	// device is revoked or its account is deleted. Used to BIND recipient_account_id
	// to the target device rather than trusting the client-supplied value: a
	// spoofed (recipient_account_id, conversation_id) otherwise let a sender's own
	// device inflate — and evict — ANOTHER account's undelivered FIFO queue.
	AccountForDevice(ctx context.Context, deviceID string) (accountID string, live bool, err error)
}

type ServiceDeps struct {
	Store             Store
	Clock             Clock
	IDGen             IDGenerator
	Hub               HubAPI
	Pusher            Pusher            // optional; if nil, no push fallback
	Recipients        RecipientResolver // optional; if nil, liveness not checked
	EnvelopeRetention time.Duration
	ConversationCap   int
	MaxCiphertextSize int
	// CallPushGate optionally rate-limits push_kind "call" (the ring) per
	// sender -> recipient pair and per sender; nil = unlimited (tests). A
	// throttled ring is downgraded to a normal wakeup, never dropped.
	CallPushGate *CallPushGate
}

type Service struct {
	deps ServiceDeps
}

// ExpiringRecipientResolver is an optional extension of RecipientResolver for
// resolvers that also know when a device stops being active (web devices have
// an expires_at). Caching wrappers use it to never hold a device live past its
// expiry. expiresAt is nil for devices that never expire.
type ExpiringRecipientResolver interface {
	RecipientResolver
	AccountForDeviceExpiry(ctx context.Context, deviceID string) (accountID string, live bool, expiresAt *time.Time, err error)
}

func NewService(deps ServiceDeps) *Service {
	return &Service{deps: deps}
}

var validEnvelopeTypes = map[string]struct{}{
	proto.EnvelopeTypeMLSApplication:    {},
	proto.EnvelopeTypeMLSHandshake:      {},
	proto.EnvelopeTypeMLSWelcome:        {},
	proto.EnvelopeTypeKeyPackagePublish: {},
	proto.EnvelopeTypeMediaEnvelope:     {},
	proto.EnvelopeTypeTextLegacy:        {},
	proto.EnvelopeTypeSealed:            {},
}

const defaultCatchupLimit = 200

// maxCatchupLimit is the hard ceiling on how many envelopes a single catchup
// may return. A client-supplied Limit is clamped to this so a caller cannot ask
// the server to marshal an unbounded result set in one round-trip (memory +
// latency). A device with a larger backlog pages through it across several
// catchups (each advances SinceServerTS).
const maxCatchupLimit = 500

// isGroupManagementEnvelope reports whether envelopeType is an MLS Commit/Welcome:
// protocol traffic with no user-visible content, which must never wake a device
// with a "new message" notification.
func isGroupManagementEnvelope(envelopeType string) bool {
	return envelopeType == proto.EnvelopeTypeMLSHandshake ||
		envelopeType == proto.EnvelopeTypeMLSWelcome
}

func (s *Service) SubmitMessage(ctx context.Context, senderDeviceID string, req proto.SubmitMessageRequest) (proto.SubmitMessageResponse, error) {
	var resp proto.SubmitMessageResponse

	// Sealed-sender (Phase 1): the real conversation is hidden inside the opaque
	// payload, so a sealed envelope legitimately carries no conversation_id. For
	// every other type it's still required.
	sealed := req.EnvelopeType == proto.EnvelopeTypeSealed
	if req.RecipientAccountID == "" || (req.ConversationID == "" && !sealed) {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "missing required fields"}
	}
	if len(req.Ciphertext) == 0 {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "empty ciphertext"}
	}
	if len(req.Ciphertext) > s.deps.MaxCiphertextSize {
		return resp, proto.APIError{Code: proto.ErrCodePayloadTooLarge, Message: "ciphertext exceeds max size"}
	}
	if _, ok := validEnvelopeTypes[req.EnvelopeType]; !ok {
		return resp, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "unknown envelope type"}
	}

	// Sender liveness: deletion only soft-deletes the account — the JWT keeps
	// verifying until expiry, so without this check a freshly-deleted account
	// could keep posting for up to the token lifetime. Same resolver as the
	// recipient check below. SKIPPED for the unauthenticated sealed path
	// (sealed-sender Phase 2): there is no sender to check — senderDeviceID is the
	// zero-UUID sentinel — and authorization there is the recipient's UAK, already
	// verified by the handler before calling in.
	if s.deps.Recipients != nil && senderDeviceID != proto.SealedSentinelUUID {
		live, err := s.deps.Recipients.RecipientLive(ctx, senderDeviceID)
		if err != nil {
			return resp, apierr.Internal(err)
		}
		if !live {
			return resp, proto.APIError{
				Code:    proto.ErrCodeUnauthorized,
				Message: "sender account deleted or device revoked",
			}
		}
	}

	// Validate: exactly one of singular/plural must be present.
	hasSingular := req.RecipientDeviceID != ""
	hasPlural := len(req.RecipientDeviceIDs) > 0
	if hasSingular && hasPlural {
		return resp, proto.APIError{
			Code:    proto.ErrCodeBadRequest,
			Message: "recipient_device_id and recipient_device_ids are mutually exclusive",
		}
	}
	if !hasSingular && !hasPlural {
		return resp, proto.APIError{
			Code:    proto.ErrCodeBadRequest,
			Message: "must provide recipient_device_id or recipient_device_ids",
		}
	}

	// Normalise to a slice. Singular path becomes a 1-element list.
	recipients := req.RecipientDeviceIDs
	if hasSingular {
		recipients = []string{req.RecipientDeviceID}
	}

	// Recipient liveness + server-authoritative account binding. A deleted
	// account's old conversations live on in every peer's app and would
	// otherwise accept sends forever (stored for a revoked device that never
	// fetches; sender sees an ack). 1:1 sends fail loudly with account_not_found
	// so the client can mark the message failed; group fan-outs skip dead
	// members but deliver to the rest.
	//
	// recipient_account_id and conversation_id are CLIENT-supplied, so we cannot
	// trust them: a sender that addressed an envelope to its OWN device while
	// claiming a VICTIM's (recipient_account_id, conversation_id) could inflate
	// the victim's per-conversation queue count.
	// So we DERIVE the owning account from each target device and store THAT,
	// discarding the client's value. (Sealed sends already carry a server-derived
	// account from the UAK check; re-deriving here yields the same value.)
	recipientAccounts := make([]string, len(recipients))
	for i := range recipients {
		recipientAccounts[i] = req.RecipientAccountID // used only when no resolver is wired (tests)
	}
	if s.deps.Recipients != nil {
		if hasSingular {
			acctID, live, err := s.deps.Recipients.AccountForDevice(ctx, recipients[0])
			if err != nil {
				return resp, apierr.Internal(err)
			}
			if !live {
				return resp, proto.APIError{
					Code:    proto.ErrCodeAccountNotFound,
					Message: "recipient account deleted or device revoked",
				}
			}
			recipientAccounts[0] = acctID
		} else {
			// NOTE: the current Flutter client always uses the SINGULAR path
			// (one POST per recipient device) and does group fan-out + partial-
			// failure tolerance client-side (see conversations_notifier
			// sendMessage: it succeeds when at least one device accepts). This
			// plural branch is therefore not exercised in production today — it
			// exists for a future client that submits a whole fan-out in one
			// call. Keep it in sync with the client's "deliver to the reachable,
			// fail only when nobody's left" posture if that switch ever happens.
			liveOnes := make([]string, 0, len(recipients))
			liveAccounts := make([]string, 0, len(recipients))
			for _, r := range recipients {
				acctID, live, err := s.deps.Recipients.AccountForDevice(ctx, r)
				if err != nil {
					return resp, apierr.Internal(err)
				}
				if live {
					liveOnes = append(liveOnes, r)
					liveAccounts = append(liveAccounts, acctID)
				} else {
					log.Printf("delivery: skipping dead recipient device %s", r)
				}
			}
			if len(liveOnes) == 0 {
				return resp, proto.APIError{
					Code:    proto.ErrCodeAccountNotFound,
					Message: "no live recipient devices",
				}
			}
			recipients = liveOnes
			recipientAccounts = liveAccounts
		}
	}

	now := s.deps.Clock.Now()
	// The sender's retention preference can only SHORTEN the envelope's
	// life below the server ceiling — mirrors the media TTL behavior.
	retention := s.deps.EnvelopeRetention
	if req.TTLSeconds > 0 {
		if want := time.Duration(req.TTLSeconds) * time.Second; want < retention {
			retention = want
		}
	}
	expiresAt := now.Add(retention)

	// Sealed-sender (Phase 1): persist NO linking metadata for a sealed envelope
	// — the server must not store the conversation or the sender. (The sender was
	// still JWT-authenticated at submit; we just don't keep it.) Empty strings
	// carry the same zero information as NULL and satisfy the existing NOT NULL
	// columns, so this needs no schema migration.
	storedConversationID := req.ConversationID
	storedSenderDeviceID := senderDeviceID
	if sealed {
		// UUID columns reject "" — use the all-zero sentinel (valid, constant,
		// no info). See proto.SealedSentinelUUID.
		storedConversationID = proto.SealedSentinelUUID
		storedSenderDeviceID = proto.SealedSentinelUUID
	}

	var insertedIDs []string
	for i, recipientDeviceID := range recipients {
		// Per-device mailbox cap: when the device's queue is full, refuse THIS
		// new envelope for this device only. Nothing already queued is ever
		// dropped to make room — evicting the oldest let any authenticated
		// sender (the sealed path stores no sender, so there is nobody to
		// attribute the flood to) push a device past the cap and silently
		// delete its owner's real undelivered messages. A full device in a
		// multi-device fan-out is skipped; the rest still get their copy.
		full, err := s.mailboxFull(ctx, recipientDeviceID, sealed, req.ConversationID)
		if err != nil {
			return proto.SubmitMessageResponse{}, apierr.Internal(err)
		}
		if full {
			log.Printf("delivery: mailbox full for device %s (sealed=%v); new envelope not stored", recipientDeviceID, sealed)
			continue
		}

		envelopeID := s.deps.IDGen.Next()
		recipientAccountID := recipientAccounts[i]

		env := proto.Envelope{
			EnvelopeID:         envelopeID,
			Version:            "v1",
			Domain:             "nanb.link",
			EnvelopeType:       req.EnvelopeType,
			ConversationID:     storedConversationID,
			SenderDeviceID:     storedSenderDeviceID,
			RecipientAccountID: recipientAccountID,
			RecipientDeviceID:  recipientDeviceID,
			Ciphertext:         req.Ciphertext,
			ServerTS:           now,
		}

		if err := s.deps.Store.InsertEnvelope(ctx, env, expiresAt); err != nil {
			return proto.SubmitMessageResponse{}, apierr.Internal(err)
		}

		delivered := s.deps.Hub.Broadcast(recipientDeviceID, env)
		// A call invite MUST ring the callee. The WS hub can report "delivered"
		// to a socket that is actually dead (the app was just swiped away) or to
		// a backgrounded app with no visible UI to ring — in both cases the
		// in-band delivery is silently lost. So for a call push we ALWAYS fire
		// the wakeup too, not only when the hub had no live connection. A truly
		// foreground app receives the FCM data via onMessage (which posts no
		// notification) and rings in-band off the WS frame, so there is no
		// double-ring. Normal messages keep the offline-only fallback.
		//
		// A "silent" envelope is a control/protocol-only message (read receipt,
		// reaction, pin, MLS Welcome, access-key share, non-invite call signal).
		// It carries no user-visible content, so it must NEVER wake a closed
		// device with a "new message" banner — opening a chat fires a read
		// receipt, which otherwise buzzed the offline peer. The recipient applies
		// it on the next foreground catchup instead.
		// ALWAYS wake for anything user-visible — not only when the hub missed.
		// `delivered` means "handed to a registered socket", which is NOT the
		// same as "the user will see it": a backgrounded iOS app keeps its
		// socket registered while the OS suspends the process, so the hub
		// reports delivered, the push is suppressed, and the frame is only
		// processed on next foreground. Result: no notification at all while
		// backgrounded, reported live on an iPhone (Android was unaffected —
		// its socket behaves differently in background). Closed apps worked
		// precisely because iOS tears the socket down, so delivered=false.
		//
		// This is the same reasoning calls already used; the only thing that
		// made messages different was the assumption that a live socket means
		// a live app. Safe against double-notify: pushes are DATA-only and
		// there is no `FirebaseMessaging.onMessage` listener, so a foreground
		// app displays nothing — only `onBackgroundMessage` posts a banner.
		//
		// MLS group-management envelopes (a Commit, a Welcome) are protocol-only
		// too, whatever the client said: linking a device, a re-key, or adding a
		// member sends them to every member device, and with no push hint they
		// were pushed as a generic "New message" — a notification for a message
		// that does not exist (reported when a second device was linked). The
		// recipient applies them on its next foreground catchup. A real chat
		// message in the same group is an application envelope and still pushes.
		pushKind := req.PushKind
		if pushKind == PushKindCall && s.deps.CallPushGate != nil &&
			!s.deps.CallPushGate.Allow(senderDeviceID, recipientAccountID) {
			// Too many rings for this pair/sender: keep the envelope and still
			// wake the device, but as an ordinary message, not a ring.
			log.Printf("delivery: call push throttled for device %s; downgraded to a normal wakeup", recipientDeviceID)
			pushKind = ""
		}
		shouldPush := pushKind != "silent" && !isGroupManagementEnvelope(req.EnvelopeType)
		if shouldPush && s.deps.Pusher != nil {
			// Log the kind + whether the hub already delivered, so a call wakeup
			// (must ring full-screen) is distinguishable from a generic message
			// wakeup, and a misconfigured/stale FCM setup can't fail silently.
			// No conversation id: device + time + conversation would map who
			// talks in which conversation.
			log.Printf("delivery: wakeup device=%s pushKind=%q delivered=%v", recipientDeviceID, pushKind, delivered)
			// Sealed-sender: inline the opaque outer blob so the recipient's
			// background isolate can send a closed-app "delivered" receipt without
			// an identity-revealing fetch. Nil for non-sealed envelopes (push stays
			// a pure beacon). DispatchWakeup drops it if it exceeds the FCM budget.
			var sealedPayload []byte
			if sealed {
				sealedPayload = env.Ciphertext
			}
			// Detached from the request: the envelope is ALREADY stored, so its
			// wakeup must go out even if the sender hangs up now. On a Tor client
			// the HTTP request is routinely abandoned (circuit drop, client
			// timeout) right after the insert — and with the request ctx both the
			// provider send AND the retry-queue insert failed with "context
			// canceled", so the recipient was never notified of a message that
			// was in fact delivered. Bounded so a hung provider can't stall the
			// submit indefinitely.
			pushCtx, cancelPush := context.WithTimeout(context.WithoutCancel(ctx), wakeupDispatchTimeout)
			if err := s.deps.Pusher.DispatchWakeup(pushCtx, recipientDeviceID, env.EnvelopeID, env.ConversationID, pushKind, sealedPayload); err != nil {
				log.Printf("delivery: push wakeup for device %s failed: %v", recipientDeviceID, err)
			}
			cancelPush()
		}

		insertedIDs = append(insertedIDs, envelopeID)
	}

	if len(insertedIDs) == 0 {
		// Every addressed device was full (always the case for a singular
		// send that hit the cap). Say so rather than ack a message that was
		// never stored.
		return proto.SubmitMessageResponse{}, proto.APIError{
			Code:    proto.ErrCodeMailboxFull,
			Message: "recipient device has too many undelivered messages",
		}
	}

	resp.ServerTS = now
	if hasSingular {
		resp.EnvelopeID = insertedIDs[0]
	} else {
		resp.EnvelopeIDs = insertedIDs
	}
	return resp, nil
}

// mailboxFull reports whether recipientDeviceID's queue is already at the cap.
// Scoped to the recipient DEVICE so one device's backlog never blocks another
// device's (or another account's) delivery. A sealed envelope has no stored
// conversation, so it is capped per device alone; everything else per (device,
// conversation), keeping the original per-conversation fairness. The check
// precedes the insert, so concurrent submits can overshoot by at most the
// number in flight — harmless, and never at the expense of a queued envelope.
func (s *Service) mailboxFull(ctx context.Context, recipientDeviceID string, sealed bool, conversationID string) (bool, error) {
	if s.deps.ConversationCap <= 0 {
		return false, nil
	}
	var count int
	var err error
	if sealed {
		count, err = s.deps.Store.CountForDevice(ctx, recipientDeviceID)
	} else {
		count, err = s.deps.Store.CountForDeviceConversation(ctx, recipientDeviceID, conversationID)
	}
	if err != nil {
		return false, err
	}
	return count >= s.deps.ConversationCap, nil
}

// DeleteExpired hard-deletes one batch of expired envelopes. Implements
// retention.Cleaner so the retention worker sweeps envelopes alongside
// media — query-time filters already hide expired rows; this reclaims
// the storage.
func (s *Service) DeleteExpired(ctx context.Context, batchSize int) (int, error) {
	return s.deps.Store.DeleteExpiredEnvelopes(ctx, s.deps.Clock.Now(), batchSize)
}

func (s *Service) CatchupMessages(ctx context.Context, deviceID string, req proto.CatchupRequest) (proto.CatchupResponse, error) {
	limit := req.Limit
	if limit <= 0 {
		limit = defaultCatchupLimit
	}
	if limit > maxCatchupLimit {
		limit = maxCatchupLimit
	}
	envs, err := s.deps.Store.CatchupForDevice(ctx, deviceID, req.SinceServerTS, limit)
	if err != nil {
		return proto.CatchupResponse{}, apierr.Internal(err)
	}
	return proto.CatchupResponse{Envelopes: envs}, nil
}

// MaxAckIDs caps one ack: clients batch theirs (at most a catch-up page).
const MaxAckIDs = 1000

func (s *Service) AckMessages(ctx context.Context, deviceID string, req proto.AckRequest) (proto.AckResponse, error) {
	if len(req.EnvelopeIDs) == 0 {
		return proto.AckResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "empty envelope_ids"}
	}
	if len(req.EnvelopeIDs) > MaxAckIDs {
		return proto.AckResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "too many envelope ids"}
	}
	count, err := s.deps.Store.AckEnvelopes(ctx, deviceID, req.EnvelopeIDs, s.deps.Clock.Now())
	if err != nil {
		return proto.AckResponse{}, apierr.Internal(err)
	}
	return proto.AckResponse{AckedCount: count}, nil
}

// IsEnvelopeConsumed reports whether there is nothing left to wake
// recipientDeviceID about for envelopeID — it was acked, or the row is gone.
// Satisfies push.EnvelopeConsumedChecker so the push retry queue can drop a
// queued wakeup for a message the recipient has since pulled, instead of
// buzzing them about something they already read. On error it returns false so
// an unreadable store degrades to "send the retry" (a duplicate wakeup the
// client's conversation-keyed collapse folds away) rather than to silence.
func (s *Service) IsEnvelopeConsumed(ctx context.Context, envelopeID, recipientDeviceID string) (bool, error) {
	return s.deps.Store.EnvelopeConsumed(ctx, envelopeID, recipientDeviceID)
}

// ConfirmReceived records a recipient device's confirmation that a wakeup push
// for envelopeID physically landed, and — on the FIRST such confirmation —
// relays an ephemeral delivery-status signal to the original sender's live
// connection so the sender's UI can show a transport-level "delivered" ahead
// of the recipient opening the app. Best-effort: if the sender is offline the
// signal is dropped and the durable end-to-end receipt (sent once the
// recipient foregrounds) remains the backstop. deviceID is the AUTHENTICATED
// caller — the store enforces that it owns the envelope.
func (s *Service) ConfirmReceived(ctx context.Context, deviceID, envelopeID string) (proto.ConfirmReceivedResponse, error) {
	if envelopeID == "" {
		return proto.ConfirmReceivedResponse{}, proto.APIError{Code: proto.ErrCodeBadRequest, Message: "missing envelope_id"}
	}
	senderDeviceID, conversationID, first, err := s.deps.Store.MarkReceived(ctx, envelopeID, deviceID, s.deps.Clock.Now())
	if err != nil {
		return proto.ConfirmReceivedResponse{}, apierr.Internal(err)
	}
	if !first {
		// Duplicate push, wrong recipient, or missing envelope — all no-ops.
		return proto.ConfirmReceivedResponse{Relayed: false}, nil
	}
	if senderDeviceID == "" || senderDeviceID == proto.SealedSentinelUUID {
		// Sealed-sender (Phase 1): we never stored the real sender (it's the
		// zero-UUID sentinel), so there's nobody to relay the transport
		// "delivered" signal to. The E2EE read receipt remains the delivery
		// signal for sealed messages.
		return proto.ConfirmReceivedResponse{Relayed: false}, nil
	}
	relayed := s.deps.Hub.Broadcast(senderDeviceID, proto.Envelope{
		Version:           "v1",
		Domain:            "nanb.link",
		EnvelopeType:      proto.EnvelopeTypeDeliveryStatus,
		ConversationID:    conversationID,
		SenderDeviceID:    deviceID,       // the recipient device that confirmed
		RecipientDeviceID: senderDeviceID, // the original sender (relay target)
		Ciphertext:        []byte(envelopeID),
	})
	return proto.ConfirmReceivedResponse{Relayed: relayed}, nil
}

// GetEnvelopeByIDForRecipient returns a single envelope, refusing if it
// is not addressed to recipientDeviceID. Used by the iOS NSE to fetch
// the encrypted blob it needs to decrypt for a lockscreen preview.
func (s *Service) GetEnvelopeByIDForRecipient(ctx context.Context, envelopeID, recipientDeviceID string) (proto.Envelope, error) {
	e, err := s.deps.Store.GetEnvelopeByID(ctx, envelopeID, recipientDeviceID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return proto.Envelope{}, proto.APIError{
				Code: proto.ErrCodeEnvelopeNotFound, Message: "envelope not found",
			}
		}
		return proto.Envelope{}, apierr.Internal(err)
	}
	return e, nil
}
