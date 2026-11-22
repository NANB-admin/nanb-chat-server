package push

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/messaging"
	"google.golang.org/api/option"

	"github.com/nanb/nanb-server/internal/proto"
)

type FCMConfig struct {
	// ServiceAccountJSON contains the bytes of the Firebase service-account JSON key.
	ServiceAccountJSON []byte
}

type FCMClient struct {
	msg *messaging.Client
	now func() time.Time
}

// callWakeupTTL bounds how long FCM / APNs may hold an undelivered incoming-call
// wakeup. A ring is only meaningful while the caller is still ringing; without a
// bound FCM keeps a data message for its default FOUR WEEKS, so a phone that was
// offline (or in deep Doze with the push deferred) during a call rang for it
// whenever it came back — minutes or hours after the caller hung up. Matches the
// PushKit ring's [voipExpiration] so both iOS ring paths and Android agree.
// Message wakeups deliberately keep the provider default: a "New message"
// that arrives late is still true.
const callWakeupTTL = voipExpiration

func NewFCMClient(ctx context.Context, cfg FCMConfig) (*FCMClient, error) {
	app, err := firebase.NewApp(ctx, nil, option.WithCredentialsJSON(cfg.ServiceAccountJSON))
	if err != nil {
		return nil, fmt.Errorf("fcm init: %w", err)
	}
	m, err := app.Messaging(ctx)
	if err != nil {
		return nil, fmt.Errorf("fcm messaging: %w", err)
	}
	return &FCMClient{msg: m, now: time.Now}, nil
}

func (f *FCMClient) SendWakeup(ctx context.Context, t Token, extra map[string]string) error {
	data := map[string]string{
		"v":    "1",
		"type": "wakeup",
	}
	for k, v := range extra {
		data[k] = v
	}
	// Collapse key: one logical inbound message can fan out to the same device
	// across SEVERAL envelopes (e.g. an MLS migration's Welcome + application
	// pair, or a group/self-sync fan-out). Each envelope fires its own wakeup,
	// which without coalescing makes the device buzz once per envelope. Keying
	// the collapse on the conversation tells FCM to fold pending wakeups for the
	// same conversation+device into a single delivery while the device is
	// offline. The client also de-dups on its side (notification id keyed on the
	// conversation), so this is defence-in-depth: it cuts redundant network
	// wakeups, and the body carries no per-envelope content to lose (the wake is
	// generic; the foreground catches up and decrypts every envelope on resume).
	pushKind := extra["push_kind"]
	apnsCfg := buildAPNSConfig(extra["conversation_id"], pushKind)
	applyCallExpiry(apnsCfg, pushKind, f.now())
	_, err := f.msg.Send(ctx, &messaging.Message{
		Token:   t.Token,
		Data:    data,
		Android: buildAndroidConfig(t.DeviceID, extra["conversation_id"], pushKind),
		// iOS path: FCM forwards to APNs. iOS does NOT reliably deliver SILENT
		// content-available pushes to a backgrounded app (unlike Android, whose
		// data-only push wakes a background isolate that posts the notification),
		// so the iOS notification must ride in the push itself as a VISIBLE alert.
		// This block builds that alert (or, for a control-only "silent" kind, a
		// silent background push). Android ignores the APNS block entirely, so its
		// data-only wakeup path is unaffected.
		APNS: apnsCfg,
	})
	// Tag a dead-token rejection so the caller can prune the token instead of
	// retrying it forever; everything else stays retryable.
	return classifyFCMError(err)
}

// buildAndroidConfig builds the Android half of a wakeup: always HIGH priority
// (a normal-priority data message is deferred to a Doze maintenance window, so a
// dozing phone would show the notification minutes late), the conversation-
// scoped collapse key, and — for a call only — a TTL bounded to the ring window
// (see [callWakeupTTL]). A nil TTL leaves FCM's default (four weeks), which is
// what a message wakeup wants.
// pushKindCallCancel is the push_kind of a "stop ringing" call signal (the call
// was answered on another of the user's devices, or the caller gave up). It
// wakes a device whose app is closed or backgrounded so it can dismiss the
// incoming-call ring it is still showing; it shows nothing itself, and a cancel
// older than the ring window is worthless, so it shares the call TTL.
const pushKindCallCancel = "call_cancel"

func buildAndroidConfig(deviceID, conversationID, pushKind string) *messaging.AndroidConfig {
	cfg := &messaging.AndroidConfig{
		Priority:    "high",
		CollapseKey: collapseKeyFor(deviceID, conversationID, pushKind),
	}
	if pushKind == "call" || pushKind == pushKindCallCancel {
		ttl := callWakeupTTL
		cfg.TTL = &ttl
	}
	return cfg
}

// applyCallExpiry bounds an incoming-call alert's APNs lifetime to the ring
// window (see [callWakeupTTL]) so a phone that was unreachable during the call
// doesn't show "Incoming call" for it long afterwards. A no-op for every other
// kind: APNs' default store-and-forward is what a message alert wants.
func applyCallExpiry(cfg *messaging.APNSConfig, pushKind string, now time.Time) {
	if cfg == nil || (pushKind != "call" && pushKind != pushKindCallCancel) {
		return
	}
	if cfg.Headers == nil {
		cfg.Headers = map[string]string{}
	}
	cfg.Headers["apns-expiration"] = strconv.FormatInt(now.Add(callWakeupTTL).Unix(), 10)
}

// buildAPNSConfig builds the APNs half of an iOS wakeup.
//
// For a real message (or a "call"), it is a VISIBLE alert: iOS does NOT reliably
// deliver SILENT content-available pushes to a backgrounded app, so — unlike
// Android, whose data-only push wakes a background isolate that posts the
// notification — nothing would appear unless the alert rides in the push itself.
// The body is generic ("New message" / "Incoming call"): the server is blind to
// the E2EE content (and to the sender under sealed sender), so there is nothing
// to preview, exactly like Android's generic wake notification.
//
// For a control-only "silent" kind it stays a silent content-available push so
// iOS shows nothing. The delivery layer already declines to push "silent" kinds
// (delivery.service shouldPush), so that branch is defensive.
func buildAPNSConfig(conversationID, pushKind string) *messaging.APNSConfig {
	// Coalesce like Android's CollapseKey: APNs folds pushes that share a
	// collapse id, so several envelopes for one thread wake the device once.
	// Keyed on the conversation + kind; omitted when there is no conversation to
	// key on (see [collapsibleConversationID] — critically, every SEALED push
	// carries the same sentinel, and on iOS a shared collapse id makes each new
	// alert REPLACE the last one rather than merely coalescing undelivered ones)
	// or when the id would exceed the 64-byte APNs cap.
	collapse := ""
	if conv := collapsibleConversationID(conversationID); conv != "" {
		collapse = collapseClass(pushKind) + ":" + conv
		if len(collapse) > 64 {
			collapse = ""
		}
	}
	withCollapse := func(h map[string]string) map[string]string {
		if collapse != "" {
			h["apns-collapse-id"] = collapse
		}
		return h
	}

	// A call cancel is silent on iOS too: the app dismisses its ring itself, so
	// no banner (and no sound) may appear for it.
	if pushKind == "silent" || pushKind == pushKindCallCancel {
		return &messaging.APNSConfig{
			Headers: withCollapse(map[string]string{
				"apns-push-type": "background",
				"apns-priority":  "5",
			}),
			Payload: &messaging.APNSPayload{Aps: &messaging.Aps{ContentAvailable: true}},
		}
	}

	body := "New message"
	if pushKind == "call" {
		body = "Incoming call"
	}
	return &messaging.APNSConfig{
		Headers: withCollapse(map[string]string{
			// Visible alerts use the alert push type at priority 10.
			"apns-push-type": "alert",
			"apns-priority":  "10",
		}),
		Payload: &messaging.APNSPayload{
			Aps: &messaging.Aps{
				Alert: &messaging.ApsAlert{Title: "Chat", Body: body},
				Sound: "default",
				// mutable-content makes iOS launch our Notification Service
				// Extension BEFORE showing the banner. Unlike Android (whose
				// data-only push wakes a Dart background isolate), iOS shows a
				// visible alert without running any app code — so the NSE is the
				// only place we can send the closed-app sealed "delivered" receipt
				// (and recover the real conversation for the banner). The data
				// keys (envelope_id, conversation_id, sealed_payload) ride the FCM
				// `data` map, which FCM forwards into the APNs userInfo the NSE
				// reads. Harmless before the NSE ships: the alert just shows
				// normally. Android ignores this whole APNS block.
				MutableContent: true,
			},
		},
	}
}

// collapseKeyFor builds the FCM collapse key for a wakeup. It is scoped to a
// single device + conversation + kind, so wakeups for ONE thread coalesce while
// wakeups for different threads, different devices of the same account, or a
// ring vs a message stay independent. Empty (= no coalescing at all) when there
// is no conversation to key on — see [collapsibleConversationID].
func collapseKeyFor(deviceID, conversationID, pushKind string) string {
	conv := collapsibleConversationID(conversationID)
	if conv == "" {
		return ""
	}
	return "wakeup:" + deviceID + ":" + collapseClass(pushKind) + ":" + conv
}

// collapsibleConversationID returns the conversation a wakeup may coalesce on,
// or "" when this push must NOT be collapsed with any other.
//
// Coalescing needs a real conversation to key on. Under SEALED SENDER there
// isn't one: the server is deliberately blind to the conversation and stores —
// and therefore pushes — [proto.SealedSentinelUUID] for EVERY sealed envelope.
// Keying the collapse on that constant put every sealed wakeup for a device in
// ONE bucket, so unrelated threads folded into a single FCM slot while the
// device was offline (Android) and each new APNs alert REPLACED the previous
// one (iOS) — the user saw a single "New message" no matter how many people had
// written, which reads exactly like "notifications aren't arriving".
//
// With no conversation, the correct behaviour is no coalescing: a duplicate
// wakeup is cheap and the client folds it anyway (its notification id is keyed
// on the REAL conversation, which it recovers from the sealed blob), whereas a
// collapsed-away wakeup is a notification the user never sees.
func collapsibleConversationID(conversationID string) string {
	if conversationID == proto.SealedSentinelUUID {
		return ""
	}
	return conversationID
}

// collapseClass keeps an incoming-call ring in its own coalescing bucket. A
// ring and a chat message in the same thread are different events with
// different urgency, so a later "New message" wakeup must never replace an
// undelivered call ring (or the other way round).
func collapseClass(pushKind string) string {
	// A cancel shares the ring's bucket on purpose: while the device is offline
	// it REPLACES the undelivered ring, so a call that is already over never
	// rings it late.
	if pushKind == "call" || pushKind == pushKindCallCancel {
		return "call"
	}
	return "msg"
}

// LoadFCMServiceAccountFromFile returns the raw JSON bytes for use with NewFCMClient.
func LoadFCMServiceAccountFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fcm service account: %w", err)
	}
	return data, nil
}
