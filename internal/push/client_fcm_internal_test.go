package push

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nanb/nanb-server/internal/proto"
)

// The wakeup collapse key folds the multiple pushes a single inbound message
// can generate (an MLS migration's Welcome + application envelopes, group /
// self-sync fan-out) into one FCM delivery per conversation+device, so an
// offline device is woken once per thread rather than once per envelope. It
// must stay SCOPED so wakeups for different threads — or different devices of
// the same account — never collapse into each other.
func TestCollapseKeyFor(t *testing.T) {
	t.Run("same device + same conversation collapse together", func(t *testing.T) {
		a := collapseKeyFor("dev-1", "conv-1", "")
		b := collapseKeyFor("dev-1", "conv-1", "")
		if a != b {
			t.Fatalf("expected equal collapse keys, got %q and %q", a, b)
		}
	})

	t.Run("different conversations stay independent", func(t *testing.T) {
		a := collapseKeyFor("dev-1", "conv-1", "")
		b := collapseKeyFor("dev-1", "conv-2", "")
		if a == b {
			t.Fatalf("expected distinct collapse keys per conversation, both were %q", a)
		}
	})

	t.Run("different devices stay independent", func(t *testing.T) {
		a := collapseKeyFor("dev-1", "conv-1", "")
		b := collapseKeyFor("dev-2", "conv-1", "")
		if a == b {
			t.Fatalf("expected distinct collapse keys per device, both were %q", a)
		}
	})

	// A ring and a chat message are different events; a later "New message"
	// wakeup must never replace an undelivered incoming-call ring.
	t.Run("a call never shares a bucket with a message", func(t *testing.T) {
		a := collapseKeyFor("dev-1", "conv-1", "call")
		b := collapseKeyFor("dev-1", "conv-1", "")
		if a == b {
			t.Fatalf("expected distinct collapse keys per kind, both were %q", a)
		}
	})

	// REGRESSION GUARD. Every SEALED envelope is stored (and pushed) with the
	// all-zero sentinel conversation id, so keying the collapse on it put every
	// sealed wakeup for a device in ONE bucket: unrelated threads folded into a
	// single FCM slot and only the last survived. No conversation => no
	// coalescing; an empty key is omitted by the SDK (`omitempty`).
	t.Run("a sealed sentinel conversation disables coalescing entirely", func(t *testing.T) {
		if k := collapseKeyFor("dev-1", proto.SealedSentinelUUID, ""); k != "" {
			t.Fatalf("sealed wakeups must not collapse; got key %q", k)
		}
	})

	t.Run("missing conversation disables coalescing entirely", func(t *testing.T) {
		if k := collapseKeyFor("dev-1", "", ""); k != "" {
			t.Fatalf("a wakeup with no conversation must not collapse; got key %q", k)
		}
	})

	// Privacy note / regression guard: the collapse key intentionally STAYS
	// conversation-scoped. It is tempting to drop conversation_id from the
	// collapse key for privacy, but that yields zero gain while conversation_id
	// must remain in the (FCM-visible, plaintext) data payload for the client to
	// post notifications without decrypting — Google already sees it there. A
	// device-level collapse key would also REGRESS offline coalescing: distinct
	// threads would fold into one FCM slot and only the last wakeup would
	// survive, dropping notifications for the other threads. conversation_id can
	// only leave BOTH places together, after the client redesign documented in
	// nanb-mobile/docs/fcm-metadata.md.
	t.Run("collapse key embeds the conversation (matches the data payload)", func(t *testing.T) {
		k := collapseKeyFor("dev-1", "conv-1", "")
		want := "wakeup:dev-1:msg:conv-1"
		if k != want {
			t.Fatalf("collapse key = %q, want %q", k, want)
		}
	})
}

// iOS does not reliably deliver SILENT content-available pushes to a
// backgrounded app, so a real message must carry a VISIBLE alert in the push
// itself; a control-only "silent" kind stays a silent background push. These
// guard the APNs headers/payload Apple requires for each class.
func TestBuildAPNSConfig(t *testing.T) {
	t.Run("a normal message is a visible alert at priority 10", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", "")
		if cfg == nil || cfg.Payload == nil || cfg.Payload.Aps == nil {
			t.Fatal("expected an aps payload")
		}
		if cfg.Payload.Aps.Alert == nil || cfg.Payload.Aps.Alert.Body != "New message" {
			t.Fatalf("expected a visible 'New message' alert, got %+v", cfg.Payload.Aps.Alert)
		}
		if cfg.Payload.Aps.ContentAvailable {
			t.Fatal("a visible alert must not also be content-available")
		}
		// mutable-content makes iOS launch the Notification Service Extension
		// before showing the banner, so it can send the closed-app delivered
		// receipt + recover the real conversation. Without it the NSE never runs.
		if !cfg.Payload.Aps.MutableContent {
			t.Fatal("a visible alert must set mutable-content so the NSE runs")
		}
		if got := cfg.Headers["apns-push-type"]; got != "alert" {
			t.Fatalf("apns-push-type = %q, want alert", got)
		}
		if got := cfg.Headers["apns-priority"]; got != "10" {
			t.Fatalf("apns-priority = %q, want 10", got)
		}
	})

	t.Run("a call cancel is a silent background push with no alert", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", pushKindCallCancel)
		if cfg.Payload.Aps.Alert != nil {
			t.Fatalf("a call cancel must not show an alert, got %+v", cfg.Payload.Aps.Alert)
		}
		if !cfg.Payload.Aps.ContentAvailable {
			t.Fatal("a call cancel must be content-available so it wakes the app")
		}
		if got := cfg.Headers["apns-push-type"]; got != "background" {
			t.Fatalf("apns-push-type = %q, want background", got)
		}
	})

	t.Run("a call uses an incoming-call alert body", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", "call")
		if cfg.Payload.Aps.Alert == nil || cfg.Payload.Aps.Alert.Body != "Incoming call" {
			t.Fatalf("expected an 'Incoming call' alert, got %+v", cfg.Payload.Aps.Alert)
		}
	})

	t.Run("a silent control kind stays a silent content-available push", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", "silent")
		if !cfg.Payload.Aps.ContentAvailable {
			t.Fatal("silent kind must stay content-available")
		}
		if cfg.Payload.Aps.Alert != nil || cfg.Payload.Aps.Sound != "" {
			t.Fatal("silent kind must carry no alert/sound")
		}
		if cfg.Payload.Aps.MutableContent {
			t.Fatal("a silent control push must not set mutable-content (no banner to enrich)")
		}
		if got := cfg.Headers["apns-push-type"]; got != "background" {
			t.Fatalf("apns-push-type = %q, want background", got)
		}
		if got := cfg.Headers["apns-priority"]; got != "5" {
			t.Fatalf("apns-priority = %q, want 5", got)
		}
	})

	t.Run("collapses on the conversation when present", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", "")
		if got := cfg.Headers["apns-collapse-id"]; got != "msg:conv-1" {
			t.Fatalf("apns-collapse-id = %q, want msg:conv-1", got)
		}
	})

	t.Run("omits the collapse id when no conversation is known", func(t *testing.T) {
		cfg := buildAPNSConfig("", "")
		if _, ok := cfg.Headers["apns-collapse-id"]; ok {
			t.Fatal("apns-collapse-id must be omitted (empty header is invalid)")
		}
	})

	// REGRESSION GUARD (iOS is the worse half of the sealed-sentinel bug: APNs
	// REPLACES a displayed alert that shares a collapse id, so every sealed
	// message notification overwrote the previous one).
	t.Run("omits the collapse id for a sealed sentinel conversation", func(t *testing.T) {
		cfg := buildAPNSConfig(proto.SealedSentinelUUID, "")
		if _, ok := cfg.Headers["apns-collapse-id"]; ok {
			t.Fatal("a sealed push must carry no apns-collapse-id")
		}
	})

	t.Run("a call ring collapses separately from messages", func(t *testing.T) {
		call := buildAPNSConfig("conv-1", "call").Headers["apns-collapse-id"]
		msg := buildAPNSConfig("conv-1", "").Headers["apns-collapse-id"]
		if call == msg {
			t.Fatalf("call and message must not share a collapse id (both %q)", call)
		}
	})

	t.Run("omits the collapse id when it would exceed the 64-byte APNs cap", func(t *testing.T) {
		cfg := buildAPNSConfig(strings.Repeat("x", 65), "")
		if _, ok := cfg.Headers["apns-collapse-id"]; ok {
			t.Fatal("apns-collapse-id over 64 bytes must be omitted")
		}
	})
}

// Android wakeups must be HIGH priority (normal priority is deferred to a Doze
// maintenance window), and only a call may carry a bounded TTL: FCM's default
// lifetime is four weeks, which rang an offline phone for a call long over.
func TestBuildAndroidConfig(t *testing.T) {
	t.Run("a message wakeup is high priority", func(t *testing.T) {
		if got := buildAndroidConfig("dev-1", "conv-1", "").Priority; got != "high" {
			t.Fatalf("priority = %q, want high", got)
		}
	})

	t.Run("a call wakeup is high priority", func(t *testing.T) {
		if got := buildAndroidConfig("dev-1", "conv-1", "call").Priority; got != "high" {
			t.Fatalf("priority = %q, want high", got)
		}
	})

	t.Run("a message wakeup keeps the provider default TTL", func(t *testing.T) {
		if ttl := buildAndroidConfig("dev-1", "conv-1", "").TTL; ttl != nil {
			t.Fatalf("message TTL = %v, want unset (provider default)", *ttl)
		}
	})

	t.Run("a call cancel wakeup is high priority and expires with the ring window", func(t *testing.T) {
		cfg := buildAndroidConfig("dev-1", "conv-1", pushKindCallCancel)
		if cfg.Priority != "high" {
			t.Fatalf("priority = %q, want high", cfg.Priority)
		}
		if cfg.TTL == nil || *cfg.TTL != callWakeupTTL {
			t.Fatalf("call cancel TTL = %v, want %v", cfg.TTL, callWakeupTTL)
		}
	})

	t.Run("a call wakeup expires with the ring window", func(t *testing.T) {
		ttl := buildAndroidConfig("dev-1", "conv-1", "call").TTL
		if ttl == nil || *ttl != callWakeupTTL {
			t.Fatalf("call TTL = %v, want %v", ttl, callWakeupTTL)
		}
	})

	t.Run("the TTL is never zero (a zero TTL is drop-if-offline)", func(t *testing.T) {
		if callWakeupTTL <= 0 {
			t.Fatalf("callWakeupTTL = %v, must be positive", callWakeupTTL)
		}
	})

	t.Run("the collapse key is the scoped wakeup key", func(t *testing.T) {
		got := buildAndroidConfig("dev-1", "conv-1", "").CollapseKey
		if want := collapseKeyFor("dev-1", "conv-1", ""); got != want {
			t.Fatalf("collapse key = %q, want %q", got, want)
		}
	})
}

func TestApplyCallExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)

	t.Run("a call alert expires with the ring window", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", "call")
		applyCallExpiry(cfg, "call", now)
		want := strconv.FormatInt(now.Add(callWakeupTTL).Unix(), 10)
		if got := cfg.Headers["apns-expiration"]; got != want {
			t.Fatalf("apns-expiration = %q, want %q", got, want)
		}
	})

	t.Run("a call cancel expires with the ring window", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", pushKindCallCancel)
		applyCallExpiry(cfg, pushKindCallCancel, now)
		want := strconv.FormatInt(now.Add(callWakeupTTL).Unix(), 10)
		if got := cfg.Headers["apns-expiration"]; got != want {
			t.Fatalf("apns-expiration = %q, want %q", got, want)
		}
	})

	t.Run("a message alert keeps the APNs default lifetime", func(t *testing.T) {
		cfg := buildAPNSConfig("conv-1", "")
		applyCallExpiry(cfg, "", now)
		if got, ok := cfg.Headers["apns-expiration"]; ok {
			t.Fatalf("message alert must not expire early; got apns-expiration %q", got)
		}
	})
}
