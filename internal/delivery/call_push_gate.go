package delivery

import (
	"time"

	"golang.org/x/time/rate"

	"github.com/nanb/nanb-server/internal/proto"
	"github.com/nanb/nanb-server/internal/ratelimit"
)

// PushKindCall is the sender-chosen push_kind that makes a closed iPhone ring
// (VoIP/CallKit) and an Android phone show a full-screen incoming call.
const PushKindCall = "call"

// The server has NO contact graph — envelopes are deleted on ack and sealed
// ones carry no sender — so it cannot tell whether a caller "knows" the callee.
// Instead the one thing that is abusable, ringing a stranger's phone over and
// over, is rate-limited. NORMAL message pushes are never gated.
//
// Budgets count call PUSHES, and one call invite fans out one push per
// recipient DEVICE (a 3-device callee is 3 pushes, a group call one per member
// device), so the numbers are sized in pushes, not calls:
//   - per sender -> recipient account: 12/min (a few calls a minute, even to a
//     multi-device callee) — a harasser redialling one victim is throttled.
//   - per sender: 60/min (a full 8-way group ring is ~20 pushes) — one device
//     can't ring a list of strangers in bulk.
//   - per recipient account, for UNAUTHENTICATED sealed sends where the sender
//     is unknowable: 12/min — the only handle available.
const (
	callPairBurst        = 12
	callPairRefill       = 5 * time.Second
	callSenderBurst      = 60
	callSenderRefill     = time.Second
	callRecipientBurst   = 12
	callRecipientRefill  = 5 * time.Second
	callGateMaxKeys      = 100_000
	callGateKeyPairSep   = ">"
	callGateRecipientKey = "recipient:"
)

// CallPushGate decides whether a call-kind push may ring the recipient. When it
// says no the envelope is STILL stored and delivered; only the ring is
// downgraded to an ordinary message wakeup (see Service.SubmitMessage), so spam
// never loses a message and a real call degrades to a banner rather than failing.
type CallPushGate struct {
	pair      *ratelimit.Keyed
	sender    *ratelimit.Keyed
	recipient *ratelimit.Keyed
}

// NewCallPushGate builds the gate with the production budgets. now is
// injectable for tests; nil means time.Now.
func NewCallPushGate(now func() time.Time) *CallPushGate {
	keyed := func(burst int, refill time.Duration) *ratelimit.Keyed {
		return ratelimit.NewKeyed(ratelimit.KeyedConfig{
			Rate: rate.Every(refill), Burst: burst, MaxKeys: callGateMaxKeys,
		}, now)
	}
	return &CallPushGate{
		pair:      keyed(callPairBurst, callPairRefill),
		sender:    keyed(callSenderBurst, callSenderRefill),
		recipient: keyed(callRecipientBurst, callRecipientRefill),
	}
}

// Allow spends one call-push token for senderDeviceID ringing recipientAccountID
// and reports whether the ring may proceed. An unauthenticated sealed sender
// (the zero-UUID sentinel) is charged to the recipient alone.
func (g *CallPushGate) Allow(senderDeviceID, recipientAccountID string) bool {
	if senderDeviceID == proto.SealedSentinelUUID {
		return g.recipient.Allow(callGateRecipientKey + recipientAccountID)
	}
	if !g.pair.Allow(senderDeviceID + callGateKeyPairSep + recipientAccountID) {
		return false
	}
	return g.sender.Allow(senderDeviceID)
}
