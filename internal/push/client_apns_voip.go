package push

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/sideshow/apns2"
)

// errWrongAPNSEnvironment marks the ONE rejection that a token minted for the
// other APNs environment produces. Narrower than [ErrTokenInvalid] on purpose:
// Unregistered / DeviceTokenNotForTopic really are terminal, and re-sending
// those to the other host would just double the failed traffic.
var errWrongAPNSEnvironment = errors.New("apns: token may belong to the other environment")

// voipExpiration bounds how long APNs may keep retrying an undelivered ring.
// A call invite is worthless once the caller has given up (the client's
// outgoing-ring window is 60s), and a VoIP push delivered after that would
// make a dead call ring on the callee's phone — so it must EXPIRE, not queue.
const voipExpiration = 45 * time.Second

// APNSVoipClient sends PushKit (VoIP) pushes straight to APNs.
//
// It cannot go through FCM: FCM speaks only the standard alert/background APNs
// shapes, while a VoIP push needs `apns-push-type: voip` on the dedicated
// `<bundleID>.voip` topic. That topic is also why this can't reuse
// [APNSClient] — same auth key, different topic and push type.
//
// The point of it is CallKit: iOS hands a VoIP push to the app even when it is
// suspended or was never launched, and the app must report it to CallKit
// immediately — which is what makes a locked iPhone ring like a phone call
// instead of showing a banner it will silently replace.
type APNSVoipClient struct {
	primary *apns2.Client
	// fallback is the OTHER APNs environment. A PushKit token belongs to the
	// environment the app was SIGNED for, and this fleet legitimately runs
	// both at once: a TestFlight/App Store build registers a production token,
	// while the same commit sideloaded (re-signed with a development profile)
	// registers a sandbox one. Sending a token to the wrong host is rejected
	// with BadDeviceToken — indistinguishable, on its face, from an uninstalled
	// app — so one fixed environment would silently stop half the fleet from
	// ringing AND prune their tokens as "dead". Trying the other host on that
	// specific rejection makes the deployment environment-agnostic.
	fallback *apns2.Client
	topic    string
}

// NewAPNSVoipClient builds the VoIP sender from the SAME APNs auth key as
// [NewAPNSClient]; only the topic and push type differ. [primary] is the
// environment tried first (production for a store build); [fallback] may be nil
// to disable the cross-environment retry.
func NewAPNSVoipClient(primary, fallback *apns2.Client, bundleID string) *APNSVoipClient {
	return &APNSVoipClient{primary: primary, fallback: fallback, topic: bundleID + ".voip"}
}

func (a *APNSVoipClient) SendVoipWakeup(_ context.Context, t VoipToken, extra map[string]string) error {
	// A VoIP payload carries NO `aps` alert — iOS shows nothing itself; the app
	// gets the raw payload and owns the ringing UI via CallKit. So the body is
	// just our routing keys (envelope_id, conversation_id, push_kind, and the
	// inlined sealed blob when it fits), exactly as the FCM data map carries.
	body, err := json.Marshal(extra)
	if err != nil {
		return fmt.Errorf("voip payload: %w", err)
	}
	n := &apns2.Notification{
		DeviceToken: t.Token,
		Topic:       a.topic,
		PushType:    apns2.PushTypeVOIP,
		Priority:    apns2.PriorityHigh,
		Expiration:  time.Now().Add(voipExpiration),
		Payload:     body,
	}
	err = pushVoipOnce(a.primary, n)
	// BadDeviceToken is the signature of a token minted for the OTHER APNs
	// environment as well as of a genuinely dead one, so try the other host
	// before believing it. Anything else (a real failure, or success) stands.
	if a.fallback != nil && errors.Is(err, errWrongAPNSEnvironment) {
		fbErr := pushVoipOnce(a.fallback, n)
		if fbErr == nil {
			return nil
		}
		// Do NOT let this prune the token. The primary's BadDeviceToken only
		// says "not a token for THIS environment"; when the other environment
		// rejected our AUTH KEY (BadEnvironmentKeyInToken) rather than the
		// token, the token is likely fine and the fault is ours. Pruning on
		// that deleted a LIVE token and silently disabled CallKit until the app
		// was next opened — so one config error became a lasting outage.
		// Observed 2026-08-20.
		if !errors.Is(fbErr, ErrTokenInvalid) {
			return fmt.Errorf(
				"voip push failed on both environments (keeping token): %v; other environment: %v",
				err, fbErr)
		}
		// Report BOTH outcomes. Returning only the primary's error made the two
		// environments indistinguishable in the log: a fallback that failed for
		// a DIFFERENT reason (bad auth key, wrong team, a network blip) read
		// exactly like "this token is dead on both hosts". That ambiguity is
		// what made a live BadDeviceToken undiagnosable from the server side.
		// %w keeps the primary wrapped, so ErrTokenInvalid still drives pruning.
		return fmt.Errorf("%w (other environment: %v)", err, fbErr)
	}
	return err
}

// pushVoipOnce sends to one APNs host and normalises the outcome.
func pushVoipOnce(cli *apns2.Client, n *apns2.Notification) error {
	resp, err := cli.Push(n)
	if err != nil {
		return err
	}
	if resp.Sent() {
		return nil
	}
	// Same classification as the alert path: a rejection naming a dead token is
	// wrapped so the caller prunes it, everything else stays retryable.
	if apnsReasonIsDeadToken(resp.Reason) {
		base := fmt.Errorf("apns voip push rejected: %s (%s): %w", resp.Reason, resp.ApnsID, ErrTokenInvalid)
		if resp.Reason == apns2.ReasonBadDeviceToken {
			return errors.Join(base, errWrongAPNSEnvironment)
		}
		return base
	}
	return fmt.Errorf("apns voip push rejected: %s (%s)", resp.Reason, resp.ApnsID)
}
