package push

import "context"

// PlatformVoip is the `platform` value a client registers a PushKit (VoIP)
// token under. It is deliberately distinct from "apns": an iPhone holds BOTH at
// once — an FCM-backed ALERT token for message wakeups and this one for CallKit
// ringing — and they are reached over different transports and topics.
const PlatformVoip = "apns_voip"

// VoipToken is a device's PushKit token. Unlike [Token] it carries no platform:
// PushKit is iOS-only, so the store IS the platform.
type VoipToken struct {
	DeviceID  string
	AccountID string
	Token     string
}

// VoipStore persists PushKit tokens. Separate from [Store] because a device has
// one of each and `push_tokens` is keyed by device id alone.
type VoipStore interface {
	Upsert(ctx context.Context, t VoipToken) error
	GetByDeviceID(ctx context.Context, deviceID string) (VoipToken, error)
	Delete(ctx context.Context, deviceID string) error
}

// VoipPushClient sends one VoIP push. Implemented by [APNSVoipClient]; injected
// so the service is testable without APNs.
type VoipPushClient interface {
	SendVoipWakeup(ctx context.Context, t VoipToken, payload map[string]string) error
}
