package push

import (
	"context"
	"errors"
)

var (
	ErrPushNotConfigured = errors.New("push not configured")
	ErrUnknownPlatform   = errors.New("unknown push platform")
)

// PushClient sends a wakeup ping to a single device.
type PushClient interface {
	SendWakeup(ctx context.Context, t Token, payload map[string]string) error
}

// CompositeClient routes by Platform to the right PushClient.
type CompositeClient struct {
	APNS PushClient
	FCM  PushClient
}

func (c *CompositeClient) SendWakeup(ctx context.Context, t Token, payload map[string]string) error {
	switch t.Platform {
	case "apns":
		if c.APNS == nil {
			return ErrPushNotConfigured
		}
		return c.APNS.SendWakeup(ctx, t, payload)
	case "fcm":
		if c.FCM == nil {
			return ErrPushNotConfigured
		}
		return c.FCM.SendWakeup(ctx, t, payload)
	default:
		return ErrUnknownPlatform
	}
}
