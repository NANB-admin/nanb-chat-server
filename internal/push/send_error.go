package push

import (
	"errors"

	"firebase.google.com/go/v4/messaging"
)

// ErrTokenInvalid marks a send failure the device token itself caused: the app
// was uninstalled, the token was reissued, or it belongs to another sender /
// topic. Retrying is pointless and the row should be dropped from push_tokens
// so the device stops being pushed at until it re-registers.
//
// Both clients wrap it, so callers classify with errors.Is and never by string.
var ErrTokenInvalid = errors.New("push token invalid")

// IsPermanentSendError reports whether [err] can never succeed on retry, so the
// caller must give up instead of queueing the push. Anything else (network
// error, provider 5xx, throttle) is treated as transient and retried — the
// safe default, since a wrongly-retried push costs one duplicate wakeup that
// the client's conversation-keyed collapse folds away, while a wrongly-dropped
// one is a notification the user never sees.
func IsPermanentSendError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrTokenInvalid) {
		return true
	}
	if errors.Is(err, ErrPushNotConfigured) || errors.Is(err, ErrUnknownPlatform) {
		// Misconfiguration, not a transient fault: retrying every device's push
		// forever would just fill the queue until someone fixes the deployment.
		return true
	}
	return false
}

// IsDeadTokenError reports whether [err] proves the stored device token is
// dead, so it should be deleted rather than left to fail on every future send.
func IsDeadTokenError(err error) bool {
	return err != nil && errors.Is(err, ErrTokenInvalid)
}

// classifyFCMError maps a Firebase Admin SDK send error onto [ErrTokenInvalid]
// where it identifies a dead token, and passes everything else through
// unchanged (so it stays retryable).
//
//   - Unregistered: the app was uninstalled or the token expired/rotated.
//   - SenderIDMismatch: the token belongs to a different Firebase project.
//   - InvalidArgument: FCM rejected the token string itself as malformed.
//
// Unavailable / Internal / QuotaExceeded are deliberately NOT here — those are
// exactly the transient faults the retry queue exists for.
func classifyFCMError(err error) error {
	if err == nil {
		return nil
	}
	if messaging.IsUnregistered(err) ||
		messaging.IsSenderIDMismatch(err) ||
		messaging.IsInvalidArgument(err) {
		return errors.Join(err, ErrTokenInvalid)
	}
	return err
}

// apnsReasonIsDeadToken reports whether an APNs rejection reason identifies a
// dead device token (as opposed to a transient failure or our own bug).
// Reference: APNs "Handling Notification Responses from APNs".
func apnsReasonIsDeadToken(reason string) bool {
	switch reason {
	case "BadDeviceToken", "Unregistered", "DeviceTokenNotForTopic":
		return true
	default:
		return false
	}
}
