package proto

type ErrorCode string

const (
	ErrCodeUsernameTaken       ErrorCode = "username_taken"
	ErrCodeUsernameInvalid     ErrorCode = "username_invalid"
	ErrCodeUsernameOnHold      ErrorCode = "username_on_hold"
	ErrCodeIdentityKeyTaken    ErrorCode = "identity_key_taken"
	ErrCodeBadSignature        ErrorCode = "bad_signature"
	ErrCodeAccountNotFound     ErrorCode = "account_not_found"
	ErrCodeDeviceNotFound      ErrorCode = "device_not_found"
	ErrCodeChallengeNotFound   ErrorCode = "challenge_not_found"
	ErrCodeChallengeExpired    ErrorCode = "challenge_expired"
	ErrCodeKeyPackageInvalid   ErrorCode = "key_package_invalid"
	ErrCodeKeyPackageExhausted ErrorCode = "key_package_exhausted"
	ErrCodeDeviceLimit         ErrorCode = "device_limit"
	ErrCodeInternal            ErrorCode = "internal"

	ErrCodeUnauthorized    ErrorCode = "unauthorized"
	ErrCodeForbidden       ErrorCode = "forbidden"
	ErrCodeBadRequest      ErrorCode = "bad_request"
	ErrCodePayloadTooLarge ErrorCode = "payload_too_large"

	ErrCodeMediaNotFound    ErrorCode = "media_not_found"
	ErrCodeMediaExpired     ErrorCode = "media_expired"
	ErrCodeEnvelopeNotFound ErrorCode = "envelope_not_found"

	// ErrCodeMailboxFull: the recipient device already holds the maximum number
	// of undelivered envelopes, so this new one was not stored. Nothing already
	// queued is ever dropped to make room for it.
	ErrCodeMailboxFull ErrorCode = "mailbox_full"
)

type APIError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
}

func (e APIError) Error() string {
	return string(e.Code) + ": " + e.Message
}
