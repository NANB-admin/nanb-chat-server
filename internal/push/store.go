package push

import (
	"context"
	"errors"
)

var ErrNotFound = errors.New("token not found")

type Token struct {
	DeviceID  string
	AccountID string
	Platform  string
	Token     string
}

type Store interface {
	Upsert(ctx context.Context, t Token) error
	GetByDeviceID(ctx context.Context, deviceID string) (Token, error)
	Delete(ctx context.Context, deviceID string) error
}
