package proto

import "time"

// Device kinds (identity_db.devices.kind).
const (
	DeviceKindPhone = "phone"
	DeviceKindWeb   = "web"
)

// ValidDeviceKind reports whether k is an accepted device kind.
func ValidDeviceKind(k string) bool {
	return k == DeviceKindPhone || k == DeviceKindWeb
}

// ActiveAt is the single in-code definition of "not expired": a device with no
// expires_at never expires; otherwise it is active strictly before expires_at
// (expires_at <= now means expired). The Postgres equivalent is
// identity.deviceLiveSQL; revocation is handled separately (revoked rows are
// never returned by the active-device queries).
func (d Device) ActiveAt(now time.Time) bool {
	return d.ExpiresAt == nil || now.Before(*d.ExpiresAt)
}
