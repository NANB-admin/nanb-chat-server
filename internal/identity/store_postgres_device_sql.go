package identity

import (
	"github.com/jackc/pgx/v5"

	"github.com/nanb/nanb-server/internal/proto"
)

// deviceLive is the ONE SQL definition of an "active" device: not revoked and
// not expired (expires_at <= now() counts as expired, mirroring
// proto.Device.ActiveAt). alias is a table alias prefix such as "d." or "".
// Every active-device query in this package (and the key-package queries, which
// embed the same predicate) must use it so expiry is treated exactly like
// revocation everywhere. now() is the DB clock, evaluated per statement.
func deviceLive(alias string) string {
	return alias + "revoked_at IS NULL AND (" + alias + "expires_at IS NULL OR " + alias + "expires_at > now())"
}

// deviceColumns is the column list scanDevice expects (no table alias).
const deviceColumns = `device_id, account_id, device_pub_key, x25519_pub_key, display_name, linked_at, ` +
	`supports_sealed, linked_by_device_id, kind, expires_at`

// scanDevice reads one row selected with deviceColumns.
func scanDevice(row pgx.Row) (proto.Device, error) {
	var d proto.Device
	var displayName, linkedBy *string
	if err := row.Scan(&d.DeviceID, &d.AccountID, &d.DevicePubKey, &d.X25519PubKey, &displayName,
		&d.LinkedAt, &d.SupportsSealed, &linkedBy, &d.Kind, &d.ExpiresAt); err != nil {
		return d, err
	}
	if displayName != nil {
		d.DisplayName = *displayName
	}
	if linkedBy != nil {
		d.LinkedByDeviceID = *linkedBy
	}
	return d, nil
}
