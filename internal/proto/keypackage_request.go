package proto

type PublishKeyPackagesRequest struct {
	KeyPackages [][]byte `json:"key_packages"`

	// Reset marks this batch as REPLACING the device's previously published
	// packages rather than adding to them. Set by a client whose local MLS
	// store was recreated: every package it published before holds a private
	// key it no longer has, so peers that fetch one build a Welcome the device
	// can never process — the same dead-package problem the restore path
	// already purges for (identity.Service.RestoreSession).
	//
	// The client cannot solve this by publishing more: the pool still looks
	// full to the replenisher (low-water 10), and PopOne hands out the dead
	// ones first. The stale rows have to be dropped server-side.
	Reset bool `json:"reset,omitempty"`
}

type PublishKeyPackagesResponse struct {
	StoredCount int `json:"stored_count"`
}

type FetchKeyPackageResponse struct {
	KeyPackage       []byte `json:"key_package"`
	ReplenishNeeded  bool   `json:"replenish_needed"`
	RemainingForUser int    `json:"remaining_for_user"`
}

// DeviceKeyPackage pairs one freshly-consumed KeyPackage with the device it
// belongs to, so a multi-device MLS inviter can add every device of an account
// to a group (one leaf per device).
type DeviceKeyPackage struct {
	DeviceID   string `json:"device_id"`
	KeyPackage []byte `json:"key_package"`
}

// FetchDeviceKeyPackagesResponse returns one KeyPackage per active device of an
// account (every device that has an unconsumed package). Devices with none are
// silently omitted — they simply can't be added to a group until they publish.
type FetchDeviceKeyPackagesResponse struct {
	Devices []DeviceKeyPackage `json:"devices"`
}

type KeyPackageCountResponse struct {
	Count int `json:"count"`
}
