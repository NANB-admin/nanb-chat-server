package identity

// restoreOptions tunes CompleteRestoreSession. Zero value = the default
// takeover behaviour (revoke the account's other devices).
type restoreOptions struct {
	keepOtherDevices bool
}

// RestoreOption customises a phrase restore.
type RestoreOption func(*restoreOptions)

// KeepOtherDevices makes a restore that mints a new device leave the account's
// existing devices active instead of revoking them.
func KeepOtherDevices() RestoreOption {
	return func(o *restoreOptions) { o.keepOtherDevices = true }
}
