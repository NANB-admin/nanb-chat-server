package identity

// DevicesChangedNotifier tells already-connected devices of an account that
// its device list just changed, so they can react immediately (a freshly linked
// device is only pulled into existing MLS 1:1 groups by one of the account's
// OLD devices, which otherwise notices only on its next reconnect). It is
// best-effort and ephemeral: an offline device simply reconciles on its next
// connect, exactly as before. Optional on ServiceDeps — nil disables it.
type DevicesChangedNotifier interface {
	NotifyDevicesChanged(deviceIDs []string)
}
