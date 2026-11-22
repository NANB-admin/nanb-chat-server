package keypackages

// PublishListener hears that a device has just published KeyPackages. A device
// that had none could not be added to its account's groups; this is the moment
// its sibling devices can add it, so they are told instead of finding out on
// their next reconnect. Optional on ServiceDeps: nil disables it.
type PublishListener interface {
	KeyPackagesPublished(accountID, deviceID string)
}
