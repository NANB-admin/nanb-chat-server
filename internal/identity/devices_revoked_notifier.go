package identity

// DevicesRevokedNotifier is told which devices were just revoked, so their live
// connections can be closed at once. Without it a revoked device kept its open
// WebSocket (it is only refused at the NEXT handshake): the app still showed
// "Connected" and its typing signals were still relayed. Best-effort and
// detached; optional on ServiceDeps (nil disables it).
type DevicesRevokedNotifier interface {
	NotifyDevicesRevoked(deviceIDs []string)
}
