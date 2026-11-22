package proto

type RegisterPushTokenRequest struct {
	// "apns" | "fcm" | "apns_voip". The last is a PushKit token for the iOS
	// CallKit ring and is stored SEPARATELY (see push.PlatformVoip) — an iPhone
	// registers it ALONGSIDE its FCM alert token, not instead of it.
	Platform string `json:"platform"`
	Token    string `json:"token"`
}

type RegisterPushTokenResponse struct {
	OK bool `json:"ok"`
}

type DeletePushTokenResponse struct {
	OK bool `json:"ok"`
}
