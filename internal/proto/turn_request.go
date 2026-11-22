package proto

// TurnCredentialsResponse is a short-lived WebRTC ICE/TURN credential set,
// generated with coturn's use-auth-secret (TURN REST) scheme. The client feeds
// URLs + Username + Credential straight into its RTCPeerConnection iceServers.
type TurnCredentialsResponse struct {
	Username   string   `json:"username"`
	Credential string   `json:"credential"`
	TTL        int      `json:"ttl"`  // seconds the credential stays valid
	URLs       []string `json:"urls"` // turn(s):/stun: URIs
}
